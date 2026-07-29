"""G20 — Disk/volume acquisition & chain-of-custody.

A **deterministic workflow** goal (like G01, not a ReAct loop). Real forensic
acquisition must run on the *live target system* with raw block-device access;
the Svetovid agent loop runs inside a container and cannot image disks.
So instead of actually acquiring, this goal:

  1. **triage**        — enumerates acquisition sources: block devices,
                         mounted volumes, live memory, and any image files
                         already present under ``evidence_path``.
  2. **select_source** — marks each source for acquisition and assigns a
                         target format (E01 for disks, raw for memory) + tool.
  3. **acquire**       — emits a detailed **acquisition plan** (the commands
                         that WOULD run on the target) as the report. Any image
                         files already on disk are treated as already-acquired.
  4. **verify_hashes** — computes SHA-256/MD5 for any present image files
                         (real verification) and describes the post-acquisition
                         verification step for planned sources.
  5. **finalize**      — produces the **chain-of-custody manifest**: case ID,
                         acquisition time, operator, source device serial,
                         image hash, image path, plus a tamper-evident
                         integrity seal over the canonical record.

The output is a structured acquisition manifest + signed chain-of-custody
document, written to ``~/.svetovid/cases/<case>/<inv>/acquisition_manifest.json``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..agent import events as E
from ..config import load_settings
from .base import Goal, GoalNode

# Extensions that indicate an already-acquired forensic image / memory dump.
_DISK_IMAGE_EXTS = (".e01", ".ex01", ".raw", ".dd", ".img", ".aff", ".aff4", ".000")
_MEMORY_IMAGE_EXTS = (".vmem", ".mem", ".lime", ".dmp", ".raw.mem")

# Pseudo-/virtual filesystems we never treat as acquisition sources.
_SKIP_FSTYPES = {
    "proc", "sysfs", "devpts", "tmpfs", "devtmpfs", "cgroup", "cgroup2",
    "mqueue", "shm", "overlay", "squashfs", "fusectl", "fuse.snapfuse",
    "autofs", "rpc_pipefs", "nsfs", "binfmt_misc", "securityfs", "tracefs",
    "debugfs", "pstore", "hugetlbfs", "bpf", "efivarfs",
}


class AcquisitionGoal(Goal):
    id = "G20"
    cluster = "Cross-cutting"
    label = "Evidence acquisition & chain-of-custody"
    description = (
        "Acquire forensic images of disks, memory, and mobile devices with "
        "verified chain-of-custody. Produces E01/raw images with hash "
        "manifests and a signed audit trail."
    )
    input_artifacts = ["B3", "B4", "B5", "B6"]
    tools = ["C11", "C13a", "C13b", "C13c"]
    icon = "hard-drive-download"

    def nodes(self) -> list[GoalNode]:
        return [
            GoalNode("triage", "Triage acquisition sources"),
            GoalNode("select_source", "Select sources & formats"),
            GoalNode("acquire", "Build acquisition plan"),
            GoalNode("verify_hashes", "Verify image hashes"),
            GoalNode("finalize", "Finalize chain-of-custody"),
        ]

    async def run(self, *, investigation_id: str, case_id: str,
                  evidence_path: str, user_prompt: str, bus) -> None:
        out_dir = str(Path.home() / ".svetovid" / "cases" / case_id / investigation_id)
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        operator = self._operator()

        # ---- triage: enumerate what can be acquired ----
        await self._set_node(bus, investigation_id, "triage", "running")
        loop = asyncio.get_event_loop()
        sources = await loop.run_in_executor(None, _enumerate_sources, evidence_path)
        bus.publish(E.agent_thought(
            investigation_id,
            f"Triage found {len(sources)} acquisition source(s): "
            + (", ".join(f"{s['kind']}:{s['identifier']}" for s in sources) or "none"),
        ))
        bus.publish(E.provenance_recorded(investigation_id, {
            "node": "triage", "ts": E._now_iso(),
            "source_count": len(sources),
            "evidence_path": evidence_path,
            "host": socket.gethostname(),
        }))
        await self._set_node(bus, investigation_id, "triage", "done")

        # ---- select_source: assign format + tool to each source ----
        await self._set_node(bus, investigation_id, "select_source", "running")
        selected = self._select_sources(sources)
        bus.publish(E.report_section_added(
            investigation_id, "source_inventory", "Acquisition sources",
            _render_source_table(selected),
        ))
        bus.publish(E.agent_thought(
            investigation_id,
            f"Selected {len(selected)} source(s) for acquisition.",
        ))
        await self._set_node(bus, investigation_id, "select_source", "done")

        # ---- acquire: emit the acquisition plan (no live imaging in-container) ----
        await self._set_node(bus, investigation_id, "acquire", "running")
        plan = self._build_acquisition_plan(
            selected, case_id=case_id, investigation_id=investigation_id,
        )
        bus.publish(E.report_section_added(
            investigation_id, "acquisition_plan", "Acquisition plan",
            _render_acquisition_plan(plan),
        ))
        bus.publish(E.agent_thought(
            investigation_id,
            "Acquisition plan generated. Live imaging requires running on the "
            "target host with raw block-device access (out of scope for the "
            "in-container agent loop).",
        ))
        bus.publish(E.provenance_recorded(investigation_id, {
            "node": "acquire", "ts": E._now_iso(),
            "planned": len([i for i in plan["images"] if i["status"] == "planned"]),
            "already_acquired": len([i for i in plan["images"] if i["status"] == "already_acquired"]),
        }))
        await self._set_node(bus, investigation_id, "acquire", "done")

        # ---- verify_hashes ----
        await self._set_node(bus, investigation_id, "verify_hashes", "running")
        verification = await loop.run_in_executor(None, _verify_hashes, plan, evidence_path)
        bus.publish(E.report_section_added(
            investigation_id, "hash_verification", "Hash verification",
            _render_hash_verification(verification),
        ))
        await self._set_node(bus, investigation_id, "verify_hashes", "done")

        # ---- finalize: chain-of-custody manifest ----
        await self._set_node(bus, investigation_id, "finalize", "running")
        custody = self._build_custody_manifest(
            plan, verification, case_id=case_id, investigation_id=investigation_id,
            operator=operator, evidence_path=evidence_path,
        )
        manifest_path = Path(out_dir) / "acquisition_manifest.json"
        manifest_path.write_text(json.dumps(custody, ensure_ascii=False, indent=2))
        bus.publish(E.report_section_added(
            investigation_id, "chain_of_custody", "Chain-of-custody",
            _render_custody_document(custody),
        ))
        bus.publish(E.report_section_added(
            investigation_id, "summary", "Summary",
            f"**Acquisition manifest complete** — {len(custody['images'])} image(s), "
            f"integrity seal `{custody['integrity_seal']}`. "
            f"Manifest written to `{manifest_path}`.",
        ))
        bus.publish(E.provenance_recorded(investigation_id, {
            "node": "finalize", "ts": custody["acquisition_time"],
            "integrity_seal": custody["integrity_seal"],
            "manifest_path": str(manifest_path),
            "operator": operator,
        }))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    def _operator(self) -> str:
        """Who is performing the acquisition (custody 'taken by' field)."""
        env_op = os.environ.get("SVETOVID_OPERATOR")
        if env_op:
            return env_op
        try:
            provider = load_settings().active_provider
            if provider:
                return f"svetovid-agent ({provider})"
        except Exception:
            pass
        return "svetovid-operator"

    def _select_sources(self, sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Assign each source a target image format + imaging tool."""
        out: list[dict[str, Any]] = []
        for idx, s in enumerate(sources, 1):
            kind = s["kind"]
            if kind == "memory":
                fmt, tool = "raw", "C13c (LiME / winpmem / avml)"
            elif kind == "disk" or kind == "volume":
                fmt, tool = "E01", "C11 (ewfacquire / dc3dd)"
            else:
                fmt, tool = "raw", "C11 (dc3dd)"
            sel = dict(s)
            sel["seq"] = idx
            sel["selected"] = True
            sel["target_format"] = fmt
            sel["tool"] = tool
            out.append(sel)
        return out

    def _build_acquisition_plan(self, selected: list[dict[str, Any]], *,
                                case_id: str, investigation_id: str) -> dict[str, Any]:
        """Produce the acquisition plan: what WOULD be acquired, with commands."""
        images: list[dict[str, Any]] = []
        img_dir = f"{case_id}/{investigation_id}/images"
        for s in selected:
            seq = s["seq"]
            base = f"{img_dir}/src_{seq:03d}_{s['kind']}"
            if s["source"] in ("disk_image", "memory_image"):
                # Already on disk — treat as acquired; we just verify it.
                status = "already_acquired"
                target_path = s["identifier"]
                cmd = "(present on disk — no acquisition command needed; verify hashes only)"
            else:
                status = "planned"
                ext = ".E01" if s["target_format"] == "E01" else ".raw"
                target_path = base + ext
                cmd = _acquisition_command(s, target_path)
            images.append({
                "seq": seq,
                "source_id": s.get("id", f"src_{seq:03d}"),
                "source_kind": s["kind"],
                "source_identifier": s["identifier"],
                "source_serial": s.get("serial"),
                "size_bytes": s.get("size_bytes"),
                "target_format": s["target_format"],
                "target_path": target_path,
                "tool": s["tool"],
                "hash_algorithm": "SHA-256",
                "acquire_command": cmd,
                "status": status,
            })
        return {
            "case_id": case_id,
            "investigation_id": investigation_id,
            "generated_at": E._now_iso(),
            "note": (
                "Live acquisition requires running on the target system with raw "
                "block-device / memory access. This plan records the commands and "
                "targets; the in-container agent loop does not perform imaging."
            ),
            "images": images,
        }

    def _build_custody_manifest(self, plan: dict[str, Any],
                                verification: dict[str, Any], *,
                                case_id: str, investigation_id: str,
                                operator: str, evidence_path: str) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        images: list[dict[str, Any]] = []
        ver_by_path = {v["target_path"]: v for v in verification["results"]}
        for img in plan["images"]:
            ver = ver_by_path.get(img["target_path"], {})
            images.append({
                "seq": img["seq"],
                "source_identifier": img["source_identifier"],
                "source_serial": img.get("source_serial"),
                "source_kind": img["source_kind"],
                "image_path": img["target_path"],
                "image_format": img["target_format"],
                "image_hash": ver.get("sha256") or "pending (computed post-acquisition)",
                "hash_algorithm": img["hash_algorithm"],
                "status": img["status"],
            })
        record = {
            "case_id": case_id,
            "investigation_id": investigation_id,
            "evidence_path": evidence_path,
            "acquisition_time": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "operator": operator,
            "acquisition_host": socket.gethostname(),
            "images": images,
        }
        # Tamper-evident integrity seal over the canonical custody record.
        # A production deployment signs this with the operator's PGP/HSM key;
        # here we emit a SHA-256 digest of the canonical JSON as the seal.
        canonical = json.dumps(record, ensure_ascii=False, sort_keys=True)
        record["integrity_seal"] = f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"
        record["seal_algorithm"] = "SHA-256 over canonical JSON (M10 placeholder for PKI signature)"
        return record


# ---------------------------------------------------------------------------
# Source enumeration (runs on the host/container filesystem; degrades safely)
# ---------------------------------------------------------------------------


def _enumerate_sources(evidence_path: str) -> list[dict[str, Any]]:
    """Discover acquirable sources.

    Order: existing image files first (forensically interesting), then live
    block devices, then mounted volumes, then live memory. Every accessor is
    wrapped defensively — these /proc & /sys entries are absent or unreadable
    inside the agent container, and that's fine.
    """
    sources: list[dict[str, Any]] = []
    seq = 0

    def _next() -> str:
        nonlocal seq
        seq += 1
        return f"src_{seq:03d}"

    # 1. Image / memory files already present under evidence_path.
    root = Path(evidence_path)
    if root.exists():
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            fl = p.name.lower()
            if fl.endswith(_MEMORY_IMAGE_EXTS):
                sources.append(_src(_next(), "memory", str(p), "memory_image",
                                    size_bytes=_file_size(p)))
            elif fl.endswith(_DISK_IMAGE_EXTS):
                sources.append(_src(_next(), "disk", str(p), "disk_image",
                                    size_bytes=_file_size(p)))

    # 2. Live block devices (Linux): /sys/block/<dev>, size in 512-byte sectors.
    try:
        for dev in sorted(os.listdir("/sys/block")):
            if dev.startswith(("loop", "ram", "sr")):  # skip loop/ram/optical
                continue
            sources.append(_src(_next(), "disk", f"/dev/{dev}", "block_device",
                                size_bytes=_block_size(dev),
                                serial=_block_attr(dev, "serial") or _block_attr(dev, "model")))
    except (FileNotFoundError, PermissionError, OSError):
        pass

    # 3. Mounted volumes from /proc/mounts (skip pseudo-filesystems & our own root).
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                _dev, mount, fstype = parts[0], parts[1], parts[2]
                if fstype in _SKIP_FSTYPES:
                    continue
                if _dev in ("/", "rootfs") or not _dev.startswith("/"):
                    continue
                sources.append(_src(_next(), "volume", _dev, "mounted_volume",
                                    extra={"mount": mount, "fstype": fstype}))
    except (FileNotFoundError, PermissionError, OSError):
        pass

    # 4. Live memory sources.
    for memdev in ("/dev/mem", "/proc/kcore"):
        try:
            if os.path.exists(memdev):
                sources.append(_src(_next(), "memory", memdev, "memory_proc"))
        except OSError:
            pass

    return sources


def _src(sid: str, kind: str, identifier: str, source: str, *,
         size_bytes: int | None = None, serial: str | None = None,
         extra: dict[str, Any] | None = None) -> dict[str, Any]:
    label_map = {"disk": "Disk", "volume": "Volume", "memory": "Memory"}
    rec = {
        "id": sid,
        "kind": kind,
        "identifier": identifier,
        "label": f"{label_map.get(kind, kind)} {identifier}",
        "source": source,
        "size_bytes": size_bytes,
        "serial": serial,
    }
    if extra:
        rec.update(extra)
    return rec


def _file_size(p: Path) -> int | None:
    try:
        return p.stat().st_size
    except OSError:
        return None


def _block_size(dev: str) -> int | None:
    try:
        sectors = int((Path("/sys/block") / dev / "size").read_text().strip())
        return sectors * 512
    except Exception:
        return None


def _block_attr(dev: str, attr: str) -> str | None:
    try:
        v = (Path("/sys/block") / dev / "device" / attr).read_text().strip()
        return v or None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Acquisition command synthesis
# ---------------------------------------------------------------------------


def _acquisition_command(source: dict[str, Any], target_path: str) -> str:
    """The command that WOULD run on the live target to acquire this source."""
    ident = source["identifier"]
    fmt = source["target_format"]
    if source["kind"] == "memory":
        # Live RAM: Linux (LiME/avml), Windows (winpmem/WinPmem). We show dc3dd
        # as the hashing/verification backstop for the captured dump.
        return (
            f"# Linux RAM (run on target):  insmod lime.ko 'path={target_path} format=raw'\n"
            f"# Windows RAM (run on target): winpmem_mini_x64.exe {target_path}\n"
            f"# Verify:  dc3dd if={target_path} hash=sha256,md5"
        )
    if fmt == "E01":
        return (
            f"ewfacquire -u -t {target_path[:-4]} -f ewx {ident}   "
            f"# E01 with embedded hashes; or: dc3dd if={ident} of={target_path} "
            f"hash=sha256 conv=noerror,sync"
        )
    return f"dc3dd if={ident} of={target_path} hash=sha256,md5 conv=noerror,sync bs=4M"


# ---------------------------------------------------------------------------
# Hash verification
# ---------------------------------------------------------------------------


def _verify_hashes(plan: dict[str, Any], evidence_path: str) -> dict[str, Any]:
    """Compute real hashes for present image files; mark planned sources pending."""
    results: list[dict[str, Any]] = []
    for img in plan["images"]:
        sha = md5 = None
        note = ""
        path = img["target_path"]
        if img["status"] == "already_acquired" and os.path.isfile(path):
            sha, md5 = _hash_file(Path(path))
            note = "verified against on-disk image"
        else:
            note = "pending — compute SHA-256/MD5 immediately after acquisition"
        results.append({
            "seq": img["seq"],
            "target_path": path,
            "status": img["status"],
            "sha256": sha,
            "md5": md5,
            "note": note,
        })
    return {
        "algorithm": "SHA-256 (primary) + MD5 (legacy corroboration)",
        "results": results,
        "evidence_path": evidence_path,
    }


def _hash_file(p: Path) -> tuple[str | None, str | None]:
    if not p.exists():
        return None, None
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    try:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
                md5.update(chunk)
        return f"sha256:{sha.hexdigest()}", f"md5:{md5.hexdigest()}"
    except OSError:
        return None, None


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _human_bytes(n: int | None) -> str:
    if n is None:
        return "—"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def _render_source_table(selected: list[dict[str, Any]]) -> str:
    if not selected:
        return ("_No acquisition sources detected._ This is expected inside the "
                "agent container — on the target host, block devices, mounted "
                "volumes, and live RAM will be enumerated here.")
    head = ("| # | Kind | Identifier | Source | Size | Serial | Format | Tool |\n"
            "|---|---|---|---|---|---|---|---|")
    rows = []
    for s in selected:
        rows.append(
            f"| {s['seq']} | {s['kind']} | `{s['identifier']}` | "
            f"{s['source']} | {_human_bytes(s.get('size_bytes'))} | "
            f"{s.get('serial') or '—'} | {s['target_format']} | {s['tool']} |"
        )
    return head + "\n" + "\n".join(rows)


def _render_acquisition_plan(plan: dict[str, Any]) -> str:
    lines = [
        "## Acquisition plan",
        "",
        f"_Generated {plan['generated_at']} · case `{plan['case_id']}` · "
        f"investigation `{plan['investigation_id']}`_",
        "",
        f"> {plan['note']}",
        "",
    ]
    if not plan["images"]:
        lines.append("_No sources to acquire._")
        return "\n".join(lines)
    lines += ["| # | Source | Size | Format | Target | Status |",
              "|---|---|---|---|---|---|"]
    for img in plan["images"]:
        lines.append(
            f"| {img['seq']} | `{img['source_identifier']}` "
            f"({img['source_kind']}) | {_human_bytes(img.get('size_bytes'))} | "
            f"{img['target_format']} | `{img['target_path']}` | {img['status']} |"
        )
    lines += ["", "### Commands (run on the live target)", ""]
    for img in plan["images"]:
        lines.append(f"**src {img['seq']}** — `{img['source_identifier']}`:")
        lines.append("")
        lines.append("```")
        lines.append(img["acquire_command"])
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def _render_hash_verification(verification: dict[str, Any]) -> str:
    lines = [
        "## Hash verification",
        "",
        f"_Algorithm: {verification['algorithm']}_",
        "",
    ]
    if not verification["results"]:
        lines.append("_No images to verify._")
        return "\n".join(lines)
    lines += ["| # | Image | SHA-256 | MD5 | Note |", "|---|---|---|---|---|"]
    for r in verification["results"]:
        lines.append(
            f"| {r['seq']} | `{r['target_path']}` | "
            f"`{(r['sha256'] or 'pending')[:24]}…` | "
            f"`{(r['md5'] or 'pending')[:24]}…` | {r['note']} |"
        )
    lines += [
        "",
        "Planned sources are hashed immediately after acquisition and the digest "
        "is recorded in the chain-of-custody manifest below. Any later mismatch "
        "between the acquisition-time hash and a re-verification hash indicates "
        "tampering or corruption and breaks the custody chain.",
    ]
    return "\n".join(lines)


def _render_custody_document(custody: dict[str, Any]) -> str:
    lines = [
        "## Chain-of-custody manifest",
        "",
        f"- **Case ID:** `{custody['case_id']}`",
        f"- **Investigation:** `{custody['investigation_id']}`",
        f"- **Acquisition time (UTC):** {custody['acquisition_time']}",
        f"- **Operator:** {custody['operator']}",
        f"- **Acquisition host:** {custody['acquisition_host']}",
        f"- **Evidence path:** `{custody['evidence_path']}`",
        "",
        "### Custody items",
        "",
        "| # | Source | Serial | Image | Format | Hash | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for img in custody["images"]:
        h = img["image_hash"]
        hshort = h[:24] + "…" if h.startswith("sha256:") else h
        lines.append(
            f"| {img['seq']} | `{img['source_identifier']}` | "
            f"{img.get('source_serial') or '—'} | `{img['image_path']}` | "
            f"{img['image_format']} | `{hshort}` | {img['status']} |"
        )
    lines += [
        "",
        "### Integrity seal",
        "",
        f"```\n{custody['integrity_seal']}\n```",
        "",
        f"_{custody['seal_algorithm']}._ A production deployment replaces this "
        "with a PKI signature (PGP / HSM) over the canonical manifest; the seal "
        "lets any later party detect alteration of the custody record.",
    ]
    return "\n".join(lines)


goal = AcquisitionGoal()
