"""Evidence relationship grapher (EnScript gap — Tool 6).

EnCase's "Find Related" feature auto-discovers links between evidence items:
the same file hash appearing in multiple locations (installers dropped on
several hosts), the same user account surfacing across artifact types, the
same timestamp window implying correlated activity, and parent→child process
chains. No OSS tool does this cross-evidence correlation automatically.

This is a POST-PROCESSING tool: it takes the accumulated JSON from prior tool
calls (flattened evidence items) and emits typed relationships. The discovery
logic is factored into ``find_relationships`` so the unit test can drive it
with synthetic items without Docker.

Relationship types emitted:
  - ``same_hash``       : two items share a SHA/MD5 hash but differ in location
  - ``same_actor``      : two items reference the same username/account
  - ``correlated_time`` : two items fall within a configurable time window
  - ``process_tree``    : a process-creation event links a parent to a child
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

# Window (seconds) within which two timestamps are considered correlated.
DEFAULT_TIME_WINDOW_S = 5.0


def _parse_ts(value: Any) -> datetime | None:
    """Best-effort parse of a timestamp into an aware UTC datetime."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    iso = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _item_hashes(item: dict[str, Any]) -> list[str]:
    """Collect every hash-like value on an item (sha256/sha1/md5/hash)."""
    out: list[str] = []
    for k, v in item.items():
        if not isinstance(v, str):
            continue
        kl = k.lower()
        if "hash" in kl or kl in ("sha256", "sha1", "md5", "sha-256", "sha-1"):
            cleaned = v.strip().lower()
            if cleaned:
                out.append(cleaned)
    return out


def find_relationships(
    items: list[dict[str, Any]],
    time_window_s: float = DEFAULT_TIME_WINDOW_S,
) -> list[dict[str, Any]]:
    """Discover relationships across a flat list of evidence items.

    Each item is a dict; we look for the common keys produced by the other
    Svetovid tools (``file``/``path``/``process``, ``sha256``/``hash``,
    ``user``/``actor``, ``timestamp``/``ts``, and process-creation fields
    ``parent_process``/``process``/``ppid``/``pid``). Host-testable.
    """
    relationships: list[dict[str, Any]] = []

    # --- same_hash: group by hash, emit pairwise within each group --------
    by_hash: dict[str, list[int]] = {}
    for i, item in enumerate(items):
        for h in _item_hashes(item):
            by_hash.setdefault(h, []).append(i)
    for h, idxs in by_hash.items():
        if len(idxs) < 2:
            continue
        for a in range(len(idxs)):
            for b in range(a + 1, len(idxs)):
                ia, ib = idxs[a], idxs[b]
                relationships.append({
                    "type": "same_hash",
                    "source_item": _item_label(items[ia]),
                    "target_item": _item_label(items[ib]),
                    "confidence": 0.99,
                    "detail": f"identical hash {h[:16]}",
                })

    # --- same_actor: group by username/account ---------------------------
    by_actor: dict[str, list[int]] = {}
    for i, item in enumerate(items):
        actor = item.get("user") or item.get("actor") or item.get("username")
        if isinstance(actor, str) and actor.strip():
            by_actor.setdefault(actor.strip().lower(), []).append(i)
    for actor, idxs in by_actor.items():
        if len(idxs) < 2:
            continue
        for a in range(len(idxs)):
            for b in range(a + 1, len(idxs)):
                relationships.append({
                    "type": "same_actor",
                    "source_item": _item_label(items[idxs[a]]),
                    "target_item": _item_label(items[idxs[b]]),
                    "confidence": 0.6,
                    "detail": f"same account '{actor}'",
                })

    # --- correlated_time: items within the window ------------------------
    stamped = []
    for i, item in enumerate(items):
        ts = _parse_ts(item.get("timestamp") or item.get("ts") or item.get("time"))
        if ts is not None:
            stamped.append((ts, i))
    stamped.sort(key=lambda t: t[0])
    for a in range(len(stamped)):
        for b in range(a + 1, len(stamped)):
            delta = (stamped[b][0] - stamped[a][0]).total_seconds()
            if delta > time_window_s:
                break  # sorted; nothing later can be in-window
            ia, ib = stamped[a][1], stamped[b][1]
            relationships.append({
                "type": "correlated_time",
                "source_item": _item_label(items[ia]),
                "target_item": _item_label(items[ib]),
                "confidence": 0.5,
                "detail": f"events within {delta:.2f}s",
            })

    # --- process_tree: parent/child links from process-creation events ---
    for item in items:
        parent = item.get("parent_process") or item.get("parent_image")
        child = item.get("process") or item.get("image") or item.get("child_process")
        if parent and child:
            relationships.append({
                "type": "process_tree",
                "source_item": str(parent),
                "target_item": str(child),
                "confidence": 0.9,
                "detail": "parent spawned child process",
            })

    return relationships


def _item_label(item: dict[str, Any]) -> str:
    """A short human label for an item (path > process > hash > repr)."""
    for k in ("file", "path", "filename", "process", "image", "rule", "name"):
        v = item.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return json.dumps(item, default=str)[:64]


# ---------------------------------------------------------------------------
# Embedded correlator script run inside svetovid/base.
# ---------------------------------------------------------------------------

_CORRELATOR_SCRIPT = r'''#!/usr/bin/env python3
"""Evidence relationship correlator — runs inside svetovid/base.

Reads a JSON document of accumulated evidence items (one JSON array or one
JSON object per line / a single object wrapping a list), discovers
relationships, and writes them to the output path.

Usage:
    evidence_graph.py <items_json_path> <output_json> <time_window_s>
"""
from __future__ import annotations

import datetime as _dt
import json
import sys
from pathlib import Path


def _parse_ts(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return _dt.datetime.fromtimestamp(float(value), tz=_dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    iso = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = _dt.datetime.fromisoformat(iso)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc)


def _hashes(item):
    out = []
    for k, v in item.items():
        if not isinstance(v, str):
            continue
        kl = k.lower()
        if "hash" in kl or kl in ("sha256", "sha1", "md5", "sha-256", "sha-1"):
            c = v.strip().lower()
            if c:
                out.append(c)
    return out


def _label(item):
    for k in ("file", "path", "filename", "process", "image", "rule", "name"):
        v = item.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return json.dumps(item, default=str)[:64]


def find_relationships(items, time_window_s):
    rels = []
    by_hash = {}
    for i, item in enumerate(items):
        for h in _hashes(item):
            by_hash.setdefault(h, []).append(i)
    for h, idxs in by_hash.items():
        if len(idxs) < 2:
            continue
        for a in range(len(idxs)):
            for b in range(a + 1, len(idxs)):
                rels.append({"type": "same_hash",
                             "source_item": _label(items[idxs[a]]),
                             "target_item": _label(items[idxs[b]]),
                             "confidence": 0.99,
                             "detail": "identical hash " + h[:16]})
    by_actor = {}
    for i, item in enumerate(items):
        actor = item.get("user") or item.get("actor") or item.get("username")
        if isinstance(actor, str) and actor.strip():
            by_actor.setdefault(actor.strip().lower(), []).append(i)
    for actor, idxs in by_actor.items():
        if len(idxs) < 2:
            continue
        for a in range(len(idxs)):
            for b in range(a + 1, len(idxs)):
                rels.append({"type": "same_actor",
                             "source_item": _label(items[idxs[a]]),
                             "target_item": _label(items[idxs[b]]),
                             "confidence": 0.6,
                             "detail": "same account '" + actor + "'"})
    stamped = []
    for i, item in enumerate(items):
        ts = _parse_ts(item.get("timestamp") or item.get("ts") or item.get("time"))
        if ts is not None:
            stamped.append((ts, i))
    stamped.sort(key=lambda t: t[0])
    for a in range(len(stamped)):
        for b in range(a + 1, len(stamped)):
            delta = (stamped[b][0] - stamped[a][0]).total_seconds()
            if delta > time_window_s:
                break
            rels.append({"type": "correlated_time",
                         "source_item": _label(items[stamped[a][1]]),
                         "target_item": _label(items[stamped[b][1]]),
                         "confidence": 0.5,
                         "detail": "events within %.2fs" % delta})
    for item in items:
        parent = item.get("parent_process") or item.get("parent_image")
        child = item.get("process") or item.get("image") or item.get("child_process")
        if parent and child:
            rels.append({"type": "process_tree",
                         "source_item": str(parent),
                         "target_item": str(child),
                         "confidence": 0.9,
                         "detail": "parent spawned child process"})
    return rels


def _load_items(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    text = text.strip()
    items = []
    # Accept: a single JSON array, a single object with a list field, or JSONL.
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, list):
        items = [x for x in doc if isinstance(x, dict)]
    elif isinstance(doc, dict):
        for v in doc.values():
            if isinstance(v, list):
                items = [x for x in v if isinstance(x, dict)]
                break
        if not items:
            items = [doc]
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                items.append(obj)
    return items


def main(argv):
    if len(argv) != 4:
        print("usage: evidence_graph.py <items_json> <output_json> <time_window_s>",
              file=sys.stderr)
        return 2
    items_path, out_json, window_s = argv[1], argv[2], argv[3]
    try:
        window = float(window_s)
    except ValueError:
        window = 5.0
    if not Path(items_path).exists():
        with open(out_json, "w") as fh:
            json.dump({"relationships": [], "error": "items file not found"}, fh)
        return 0
    items = _load_items(items_path)
    rels = find_relationships(items, window)
    summary = str(len(rels)) + " relationship(s) across " + str(len(items)) + " item(s)"
    payload = {"relationships": rels, "item_count": len(items), "summary": summary}
    with open(out_json, "w") as fh:
        json.dump(payload, fh, ensure_ascii=False, default=str)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


class EvidenceGraphTool(Tool):
    name = "evidence_correlate"
    image = "svetovid/base"
    description = (
        "Post-processing tool that discovers relationships across accumulated "
        "evidence from prior tool calls: identical file hashes in multiple "
        "locations (same dropped file), same user/account across artifact "
        "types (same actor), events within a small time window (correlated "
        "activity), and parent/child process links. Fills the EnCase "
        "'Find Related' EnScript gap."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "investigation_context": {
                    "type": "string",
                    "description": (
                        "JSON string of accumulated evidence items (a flat "
                        "array of dicts, or JSONL). Each item may carry "
                        "file/hash/user/timestamp/parent_process fields."
                    ),
                },
                "time_window_seconds": {
                    "type": "number",
                    "default": DEFAULT_TIME_WINDOW_S,
                    "description": (
                        "Seconds within which two timestamps are considered "
                        "correlated activity."
                    ),
                },
            },
            "required": [],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        context_str = args.get("investigation_context") or ""
        window = float(args.get("time_window_seconds", DEFAULT_TIME_WINDOW_S))

        # Persist the context to the per-call output dir so the container (and
        # host fallback) can read it as a file.
        items_host = Path(ctx.output_dir) / "evidence_items.json"
        items_host.write_text(context_str if context_str else "[]")

        out_json = "/work/evidence_graph.json"
        script_host = Path(ctx.output_dir) / "evidence_graph.py"
        script_host.write_text(_CORRELATOR_SCRIPT)

        cmd = [
            "python3", "/work/evidence_graph.py",
            "/work/evidence_items.json",
            out_json,
            str(window),
        ]

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(
            ctx.investigation_id, tool=self.name, args=args,
        ))

        def on_stdout(line: str) -> None:
            ctx.bus.publish(E.tool_stdout(ctx.investigation_id, call_id, line))

        def on_stderr(line: str) -> None:
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, line))

        try:
            res = await run_in_sandbox(
                image=self.image or "",
                command=cmd,
                evidence_path=ctx.evidence_path,
                output_dir=ctx.output_dir,
                investigation_id=ctx.investigation_id,
                on_stdout=on_stdout,
                on_stderr=on_stderr,
                host_fallback=True,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(
                ctx.investigation_id, f"evidence_correlate failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"evidence_correlate failed: {e}",
            )

        relationships: list[dict[str, Any]] = []
        summary = ""
        local_out = Path(ctx.output_dir) / "evidence_graph.json"
        if local_out.exists():
            try:
                payload = json.loads(local_out.read_text())
                if isinstance(payload, dict):
                    relationships = payload.get("relationships", [])
                    summary = payload.get("summary", "")
            except Exception as e:
                summary = f"evidence_graph output couldn't be parsed: {e}"
        if not summary:
            summary = f"evidence_correlate exited {res.exit_code} with no output"

        output_hash = _hash_file(local_out)
        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s,
            output_hash,
        ))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": args,
            "exit_code": res.exit_code, "duration_s": res.duration_s,
            "output_hash": output_hash, "ts": E._now_iso(),
        }))

        try:
            from ._reporting import record_tool_call_db
            await record_tool_call_db(
                call_id=call_id, investigation_id=ctx.investigation_id,
                tool=self.name, args=args, exit_code=res.exit_code,
                duration_s=res.duration_s, output_hash=output_hash,
            )
        except Exception:
            pass

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
            output_path=str(local_out) if local_out.exists() else None,
            summary=summary, data={"relationships": relationships},
        )


def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


tool = EvidenceGraphTool()
