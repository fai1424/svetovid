"""List evidence directory contents.

The MOST important tool for the agent — without it, the agent can't see what
files are in the evidence folder and wastes all its iterations guessing paths.

Returns a recursive file listing with sizes and detected types, so the agent
knows exactly what to investigate.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


class ListEvidenceTool(Tool):
    name = "list_evidence"
    image = None  # runs on host — just os.walk, no Docker needed
    description = (
        "List all files in the evidence directory. ALWAYS call this FIRST "
        "before any other tool, so you know what evidence files are available. "
        "Returns filename, size, and detected type for each file."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "subpath": {
                    "type": "string",
                    "description": "Subdirectory under the evidence root to list (default: root).",
                },
            },
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        call_id = ctx.make_call_id()
        sub = args.get("subpath") or ""
        root = os.path.join(ctx.evidence_path, sub) if sub else ctx.evidence_path

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=False, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

        files: list[dict[str, Any]] = []
        try:
            if os.path.isfile(root):
                # Single file
                st = os.stat(root)
                files.append({
                    "path": root,
                    "name": os.path.basename(root),
                    "size_bytes": st.st_size,
                    "type": _detect_type(root),
                })
            else:
                for dirpath, dirnames, filenames in os.walk(root):
                    # skip hidden dirs
                    dirnames[:] = [d for d in dirnames if not d.startswith('.')]
                    for fn in sorted(filenames):
                        if fn.startswith('.'):
                            continue
                        fpath = os.path.join(dirpath, fn)
                        try:
                            st = os.stat(fpath, follow_symlinks=False)
                        except OSError:
                            continue
                        relpath = os.path.relpath(fpath, ctx.evidence_path)
                        files.append({
                            "path": relpath,
                            "name": fn,
                            "size_bytes": st.st_size,
                            "type": _detect_type(fpath),
                        })
                    if len(files) > 500:
                        break
        except Exception as e:
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, 0.0, None))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"list_evidence failed: {e}",
            )

        summary = f"Found {len(files)} file(s) in evidence"
        if files:
            type_counts: dict[str, int] = {}
            for f in files:
                t = f["type"]
                type_counts[t] = type_counts.get(t, 0) + 1
            type_str = ", ".join(f"{v} {k}" for k, v in sorted(type_counts.items()))
            summary = f"{summary}: {type_str}"

        ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 0, 0.0, None))
        ctx.bus.publish(E.agent_observation(ctx.investigation_id, tool=self.name, summary=summary))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": args,
            "exit_code": 0, "duration_s": 0.0,
            "output_hash": None, "ts": E._now_iso(),
        }))

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=0, duration_s=0.0,
            output_hash=None, output_path=None,
            summary=summary, data={"files": files, "count": len(files)},
        )


def _detect_type(path: str) -> str:
    """Quick file-type detection by extension + first bytes."""
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]

    # Extension-based
    ext_map = {
        ".evtx": "Windows Event Log (.evtx)",
        ".pcap": "Network capture (PCAP)",
        ".pcapng": "Network capture (PCAPNG)",
        ".raw": "Memory/disk image (raw)",
        ".mem": "Memory image",
        ".vmem": "VMware memory image",
        ".lime": "LiME memory image",
        ".dmp": "Windows crash/memory dump",
        ".e01": "EnCase EWF image",
        ".dd": "Raw disk image",
        ".001": "Split disk image",
        ".pf": "Windows Prefetch",
        ".mbox": "Mailbox (MBOX)",
        ".eml": "Email (EML)",
        ".pst": "Outlook PST",
        ".ost": "Outlook OST",
        ".msg": "Outlook MSG",
        ".ab": "Android backup",
        ".log": "Log file",
        ".json": "JSON data",
        ".jsonl": "JSON Lines",
        ".csv": "CSV data",
        ".zip": "ZIP archive",
        ".tar": "TAR archive",
        ".gz": "Gzip archive",
        ".tar.gz": "TAR+Gzip archive",
        ".7z": "7-Zip archive",
        ".yml": "YAML file",
        ".yaml": "YAML file",
    }
    if ext in ext_map:
        return ext_map[ext]

    # Name-based
    name_map = {
        "$mft": "NTFS Master File Table ($MFT)",
        "mft": "NTFS Master File Table ($MFT)",
        "ntuser.dat": "Windows registry hive (NTUSER.DAT)",
        "usrclass.dat": "Windows registry hive (USRCLASS.DAT)",
        "system": "Windows registry hive (SYSTEM)",
        "software": "Windows registry hive (SOFTWARE)",
        "sam": "Windows registry hive (SAM)",
        "security": "Windows registry hive (SECURITY)",
    }
    if name in name_map:
        return name_map[name]

    # Magic bytes
    try:
        with open(path, "rb") as f:
            head = f.read(16)
        if head.startswith(b"ElfFile\x00"):
            return "Windows Event Log (.evtx)"
        if head.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")):
            return "Network capture (PCAP)"
        if head.startswith(b"regf"):
            return "Windows registry hive"
        if head.startswith(b"PK\x03\x04"):
            return "ZIP archive"
        if head.startswith(b"\x1f\x8b"):
            return "Gzip archive"
        if head.startswith(b"\x7fELF"):
            return "ELF binary"
        if head.startswith(b"MZ"):
            return "Windows PE binary"
    except Exception:
        pass

    return "unknown"


tool = ListEvidenceTool()
