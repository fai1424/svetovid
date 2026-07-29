"""Eric Zimmerman tools wrapper (research item C12).

Wraps the EZ tool family (.NET CLI binaries) for Windows artifact parsing:
  - EvtxECmd   — .evtx → CSV/JSON
  - MFTECmd    — $MFT / $LogFile / $J → CSV/JSON
  - PECmd      — Prefetch .pf → CSV/JSON
  - AmcacheParser — Amcache.hve → CSV/JSON
  - RECmd      — registry hives → batch extraction
  - JLECmd / LECmd / RBCmd / SrumECmd — JumpLists / LNK / Recycle Bin / SRUM

These run on Linux via .NET 9 (mono is deprecated; .NET 9 native is preferred).
The svetovid/eztools image installs them at /opt/eztools/<tool>/<tool>.dll.

Flat schema: agent picks the tool + provides the file path. Output is parsed
into JSON rows matching the tool's CSV column names.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


# Tool → evidence pattern. The agent picks a tool by name; we know what file
# extension / filename pattern that tool expects.
EZ_TOOLS: dict[str, str] = {
    "EvtxECmd": "Parses Windows .evtx event logs. Pass evidence_subpath to a .evtx file or dir.",
    "MFTECmd":  "Parses NTFS $MFT, $LogFile, $UsnJrnl:$J, $J. Pass --sub-parameter 'MFT' or 'J' to select.",
    "PECmd":    "Parses Windows Prefetch (.pf). Pass a .pf file or directory of them.",
    "AmcacheParser": "Parses Amcache.hve for program execution evidence (SHA-1 hashes, paths).",
    "RECmd":    "Batch-extracts registry hives using batch files. Pass --batch to specify.",
    "JLECmd":   "Parses JumpLists (.automaticDestinations / .customDestinations).",
    "LECmd":    "Parses .lnk shortcut files.",
    "RBCmd":    "Parses Recycle Bin ($I / $R).",
    "SrumECmd": "Parses SRUDB.dat (System Resource Usage Monitor).",
}


class EzTool(Tool):
    name = "eztools"
    image = "svetovid/eztools"
    description = (
        "Run an Eric Zimmerman forensic parser on Windows artifacts. "
        "Each tool outputs structured CSV → we parse to JSON rows. "
        "Choose the tool based on the artifact type: EvtxECmd for .evtx, "
        "MFTECmd for $MFT/$J, PECmd for Prefetch, RECmd for registry."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "tool": {
                    "type": "string",
                    "enum": list(EZ_TOOLS.keys()),
                    "description": "Which EZ parser to run.",
                },
                "evidence_subpath": {
                    "type": "string",
                    "description": "Subpath under /evidence to the artifact file/dir.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Optional tool-specific args (e.g. 'MFT' for MFTECmd).",
                },
            },
            "required": ["tool", "evidence_subpath"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        tool_name = args.get("tool", "")
        if tool_name not in EZ_TOOLS:
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"unknown EZ tool {tool_name!r}; pick from {list(EZ_TOOLS)}",
            )
        sub = args.get("evidence_subpath", "")
        extra = args.get("extra_args") or ""

        # Each EZ tool takes --csv <dir> --json <dir> for output. We use --csv
        # because the JSON format varies; CSV is universal.
        out_dir = "/work"
        target = f"/evidence/{sub}"
        cmd = [
            "dotnet", f"/opt/eztools/{tool_name}/{tool_name}.dll",
            "-f", target,
            "--csv", out_dir,
            "--csvf", f"ez_{tool_name.lower()}_out",  # output filename prefix
        ]
        if extra:
            cmd.extend(extra.split())

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

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
                timeout_s=900,
                mem_limit="4g",
                host_fallback=False,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(ctx.investigation_id, f"{tool_name} failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None, summary=f"{tool_name} failed: {e}",
            )

        # Find the CSV output (EZ tools write to <outdir>/<prefix>_<timestamp>.csv)
        rows: list[dict[str, Any]] = []
        local_out_dir = Path(ctx.output_dir)
        csv_files = sorted(local_out_dir.glob(f"ez_{tool_name.lower()}_out*.csv"))
        summary = ""
        output_hash = None
        if csv_files:
            csv_path = csv_files[-1]   # latest
            try:
                with open(csv_path, encoding="utf-8-sig", errors="replace") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        rows.append({k: v for k, v in row.items() if v})
                rows = rows[:2000]
                summary = f"{tool_name}: {len(rows)} row(s) from {csv_path.name}"
                output_hash = _hash_file(csv_path)
            except Exception as e:
                summary = f"{tool_name} ran but CSV parse failed: {e}"
        else:
            summary = f"{tool_name} exited {res.exit_code} but produced no CSV"

        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s, output_hash,
        ))
        ctx.bus.publish(E.agent_observation(ctx.investigation_id, tool=self.name, summary=summary))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": args,
            "exit_code": res.exit_code, "duration_s": res.duration_s,
            "output_hash": output_hash, "ts": E._now_iso(),
        }))

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
            output_path=str(csv_files[-1]) if csv_files else None,
            summary=summary, data={"tool": tool_name, "rows": rows},
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


tool = EzTool()
