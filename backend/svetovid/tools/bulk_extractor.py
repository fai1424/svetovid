"""Bulk Extractor tool wrapper (research item C11f).

Whole-image scanner for emails/URLs/IPs/credit-cards/EXIF/etc without filesystem
parsing. Used by G03 (deadbox examination) for fast triage of disk images.
Output is feature_files (TSV) + report.xml.

CLI shape::

    bulk_extractor -o /work/be_out /evidence/image.E01 \\
        -j 4 -S 30
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


class BulkExtractorTool(Tool):
    name = "bulk_extractor"
    image = "svetovid/eztools"  # reuse eztools (has TSK + bulk_extractor via apt)
    description = (
        "Scan a disk image or raw file for features (emails, URLs, IPs, "
        "credit cards, EXIF) without filesystem parsing. Fast triage; "
        "outputs feature files (TSV). Use on E01/raw images."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {
                    "type": "string",
                    "description": "Path to the image file under /evidence.",
                },
                "scanners": {
                    "type": "string",
                    "description": "Comma-separated scanners to run (default: all). e.g. 'email,url,exif,gps'.",
                },
                "jobs": {"type": "number", "default": 4},
            },
            "required": ["evidence_subpath"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        sub = args.get("evidence_subpath", "")
        scanners = args.get("scanners") or ""
        jobs = str(int(args.get("jobs", 4)))

        out_dir = "/work/be_out"
        cmd = [
            "bulk_extractor",
            "-o", out_dir,
            "-j", jobs,
        ]
        if scanners:
            for s in scanners.split(","):
                cmd.extend(["-E", s.strip()])  # -E runs only the named scanner
        cmd.append(f"/evidence/{sub}")

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
                timeout_s=3600,
                mem_limit="8g",
                host_fallback=False,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(ctx.investigation_id, f"bulk_extractor failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"bulk_extractor failed: {e}",
            )

        # Tally feature files
        local_out = Path(ctx.output_dir) / "be_out"
        features: dict[str, int] = {}
        if local_out.exists():
            for f in local_out.glob("*.txt"):
                # count lines (each line = one feature)
                try:
                    with open(f, encoding="utf-8", errors="replace") as fh:
                        features[f.name] = sum(1 for _ in fh)
                except Exception:
                    features[f.name] = -1
        summary = f"bulk_extractor: {sum(v for v in features.values() if v > 0)} features across {len(features)} files"

        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s, None,
        ))
        ctx.bus.publish(E.agent_observation(ctx.investigation_id, tool=self.name, summary=summary))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": args,
            "exit_code": res.exit_code, "duration_s": res.duration_s,
            "output_hash": None, "ts": E._now_iso(),
        }))

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=None,
            output_path=str(local_out) if local_out.exists() else None,
            summary=summary, data={"feature_counts": features},
        )


tool = BulkExtractorTool()
