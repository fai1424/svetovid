"""Hayabusa tool wrapper (research item C12 / C16).

Yamato-Security's Rust-based Sigma timeline generator. Complements Chainsaw
(C17b): Chainsaw is fast search/hunt; Hayabusa produces a normalized
csv/json timeline. Used by G01 (cross-validation with Chainsaw) and G02
(deeper Sigma coverage).

CLI shape (inside svetovid/eztools)::

    hayabusa csv-timeline -d /evidence \\
        -r /opt/hayabusa-bin/rules \\
        -o /work/hayabusa_timeline.csv \\
        -p super-verbose \\
        -w no-wizard -q
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


class HayabusaTool(Tool):
    name = "hayabusa_timeline"
    image = "svetovid/eztools"
    description = (
        "Generate a Sigma-matched event timeline from EVTX files using "
        "Hayabusa. Returns CSV rows with timestamp, event_id, rule, level, "
        "computer, and ATT&CK tags."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {
                    "type": "string",
                    "description": "Subpath under /evidence (default: whole tree).",
                },
                "profile": {
                    "type": "string",
                    "enum": ["minimal", "standard", "verbose", "super-verbose", "all-field-info"],
                    "default": "super-verbose",
                },
                "min_level": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "informational"],
                    "default": "informational",
                },
            },
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        sub = args.get("evidence_subpath") or ""
        profile = args.get("profile", "super-verbose")
        level = args.get("min_level", "informational")

        out_file = "/work/hayabusa_timeline.csv"
        cmd = [
            "hayabusa", "csv-timeline",
            "-d", f"/evidence/{sub}".rstrip("/") if sub else "/evidence",
            "-r", "/opt/hayabusa-bin/rules",
            "-o", out_file,
            "-p", profile,
            "-L", level,
            "-w", "no-wizard",
            "-q",   # quiet
            "-C",   # no color
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
                timeout_s=600,  # Hayabusa can be slower than Chainsaw
                host_fallback=True,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(ctx.investigation_id, f"hayabusa failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None, summary=f"hayabusa failed: {e}",
            )

        # Parse CSV → structured rows
        rows: list[dict[str, Any]] = []
        local_out = Path(ctx.output_dir) / "hayabusa_timeline.csv"
        summary = ""
        if local_out.exists():
            try:
                with open(local_out, encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        rows.append({
                            "timestamp": row.get("Timestamp") or row.get("timestamp"),
                            "computer": row.get("Computer") or row.get("computer"),
                            "event_id": row.get("EventID") or row.get("event_id"),
                            "rule_name": row.get("RuleTitle") or row.get("RuleName") or row.get("rule_title"),
                            "level": row.get("Level") or row.get("level"),
                            "mitre_tags": (row.get("MitreTags") or row.get("mitre_tags") or "").split(),
                            "details": row.get("Details") or row.get("details", ""),
                        })
                # cap rows to keep the payload bounded
                total = len(rows)
                rows = rows[:500]
                summary = f"{total} Hayabusa hit(s) (returning first {len(rows)})"
            except Exception as e:
                summary = f"hayabusa ran but CSV parse failed: {e}"
        else:
            summary = f"hayabusa exited {res.exit_code} but produced no CSV"

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

        # Persist this tool call to the case DB and emit timeline / IOC events
        # from the parsed Hayabusa rows. Each row becomes a timeline entry;
        # IP/domain/hash indicators in the Details column become IOCs.
        from ._reporting import record_tool_call_db, emit_hit_events
        await record_tool_call_db(
            call_id=call_id, investigation_id=ctx.investigation_id,
            tool=self.name, args=args, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
        )
        emit_hit_events(
            ctx.bus,
            investigation_id=ctx.investigation_id,
            source="hayabusa",
            hits=rows,
            timeline_fields={"timestamp": "timestamp", "event": "rule_name",
                             "actor": "computer"},
            ioc_text_getter=lambda h: str(h.get("details") or ""),
        )

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
            output_path=str(local_out) if local_out.exists() else None,
            summary=summary, data={"hits": rows, "count": len(rows)},
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


tool = HayabusaTool()
