"""Chainsaw tool wrapper (research item C17b).

Wraps the WithSecure Chainsaw CLI for fast Sigma-rule hunting over EVTX
corpora. Runs inside the ``svetovid/eztools`` Docker image; outputs JSON to
``/work/hits.jsonl`` which we parse and feed back to the agent.

CLI shape (inside the container)::

    chainsaw hunt /evidence \\
        -r /opt/sigma/rules/windows/sysmon \\
        --mapping /opt/chainsaw/mappings/sigma-event-logs-all.yml \\
        --kind sigma --level high,medium \\
        --json -o /work/hits.json
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


class ChainsawTool(Tool):
    name = "chainsaw_hunt"
    image = "svetovid/eztools"
    description = (
        "Hunt Sigma rules across EVTX files using Chainsaw. "
        "Returns high/medium severity hits with ATT&CK tags."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {
                    "type": "string",
                    "description": "Subpath under /evidence to scan (default: whole evidence tree).",
                },
                "min_level": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "default": "medium",
                },
            },
            "required": [],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        sub = args.get("evidence_subpath") or ""
        level = args.get("min_level", "medium")
        # chainsaw's enum is: critical > high > medium > low > info
        levels = ["critical", "high", "medium", "low", "info"]
        try:
            level_idx = levels.index(level)
        except ValueError:
            level_idx = 2
        level_arg = ",".join(levels[:level_idx + 1])

        out_file = "/work/chainsaw_hits.json"
        # SigmaHQ reorganized `windows/` → `builtin/` and split per-provider.
        # Hunt the whole builtin tree — Chainsaw filters by mapping.
        cmd = [
            "chainsaw", "hunt",
            f"/evidence/{sub}".rstrip("/") if sub else "/evidence",
            "-r", "/opt/sigma/rules/builtin",
            "--mapping", "/opt/chainsaw-bin/mappings/sigma-event-logs-all.yml",
            "--kind", "sigma",
            "--level", level_arg,
            "--json",
            "-o", out_file,
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
            ctx.bus.publish(E.error_event(ctx.investigation_id, f"chainsaw failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"chainsaw failed: {e}",
            )

        # Parse the JSON output
        hits: list[dict[str, Any]] = []
        summary = ""
        local_out = Path(ctx.output_dir) / "chainsaw_hits.json"
        if local_out.exists():
            try:
                payload = json.loads(local_out.read_text())
                # Chainsaw emits a list of groups; flatten to hits
                for group in payload if isinstance(payload, list) else [payload]:
                    for hit in group.get("hits", []) if isinstance(group, dict) else []:
                        hits.append({
                            "timestamp": hit.get("time"),
                            "event_id": hit.get("event_id"),
                            "computer": hit.get("computer"),
                            "rule_name": hit.get("name") or hit.get("Title"),
                            "level": hit.get("level"),
                            "status": hit.get("status"),
                            "mitre_tags": hit.get("tags", []),
                            "details": hit.get("details", {}),
                        })
                summary = f"{len(hits)} Sigma hit(s) at level ≥ {level}"
            except Exception as e:
                summary = f"chainsaw ran but output couldn't be parsed: {e}"
        else:
            summary = f"chainsaw exited {res.exit_code} but produced no JSON output"

        output_hash = _hash_file(local_out)
        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s,
            output_hash,
        ))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        # Provenance record (governance)
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name,
            "image": self.image,
            "args": args,
            "exit_code": res.exit_code,
            "duration_s": res.duration_s,
            "output_hash": output_hash,
            "ts": E._now_iso(),
        }))

        # Persist this tool call to the case DB (Cases screen + exports) and
        # emit timeline / IOC events so the Timeline, IoC, and ATT&CK tabs
        # populate from real Chainsaw hits instead of staying empty.
        from ._reporting import record_tool_call_db, emit_hit_events
        await record_tool_call_db(
            call_id=call_id, investigation_id=ctx.investigation_id,
            tool=self.name, args=args, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
        )
        emit_hit_events(
            ctx.bus,
            investigation_id=ctx.investigation_id,
            source="chainsaw",
            hits=hits,
            timeline_fields={"timestamp": "timestamp", "event": "rule_name",
                             "actor": "computer"},
            ioc_text_getter=lambda h: _hit_ioc_text(h),
        )

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
            output_path=str(local_out) if local_out.exists() else None,
            summary=summary, data={"hits": hits},
        )


def _hit_ioc_text(hit: dict[str, Any]) -> str:
    """Flatten a Chainsaw hit into the text we scan for IP/domain/hash IOCs."""
    parts = [str(hit.get("rule_name") or ""), str(hit.get("computer") or "")]
    details = hit.get("details")
    if isinstance(details, dict):
        parts.append(" ".join(f"{k}={v}" for k, v in details.items()))
    elif details:
        parts.append(str(details))
    return " ".join(p for p in parts if p)


def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


# Module-level instance the registry can pick up if we ever want to enumerate
# tools the same way we enumerate goals.
tool = ChainsawTool()
