"""MITRE ATT&CK lookup tool (research item A2).

Read-only lookup against the ATT&CK STIX bundle baked into the Docker image.
Exposes two operations chosen by ``args['op']``:

  - ``lookup``      : given a technique ID (T1059.001), return name/tactic/detect/mitigations
  - ``reverse_event``: given a Windows event ID (4688), return candidate techniques

Runs locally (no Docker) — the bundle is small and queries are sub-ms, so a
host call is fine. Bundle path comes from ``SVETOVID_ATTACK_BUNDLE`` or
defaults to ``/opt/attack/enterprise-attack.json`` (the path inside the image).
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

# Event-ID → ATT&CK technique hints. Deliberately small and high-precision;
# the real expansion comes from Sigma rule tags when chainsaw runs.
EVENT_HINTS: dict[str, list[str]] = {
    "4624": ["T1078"],          # Valid Accounts
    "4625": ["T1110"],          # Brute Force
    "4688": ["T1059"],          # Command and Scripting Interpreter
    "4698": ["T1053.005"],      # Scheduled Task
    "4720": ["T1136"],          # Create Account
    "4732": ["T1098"],          # Account Manipulation
    "7045": ["T1543.003"],      # Service Installation
    "4689": [],
    "1":     ["T1059", "T1129", "T1106"],   # Sysmon process create
    "3":     ["T1071"],         # Sysmon network connection
    "11":    ["T1105"],         # Sysmon file create
    "13":    ["T1547.001"],     # Sysmon registry value set
    "22":    ["T1105", "T1071.001"],  # Sysmon DNS
}


class MitreAttackTool(Tool):
    name = "mitre_attack"
    image = None                # runs on host; reads STIX bundle directly
    description = "Lookup MITRE ATT&CK techniques by ID or reverse-lookup from event_id."

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "op": {"type": "string", "enum": ["lookup", "reverse_event"]},
                "technique_id": {"type": "string"},
                "event_id": {"type": "string"},
            },
            "required": ["op"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        call_id = ctx.make_call_id()
        op = args.get("op")
        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=False, container_id=None,
        ))

        bundle = _load_bundle()
        if bundle is None:
            ctx.bus.publish(E.tool_stderr(
                ctx.investigation_id, call_id,
                "[mitre_attack] STIX bundle not found; returning event-ID hints only.",
            ))

        try:
            if op == "lookup":
                result = _lookup_technique(bundle, args.get("technique_id", ""))
                summary = f"ATT&CK {args.get('technique_id')}: {result.get('name', '?')}"
            elif op == "reverse_event":
                hints = EVENT_HINTS.get(str(args.get("event_id")), [])
                enriched = [t | {"detail": _lookup_technique(bundle, t["id"])} for t in
                            ({"id": h} for h in hints)]
                result = {"event_id": args.get("event_id"), "candidates": enriched}
                summary = f"event_id {args.get('event_id')} → {len(enriched)} candidate(s)"
            else:
                raise ValueError(f"unknown op {op!r}")
        except Exception as e:
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, 0.0, None))
            return ToolResult(call_id=call_id, tool=self.name, exit_code=1, duration_s=0.0,
                              output_hash=None, output_path=None, summary=f"error: {e}")

        ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 0, 0.0, None))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        return ToolResult(call_id=call_id, tool=self.name, exit_code=0, duration_s=0.0,
                          output_hash=None, output_path=None, summary=summary, data=result)


@lru_cache(maxsize=1)
def _load_bundle() -> dict[str, Any] | None:
    path = os.environ.get("SVETOVID_ATTACK_BUNDLE", "/opt/attack/enterprise-attack.json")
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _lookup_technique(bundle: dict[str, Any] | None, tid: str) -> dict[str, Any]:
    if not bundle or not tid:
        return {"id": tid, "name": None}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern" and obj.get("external_references"):
            for ref in obj["external_references"]:
                if ref.get("external_id") == tid:
                    return {
                        "id": tid,
                        "name": obj.get("name"),
                        "description": (obj.get("description") or "")[:280],
                        "tactic": [ph.get("phase_name") for ph in obj.get("kill_chain_phases", [])],
                        "url": ref.get("url"),
                        "deprecated": obj.get("x_mitre_deprecated", False),
                    }
    return {"id": tid, "name": None}


tool = MitreAttackTool()
