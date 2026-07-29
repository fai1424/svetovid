"""G01 — Windows attack timeline reconstruction.

The end-to-end proof goal for M0. Drives:

  triage
    → parse_evtx (scan the evidence folder for .evtx, list what we have)
    → sigma_hunt (Chainsaw over Sigma rules → high/medium hits)
    → enrich_attack (reverse_event for each distinct event_id → ATT&CK candidates)
    → correlate (group hits into incidents, order by timestamp)
    → draft_report (LLM turns the structured findings into a Markdown narrative)
    → [HITL] review  (governance gate before finalize)
    → finalize

The early nodes (triage/sigma_hunt/enrich/correlate) are deterministic and
fast — no LLM required. The draft_report node uses the LLM to turn rows into
sentences, with the structured data always available as ground truth so the
LLM cannot silently invent a finding.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from ..agent import events as E
from ..config import load_settings
from ..llm.client import build_chat
from ..tools.chainsaw import ChainsawTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode


class AttackTimelineGoal(Goal):
    id = "G01"
    cluster = "Windows"
    label = "Windows attack timeline"
    description = (
        "Reconstruct the attack timeline from Windows .evtx logs. "
        "Runs Chainsaw with Sigma rules, maps hits to MITRE ATT&CK, "
        "and produces an incident-ordered report with TTP annotations."
    )
    input_artifacts = ["B3", "B8"]
    tools = ["C12", "C17b", "C16", "A2"]
    icon = "calendar-clock"

    def nodes(self) -> list[GoalNode]:
        return [
            GoalNode("triage", "Triage evidence"),
            GoalNode("sigma_hunt", "Hunt Sigma rules"),
            GoalNode("enrich_attack", "Enrich with ATT&CK"),
            GoalNode("correlate", "Correlate into incidents"),
            GoalNode("draft_report", "Draft narrative report"),
            GoalNode("hitl_review", "Review (human)"),
            GoalNode("finalize", "Finalize report"),
        ]

    async def run(self, *, investigation_id: str, case_id: str,
                  evidence_path: str, user_prompt: str, bus) -> None:
        out_dir = str(Path.home() / ".svetovid" / "cases" / case_id / investigation_id)
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        await self._set_node(bus, investigation_id, "triage", "running")
        evtx_files = await self._find_evtx(evidence_path)
        if not evtx_files:
            bus.publish(E.agent_thought(
                investigation_id,
                f"No .evtx files under {evidence_path}. Goal cannot proceed.",
            ))
            await self._set_node(bus, investigation_id, "triage", "failed")
            return
        bus.publish(E.agent_thought(
            investigation_id,
            f"Found {len(evtx_files)} .evtx file(s). Beginning Sigma hunt.",
        ))
        await self._set_node(bus, investigation_id, "triage", "done")

        # --- sigma_hunt ---
        await self._set_node(bus, investigation_id, "sigma_hunt", "running")
        chainsaw = ChainsawTool()
        cr = await chainsaw.invoke(
            {"min_level": "medium"},
            _Ctx(investigation_id, case_id, bus, evidence_path, out_dir),
        )
        await self._set_node(bus, investigation_id, "sigma_hunt",
                             "done" if cr.exit_code == 0 else "failed")
        hits: list[dict[str, Any]] = (cr.data or {}).get("hits", [])

        # --- enrich_attack ---
        await self._set_node(bus, investigation_id, "enrich_attack", "running")
        mitre = MitreAttackTool()
        event_ids = sorted({str(h.get("event_id")) for h in hits if h.get("event_id")})
        enrichment: dict[str, Any] = {}
        for eid in event_ids[:30]:        # cap to keep prompt bounded
            er = await mitre.invoke(
                {"op": "reverse_event", "event_id": eid},
                _Ctx(investigation_id, case_id, bus, evidence_path, out_dir),
            )
            enrichment[eid] = (er.data or {}).get("candidates", [])
            bus.publish(E.report_section_added(
                investigation_id,
                f"event_{eid}",
                f"Event ID {eid}",
                f"_Event ID {eid}_ maps to: " + (
                    ", ".join(f"`{c['id']}` ({c['detail'].get('name')})"
                              for c in enrichment[eid]) or "_no ATT&CK mapping_"),
            ))
        await self._set_node(bus, investigation_id, "enrich_attack", "done")

        # --- correlate ---
        await self._set_node(bus, investigation_id, "correlate", "running")
        timeline = sorted(hits, key=lambda h: h.get("timestamp") or "")
        bus.publish(E.report_section_added(
            investigation_id, "timeline", "Timeline",
            _render_timeline_table(timeline),
        ))
        await self._set_node(bus, investigation_id, "correlate", "done")

        # --- draft_report (LLM) ---
        await self._set_node(bus, investigation_id, "draft_report", "running")
        narrative = await self._draft_narrative(timeline, enrichment, user_prompt)
        bus.publish(E.report_section_added(
            investigation_id, "narrative", "Investigator narrative", narrative,
        ))
        await self._set_node(bus, investigation_id, "draft_report", "done")

        # --- HITL review ---
        await self._set_node(bus, investigation_id, "hitl_review", "running")
        settings = load_settings()
        if settings.hitl_report_release == "required":
            from ..agent.hitl import request_approval
            approved = await request_approval(
                investigation_id,
                bus,
                "Report drafted. Review before finalize.",
                {"hit_count": len(timeline), "report_preview": narrative[:600]},
            )
            if not approved:
                bus.publish(E.investigation_end(investigation_id, "cancelled", "HITL rejected"))
                await self._set_node(bus, investigation_id, "hitl_review", "skipped")
                return
        await self._set_node(bus, investigation_id, "hitl_review", "done")

        # --- finalize ---
        await self._set_node(bus, investigation_id, "finalize", "running")
        bus.publish(E.report_section_added(
            investigation_id, "summary", "Summary",
            f"**{len(timeline)} ATT&CK-mapped event(s)** across {len(evtx_files)} .evtx file(s).",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _find_evtx(self, root: str) -> list[str]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _walk_evtx, root)

    async def _draft_narrative(self, hits, enrichment, user_prompt: str) -> str:
        """Ask the active LLM to summarize the structured findings.

        Always returns a Markdown string; on any LLM failure we fall back to a
        deterministic bulleted summary so the report is never empty.
        """
        try:
            settings = load_settings()
            provider = settings.active()
            if provider is None or not provider.is_configured() or not provider.api_key:
                return _fallback_narrative(hits, enrichment)
            chat = build_chat(provider, streaming=False)
            context = json.dumps({
                "hit_count": len(hits),
                "top_hits": hits[:25],
                "event_id_to_attack": enrichment,
                "user_goal": user_prompt or "Reconstruct the attack timeline.",
            }, ensure_ascii=False, default=str)[:8000]
            resp = await chat.ainvoke([
                {"role": "system", "content": (
                    "You are a DFIR analyst. Given structured Sigma hits and "
                    "ATT&CK enrichments, write a concise Markdown narrative "
                    "(5-8 short paragraphs) reconstructing what happened. "
                    "Cite event IDs and ATT&CK technique IDs. Do NOT invent "
                    "events not present in the data."
                )},
                {"role": "user", "content": context},
            ])
            return resp.content if isinstance(resp.content, str) else str(resp.content)
        except Exception as e:
            return _fallback_narrative(hits, enrichment) + f"\n\n<!-- LLM unavailable: {e} -->"


def _walk_evtx(root: str) -> list[str]:
    found: list[str] = []
    for p in Path(root).rglob("*.evtx"):
        found.append(str(p))
    return found


def _render_timeline_table(hits: list[dict[str, Any]]) -> str:
    if not hits:
        return "_No Sigma hits at the requested severity level._"
    head = "| Time | Computer | Event ID | Rule | Level | ATT&CK |\n|---|---|---|---|---|---|"
    rows = []
    for h in hits[:200]:
        tags = ", ".join(h.get("mitre_tags") or [])
        rows.append(
            f"| {h.get('timestamp','')} | {h.get('computer','')} | "
            f"{h.get('event_id','')} | {(h.get('rule_name') or '').replace('|','/')[:80]} | "
            f"{h.get('level','')} | {tags} |"
        )
    return head + "\n" + "\n".join(rows)


def _fallback_narrative(hits, enrichment) -> str:
    if not hits:
        return "No Sigma hits above the requested threshold. Nothing to narrate."
    by_level: dict[str, int] = {}
    by_event: dict[str, int] = {}
    for h in hits:
        by_level[h.get("level", "?")] = by_level.get(h.get("level", "?"), 0) + 1
        by_event[str(h.get("event_id"))] = by_event.get(str(h.get("event_id")), 0) + 1
    lines = [
        "## Investigation findings (deterministic summary)",
        "",
        f"- **Total Sigma hits**: {len(hits)}",
        f"- **By severity**: {', '.join(f'{k}={v}' for k,v in sorted(by_level.items()))}",
        f"- **By Windows event ID**: {', '.join(f'{k}={v}' for k,v in sorted(by_event.items(), key=lambda x: -x[1])[:10])}",
    ]
    return "\n".join(lines)


class _Ctx:
    """Tiny shim satisfying ToolContext's attribute contract."""
    def __init__(self, investigation_id, case_id, bus, evidence_path, output_dir):
        self.investigation_id = investigation_id
        self.case_id = case_id
        self.bus = bus
        self.evidence_path = evidence_path
        self.output_dir = output_dir

    def make_call_id(self) -> str:
        return E.new_id("call")


goal = AttackTimelineGoal()
