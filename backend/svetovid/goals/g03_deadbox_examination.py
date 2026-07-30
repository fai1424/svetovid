"""G03 — Windows deadbox forensic examination.

Full-disk / triage-folder forensic examination: parse the filesystem, extract
deleted files, hash-lookup against NSRL, scan for embedded features (emails,
URLs, EXIF), and build a super-timeline. The agent decides the order based
on what's present (E01 image vs. loose triage files).

Tools available:
  - tsk              — fls (list files), icat (extract), mmls (partitions),
                       mactime (body→timeline)
  - bulk_extractor   — feature scan over the image
  - eztools          — MFTECmd, EvtxECmd, RECmd for artifact-level parsing
  - chainsaw_hunt    — Sigma hunt over any .evtx in the image
  - mitre_attack     — Map findings to TTPs

This goal leans more deterministic than G02 (filesystem structure is fixed),
but still uses ReAct for the higher-level "what to investigate next" decisions
once the initial filesystem walk is done.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.sleuthkit import SleuthKitTool
from ..tools.bulk_extractor import BulkExtractorTool
from ..tools.eztools import EzTool
from ..tools.chainsaw import ChainsawTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior Windows deadbox forensic examiner. Your evidence is an \
E01/raw disk image or a triage folder, mounted read-only at /evidence.

## Your mission
1. Identify the disk layout (mmls) and the filesystem type (fsstat).
2. List all allocated + deleted files (fls) and produce a body file.
3. Run bulk_extractor to extract embedded features (emails, URLs, EXIF).
4. Parse NTFS artifacts via EZ tools (MFTECmd for $MFT, EvtxECmd for .evtx).
5. Hunt Sigma rules over any extracted .evtx.
6. Build a timeline and map notable activity to ATT&CK.
7. Produce a forensic examination report: filesystem overview, file inventory \
highlights, artifacts of interest, recovered features, ATT&CK timeline.

## Tool-use rules
- For images (.E01, .raw, .001): start with tsk mmls to find partitions, \
then tsk fls -r -m / to list files into a body file.
- bulk_extractor is slow; only run it once on the whole image.
- Stop when you have a body file + a feature scan + parsed key artifacts.
"""


class DeadboxExaminationGoal(Goal):
    id = "G03"
    cluster = "Windows"
    label = "Deadbox examination"
    description = (
        "Full forensic examination of a Windows disk image or triage folder. "
        "Parses the filesystem (TSK), extracts deleted files, scans for "
        "embedded features (Bulk Extractor), parses NTFS artifacts, and "
        "builds a super-timeline. The agent decides what to focus on."
    )
    input_artifacts = ["B3"]
    tools = ["C11a", "C11f", "C12", "C17b", "A2"]
    icon = "hard-drive"

    def nodes(self) -> list[GoalNode]:
        return [
            GoalNode("triage", "Triage evidence"),
            GoalNode("react_loop", "Agent examination (ReAct)"),
            GoalNode("draft_report", "Draft report"),
            GoalNode("hitl_review", "Review (human)"),
            GoalNode("finalize", "Finalize"),
        ]

    async def run(self, *, investigation_id: str, case_id: str,
                  evidence_path: str, user_prompt: str, bus) -> None:
        out_dir = str(Path.home() / ".svetovid" / "cases" / case_id / investigation_id)
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        await self._set_node(bus, investigation_id, "triage", "running")
        triage = await self._triage(evidence_path)
        bus.publish(E.agent_thought(investigation_id, f"Evidence triage: {triage}"))
        await self._set_node(bus, investigation_id, "triage", "done")

        settings = load_settings()
        provider = settings.active()

        await self._set_node(bus, investigation_id, "react_loop", "running")
        final_answer = ""
        if provider and provider.is_configured() and provider.api_key:
            try:
                tools = [
                    SleuthKitTool(),
                    BulkExtractorTool(),
                    EzTool(),
                    ChainsawTool(),
                    MitreAttackTool(),
                ]
                graph = build_react_graph(
                    tools=tools,
                    system_prompt=SYSTEM_PROMPT + (
                        f"\n\n## Additional user context\n{user_prompt}\n" if user_prompt else ""
                    ),
                    config=ReactConfig(),
                    investigation_id=investigation_id,
                    case_id=case_id,
                    bus=bus,
                    evidence_path=evidence_path,
                    output_dir=out_dir,
                    provider=provider,
                )
                result = await graph.ainvoke({
                    "messages": [self._initial_message(triage, user_prompt)],
                    "iteration": 0,
                })
                final_answer = result.get("final_answer") or self._fallback(triage, user_prompt)
            except Exception as e:
                bus.publish(E.error_event(investigation_id, f"agent loop failed: {e}"))
                final_answer = self._fallback(triage, user_prompt) + f"\n\n<!-- agent error: {e} -->"
        else:
            bus.publish(E.agent_thought(
                investigation_id,
                "No LLM provider configured. Deterministic triage only.",
            ))
            final_answer = self._fallback(triage, user_prompt)

        await self._set_node(bus, investigation_id, "react_loop", "done")

        await self._set_node(bus, investigation_id, "draft_report", "running")
        bus.publish(E.report_section_added(
            investigation_id, "narrative", "Examiner narrative", final_answer,
        ))
        await self._set_node(bus, investigation_id, "draft_report", "done")

        await self._set_node(bus, investigation_id, "hitl_review", "running")
        if settings.hitl_report_release == "required":
            from ..agent.hitl import request_approval
            approved = await request_approval(
                investigation_id,
                bus,
                "Report drafted. Review before finalize.",
                {"preview": final_answer[:600]},
            )
            if not approved:
                bus.publish(E.investigation_end(investigation_id, "cancelled", "HITL rejected"))
                await self._set_node(bus, investigation_id, "hitl_review", "skipped")
                return
        await self._set_node(bus, investigation_id, "hitl_review", "done")

        await self._set_node(bus, investigation_id, "finalize", "running")
        bus.publish(E.report_section_added(
            investigation_id, "summary", "Summary",
            f"Deadbox examination complete. Evidence: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _triage(self, root: str) -> str:
        import os
        counts: dict[str, int] = {"E01": 0, "raw_image": 0, "evtx": 0, "mft": 0, "registry": 0, "files": 0}
        for dp, _, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                counts["files"] += 1
                if fl.endswith((".e01", ".ex01")): counts["E01"] += 1
                elif fl.endswith((".raw", ".dd", ".001")): counts["raw_image"] += 1
                elif fl.endswith(".evtx"): counts["evtx"] += 1
                elif fl in ("$mft", "mft"): counts["mft"] += 1
                elif fl.endswith(("ntuser.dat", "system", "software", "sam", "security")):
                    counts["registry"] += 1
        parts = [f"{v} {k}" for k, v in counts.items() if v]
        return ", ".join(parts) if parts else "no recognized artifacts"

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Evidence triage complete. Found: {triage}.\n"
            f"Begin your deadbox examination. User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## Deadbox examination (deterministic triage)\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic examination. "
            "Configure one on the Model screen to enable the full investigation "
            "(filesystem parsing, feature extraction, artifact analysis, "
            "timeline building).\n\n"
            "Once configured, re-run this goal for a complete examination report."
        )


goal = DeadboxExaminationGoal()
