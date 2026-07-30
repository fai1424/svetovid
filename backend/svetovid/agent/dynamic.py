"""Dynamic investigation — no predefined goal, the agent reasons freely.

Instead of the planner picking G03 or G07 from a static menu, the agent:
1. Lists the evidence directory to see what's there
2. Reads the user's incident description
3. Dynamically decides what tools to call, in what order
4. Investigates from the FULL tool library (all 32+ tools)
5. Writes a customized report answering the user's specific questions

This replaces the rigid "pick a goal → run its fixed pipeline" model with
true agentic investigation: the LLM IS the investigator, not a dispatcher.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..goals.base import Goal, GoalNode

logger = logging.getLogger(__name__)


DYNAMIC_SYSTEM_PROMPT = """\
You are a senior DFIR analyst. The user has described an incident and pointed \
you at a folder of evidence. Your job is to investigate the evidence, answer \
the user's questions, and write a forensic report.

## How to investigate (general strategy)
1. FIRST: Call list_evidence to see exactly what files are in the evidence \
folder. Don't guess — look.
2. Based on what you find, choose the right tools:
   - .evtx files → chainsaw_hunt (Sigma rule hunting) + hayabusa_timeline
   - Windows triage folder (.pf, registry hives, $MFT) → eztools (PECmd, \
MFTECmd, RECmd, AmcacheParser)
   - Memory image (.raw, .mem, .vmem) → volatility (pslist, malfind, netscan)
   - Network capture (.pcap, .pcapng) → network_analyze (tshark, suricata)
   - Disk image (.E01, .dd, .raw) → tsk (mmls to find partitions, fls to list)
   - Linux logs (syslog, auth.log, journal) → linux_log_parse
   - macOS artifacts → macos_artifact_parse
   - iOS backup → ileapp_parse
   - Android dump → aleapp_parse
   - Kubernetes audit/logs → k8s_parse
   - CRIU checkpoint → criu_parse or criu_mem_search
   - Email files (.pst, .ost, .eml) → email_parse
   - Cloud logs (JSON) → cloud APIs (m365/gworkspace/aws/azure/gcp)
   - Any text/log files → forensic_keyword_search
3. After running tools, analyze the results. If you find suspicious activity:
   - Use mitre_attack to map findings to ATT&CK techniques
   - Use threat_intel_lookup to check IOCs against VirusTotal/abuse.ch
   - Use pii_scan if you suspect data exfiltration
   - Use timeline_gap_analysis if you suspect log tampering
   - Use evidence_correlate to find relationships across findings
4. When you've answered the user's questions, write a comprehensive report.

## Report structure
Your final report should include:
- Executive Summary (what happened, in plain language)
- Evidence Examined (what files you analyzed)
- Key Findings (each finding with: what, when, which tool found it, ATT&CK mapping)
- IOC Table (any indicators of compromise: IPs, hashes, domains, URLs)
- Timeline (chronological list of significant events)
- Recommended Actions (containment, remediation, further investigation)

## Rules
- Always cite the source tool + file for each finding.
- Don't invent findings — only report what the tools actually returned.
- If a tool fails, try a different tool. Don't retry the same call.
- If you can't answer a question because the evidence doesn't contain it, \
say so explicitly.
- Use the user's specific questions (below) as your investigation objectives.
"""


class DynamicInvestigationGoal(Goal):
    """A goal that doesn't constrain the agent — it gives it ALL tools and
    lets it investigate freely based on the user's description + evidence.

    This is the primary investigation mode. The 23 predefined goals (G01-G23)
    are still available as "browse goals" fallback, but this dynamic mode
    is the recommended path.
    """

    id = "DYNAMIC"
    cluster = "Dynamic"
    label = "Dynamic investigation"
    description = (
        "The agent examines the evidence, reads your incident description, "
        "and dynamically decides what to investigate — no predefined goal."
    )
    input_artifacts: list[str] = []  # accepts anything
    tools: list[str] = []  # uses all tools
    icon = "sparkles"

    def nodes(self) -> list[GoalNode]:
        return [
            GoalNode("triage", "Examine evidence"),
            GoalNode("investigate", "Agent investigation"),
            GoalNode("report", "Write report"),
            GoalNode("review", "Review (human)"),
            GoalNode("finalize", "Finalize"),
        ]

    async def run(self, *, investigation_id: str, case_id: str,
                  evidence_path: str, user_prompt: str, bus) -> None:
        out_dir = str(Path.home() / ".svetovid" / "cases" / case_id / investigation_id)
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        # ---- triage: list the evidence so the agent knows what it's working with ----
        await self._set_node(bus, investigation_id, "triage", "running")

        # Run list_evidence to get the file inventory
        from ..tools.list_evidence import ListEvidenceTool
        list_tool = ListEvidenceTool()
        from ..tools.base import ToolContext
        ctx = ToolContext(
            investigation_id=investigation_id, case_id=case_id, bus=bus,
            evidence_path=evidence_path, output_dir=out_dir,
        )
        list_result = await list_tool.invoke({}, ctx)
        evidence_summary = list_result.summary or "Unable to list evidence"

        bus.publish(E.agent_thought(
            investigation_id,
            f"Evidence inventory: {evidence_summary}",
        ))
        await self._set_node(bus, investigation_id, "triage", "done")

        # ---- investigate: run the agent with ALL tools ----
        await self._set_node(bus, investigation_id, "investigate", "running")

        settings = load_settings()
        provider = settings.active()

        final_answer = ""
        if provider and provider.is_configured() and provider.api_key:
            try:
                tools = self._get_all_tools()
                graph = build_react_graph(
                    tools=tools,
                    system_prompt=DYNAMIC_SYSTEM_PROMPT + (
                        f"\n\n## User's incident description and questions\n{user_prompt}\n\n"
                        f"## Evidence inventory (from list_evidence)\n{evidence_summary}\n\n"
                        f"## Evidence path\n{evidence_path}\n"
                    ),
                    config=ReactConfig(),  # unlimited iterations + tokens
                    investigation_id=investigation_id,
                    case_id=case_id,
                    bus=bus,
                    evidence_path=evidence_path,
                    output_dir=out_dir,
                    provider=provider,
                )
                result = await graph.ainvoke({
                    "messages": [self._initial_message(evidence_summary, user_prompt)],
                    "iteration": 0,
                })
                final_answer = result.get("final_answer") or self._fallback(evidence_summary, user_prompt)
            except Exception as e:
                logger.exception("dynamic investigation failed")
                bus.publish(E.error_event(investigation_id, f"agent loop failed: {e}"))
                final_answer = self._fallback(evidence_summary, user_prompt) + f"\n\n<!-- agent error: {e} -->"
        else:
            bus.publish(E.agent_thought(
                investigation_id,
                "No LLM provider configured. Configure one on the Model screen.",
            ))
            final_answer = self._fallback(evidence_summary, user_prompt)

        await self._set_node(bus, investigation_id, "investigate", "done")

        # ---- report ----
        await self._set_node(bus, investigation_id, "report", "running")
        bus.publish(E.report_section_added(
            investigation_id, "narrative", "Investigator narrative", final_answer,
        ))
        await self._set_node(bus, investigation_id, "report", "done")

        # ---- HITL ----
        await self._set_node(bus, investigation_id, "review", "running")
        if settings.hitl_report_release == "required":
            from .hitl import request_approval
            approved = await request_approval(
                investigation_id, bus,
                "Report drafted. Review before finalize.",
                {"preview": final_answer[:600]},
            )
            if not approved:
                bus.publish(E.investigation_end(investigation_id, "cancelled", "HITL rejected"))
                await self._set_node(bus, investigation_id, "review", "skipped")
                return
        await self._set_node(bus, investigation_id, "review", "done")

        # ---- finalize ----
        await self._set_node(bus, investigation_id, "finalize", "running")
        bus.publish(E.report_section_added(
            investigation_id, "summary", "Summary",
            f"Investigation complete. Evidence: {evidence_summary}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    def _get_all_tools(self) -> list:
        """Return ALL available tool wrappers — the agent picks which to use."""
        from ..tools.chainsaw import ChainsawTool
        from ..tools.hayabusa import HayabusaTool
        from ..tools.eztools import EzTool
        from ..tools.volatility import VolatilityTool
        from ..tools.yara import YaraTool
        from ..tools.sleuthkit import SleuthKitTool
        from ..tools.forensic_search import ForensicSearchTool
        from ..tools.bulk_extractor import BulkExtractorTool
        from ..tools.threat_intel import ThreatIntelTool
        from ..tools.linux_logs import LinuxLogParseTool
        from ..tools.macos_logs import MacosArtifactTool
        from ..tools.network_analysis import NetworkAnalysisTool
        from ..tools.email_parse import EmailParseTool
        from ..tools.ileapp_parse import IleappTool
        from ..tools.aleapp_parse import AleappParseTool
        from ..tools.k8s_parse import K8sParseTool
        from ..tools.pii_scanner import PIIScannerTool
        from ..tools.timeline_gap import TimelineGapTool
        from ..tools.usb_history import USBHistoryTool
        from ..tools.registry_mru import RegistryMRUTool
        from ..tools.decryptor_lookup import RansomwareDecryptorTool
        from ..tools.evidence_graph import EvidenceGraphTool

        tools = [
            ChainsawTool(),
            HayabusaTool(),
            EzTool(),
            VolatilityTool(),
            YaraTool(),
            SleuthKitTool(),
            ForensicSearchTool(),
            BulkExtractorTool(),
            ThreatIntelTool(),
            LinuxLogParseTool(),
            MacosArtifactTool(),
            NetworkAnalysisTool(),
            EmailParseTool(),
            IleappTool(),
            AleappParseTool(),
            K8sParseTool(),
            PIIScannerTool(),
            TimelineGapTool(),
            USBHistoryTool(),
            RegistryMRUTool(),
            RansomwareDecryptorTool(),
            EvidenceGraphTool(),
        ]
        return tools

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    def _initial_message(self, evidence_summary: str, user_prompt: str) -> str:
        return (
            f"Evidence inventory complete: {evidence_summary}\n\n"
            f"User's request: {user_prompt}\n\n"
            f"Begin your investigation. Call list_evidence first if you need to "
            f"see specific file paths, then use the appropriate forensic tools "
            f"to answer the user's questions."
        )

    def _fallback(self, evidence_summary: str, user_prompt: str) -> str:
        return (
            "## Investigation report (deterministic — no LLM)\n\n"
            f"**Evidence found:** {evidence_summary}\n\n"
            f"**User request:** {user_prompt}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen for full investigation."
        )


goal = DynamicInvestigationGoal()
