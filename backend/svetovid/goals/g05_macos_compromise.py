"""G05 — macOS endpoint compromise investigation.

The macOS analog of G02. An macOS endpoint compromise investigation walks the
artifacts that make up a macOS system's "story": Unified Logs, knowledgeC.db
(app usage), TCC.db (privacy grants), LaunchAgents/Daemons (persistence),
QuarantineEvents (download provenance), FSEvents (file-system activity), and
Safari History. Available tools:

  - macos_artifact_parse — Parse any of the macOS forensic artifacts above
                           into structured rows (sqlite3/plistlib in the
                           svetovid/base image; .tracev3 metadata only)
  - mitre_attack         — Map observed behaviors to ATT&CK techniques
  - chainsaw_hunt        — Sigma hunt if any .evtx was captured from the host
                           (rare, but available so the agent can pivot)

The agent's job: reconstruct what ran, what persisted, what was downloaded,
and what privacy permissions were granted, then map it to ATT&CK and produce
a report. The system prompt encodes the macOS IR decision tree so the LLM
follows forensic best practice without us hard-coding the call order.

Falls back to a deterministic summary if no LLM provider is configured
(matching G01/G02/G03's contract).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.macos_logs import MacosArtifactTool
from ..tools.mitre_attack import MitreAttackTool
from ..tools.chainsaw import ChainsawTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior macOS DFIR analyst investigating a potential endpoint \
compromise. Your evidence is a macOS disk image or live-acquired artifact \
tree, mounted read-only at /evidence (the agent wrappers translate that path \
for you automatically).

## Your mission
1. Reconstruct the app/usage timeline and identify anomalies (knowledgeC.db).
2. Enumerate persistence mechanisms: LaunchAgents, LaunchDaemons, login \
items, and anything that runs at load / keeps itself alive.
3. Identify privacy permission grants that enabled the compromise \
(TCC.db — Full Disk Access, Accessibility, Screen Recording, etc.).
4. Trace download provenance for suspicious binaries \
(Gatekeeper QuarantineEvents).
5. Correlate file-system activity around the time of compromise (FSEvents).
6. Note Unified Log (.tracev3) presence for deeper host-side log analysis.
7. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool).
8. Produce a clear Markdown report with: (a) compromise timeline, (b) \
persistence inventory, (c) privacy-permission anomalies, (d) download \
provenance, (e) ATT&CK-mapped findings, (f) recommended remediation.

## Investigation strategy (macOS IR decision tree)
- Start with persistence: parse launchagents on the LaunchAgents/LaunchDaemons \
directories. Anything with RunAtLoad=true or KeepAlive that runs a binary \
outside /System or a known vendor path is suspicious.
- Build the activity timeline with knowledgec (knowledgeC.db) — pivot on \
suspicious bundle IDs and unusual usage bursts.
- Check tcc_db (TCC.db) for grants to unexpected clients (Accessibility / \
Full Disk Access to a non-Apple binary is a strong indicator).
- Trace every suspicious binary back to its source with quarantine \
(QuarantineEventsV2) — the origin URL is the download provenance.
- Use fsevents (.fseventsd) to see what the filesystem was doing around the \
suspected execution window.
- unified_log (.tracev3) returns metadata only — the binary records need \
Apple's `log` tool on a live macOS host. Note this limitation in the report.
- If .evtx evidence is present (rare for macOS), run chainsaw_hunt to \
cross-check; otherwise rely on the macOS artifacts above.

## Tool-use rules
- Always pass evidence_subpath as a relative path under /evidence.
- Call macos_artifact_parse once per artifact_type — don't repeat a type \
with identical args.
- Stop and write the report when you have covered the persistence, usage, \
permission, and download vectors, or hit the iteration cap.
"""


class MacosCompromiseGoal(Goal):
    id = "G05"
    cluster = "Endpoint"
    label = "macOS endpoint compromise"
    description = (
        "Investigate a macOS endpoint compromise. The agent reconstructs the "
        "app-usage timeline (knowledgeC.db), enumerates LaunchAgents/Daemons "
        "persistence, audits TCC.db privacy grants, traces download "
        "provenance via Gatekeeper Quarantine, and correlates FSEvents "
        "activity. Produces an ATT&CK-mapped compromise report."
    )
    input_artifacts = ["B5"]
    tools = ["C12a", "C16", "A2"]
    icon = "laptop"

    def nodes(self) -> list[GoalNode]:
        return [
            GoalNode("triage", "Triage evidence"),
            GoalNode("react_loop", "Agent investigation (ReAct)"),
            GoalNode("draft_report", "Draft report"),
            GoalNode("hitl_review", "Review (human)"),
            GoalNode("finalize", "Finalize"),
        ]

    async def run(self, *, investigation_id: str, case_id: str,
                  evidence_path: str, user_prompt: str, bus) -> None:
        out_dir = str(Path.home() / ".svetovid" / "cases" / case_id / investigation_id)
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        # ---- triage: list what we have ----
        await self._set_node(bus, investigation_id, "triage", "running")
        triage = await self._triage(evidence_path)
        bus.publish(E.agent_thought(
            investigation_id,
            f"Evidence triage: {triage}",
        ))
        await self._set_node(bus, investigation_id, "triage", "done")

        settings = load_settings()
        provider = settings.active()

        # ---- react loop ----
        await self._set_node(bus, investigation_id, "react_loop", "running")
        final_answer = ""
        if provider and provider.is_configured() and provider.api_key:
            try:
                tools = [
                    MacosArtifactTool(),
                    MitreAttackTool(),
                    ChainsawTool(),
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
                "No LLM provider configured. Run deterministic triage only; "
                "configure a provider on the Model screen for full agentic analysis.",
            ))
            final_answer = self._fallback(triage, user_prompt)

        await self._set_node(bus, investigation_id, "react_loop", "done")

        # ---- draft report ----
        await self._set_node(bus, investigation_id, "draft_report", "running")
        bus.publish(E.report_section_added(
            investigation_id, "narrative", "Investigator narrative", final_answer,
        ))
        await self._set_node(bus, investigation_id, "draft_report", "done")

        # ---- HITL ----
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

        # ---- finalize ----
        await self._set_node(bus, investigation_id, "finalize", "running")
        bus.publish(E.report_section_added(
            investigation_id, "summary", "Summary",
            f"macOS endpoint compromise investigation complete. Evidence: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _triage(self, root: str) -> str:
        import os
        counts: dict[str, int] = {
            "knowledgec": 0, "tcc": 0, "quarantine": 0, "install_history": 0,
            "launchagents": 0, "fsevents": 0, "tracev3": 0, "safari_history": 0,
            "evtx": 0, "files": 0,
        }
        for dp, _, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                counts["files"] += 1
                if fl == "knowledgec.db":
                    counts["knowledgec"] += 1
                elif fl == "tcc.db":
                    counts["tcc"] += 1
                elif "quarantineevents" in fl:
                    counts["quarantine"] += 1
                elif fl == "installhistory.plist":
                    counts["install_history"] += 1
                elif fl.endswith(".tracev3"):
                    counts["tracev3"] += 1
                elif fl.endswith(".evtx"):
                    counts["evtx"] += 1
                elif fl == "history.db" and "safari" in dp.lower():
                    counts["safari_history"] += 1
            # directory-name markers for LaunchAgents / FSEvents
            dpl = dp.lower()
            if dpl.endswith(("launchagents", "launchdaemons")):
                counts["launchagents"] += sum(1 for f in fns if f.lower().endswith(".plist"))
            if dpl.endswith(".fseventsd"):
                counts["fsevents"] += len(fns)
        parts = [f"{v} {k}" for k, v in counts.items() if v]
        return ", ".join(parts) if parts else "no recognized macOS artifacts"

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Evidence triage complete. Found: {triage}.\n"
            f"Begin your macOS compromise investigation. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## macOS endpoint compromise (deterministic triage)\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (knowledgeC app-usage timeline, LaunchAgents "
            "persistence enumeration, TCC privacy-grant audit, Gatekeeper "
            "quarantine provenance, FSEvents correlation, ATT&CK mapping).\n\n"
            "Once configured, re-run this goal for a complete report."
        )


goal = MacosCompromiseGoal()
