"""G11 — Android mobile device forensic examination.

The agentic mobile-forensics goal. Evidence is a mounted read-only copy of an
Android logical / physical extraction at /evidence. The agent drives the
Android-IR decision tree across the common artifact types:

  - aleapp_parse  — one tool, artifact_type selector, parses contacts, sms_mms,
                    call_log, usage_stats (XML/binary), chrome_history,
                    location_history, accounts, app_metadata (packages.xml),
                    wifi_config and firebase into structured rows
  - mitre_attack  — map observed behaviors (sideloading, account harvest,
                    location tracking, exfiltration, credential capture) to
                    ATT&CK Mobile techniques

The system prompt encodes the SANS / NIST mobile-investigation playbook
(usage_stats timeline → comms → relationships → movement → accounts →
sideloaded/backdoor apps → ATT&CK) so the LLM follows forensic best practice
without a hard-coded call order.

Falls back to a deterministic summary if no LLM provider is configured
(matching G01..G09's contract).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.aleapp_parse import AleappParseTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior mobile-forensics analyst investigating an Android device \
extraction. Your evidence is mounted read-only at /evidence (the agent \
wrappers translate that path for you automatically). The python3 stdlib \
(sqlite3, xml, json) is available inside the sandbox.

## Your mission
1. Build a usage timeline: which apps were used, when, and for how long \
(usage_stats).
2. Reconstruct communications: SMS/MMS threads and call logs (sms_mms, \
call_log).
3. Establish relationships: contacts and address books (contacts).
4. Reconstruct movement: location history / fused-location fixes \
(location_history).
5. Enumerate credentials: account manager entries and cloud project keys \
(accounts, firebase).
6. Identify sideloaded, backdoor, or otherwise suspicious apps \
(app_metadata) and the network context they could use (wifi_config) plus \
their browsing footprint (chrome_history).
7. Map every finding to MITRE ATT&CK (Mobile + Enterprise) techniques (use \
the mitre_attack tool).
8. Produce a clear Markdown report with: (a) app-usage timeline, (b) \
communications summary, (c) contacts of interest, (d) movement timeline, \
(e) account / credential inventory, (f) sideloaded / suspicious-app \
inventory, (g) ATT&CK-mapped timeline, (h) recommended remediation.

## Investigation strategy (Android IR decision tree)
- **usage_stats first (app timeline).** Parse the usagestats XML/binary \
records to learn which apps ran, in what order, and when. This anchors the \
entire timeline. Hot apps here steer the rest of the investigation.
- **sms_mms for communications.** Parse mmssms.db to recover message \
threads (address, body, date, incoming/outgoing). Flag messages containing \
one-time passcodes, URLs, or credential-bearing language.
- **call_log for comms volume.** Parse the calls table for number, \
timestamp, duration and direction; correlate frequent numbers with the \
contacts and sms hits.
- **contacts for relationships.** Parse contacts2.db for names, phone \
numbers, emails and organizations. Use these to attribute the sms / call \
addresses and to surface associations of interest.
- **location_history for movement.** Parse Google / fused-location stores \
(SQLite or JSON) for lat/lon fixes with timestamps; build a movement \
timeline and note any clustering at sensitive locations.
- **accounts for credentials.** Parse accounts.db (and the AccountManager \
stores) for account type + name. These reveal which Google / corporate / \
messaging identities the device is bound to.
- **app_metadata for sideloaded / backdoor apps.** Parse packages.xml and \
flag packages with no installer (sideloaded APKs), non-Play installers, or \
dangerous permissions (send_sms, install_packages, accessibility, \
read_contacts, record_audio). These are the prime backdoor / stalkerware \
candidates.
- **wifi_config + chrome_history for context.** WifiConfigStore.xml shows \
known SSIDs (places the device has been / softap tethering); Chrome History \
shows browsing that may corroborate phishing or C2.
- **firebase for cloud project keys.** google-services.json / Firebase \
Installations reveal project ids, API keys and SDK app ids — useful when an \
app is exfiltrating to a backend you want to attribute.
- **ATT&CK mapping.** Use the mitre_attack tool to map: T1437 / T1437.001 \
(crypto / monetization), T1417 / T1417.001 (capture audio / input), \
T1419 (malicious apps / sideloading), T1430 (data from local system), \
T1630 (credential dumping on device), T1430.001 (archive collected data), \
and the Enterprise equivalents (T1078 Valid Accounts, T1213 data from \
information repositories). Cite the technique ID in the report.

## Tool-use rules
- Always pass evidence_subpath as a relative path under /evidence.
- Parse one artifact_type per call; pick the next type based on what you found.
- Don't call the same (artifact_type, evidence_subpath) twice with identical args.
- For every notable finding, map it with mitre_attack (op=lookup) and cite \
the technique ID in your report.
- Stop and write the report when you have covered the artifact types or hit \
the iteration cap.
"""


class AndroidForensicsGoal(Goal):
    id = "G11"
    cluster = "Mobile"
    label = "Android device forensics"
    description = (
        "Parse Android extractions for contacts, messages, call logs, app "
        "usage, location, and accounts. Builds a usage timeline and "
        "identifies sideloaded or suspicious apps."
    )
    input_artifacts = ["B10b"]
    tools = ["C12b", "A2"]
    icon = "smartphone-charging"

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
                    AleappParseTool(),
                    MitreAttackTool(),
                ]
                graph = build_react_graph(
                    tools=tools,
                    system_prompt=SYSTEM_PROMPT + (
                        f"\n\n## Additional user context\n{user_prompt}\n" if user_prompt else ""
                    ),
                    config=ReactConfig(max_iterations=15),
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
            f"Android device forensic examination complete. Evidence: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _triage(self, root: str) -> str:
        import os
        counts = {
            "contacts_db": 0, "sms_db": 0, "call_db": 0,
            "usage_stats": 0, "chrome_history": 0, "location": 0,
            "accounts_db": 0, "packages_xml": 0, "wifi_config": 0,
            "firebase": 0,
        }
        for dp, dns, fns in os.walk(root):
            low_dir = dp.lower()
            for fn in fns:
                fl = fn.lower()
                if fl in ("contacts2.db", "contacts.db"):
                    counts["contacts_db"] += 1
                elif fl in ("mmssms.db", "telephony.db"):
                    counts["sms_db"] += 1
                elif fl in ("calllog.db",):
                    counts["call_db"] += 1
                elif fl.startswith("packages-") and fl.endswith(".xml"):
                    counts["usage_stats"] += 1
                elif fl in ("history", "history.db") and "chrome" in low_dir:
                    counts["chrome_history"] += 1
                elif fl.endswith((".db", ".json")) and "location" in fl:
                    counts["location"] += 1
                elif fl in ("accounts.db",):
                    counts["accounts_db"] += 1
                elif fl == "packages.xml":
                    counts["packages_xml"] += 1
                elif fl in ("wificonfigstore.xml", "wifi_config_store.xml"):
                    counts["wifi_config"] += 1
                elif fl in ("google-services.json", "google-services.xml") or \
                     "firebase" in fl:
                    counts["firebase"] += 1
        parts = [f"{v} {k}" for k, v in counts.items() if v]
        return ", ".join(parts) if parts else "no recognized Android artifacts"

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Evidence triage complete. Found: {triage}.\n"
            f"Begin your Android device forensic investigation. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## Android device forensics (deterministic triage)\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (usage_stats timeline, SMS/call parsing, contacts, "
            "location history, account / credential enumeration, sideloaded / "
            "backdoor app detection, ATT&CK mapping).\n\n"
            "Once configured, re-run this goal for a complete mobile-forensics "
            "report."
        )


goal = AndroidForensicsGoal()
