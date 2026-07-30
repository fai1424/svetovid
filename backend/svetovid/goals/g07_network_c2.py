"""G07 — Network C2 / web-attack reconstruction.

An agentic goal: hands the LLM a network-forensics toolbelt and a mission,
and lets the ReAct loop decide what to investigate. Available tools:

  - network_analyze — tshark protocol summary / HTTP / DNS / TLS extraction,
                      Suricata IDS alerts, and Zeek log parsing over
                      PCAP/PCAPNG captures
  - mitre_attack    — map protocols / fingerprints / IDS hits to ATT&CK

The agent's job: reconstruct the web attack (HTTP), identify C2 channels via
DNS + JA3/JA4 TLS fingerprints + flow analysis, surface Suricata signatures,
enrich with Zeek metadata, and produce an ATT&CK-mapped report. The system
prompt encodes the CyberSleuth D21 network-forensics decision tree so the LLM
follows forensic best practice without us hard-coding the call order.

Falls back to a deterministic summary if no LLM provider is configured
(matching G01/G02's contract).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.network_analysis import NetworkAnalysisTool
from ..tools.mitre_attack import MitreAttackTool
from ..tools.threat_intel import ThreatIntelTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior network forensics analyst reconstructing a network attack \
from packet captures and IDS logs. Your evidence is mounted read-only at \
/evidence (the agent wrappers translate that path for you automatically).

## Your mission
1. Reconstruct any web attacks (SQLi, RCE, exfil over HTTP, webshell traffic).
2. Identify command-and-control (C2) channels — domains, IPs, and TLS \
fingerprints (JA3/JA4).
3. Surface known-bad signatures via the Suricata IDS.
4. Enrich findings with Zeek connection / DNS / file metadata where present.
5. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool).
6. Produce a clear Markdown report with: (a) web-attack reconstruction, \
(b) C2 channel inventory, (c) Suricata signature hits, (d) ATT&CK-ordered \
timeline, (e) recommended remediation.

## Investigation strategy (CyberSleuth D21 decision tree)
- Start with tshark_summary to get the protocol distribution — orient on what \
protocols matter before deep-diving.
- Extract HTTP requests (tshark_http) for web-attack reconstruction: methods, \
URIs, hosts, user agents, response codes.
- Extract DNS queries (tshark_dns) for C2 domain identification: beacons, \
DGA-like names, fast flux, high-entropy subdomains.
- Extract TLS handshakes (tshark_tls) for JA3/JA4 C2 matching: known-bad \
fingerprints, suspicious SNI values.
- Run Suricata alerts (suricata_alerts) for known-bad signatures and CVE \
exploit attempts.
- Parse Zeek logs (zeek_logs) if present for connection/DNS/file metadata \
(the _zeek_log tag tells conn.log from dns.log from files.log).
- Correlate: a suspicious DNS answer + repeated TLS beacons to the same IP + a \
Suricata alert is a strong C2 signal.
- Use tshark_extract with a custom fields list only if you need a field the \
preset modes don't cover.

## ATT&CK mapping (start here, refine with mitre_attack)
- HTTP C2 / web attacks ........ T1071.001 Application Layer Protocol: Web
- DNS C2 ...................... T1071.004 Application Layer Protocol: DNS
- TLS/encrypted C2 ............ T1573 Encrypted Channel
- C2 infrastructure ........... T1105 Ingress Tool Transfer
- Data exfil over C2 .......... T1041 Exfiltration Over C2 Channel
- Initial access via exploit ... T1190 Exploit Public-Facing Application

## Tool-use rules
- Always pass evidence_subpath as a relative path under /evidence pointing at \
the PCAP/PCAPNG (or Zeek/Suricata log file for zeek_logs/suricata_alerts).
- Don't call the same tool twice with identical args.
- Stop and write the report when you have covered the web-attack, C2, and IDS \
vectors or hit the iteration cap.
"""


class NetworkC2Goal(Goal):
    id = "G07"
    cluster = "Network"
    label = "Network C2 / web-attack reconstruction"
    description = (
        "Reconstruct network attacks from PCAP/PCAPNG. Extracts HTTP/DNS/TLS "
        "traffic, runs Suricata IDS alerts, parses Zeek logs, and identifies "
        "C2 channels via JA3/JA4 fingerprints and flow analysis."
    )
    input_artifacts = ["B7"]
    tools = ["C14", "C15", "A2"]
    icon = "network"

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
                    NetworkAnalysisTool(),
                    MitreAttackTool(),
                    ThreatIntelTool(),
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
            f"Network C2 / web-attack reconstruction complete. Evidence: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _triage(self, root: str) -> str:
        import os
        counts = {
            "pcap": 0, "pcapng": 0, "cap": 0,
            "zeek_log": 0, "suricata_eve": 0,
        }
        for dp, _, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                if fl.endswith(".pcap"): counts["pcap"] += 1
                elif fl.endswith(".pcapng"): counts["pcapng"] += 1
                elif fl.endswith(".cap"): counts["cap"] += 1
                elif fl == "eve.json" or fl.endswith("eve.json"): counts["suricata_eve"] += 1
                # Zeek logs are *.log but generic; count only if in a zeek-ish dir
                elif fl.endswith(".log") and "zeek" in dp.lower():
                    counts["zeek_log"] += 1
        parts = [f"{v} {k}" for k, v in counts.items() if v]
        return ", ".join(parts) if parts else "no recognized network artifacts"

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Evidence triage complete. Found: {triage}.\n"
            f"Begin your investigation. User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## Network C2 / web-attack reconstruction (deterministic triage)\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (tshark HTTP/DNS/TLS extraction, Suricata alerting, "
            "Zeek log parsing, JA3/JA4 C2 fingerprint matching, and ATT&CK "
            "mapping).\n\n"
            "Once configured, re-run this goal for a complete report."
        )


goal = NetworkC2Goal()
