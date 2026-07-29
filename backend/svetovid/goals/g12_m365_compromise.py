"""G12 — M365 / Microsoft cloud incident.

The agentic Microsoft 365 / cloud-compromise goal. Like G17 (Slack), the
evidence here is *not* a disk image — it's the live Microsoft 365 tenant,
reached through Microsoft Graph. The agent drives the cloud-incident-response
decision tree via two tools:

  - m365_audit    — one API tool, operation selector, exposes unified_audit_log,
                    entra_signins, entra_audit, exchange_mailbox, sharepoint_files,
                    teams_activity, risky_users. Calls Graph with a token from
                    M365_ACCESS_TOKEN.
  - mitre_attack  — map observed behaviors to ATT&CK techniques.

The system prompt encodes the cloud-incident-response playbook (Unified Audit
Log first, then Entra sign-ins for auth anomalies, mailbox access, SharePoint
exfil, identity-protection risky users, then ATT&CK mapping) so the LLM
follows IR best practice without a hard-coded call order.

This tool runs on host (no Docker): the m365_audit wrapper uses
``image=None`` and ``sandboxed=False`` — it makes outbound HTTPS calls to
Microsoft Graph, it does not touch the sandbox.

Falls back to a deterministic summary if no LLM provider is configured
(matching the contract of every other agentic goal), and also degrades
gracefully if M365_ACCESS_TOKEN is unset (the tool returns a clear error and
the agent adapts).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.cloud.m365_api import M365ApiTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior cloud security / DFIR analyst investigating a potential \
compromise of a Microsoft 365 (M365) tenant. You reach the tenant through \
Microsoft Graph via the m365_audit tool (an access token is read from the \
M365_ACCESS_TOKEN environment variable by the wrapper). The MITRE ATT&CK \
knowledge base is available through the mitre_attack tool.

## Your mission
1. Establish a timeline of security-relevant events from the Unified Audit Log.
2. Detect mailbox takeover (MailItemsAccessed by unfamiliar IPs, anomalous \
Send / SendAs, suspicious inbox-rule creation, Add-MailboxPermission).
3. Detect Entra ID (Azure AD) token abuse and authentication anomalies \
(impossible-travel sign-ins, legacy-protocol auth, MFA fatigue, conditional-\
access bypass, service-principal misuse, consent grant phishing).
4. Detect SharePoint / OneDrive data exfiltration (bulk FileAccessed / \
FileDownloaded, AnonymousLinkCreated, SharingInvitationCreated to external \
recipients).
5. Detect Teams-based social engineering (unusual message reads/sends, \
external-channel creation, meeting joins by anomalous actors).
6. Check Entra ID Identity Protection for flagged risky users / sessions.
7. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool) \
and produce a clear Markdown report.

## Investigation strategy (cloud compromise decision tree)
- **Start with the Unified Audit Log (m365_audit operation=unified_audit_log).** \
The UAL is the backbone of the timeline across Exchange, SharePoint, OneDrive, \
Teams, and Entra ID. Look for bursts of activity, anomalous client IPs / user \
agents, and operations outside business hours.
- **Then check Entra ID sign-ins (m365_audit operation=entra_signins).** Flag \
impossible-travel (geo leaps), legacy auth (clientAppUsed = POP/IMAP/SMTP), \
high-risk sign-ins (riskLevelDuringSignIn), repeated failures followed by \
success (T1110 brute force), and conditional-access bypasses. Narrow with \
user_filter=<UPN> when you've identified a suspect identity.
- **Then mailbox access (m365_audit operation=exchange_mailbox).** This filters \
the UAL to Exchange + mailbox operations. MailItemsAccessed (especially with \
the AuditData property showing ClientAppId of a non-Outlook app) is the classic \
T1078 token-theft mailbox-read signal. New/Set/Update-InboxRule is T1098 \
account-manipulation / forwarding-rule persistence. Send / SendAs by an \
unfamiliar actor is outbound abuse.
- **Then SharePoint files (m365_audit operation=sharepoint_files).** A spike in \
FileDownloaded / FileAccessed, or AnonymousLinkCreated / \
SharingInvitationCreated to external addresses, is the T1567 exfiltration-to-\
cloud pattern. Cross-reference the file actors with the suspicious users from \
the UAL and sign-in logs.
- **Then Teams activity (m365_audit operation=teams_activity).** Look for \
externally-initiated messages, external-channel creation, and message reads by \
anomalous actors — these are the T1566 social-engineering and recon vectors.
- **Then identity protection (m365_audit operation=risky_users).** Entra ID \
Identity Protection surfaces users/sessions flagged for credential leaks, \
impossible travel, and malware-linked IPs. Risk state 'atRisk' / 'confirmedCompromised' \
should drive your remediation section.
- **ATT&CK mapping.** Use the mitre_attack tool: T1078 Valid Accounts (token \
abuse / account takeover), T1098 Account Manipulation (inbox rules, mailbox \
permissions, consent grants), T1110 Brute Force, T1567 Exfiltration to Web \
Service (SharePoint/OneDrive mass download), T1566 Phishing (Teams/social + \
consent-grant phishing), T1528 Steal Application Access Token (service-principal / \
consent-grant token theft). Cite the technique ID in the report.

## Adaptation rules
- If m365_audit returns a "M365_ACCESS_TOKEN ... not set" error, stop and \
report that the M365 Graph integration is unconfigured — do not retry the \
same call.
- If m365_audit returns a graph_forbidden error, the token lacks the required \
Graph permissions (AuditLog.Read.All / Directory.Read.All / \
IdentityRiskyUser.Read.All); note the gap explicitly and pivot to the \
operations the token does permit.
- Don't call the same (operation, user_filter, time_range) twice with identical \
args.
- Stop and write the report when you have covered the decision tree or hit \
the iteration cap.
"""


class M365CloudCompromiseGoal(Goal):
    id = "G12"
    cluster = "Cloud"
    label = "M365 / Microsoft cloud incident"
    description = (
        "Investigate M365 compromises via the Unified Audit Log and Graph API. "
        "Detects mailbox takeover, Entra ID token abuse, SharePoint/OneDrive "
        "exfiltration, and Teams-based social engineering."
    )
    input_artifacts = ["B10c"]
    tools = ["C16", "A2"]
    icon = "cloud"

    def nodes(self) -> list[GoalNode]:
        return [
            GoalNode("triage", "Triage tenant"),
            GoalNode("react_loop", "Agent investigation (ReAct)"),
            GoalNode("draft_report", "Draft report"),
            GoalNode("hitl_review", "Review (human)"),
            GoalNode("finalize", "Finalize"),
        ]

    async def run(self, *, investigation_id: str, case_id: str,
                  evidence_path: str, user_prompt: str, bus) -> None:
        out_dir = str(Path.home() / ".svetovid" / "cases" / case_id / investigation_id)
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        # ---- triage: do we have an M365 token? ----
        await self._set_node(bus, investigation_id, "triage", "running")
        triage = self._triage()
        bus.publish(E.agent_thought(
            investigation_id,
            f"M365 integration triage: {triage}",
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
                    M365ApiTool(),
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
            f"M365 / Microsoft cloud incident complete. Integration: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    def _triage(self) -> str:
        """Report whether the M365 Graph integration is available.

        This goal's "evidence" is the live tenant, not a disk image, so
        triage = "do we have a usable M365_ACCESS_TOKEN?".
        """
        token = os.environ.get("M365_ACCESS_TOKEN", "").strip()
        if token:
            return "M365_ACCESS_TOKEN present; Microsoft Graph reachable"
        return (
            "M365_ACCESS_TOKEN not set — Microsoft Graph integration is "
            "unconfigured; the m365_audit tool will report the missing token"
        )

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"M365 integration triage complete. {triage}.\n"
            f"Begin your Microsoft 365 compromise investigation. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## M365 / Microsoft cloud incident (deterministic triage)\n\n"
            f"**Integration status:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (Unified Audit Log triage, Entra ID sign-in anomaly "
            "hunting, mailbox-access review, SharePoint/OneDrive exfil detection, "
            "Teams activity review, Identity Protection risky-user review, "
            "ATT&CK mapping).\n\n"
            "Additionally, ensure the `M365_ACCESS_TOKEN` environment variable is "
            "set to a Microsoft Graph access token (delegated or application "
            "permissions) carrying the `AuditLog.Read.All`, `Directory.Read.All`, "
            "and `IdentityRiskyUser.Read.All` Graph scopes.\n\n"
            "Once configured, re-run this goal for a complete compromise report."
        )


goal = M365CloudCompromiseGoal()
