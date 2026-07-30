"""G13 — Cloud control-plane compromise (Google Workspace).

The agentic Google Workspace-compromise goal. Like G17 (Slack), the evidence
here is *not* a disk image — it's the live Workspace tenant, reached through
the Google Admin SDK Reports API. The agent drives the cloud-incident
decision tree:

  - gworkspace_audit — one API tool, operation selector, exposes
                       admin_reports_login / _token / _admin / _drive / _gmail,
                       oauth_grants, and user_list. Calls the Admin SDK with a
                       token from GWS_ACCESS_TOKEN.
  - mitre_attack     — map observed behaviors to ATT&CK techniques.

The system prompt encodes the Google Workspace IR playbook (login anomalies
first, then OAuth token abuse, then Drive exfil, then malicious app grants)
so the LLM follows forensic best practice without a hard-coded call order.

This tool runs on host (no Docker): the gworkspace_audit wrapper uses
``image=None`` and ``sandboxed=False`` — it makes outbound HTTPS calls to
Google, it does not touch the sandbox.

Falls back to a deterministic summary if no LLM provider is configured
(matching the contract of every other agentic goal), and also degrades
gracefully if GWS_ACCESS_TOKEN is unset (the tool returns a clear error and
the agent adapts).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.cloud.gworkspace_api import GworkspaceApiTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior cloud security / DFIR analyst investigating a potential \
compromise of a Google Workspace tenant. You reach the tenant through the \
Google Admin SDK Reports API via the gworkspace_audit tool (an OAuth2 access \
token is read from the GWS_ACCESS_TOKEN environment variable by the wrapper). \
The MITRE ATT&CK knowledge base is available through the mitre_attack tool.

## Your mission
1. Establish a timeline of security-relevant events from the Admin SDK \
Reports API.
2. Identify account takeover (impossible travel, anomalous logins, failed \
login bursts, MFA reset / disable, government-backed attack warnings).
3. Detect OAuth token abuse — malicious third-party apps granted delegated \
access (the classic consent-phishing / token-implant channel).
4. Detect Drive data exfiltration (bulk downloads, mass external shares, \
uploads to attacker-controlled external accounts).
5. Find Gmail filter / forwarding-rule injection (secret auto-forwarding \
rules and import filters are BEC-style persistence).
6. Surface admin-console abuse (privilege escalation, new admin / OAuth-app \
allowlisting, mail-routing changes).
7. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool) \
and produce a clear Markdown report.

## Investigation strategy (Google Workspace compromise decision tree)
- **Start with login anomalies (gworkspace_audit \
operation=admin_reports_login).** The login application is the backbone of \
the auth timeline. Rows flagged ``suspicious=true`` (suspicious_login, \
login_failure bursts, gov_attack_warning, logout_all) are your lead \
indicators. Look for impossible travel (rapid geo jumps), unusual ASNs / \
IPs, and logins from less-secure-app flows.
- **Then pivot to OAuth token abuse (gworkspace_audit \
operation=admin_reports_token).** The token application records authorize / \
add_access / revoke events — every consent grant and token mint. A new \
third-party app authorized by a non-admin, or a grant carrying broad scopes \
(mail.read, drive.read, domain-wide delegation), is a strong persistence + \
data-collection signal.
- **Check Drive for exfiltration (gworkspace_audit \
operation=admin_reports_drive).** Look for download / view spikes, mass \
shares to external recipients, and edits/renames by an unexpected actor. \
Cross-reference the actor with the suspicious login / OAuth app from the \
steps above. This is the T1567 / T1020 exfiltration channel.
- **Review OAuth grants inventory (gworkspace_audit \
operation=oauth_grants).** This collapses the token stream into a clean \
per-user / per-app permissions roster. Flag apps with overly broad scopes, \
apps installed outside change windows, and apps whose authorized scope set \
changed recently.
- **Check Gmail filter / forwarding injection (gworkspace_audit \
operation=admin_reports_gmail).** New forwarding rules, mail-import filters, \
or delegated-access grants that auto-exfiltrate inbound mail are the \
signature of a BEC foothold surviving a password reset.
- **ATT&CK mapping.** Use the mitre_attack tool: T1078 Valid Accounts \
(account takeover), T1098 Account Manipulation (admin changes, malicious \
OAuth grants), T1567 Exfiltration to Web Service (Drive exfil), T1136 Create \
Account (rogue admin/user), T1556 Modify Authentication Process (MFA / \
SSO changes). Cite the technique ID in the report.

## Adaptation rules
- If gworkspace_audit returns a "GWS_ACCESS_TOKEN ... not set" error, stop \
and report that the Google Workspace API integration is unconfigured — do \
not retry the same call.
- If gworkspace_audit returns an auth_forbidden error, the token lacks the \
required scopes or the caller is not a delegated admin; note the gap \
explicitly and pivot to the operations that are reachable.
- Use user_filter (primary email) to scope a query to the suspicious actor \
once you have a lead — don't re-pull the whole tenant each step.
- Don't call the same operation twice with identical args.
- Stop and write the report when you have covered the decision tree or hit \
the iteration cap.
"""


class GworkspaceCompromiseGoal(Goal):
    id = "G13"
    cluster = "Cloud"
    label = "Google Workspace incident"
    description = (
        "Investigate Google Workspace compromises via the Admin SDK Reports "
        "API. Detects account takeover, OAuth token abuse, Drive data "
        "exfiltration, and Gmail rule injection."
    )
    input_artifacts = ["B10d"]
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

        # ---- triage: do we have a Workspace token? ----
        await self._set_node(bus, investigation_id, "triage", "running")
        triage = self._triage()
        bus.publish(E.agent_thought(
            investigation_id,
            f"Google Workspace integration triage: {triage}",
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
                    GworkspaceApiTool(),
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
            f"Google Workspace incident investigation complete. Integration: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    def _triage(self) -> str:
        """Report whether the Google Workspace API integration is available.

        This goal's "evidence" is the live tenant, not a disk image, so
        triage = "do we have a usable GWS_ACCESS_TOKEN?".
        """
        token = os.environ.get("GWS_ACCESS_TOKEN", "").strip()
        if token:
            return "GWS_ACCESS_TOKEN present; Admin SDK Reports API reachable"
        return (
            "GWS_ACCESS_TOKEN not set — Google Workspace API integration is "
            "unconfigured; the gworkspace_audit tool will report the missing "
            "token"
        )

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Google Workspace integration triage complete. {triage}.\n"
            f"Begin your Google Workspace compromise investigation. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## Google Workspace incident (deterministic triage)\n\n"
            f"**Integration status:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (login-anomaly triage, OAuth token-abuse review, "
            "Drive exfiltration detection, OAuth grant inventory, Gmail "
            "filter/forwarding-rule review, ATT&CK mapping).\n\n"
            "Additionally, ensure the `GWS_ACCESS_TOKEN` environment variable "
            "is set to a Google OAuth2 access token (service-account or "
            "delegated user) carrying the `admin.reports.audit.readonly`, "
            "`admin.directory.user.readonly`, and "
            "`admin.directory.user.security` scopes.\n\n"
            "Once configured, re-run this goal for a complete compromise report."
        )


goal = GworkspaceCompromiseGoal()
