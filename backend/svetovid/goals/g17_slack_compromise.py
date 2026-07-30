"""G17 — SaaS collaboration compromise (Slack).

The agentic Slack-compromise goal. Unlike the endpoint goals, the evidence
here is *not* a disk image — it's the live Slack workspace, reached through
the Slack REST/audit API. The agent drives the SaaS compromise decision tree:

  - slack_audit   — one API tool, operation selector, exposes list_conversations,
                    message_history, audit_log, user_list, file_shares, app_perms.
                    Calls Slack's API with a token from SLACK_TOKEN.
  - mitre_attack  — map observed behaviors to ATT&CK techniques.

The system prompt encodes the SaaS-incident-response playbook (audit-log
triage first, then user-list anomalies, suspicious-channel messages, file-
exfil, malicious OAuth grants) so the LLM follows IR best practice without a
hard-coded call order.

This tool runs on host (no Docker): the slack_audit wrapper uses
``image=None`` and ``sandboxed=False`` — it makes outbound HTTPS calls to
Slack, it does not touch the sandbox.

Falls back to a deterministic summary if no LLM provider is configured
(matching the contract of every other agentic goal), and also degrades
gracefully if SLACK_TOKEN is unset (the tool returns a clear error and the
agent adapts).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.slack_api import SlackApiTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior SaaS security / DFIR analyst investigating a potential \
compromise of a Slack workspace. You reach the workspace through the Slack \
REST + audit API via the slack_audit tool (a token is read from the \
SLACK_TOKEN environment variable by the wrapper). The MITRE ATT&CK \
knowledge base is available through the mitre_attack tool.

## Your mission
1. Establish a timeline of security-relevant events from the audit log.
2. Identify account takeover (impossible travel, anomalous logins, MFA reset).
3. Detect data exfiltration via file shares (large/mass outbound file \
downloads or uploads, sensitive-keyword filenames).
4. Find malicious app installations / OAuth grants (overly broad scopes, \
recently installed apps, tokens minted by a suspicious actor).
5. Surface unauthorized message deletion / tampering in sensitive channels.
6. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool) \
and produce a clear Markdown report.

## Investigation strategy (SaaS compromise decision tree)
- **Start with the audit log (slack_audit operation=audit_log).** Security \
events (logins, logouts, MFA changes, app installs, file actions, channel \
changes, message deletions) are the backbone of the timeline. Look for \
anomalous actors, impossible-travel IPs, and a burst of admin/permission \
changes.
- **Then check the user list (slack_audit operation=user_list).** Flag new \
or recently-changed accounts: admins created outside change windows, bots / \
app users you don't recognize, reactivated deleted accounts, and email/\
display-name changes that look like staging for persistence.
- **Examine message history in suspicious channels (slack_audit \
operation=message_history, channel_id=...).** Pull messages from channels \
named in the audit events or that the suspicious actor touched. Look for \
exfiltration messages, social-engineering outreach, and (via subtype) \
message_delete events — bulk deletions are a strong anti-forensics signal.
- **Check file shares (slack_audit operation=file_shares).** A spike in \
outbound file uploads/downloads, or files with sensitive-looking names \
(customer lists, financials, source-tree archives, .pst/.zip), is the \
classic T1567 exfiltration-to-web-service pattern. Cross-reference file \
actors with the suspicious users from the audit log.
- **Check app / OAuth permissions (slack_audit operation=app_perms).** \
Filter for app_installed / oauth_authorize / app_scoped_token_added events. \
Flag any app granted broad scopes (files:write, channels:read, \
chat:write, admin) by a non-admin or in a short window — these are \
persistence and data-collection footholds.
- **ATT&CK mapping.** Use the mitre_attack tool: T1078 Valid Accounts \
(account takeover), T1567 Exfiltration to Web Service (file-share exfil), \
T1098 Account Manipulation (permission/role changes, malicious OAuth \
grants). Cite the technique ID in the report.

## Adaptation rules
- If slack_audit returns a "SLACK_TOKEN ... not set" error, stop and report \
that the Slack API integration is unconfigured — do not retry the same call.
- If slack_audit returns an audit_forbidden / audit_unavailable error, the \
workspace tier does not expose audit logs; pivot to user_list + \
message_history + file_shares + app_perms and note the gap explicitly.
- Don't call the same (operation, channel_id) twice with identical args.
- Stop and write the report when you have covered the decision tree or hit \
the iteration cap.
"""


class SlackCompromiseGoal(Goal):
    id = "G17"
    cluster = "SaaS"
    label = "Slack compromise investigation"
    description = (
        "Investigate Slack workspace compromises via the audit API. Detects "
        "account takeover, data exfiltration via file shares, malicious app "
        "installations, and unauthorized message deletion."
    )
    input_artifacts = ["B10f"]
    tools = ["C16", "A2"]
    icon = "message-square"

    def nodes(self) -> list[GoalNode]:
        return [
            GoalNode("triage", "Triage workspace"),
            GoalNode("react_loop", "Agent investigation (ReAct)"),
            GoalNode("draft_report", "Draft report"),
            GoalNode("hitl_review", "Review (human)"),
            GoalNode("finalize", "Finalize"),
        ]

    async def run(self, *, investigation_id: str, case_id: str,
                  evidence_path: str, user_prompt: str, bus) -> None:
        out_dir = str(Path.home() / ".svetovid" / "cases" / case_id / investigation_id)
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        # ---- triage: do we have a Slack token? ----
        await self._set_node(bus, investigation_id, "triage", "running")
        triage = self._triage()
        bus.publish(E.agent_thought(
            investigation_id,
            f"Slack integration triage: {triage}",
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
                    SlackApiTool(),
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
            f"Slack compromise investigation complete. Integration: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    def _triage(self) -> str:
        """Report whether the Slack API integration is available.

        This goal's "evidence" is the live workspace, not a disk image, so
        triage = "do we have a usable SLACK_TOKEN?".
        """
        token = os.environ.get("SLACK_TOKEN", "").strip()
        if token:
            # Hint at the token flavor without leaking it.
            flavor = (
                "audit-capable (xoxa-/user token)" if token.startswith(("xoxa-", "xoxp-"))
                else "bot token (xoxb-)" if token.startswith("xoxb-")
                else "unknown token type"
            )
            return f"SLACK_TOKEN present ({flavor}); audit + web API reachable"
        return (
            "SLACK_TOKEN not set — Slack API integration is unconfigured; "
            "the slack_audit tool will report the missing token"
        )

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Slack integration triage complete. {triage}.\n"
            f"Begin your Slack compromise investigation. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## Slack compromise investigation (deterministic triage)\n\n"
            f"**Integration status:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (audit-log triage, user-list anomaly hunting, "
            "message-history review, file-share exfil detection, OAuth/app "
            "permission review, ATT&CK mapping).\n\n"
            "Additionally, ensure the `SLACK_TOKEN` environment variable is "
            "set to a Slack user/bot token carrying the `audit:read`, "
            "`channels:read`, `users:read`, and `files:read` scopes. Audit-log "
            "queries require an Enterprise Grid workspace.\n\n"
            "Once configured, re-run this goal for a complete compromise report."
        )


goal = SlackCompromiseGoal()
