"""G15 — Azure cloud incident.

The agentic Azure-compromise goal. Like G17 (Slack) and G18 (DevOps), the
evidence here is *not* a disk image — it's the live Azure tenant, reached
through the Azure REST API (Activity Log) and Microsoft Graph (Entra ID
sign-ins / directory audit, Defender for Cloud). The agent drives the cloud-
incident decision tree:

  - azure_audit   — one API tool, operation selector, exposes activity_log,
                    entra_signins, entra_audit, defender_alerts,
                    resource_changes, key_vault_events. Calls Azure / Graph
                    with a bearer token from AZURE_ACCESS_TOKEN.
  - mitre_attack  — map observed behaviors to ATT&CK techniques.

The system prompt encodes the cloud-incident-response playbook (Activity Log
resource-change triage first, then Entra ID sign-in anomalies, then Defender
detection, then unauthorized resource modifications, then Key Vault secret
access) so the LLM follows IR best practice without a hard-coded call order.

This tool runs on host (no Docker): the azure_audit wrapper uses
``image=None`` and ``sandboxed=False`` — it makes outbound HTTPS calls to
Azure / Graph, it does not touch the sandbox.

Falls back to a deterministic summary if no LLM provider is configured
(matching the contract of every other agentic goal), and also degrades
gracefully if AZURE_ACCESS_TOKEN is unset (the tool returns a clear error and
the agent adapts).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.cloud.azure_api import AzureApiTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior cloud DFIR analyst investigating a potential compromise of an \
Azure tenant. You reach the tenant through the Azure REST API (Activity Log) \
and Microsoft Graph (Entra ID / Defender) via the azure_audit tool (a bearer \
token is read from the AZURE_ACCESS_TOKEN environment variable by the \
wrapper). The MITRE ATT&CK knowledge base is available through the \
mitre_attack tool.

## Your mission
1. Build a timeline of management-plane activity from the Azure Activity Log.
2. Detect service principal / managed-identity abuse (impossible-travel \
sign-ins, new credentials minted on a principal, first-seen app sign-ins).
3. Detect resource hijacking — unauthorized resource creates/updates/deletes, \
suspicious role assignments, new admins outside a change window.
4. Detect Key Vault secret/key/certificate access by unexpected actors.
5. Detect privilege escalation — role-definition and PIM changes, directory \
role grants, entra_audit AddMember / Add application events.
6. Correlate with Defender for Cloud / Defender XDR alerts.
7. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool) \
and produce a clear Markdown report.

## Investigation strategy (Azure compromise decision tree)
- **Start with the Activity Log (azure_audit operation=activity_log, \
subscription_id=...).** Management-plane events are the backbone of the \
timeline. Look for burst activity, unfamiliar callers, and operations \
outside business hours.
- **Then check Entra ID sign-ins (azure_audit operation=entra_signins).** \
Flag impossible-travel IPs, risky sign-ins, non-interactive / \
service-principal sign-ins to high-value apps, and bursts of failed logins \
(brute force). The servicePrincipal field distinguishes SPN abuse from user \
sign-ins.
- **Then Defender alerts (azure_audit operation=defender_alerts).** Pull \
security alerts for detections the platform already made — they name the \
techniques and the affected resources, saving you pivoting work.
- **Then resource changes (azure_audit operation=resource_changes).** Filter \
to Accepted/Created/Updated operations to surface unauthorized modifications \
— new VMs, modified NSGs, new role assignments, dropped diagnostic settings.
- **Then Key Vault events (azure_audit operation=key_vault_events).** Secret / \
key / certificate reads and writes by unexpected callers are strong \
credential-theft (T1552) and exfiltration signals.
- **ATT&CK mapping.** Use the mitre_attack tool: T1078 Valid Accounts (user \
or SPN takeover), T1098 Account Manipulation (role / directory changes), \
T1078.004 Cloud Accounts, T1136 Create Account (new identities), T1552 \
Unsecured Credentials (Key Vault access), T1578 Modify Cloud Compute \
Infrastructure (resource hijacking), T1530 Data from Cloud Storage. Cite the \
technique ID in the report.

## Adaptation rules
- If azure_audit returns an "AZURE_ACCESS_TOKEN ... not set" error, stop and \
report that the Azure API integration is unconfigured — do not retry the \
same call.
- If azure_audit returns auth_forbidden, the token lacks the required role / \
Graph scope; pivot to the operations that succeed and note the gap.
- The Activity-Log operations (activity_log, resource_changes, \
key_vault_events) require a subscription_id; the Graph operations \
(entra_signins, entra_audit, defender_alerts) do not — don't pass one.
- Don't call the same (operation, subscription_id) twice with identical args.
- Stop and write the report when you have covered the decision tree or hit \
the iteration cap.
"""


class AzureCompromiseGoal(Goal):
    id = "G15"
    cluster = "Cloud"
    label = "Azure cloud incident"
    description = (
        "Investigate Azure compromises via Activity Log, Entra ID sign-ins, "
        "and Defender for Cloud. Detects service principal abuse, resource "
        "hijacking, key vault access, and privilege escalation."
    )
    input_artifacts = ["B10e"]
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

        # ---- triage: do we have an Azure token? ----
        await self._set_node(bus, investigation_id, "triage", "running")
        triage = self._triage()
        bus.publish(E.agent_thought(
            investigation_id,
            f"Azure integration triage: {triage}",
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
                    AzureApiTool(),
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
            f"Azure cloud incident investigation complete. Integration: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    def _triage(self) -> str:
        """Report whether the Azure API integration is available.

        This goal's "evidence" is the live tenant, not a disk image, so
        triage = "do we have a usable AZURE_ACCESS_TOKEN?".
        """
        token = os.environ.get("AZURE_ACCESS_TOKEN", "").strip()
        if token:
            return (
                "AZURE_ACCESS_TOKEN present; Activity Log + Microsoft Graph "
                "(Entra ID sign-ins / directory audit, Defender for Cloud) "
                "reachable"
            )
        return (
            "AZURE_ACCESS_TOKEN not set — Azure API integration is "
            "unconfigured; the azure_audit tool will report the missing token"
        )

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Azure integration triage complete. {triage}.\n"
            f"Begin your Azure compromise investigation. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## Azure cloud incident (deterministic triage)\n\n"
            f"**Integration status:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (Activity Log triage, Entra ID sign-in anomaly "
            "hunting, Defender alert correlation, resource-change review, "
            "Key Vault access analysis, ATT&CK mapping).\n\n"
            "Additionally, ensure the `AZURE_ACCESS_TOKEN` environment "
            "variable is set to a bearer token for an Entra ID service "
            "principal / managed identity carrying Reader on the target "
            "subscription (for Activity Log) plus AuditLog.Read.All / "
            "Directory.Read.All / SecurityEvents.Read.All (for Graph sign-in, "
            "directory audit, and Defender alerts).\n\n"
            "Once configured, re-run this goal for a complete compromise report."
        )


goal = AzureCompromiseGoal()
