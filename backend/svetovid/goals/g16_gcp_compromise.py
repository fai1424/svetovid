"""G16 — GCP cloud compromise (Google Cloud Platform).

The agentic GCP cloud-compromise goal. Unlike the disk-image forensics goals,
G16 investigates the cloud control plane directly: the agent talks to GCP
Cloud Logging and Security Command Center APIs (via the ``gcp_audit`` tool)
using a token from the environment, and maps findings to MITRE ATT&CK.
Available tools:

  - gcp_audit      — read-only audit of a GCP project. operation selector
                     (admin_activity_logs / data_access_logs / scc_findings /
                     iam_policy_changes / compute_changes / storage_access).
                     Calls the Cloud Logging + Security Command Center APIs;
                     returns a clear error if no GCP_ACCESS_TOKEN is set.
  - mitre_attack   — map observed behaviors to ATT&CK techniques

The system prompt encodes the DFIR decision tree for a GCP cloud compromise:
start with the admin activity log for the API-call timeline, pivot to data
access logs for who-read-what, check Security Command Center for detections,
harden with IAM policy changes (privilege escalation), compute changes
(resource hijacking), and storage access (exfiltration) — then map each
finding to ATT&CK (T1078 Valid Accounts, T1098 Account Manipulation,
T1078.004 Cloud Accounts, T1530 Data from Cloud Storage, T1567.002 Exfil
to Cloud Storage, T1578 Modify Cloud Compute Infrastructure).

Falls back to a deterministic summary if no LLM provider is configured
(matching G02's contract).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.cloud.gcp_api import GcpApiTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior cloud DFIR analyst investigating a potential Google Cloud \
Platform (GCP) compromise. Your evidence is the live GCP control plane, \
accessed read-only via the gcp_audit tool using an access token already in \
the environment. The tool returns a clear error when no token is configured — \
adapt by telling the user to set GCP_ACCESS_TOKEN.

## Your mission
1. Reconstruct the attacker's API-call timeline from the Admin Activity log.
2. Identify privilege escalation (IAM role / binding mutations, service \
account creation/binding, OAuth grants).
3. Identify resource hijacking (rogue Compute Engine instances, \
startup-script / disk / service-account tampering, firewall openings).
4. Identify data exfiltration (bulk GCS object reads / copies, \
service-account key downloads).
5. Correlate detections from Security Command Center.
6. Map every finding to MITRE ATT&CK (use the mitre_attack tool).
7. Produce a clear Markdown report with: (a) compromise timeline, (b) IAM / \
privilege-escalation inventory, (c) compute-hijack inventory, (d) \
exfiltration inventory, (e) SCC detections, (f) ATT&CK mapping, (g) \
recommended remediation.

## Investigation strategy (GCP compromise decision tree)
- **Start with admin_activity_logs.** Call \
gcp_audit(operation="admin_activity_logs", project_id=<p>, time_range=<w>). \
This is always-on audit logging — every admin/config API call is recorded \
even if Data Access logs are off. Build the API-call timeline from it; flag \
rows whose method mentions SetIamPolicy, CreateServiceAccount, \
setServiceAccount, setMetadata, setMachineType, attachDisk, or instances.insert.
- **Pivot to data_access_logs.** Call \
gcp_audit(operation="data_access_logs", ...). This shows who-read-what \
(storage objects, secrets) — the exfiltration trail. Note: Data Access logs \
must be explicitly enabled per service; if empty, note the gap and rely on \
storage_access instead.
- **Check scc_findings for detections.** Call \
gcp_audit(operation="scc_findings", project_id=<p>). Security Command \
Center surfaces active findings (anomalous IAM, exposed credentials, \
container/crypto-mining). Treat HIGH/CRITICAL findings as lead indicators. \
Requires a project_id.
- **Harden with iam_policy_changes.** Call \
gcp_audit(operation="iam_policy_changes", ...). This is Admin Activity \
filtered to SetIamPolicy / role-binding mutations — privilege escalation \
(T1098 Account Manipulation, T1078.004 Cloud Accounts). Flag new \
roles/owner, roles/editor, roles/iam.serviceAccountTokenCreator, and \
service-account key creation.
- **Check compute_changes for resource hijacking.** Call \
gcp_audit(operation="compute_changes", ...). Flag instances.insert (rogue \
instances, often crypto-mining), setMetadata (startup-script injection), \
setServiceAccount (lateral movement), attachDisk (data mounting), and \
firewalls.insert (C2 openings). Map to T1578 Modify Cloud Compute \
Infrastructure (T1578.005 Modify Cloud Compute Infrastructure: Modify \
compute config / startup / service account).
- **Check storage_access for exfiltration.** Call \
gcp_audit(operation="storage_access", ...). Bulk objects.get / objects.list \
/ objects.compose from an unexpected principal is exfiltration (T1530 Data \
from Cloud Storage, T1567.002 Exfiltration to Cloud Storage).
- **Map to ATT&CK.** Use mitre_attack (op=lookup): T1078 Valid Accounts, \
T1078.004 Cloud Accounts, T1098 Account Manipulation, T1098.001 Additional \
Cloud Credentials (service-account keys), T1530 Data from Cloud Storage, \
T1567.002 Exfiltration to Cloud Storage, T1578 Modify Cloud Compute \
Infrastructure, T1199 Trusted Relationship (abused third-party / SaaS \
integration).

## Tool-use rules
- Always pass project_id (e.g. 'my-project-123'). If you don't have it, use \
the project from the user context or the GCP_PROJECT_ID env var.
- time_range is optional; '24h' / '7d' or an RFC3339 start/end. Default 24h.
- If gcp_audit returns a missing-token error, DO NOT retry — report that \
GCP_ACCESS_TOKEN must be set and stop.
- Don't call the same (operation, project_id, time_range) twice with \
identical args.
- For every notable finding, map it with mitre_attack (op=lookup) and cite \
the technique ID in the report.
- Stop and write the report when you have covered the six operations, or hit \
the iteration cap.
"""


class GcpCompromiseGoal(Goal):
    id = "G16"
    cluster = "Cloud"
    label = "GCP cloud incident"
    description = (
        "Investigate GCP compromises via Cloud Audit Logs and Security "
        "Command Center. Detects IAM abuse, compute instance hijacking, "
        "storage exfiltration, and service account compromise."
    )
    input_artifacts = ["B10e"]
    tools = ["C16", "A2"]
    icon = "cloud"

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

        # ---- triage: is the GCP token configured? ----
        await self._set_node(bus, investigation_id, "triage", "running")
        triage = self._triage()
        bus.publish(E.agent_thought(
            investigation_id,
            f"GCP triage: {triage}",
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
                    GcpApiTool(),
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
            f"GCP cloud compromise investigation complete. Triage: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    def _triage(self) -> str:
        """Report whether the GCP access token + project are configured."""
        have_token = bool(os.environ.get("GCP_ACCESS_TOKEN", "").strip())
        project = os.environ.get("GCP_PROJECT_ID", "").strip()
        if have_token and project:
            return f"token + project configured (project={project})"
        if have_token:
            return "token configured but no GCP_PROJECT_ID set (project_id must be passed per call)"
        return (
            "no GCP_ACCESS_TOKEN set; set it (plus GCP_PROJECT_ID) to run the "
            "audit"
        )

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"GCP triage complete. {triage}.\n"
            f"Begin your GCP cloud compromise investigation. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## GCP cloud compromise (deterministic triage)\n\n"
            f"**Triage:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (Cloud Audit Log review, SCC detection correlation, "
            "IAM/compute/storage abuse hunting, ATT&CK mapping).\n\n"
            "Make sure GCP_ACCESS_TOKEN is set (plus GCP_PROJECT_ID) so the "
            "agent can query Cloud Logging and Security Command Center.\n\n"
            "Once configured, re-run this goal for a complete compromise report."
        )


goal = GcpCompromiseGoal()
