"""G14 — AWS cloud incident.

The agentic AWS-compromise goal. Like G17 (Slack), the evidence here is *not* a
disk image — it's the live AWS account, reached through the AWS control-plane
APIs (CloudTrail, GuardDuty, VPC Flow Logs, CloudWatch). The agent drives the
cloud-IR decision tree:

  - aws_audit     — one API tool, operation selector. Exposes cloudtrail_events
                    (API-call timeline), guardduty_findings (detection alerts),
                    iam_changes (privilege escalation), s3_access (data exfil),
                    vpc_flows (network anomalies), cloudwatch_alarms (alarms).
                    Authenticates with SigV4 using credentials from the
                    AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
                    AWS_DEFAULT_REGION environment variables.
  - mitre_attack  — map observed behaviors to ATT&CK techniques.

The system prompt encodes the AWS-incident-response playbook (CloudTrail
timeline first → GuardDuty detections → IAM privilege escalation → S3 data
exfil → VPC flow anomalies → ATT&CK mapping) so the LLM follows IR best
practice without a hard-coded call order.

This tool runs on host (no Docker): the aws_audit wrapper uses ``image=None``
and ``sandboxed=False`` — it makes outbound SigV4-signed HTTPS calls to AWS,
it does not touch the sandbox.

Falls back to a deterministic summary if no LLM provider is configured
(matching the contract of every other agentic goal), and also degrades
gracefully if AWS credentials are unset (the tool returns a clear error and the
agent adapts).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.cloud.aws_api import AwsApiTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior cloud security / DFIR analyst investigating a potential \
compromise of an AWS account. You reach the account through the AWS \
control-plane API via the aws_audit tool (credentials are read from the \
AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION environment \
variables by the wrapper; the identity needs read-only CloudTrail, GuardDuty, \
logs, and CloudWatch permissions). The MITRE ATT&CK knowledge base is \
available through the mitre_attack tool.

## Your mission
1. Build a timeline of security-relevant API calls from CloudTrail.
2. Correlate it with GuardDuty findings (the detector's own verdict on \
malicious activity).
3. Detect IAM privilege escalation and role abuse (new roles/policies, \
access-key creation, MFA disable, AssumeRole chains, inline-policy grants).
4. Detect data exfiltration via S3 (bursts of GetObject / DeleteBucket / \
PutBucketAcl / cross-account grants, downloads from anomalous IPs).
5. Detect unauthorized API calls and lateral movement ( anomalous source IPs, \
CreateKeyPair / RunInstances from new regions, VPC changes).
6. Detect network anomalies in VPC Flow Logs (REJECT spikes, traffic to \
unusual peers/ports).
7. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool) \
and produce a clear Markdown report.

## Investigation strategy (AWS compromise decision tree)
- **Start with the CloudTrail API-call timeline (aws_audit \
operation=cloudtrail_events).** This is the backbone. Begin with a wide \
time_range (e.g. 24h or 7d) and look for a burst of activity, anomalous \
user identities / source IPs, and any event whose flag is set. Rows with \
``flagged=true`` already match known compromise/escalation/exfil event names.
- **Then pull GuardDuty findings (aws_audit operation=guardduty_findings).** \
GuardDuty has already triaged the account's traffic and CloudTrail against its \
detections — these are your highest-confidence leads (T1078 UnauthorizedAccess, \
T1110 BruteForce, T1048 Pentest/Exfiltration, T1021 Recon, \
T1098 IAMUser/AnomalousBehavior). Note the detector region; GuardDuty is \
per-region so query each region of interest.
- **Hunt IAM privilege escalation (aws_audit operation=iam_changes).** Filter \
the timeline to iam.amazonaws.com. Flag: CreateRole / AttachRolePolicy / \
PutRolePolicy, CreateAccessKey (especially for a different principal), \
DeleteLoginProfile / UpdateLoginProfile, DeactivateMFADevice / \
DeleteVirtualMFADevice, AddUserToGroup, CreatePolicyVersion with broad \
statements, and any AssumeRole chain by an unexpected identity.
- **Hunt S3 data exfiltration (aws_audit operation=s3_access).** Filter to \
s3.amazonaws.com. Flag: a burst of GetObject from one IP/principal, \
DeleteBucket / DeleteObjects (anti-forensics), PutBucketAcl / \
PutBucketPolicy granting cross-account access, and HeadBucket/Batch Delete \
from anomalous regions. Cross-reference the principal ARN and source IP with \
the suspicious actors from the CloudTrail timeline.
- **Inspect VPC flow logs for network anomalies (aws_audit operation=vpc_flows, \
optionally log_group=...).** Look for a spike of REJECT actions (probe/scan), \
traffic to unusual destination IPs/ports, and any long-lived high-volume \
flows to a single peer (possible C2 / exfil channel). If no flow-log group \
is found, the tool will tell you — note the gap explicitly.
- **Check active CloudWatch alarms (aws_audit operation=cloudwatch_alarms)** \
for corroborating signal (e.g. GuardDuty / unauthorized-API / billing alarms \
in ALARM state).
- **ATT&CK mapping.** Use the mitre_attack tool: T1078 Valid Accounts, \
T1098 Account Manipulation (IAM role/policy/key abuse), T1078.004 Cloud \
Accounts, T1530 Data from Cloud Storage (S3 GetObject), T1567.002 \
Exfiltration to Cloud Storage, T1525 Implant Internal Image (malicious \
AMI), T1578 Modify Cloud Compute Infrastructure, T1613 Container & Resource \
Discovery. Cite the technique ID in the report.

## Adaptation rules
- If aws_audit returns an "AWS credentials are not set" error, stop and report \
that the AWS integration is unconfigured — do not retry the same call.
- If GuardDuty returns "no detector" for a region, GuardDuty is not enabled \
there; pivot to CloudTrail + IAM + S3 + VPC flows and note the gap explicitly.
- CloudTrail and IAM are global-ish (us-east-1 returns global activity); \
GuardDuty/VPC/CloudWatch are per-region, so pass ``region`` to query each \
region of interest.
- Don't call the same (operation, region, time_range) twice with identical args.
- Stop and write the report when you have covered the decision tree or hit \
the iteration cap.
"""


class AwsCompromiseGoal(Goal):
    id = "G14"
    cluster = "Cloud"
    label = "AWS cloud incident"
    description = (
        "Investigate AWS compromises via CloudTrail, GuardDuty, and VPC Flow "
        "Logs. Detects IAM role abuse, data exfiltration via S3, unauthorized "
        "API calls, and lateral movement."
    )
    input_artifacts = ["B10e"]
    tools = ["C16", "C15", "A2"]
    icon = "cloud"

    def nodes(self) -> list[GoalNode]:
        return [
            GoalNode("triage", "Triage AWS integration"),
            GoalNode("react_loop", "Agent investigation (ReAct)"),
            GoalNode("draft_report", "Draft report"),
            GoalNode("hitl_review", "Review (human)"),
            GoalNode("finalize", "Finalize"),
        ]

    async def run(self, *, investigation_id: str, case_id: str,
                  evidence_path: str, user_prompt: str, bus) -> None:
        out_dir = str(Path.home() / ".svetovid" / "cases" / case_id / investigation_id)
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        # ---- triage: do we have AWS credentials? ----
        await self._set_node(bus, investigation_id, "triage", "running")
        triage = self._triage()
        bus.publish(E.agent_thought(
            investigation_id,
            f"AWS integration triage: {triage}",
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
                    AwsApiTool(),
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
            f"AWS cloud incident investigation complete. Integration: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    def _triage(self) -> str:
        """Report whether the AWS API integration is available.

        This goal's "evidence" is the live AWS account, not a disk image, so
        triage = "do we have usable AWS credentials?".
        """
        access_key = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
        region = (os.environ.get("AWS_DEFAULT_REGION", "").strip()
                  or os.environ.get("AWS_REGION", "").strip())
        has_session = bool((os.environ.get("AWS_SESSION_TOKEN")
                            or os.environ.get("AWS_SECURITY_TOKEN") or "").strip())
        if access_key and secret_key:
            flavor = "STS/temporary" if has_session else "long-lived key pair"
            reg = region or "us-east-1 (default)"
            return (f"AWS credentials present ({flavor}, region {reg}); "
                    "CloudTrail/GuardDuty/VPC/CloudWatch reachable")
        return (
            "AWS credentials not set — the aws_audit tool will report the "
            "missing credentials. Export AWS_ACCESS_KEY_ID, "
            "AWS_SECRET_ACCESS_KEY, and AWS_DEFAULT_REGION (AWS_SESSION_TOKEN "
            "optional, for STS/temporary credentials) with a read-only IAM "
            "identity to enable AWS compromise investigation."
        )

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"AWS integration triage complete. {triage}.\n"
            f"Begin your AWS compromise investigation. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## AWS cloud incident (deterministic triage)\n\n"
            f"**Integration status:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (CloudTrail API-call timeline triage, GuardDuty "
            "finding review, IAM privilege-escalation hunting, S3 data-exfil "
            "detection, VPC flow-log network-anomaly analysis, CloudWatch "
            "alarm correlation, ATT&CK mapping).\n\n"
            "Additionally, ensure the `AWS_ACCESS_KEY_ID`, "
            "`AWS_SECRET_ACCESS_KEY`, and `AWS_DEFAULT_REGION` environment "
            "variables are set to a read-only IAM identity carrying "
            "`cloudtrail:LookupEvents`, `guardduty:List*/Get*`, "
            "`logs:FilterLogEvents`/`DescribeLogGroups`, and "
            "`cloudwatch:DescribeAlarms`. GuardDuty and VPC flow logs are "
            "per-region, so query each region of interest.\n\n"
            "Once configured, re-run this goal for a complete compromise report."
        )


goal = AwsCompromiseGoal()
