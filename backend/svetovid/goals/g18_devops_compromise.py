"""G18 — DevOps / source-control compromise (GitHub, Azure DevOps, Jira).

The agentic DevOps / supply-chain compromise goal. Unlike the disk-image
forensics goals, G18 investigates the SaaS control plane directly: the agent
talks to GitHub, Azure DevOps, Jira, and GitLab REST APIs (via the
``devops_audit`` tool) using tokens from the environment, and maps findings to
MITRE ATT&CK. Available tools:

  - devops_audit  — read-only audit of a DevOps platform. platform selector
                    (github / azure_devops / jira / gitlab) + operation
                    selector (audit_log / repo_changes / user_perms /
                    pipeline_runs / secrets_scan). Calls the platform REST
                    API; returns a clear error if no token is set so the
                    agent pivots to another platform.
  - mitre_attack  — map observed behaviors to ATT&CK techniques

The system prompt encodes the DFIR decision tree for a source-control /
supply-chain compromise: start with the audit log across every configured
platform, then drill into suspicious commits (mass file changes, CI/.git
modifications), unauthorized CI/CD runs, leaked credentials, and privilege
escalation — then map each finding to ATT&CK (T1199 Trusted Relationship,
T1074.001 Data Staged, T1552 Unsecured Credentials, T1195 Supply Chain
Compromise).

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
from ..tools.devops_api import PLATFORM_TOKEN_ENV, DevOpsApiTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior DFIR analyst investigating a potential DevOps / source-control \
compromise across GitHub, Azure DevOps, Jira, and GitLab. Your evidence is the \
live SaaS control plane, accessed read-only via the devops_audit tool using \
tokens already in the environment. The tool returns a clear error when a \
platform has no token — adapt by auditing a different configured platform.

## Your mission
1. Detect malicious commits (attacker pushing backdoors, web shells, or \
dependency tampering).
2. Detect secret exfiltration / leaked credentials in code.
3. Detect pipeline tampering (unauthorized CI/CD runs, modified workflows).
4. Detect unauthorized permission / membership changes (privilege escalation, \
new admins, OAuth grants).
5. Detect supply-chain attacks (compromised dependencies, modified build \
artifacts).
6. Map every finding to MITRE ATT&CK (use the mitre_attack tool).
7. Produce a clear Markdown report with: (a) compromise timeline, (b) malicious \
commit / pipeline inventory, (c) leaked-credential inventory, (d) \
permission-change inventory, (e) ATT&CK mapping, (f) recommended remediation.

## Investigation strategy (DevOps compromise decision tree)
- **Start with audit_log across all configured platforms.** Call \
devops_audit(platform=<p>, operation="audit_log") for each platform that has a \
token (github, azure_devops, jira, gitlab). If a platform returns a \
missing-token error, skip it and move on. Flag audit rows whose action \
mentions remove/delete/role/permission/member/admin/token/secret/deploy/\
pipeline/hook — those are your lead indicators.
- **Check repo_changes for suspicious commits.** For the affected repo(s) call \
devops_audit(operation="repo_changes", repo="owner/name"). Flag commits that \
touch ≥50 files or modify CI/.git paths (.github/workflows/, .gitlab-ci.yml, \
azure-pipelines.yml, Jenkinsfile, .git/, package-lock.json, go.mod) — these are \
classic backdoor / dependency-tampering or supply-chain vectors.
- **Check pipeline_runs for unauthorized CI/CD.** Call \
devops_audit(operation="pipeline_runs", repo=...). Flag manual dispatches \
(workflow_dispatch / web / api / trigger sources) and pull_request-triggered \
runs from outside contributors — those are the most common pipeline-tampering \
vectors.
- **Check secrets_scan for leaked credentials.** Call \
devops_audit(operation="secrets_scan", repo=...). Every open secret-scanning \
alert or CI/CD secret variable is a finding (potential T1552). Note: Azure \
DevOps and Jira have limited native secret scanning; the tool surfaces stored \
secrets / keyword hits and tells you to pivot to content review.
- **Check user_perms for privilege escalation.** Call \
devops_audit(operation="user_perms") for the org and the affected repo. Flag \
new admins / maintainers / owners and any account added just before a \
suspicious commit or pipeline run (T1098 Account Manipulation).
- **Map to ATT&CK.** Use mitre_attack (op=lookup): T1199 Trusted Relationship \
(the attacker abused the trusted DevOps platform / a third-party CI integration), \
T1074.001 Data Staged (secrets/keys collected in a repo or artifact), \
T1552 Unsecured Credentials (leaked secrets / PATs), T1195 Supply Chain \
Compromise (modified dependencies / build outputs), T1195.002 Compromise \
Software Supply Chain (malicious commit to a dependency). Also T1098 Account \
Manipulation and T1078 Valid Accounts for permission changes.

## Tool-use rules
- Always pass repo in the platform's expected form: github/gitlab = \
'owner/name' or 'group/project'; azure_devops = project name; jira = \
project key. Some operations (repo_changes, pipeline_runs, secrets_scan) \
require repo.
- If a platform returns a missing-token error, DO NOT retry it — move to the \
next configured platform. Report which platforms were auditable in the report.
- Don't call the same (platform, operation, repo) twice with identical args.
- For every notable finding, map it with mitre_attack (op=lookup) and cite the \
technique ID in the report.
- Stop and write the report when you have covered the configured platforms and \
the five operations, or hit the iteration cap.
"""


class DevOpsCompromiseGoal(Goal):
    id = "G18"
    cluster = "SaaS"
    label = "DevOps / source-control compromise"
    description = (
        "Investigate GitHub, Azure DevOps, and Jira compromises. Detects "
        "malicious commits, secret exfiltration, pipeline tampering, "
        "unauthorized permission changes, and supply-chain attacks."
    )
    input_artifacts = ["B10f"]
    tools = ["C15", "C16", "A2"]
    icon = "git-branch"

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

        # ---- triage: which platforms are configured? ----
        await self._set_node(bus, investigation_id, "triage", "running")
        triage = self._triage()
        bus.publish(E.agent_thought(
            investigation_id,
            f"DevOps platform triage: {triage}",
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
                    DevOpsApiTool(),
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
            f"DevOps / source-control compromise investigation complete. "
            f"Platform triage: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    def _triage(self) -> str:
        """Report which DevOps platforms have a token in the environment."""
        configured = []
        for platform, env_var in PLATFORM_TOKEN_ENV.items():
            if os.environ.get(env_var, "").strip():
                configured.append(platform)
        if configured:
            return f"tokens configured for {', '.join(configured)}"
        return ("no DevOps platform tokens configured "
                f"({', '.join(PLATFORM_TOKEN_ENV.values())}); set at least one "
                "to run the audit")

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"DevOps platform triage complete. {triage}.\n"
            f"Begin your DevOps / source-control compromise investigation. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## DevOps / source-control compromise (deterministic triage)\n\n"
            f"**Platform triage:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (audit-log review, malicious-commit detection, "
            "pipeline-tamper analysis, leaked-credential scanning, "
            "permission-change hunting, ATT&CK mapping).\n\n"
            "Make sure at least one of GITHUB_TOKEN, AZDO_PAT, JIRA_TOKEN, or "
            "GITLAB_TOKEN is set (plus the matching org/group env var) so the "
            "agent has a platform to audit.\n\n"
            "Once configured, re-run this goal for a complete compromise report."
        )


goal = DevOpsCompromiseGoal()
