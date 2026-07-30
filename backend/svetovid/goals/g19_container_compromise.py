"""G19 — Container / Kubernetes compromise.

The agentic container / Kubernetes compromise goal. G19 investigates a
container escape, supply-chain image tampering, privilege escalation, and
lateral movement between namespaces from the forensic artifacts a responder
collects off a cluster: k8s API audit logs, pod log directories, container
image manifests, runtime detections (Falco/Tetragon), and etcd state. The
agent drives the ReAct loop over a toolbelt and maps findings to MITRE ATT&CK.
Available tools:

  - k8s_parse     — Parse a k8s/container artifact (artifact_type selector:
                    audit_log, pod_logs, kubelet_logs, etcd_state,
                    image_history, runtime_events, network_policy) into
                    structured rows. Runs in svetovid/base; read-only.
  - criu_parse    — Parse a CRIU container checkpoint directory (.img files)
                    into process tree, network connections, open files,
                    memory mappings (anon RWX = code injection), and
                    credentials (dangerous capabilities). Pure-Python; read-only.
  - mitre_attack  — Map observed behaviors to ATT&CK techniques

The system prompt encodes the DFIR decision tree for a container / k8s
compromise: build the API-call timeline from audit logs, read container
output from pod logs, check image history for supply-chain tampering, review
runtime detections for escape / privilege escalation, and inspect etcd state
for cluster config changes — then map each finding to ATT&CK (T1611 Escape to
Host, T1610 Deploy Container, T1613 Container and Resource Discovery, T1525
Implant Internal Image).

Falls back to a deterministic summary if no LLM provider is configured
(matching G02's contract).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.criu_parse import CriuParseTool
from ..tools.k8s_parse import K8sParseTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior container / Kubernetes DFIR analyst investigating a potential \
container or Kubernetes cluster compromise. Your evidence is mounted read-only \
at /evidence (the agent wrappers translate that path for you automatically). \
The evidence is a collected artifact bundle — k8s API audit logs, the \
/var/log/pods/ tree, container image manifests/configs, runtime detections \
(Falco / Tetragon / Sysdig), kubelet logs, and possibly an exported etcd \
keyspace snapshot.

## Your mission
1. Reconstruct pod / namespace activity from the k8s API audit log — who did \
what, to which object, from where, and did it succeed.
2. Detect container escape to the host (privileged pods, hostPath/hostPID/\
hostNetwork mounts, capabilities like CAP_SYS_ADMIN, node-level execution).
3. Detect unauthorized / malicious container deployment (new pods in sensitive \
namespaces like kube-system, pods pulling from unusual image registries).
4. Detect supply-chain image tampering (backdoored base images, suspicious \
RUN/COPY instructions, modified entrypoints, unexpected packages).
5. Detect privilege escalation (ClusterRoleBinding grants, service-account \
token abuse, new admins, RBAC changes).
6. Detect lateral movement between namespaces (cross-namespace API calls, \
network-policy weakening, egress to other namespaces).
7. Map every finding to MITRE ATT&CK (use the mitre_attack tool).
8. Produce a clear Markdown report with: (a) API-call timeline, (b) container \
escape / privilege-escalation findings, (c) image-tampering findings, (d) \
lateral-movement / namespace-egress findings, (e) ATT&CK mapping, (f) \
recommended remediation.

## Investigation strategy (container compromise decision tree)
- **Start with audit_log.** Call k8s_parse(artifact_type="audit_log") to build \
the API-call timeline. Sort by timestamp. Flag: create/update/patch on pods, \
deployments, daemonsets, jobs, cronjobs, roles, rolebindings, clusterroles, \
clusterrolebindings, serviceaccounts, secrets, mutatingwebhookconfigurations; \
failed (4xx/5xx) responses; calls from unusual users, sourceIPs, or userAgents; \
verb=get/list on secrets or pods across many namespaces (recon → T1613); \
pod creates with privileged securityContext or host* mounts.
- **Then read pod_logs.** Call k8s_parse(artifact_type="pod_logs") for the \
/var/log/pods/ tree (or the specific pod the audit log flagged). Look for \
shell prompts, reverse shells, curl/wget to external IPs, crypto miners, and \
credentials dumped to stdout/stderr — these prove the pod was used \
maliciously.
- **Check image_history for supply-chain tampering.** Call \
k8s_parse(artifact_type="image_history") on the suspicious image's config/\
manifest. Flag images whose config.User is root, whose Entrypoint/Cmd point \
at unexpected binaries (e.g. /backdoor, /tmp/.x, a python one-liner), whose \
created_by includes curl|wget|nc|base64|chmod|/dev/tcp, or whose repoTags \
come from an unusual registry. This is T1525 Implant Internal Image and \
T1195 Supply Chain Compromise.
- **Review runtime_events for escape / escalation detections.** Call \
k8s_parse(artifact_type="runtime_events") for Falco/Tetragon/Sysdig JSONL. \
High-signal rules: "Terminal shell in container", "Write below / or rpm db", \
"Contact Kubernetes API Server from Container", "Privileged container \
started", "Namespace change", rules referencing CAP_SYS_ADMIN / CAP_SYS_PTRACE \
/ setns / mount / nsenter — these are container-escape indicators (T1611).
- **Inspect etcd_state for cluster config changes.** Call \
k8s_parse(artifact_type="etcd_state") on the exported keyspace. Look for \
new/changed /registry/roles, /registry/clusterrolebindings, \
/registry/secrets (esp. service-account tokens), privileged pods, or RBAC \
that grants * verbs — these reveal persistence the API audit may have missed.
- **Optionally check network_policy** (k8s_parse artifact_type="network_policy") \
to map which namespaces can talk to which — weakens the lateral-movement \
picture (T1021 Remote Services / cross-namespace pivot).
- **If a CRIU checkpoint directory (.img files) is present, run criu_parse \
with analysis_type='full' to extract the process tree, network connections, \
open files, and detect code injection (anonymous RWX memory regions) and \
privilege escalation (dangerous capabilities).** A CRIU checkpoint is a frozen \
snapshot of a container's runtime state: process tree (pstree.img + core-*.img), \
memory mappings (mm-*.img), open files (fdinfo-*.img + files.img + reg-files.img), \
network connections (inetsk.img), and credentials (creds-*.img). Flag anonymous \
RWX VMAs (T1055 Process Injection), ESTABLISHED connections to non-private IPs \
(T1071 Application Layer Protocol), and processes running with CAP_SYS_ADMIN / \
CAP_SYS_PTRACE or setuid-root (T1548 Privilege Escalation).
- **Map to ATT&CK.** Use mitre_attack (op=lookup): T1611 Escape to Host, \
T1610 Deploy Container, T1613 Container and Resource Discovery, T1525 Implant \
Internal Image. Also relevant: T1611's sub-techniques, T1098 Account \
Manipulation (RBAC/service-account abuse), T1078 Valid Accounts (stolen \
service-account tokens), T1195 Supply Chain Compromise, T1609 Container and \
Resource Discovery.

## Tool-use rules
- Always pass evidence_subpath as a relative path under /evidence. If omitted, \
k8s_parse discovers the canonical location (e.g. /var/log/pods/, *audit*.log, \
an etcd export) under /evidence.
- Don't call the same (artifact_type, evidence_subpath) twice with identical args.
- For every notable finding, map it with mitre_attack (op=lookup) and cite the \
technique ID in the report.
- Stop and write the report when you have covered audit_log, pod_logs, \
image_history, runtime_events, and (if present) etcd_state, or hit the \
iteration cap.
"""


class ContainerCompromiseGoal(Goal):
    id = "G19"
    cluster = "Container"
    label = "K8s / container compromise"
    description = (
        "Reconstruct pod/namespace activity from k8s audit logs, runtime "
        "metadata, and etcd state. Detects container escape, image tampering, "
        "privilege escalation, and lateral movement between namespaces."
    )
    input_artifacts = ["B12"]
    tools = ["C16", "C17c", "C15", "A2"]
    icon = "box"

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

        # ---- triage: which k8s/container artifacts are present? ----
        await self._set_node(bus, investigation_id, "triage", "running")
        triage = await self._triage(evidence_path)
        bus.publish(E.agent_thought(
            investigation_id,
            f"Container / k8s evidence triage: {triage}",
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
                    K8sParseTool(),
                    CriuParseTool(),
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
            f"K8s / container compromise investigation complete. Evidence: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    @staticmethod
    def _looks_like_image_manifest(path: str) -> bool:
        """Heuristic: a saved-image manifest.json references Layers/Config.
        Reads only the first 1KB to stay cheap during the walk."""
        try:
            with open(path, "rb") as f:
                head = f.read(1024).decode("utf-8", "replace").lower()
            return "layers" in head or "config" in head or "repotags" in head
        except Exception:
            return False

    async def _triage(self, root: str) -> str:
        """Count the recognizable k8s/container artifacts under the evidence tree."""
        import os
        counts = {
            "audit_log": 0, "pod_logs": 0, "kubelet_logs": 0,
            "etcd_state": 0, "image_history": 0, "runtime_events": 0,
            "network_policy": 0,
        }
        for dp, dns, fns in os.walk(root):
            # directory-based artifacts
            base = os.path.basename(dp).lower()
            if base == "pods" and dp.lower().endswith("var/log/pods"):
                counts["pod_logs"] += 1
            for fn in fns:
                fl = fn.lower()
                # audit log (JSON lines mentioning audit, or kube-apiserver-audit)
                if ("audit" in fl and fl.endswith(".log")) or \
                   fl.endswith(("-audit.log", "-audit.log.1")) or \
                   fl in ("audit.jsonl", "kube-apiserver-audit.log"):
                    counts["audit_log"] += 1
                # kubelet logs
                elif fl.startswith("kubelet") and fl.endswith((".log", ".journal")):
                    counts["kubelet_logs"] += 1
                # etcd snapshot / export
                elif "etcd" in fl and fl.endswith((".json", ".jsonl")):
                    counts["etcd_state"] += 1
                # runtime detections (Falco / Tetragon / Sysdig)
                elif any(k in fl for k in ("falco", "tetragon", "sysdig")) and \
                     fl.endswith((".jsonl", ".log")):
                    counts["runtime_events"] += 1
                # container image config / manifest history
                elif fl in ("config.json", "image-config.json", "image.json",
                            "inspect.json") or \
                     (fl == "manifest.json" and self._looks_like_image_manifest(
                         os.path.join(dp, fn))):
                    counts["image_history"] += 1
                # network policy manifests
                elif (fl.endswith((".yaml", ".yml")) and
                      any(k in fl for k in ("networkpolic", "netpol", "cnp", "ciliumnetworkpolic", "globalnetwork"))):
                    counts["network_policy"] += 1
        parts = [f"{v} {k}" for k, v in counts.items() if v]
        return ", ".join(parts) if parts else "no recognized container / k8s artifacts"

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Evidence triage complete. Found: {triage}.\n"
            f"Begin your container / Kubernetes compromise investigation. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## K8s / container compromise (deterministic triage)\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (k8s audit-log timeline, pod-log review, image-"
            "history supply-chain check, runtime-detection triage, etcd-state "
            "inspection, ATT&CK mapping).\n\n"
            "Once configured, re-run this goal for a complete report."
        )


goal = ContainerCompromiseGoal()
