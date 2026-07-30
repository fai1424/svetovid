"""G23 — CRIU container-checkpoint memory investigation (honeypot variant).

A specialized goal for evidence that is a Kubernetes/CRI-O container
**checkpoint** (CRIU dump): checkpoint/pages-*.img raw memory pages, plus
spec.dump / config.dump (runc config) and rootfs-diff.tar. This is the artifact
shape produced by `kubectl debug --image` checkpointing or `crictl checkpoint`.

The stock G19 (k8s compromise) targets audit logs / pod logs / etcd, which a
CRIU dump does NOT contain. This goal gives the agent the tools that actually
work on a CRIU memory dump:

  - criu_mem_search  — Boolean keyword search over printable strings extracted
                        from the raw memory pages (the only way to answer "what
                        was in this container's RAM").
  - k8s_parse        — still useful for spec.dump / config.dump / rootfs
                        container metadata.
  - forensic_keyword_search — Boolean search over the textual artifacts
                        (spec.dump, rootfs-diff files).
  - mitre_attack     — map findings to ATT&CK.

The system prompt encodes the CRIU triage decision tree: read container
identity from spec.dump, extract ransom/C2/process strings from memory, map
to ATT&CK (T1496 Resource Hijacking for the cryptominer, T1059 Command exec,
T1210 Exploitation of Remote Services for the postgres→miner pivot).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.criu_mem import CriuMemTool
from ..tools.k8s_parse import K8sParseTool
from ..tools.forensic_search import ForensicSearchTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior container / memory DFIR analyst investigating a compromised \
Kubernetes honeypot pod. The evidence is a **CRIU container checkpoint**: \
checkpoint/pages-*.img hold the raw 4KiB memory pages of every process in the \
container; spec.dump and config.dump are the runc config (container \
annotations, image, command, env); rootfs-diff.tar is the filesystem delta.

## Your mission — answer these questions precisely, citing the exact strings \
you found in memory and the file+offset:
1. The compromised Pod name and container name (from spec.dump / config.dump).
2. The C2 server IP address and port from which the attacker fetched the \
malicious payload (search memory for URLs, curl/wget, IP:port, mining pools).
3. The full path of the first sub-process executed by the malware (search \
memory for process paths, /proc/<pid>/fd, PWD=, _=, argv).
4. Any extortion / ransom message left in memory (search for "BTC", "pay", \
"backed up", "ransom", "onionmail", bitcoin addresses).

## Investigation strategy (CRIU triage decision tree)
- **Read container identity first.** Use k8s_parse or forensic_keyword_search \
on spec.dump/config.dump to get the sandbox-name (Pod), container-name, \
namespace, image, and the container's argv/env. The annotation \
io.kubernetes.cri.sandbox-name is the Pod; io.kubernetes.cri.container-name \
is the container.
- **Then mine the memory pages.** Use criu_mem_search heavily — it is the only \
tool that can read the binary pages-*.img. Useful queries: "BTC", \
"backed up", "xmrig", "mine.c3pool", "47.", "cpu_hu", "/proc/", "PWD=", \
"http", "config.json", "pools". Pass an EMPTY query to dump the distinct \
string index, then grep it. For each hit note the source file + file_offset.
- **Reconstruct the process tree.** The CRIU pstree.img lists PID/PPID. The \
malware's children (higher PID, ppid = malware pid) are its sub-processes; \
their argv/exe appear in memory as PWD= and _= env vars near the process.
- **Identify the malware family.** Look for "XMRig", "c3pool", mining pool \
URLs, "donate-level", RandomX/GhostRider algo names, "new job from" log lines \
→ this is a cryptominer (ATT&CK T1496 Resource Hijacking).
- **Find the initial-access pivot.** If the container runs postgres/postmaster \
and the miner's PPID is the postmaster PID, the attacker abused PostgreSQL \
RCE (COPY ... TO PROGRAM / UDF) to launch the miner (T1059.004 + T1210).
- **Map every finding to ATT&CK** with mitre_attack (op=lookup): T1496 \
Resource Hijacking, T1059 Command and Scripting Interpreter, T1210 \
Exploitation of Remote Services, T1071 Application Layer Protocol, T1567 \
Exfiltration Over Web Service.

## Tool-use rules
- criu_mem_search runs over ALL pages-*.img by default; you do NOT need to \
pass evidence_subpath unless you want one specific file.
- Boolean operators AND/OR/NOT and quoted phrases are supported in criu_mem_search.
- Always cite the source pages file + byte offset for each finding.
- Don't call the same query twice with identical args.
- Stop and write the report when you have answered all 4 questions.
"""


class CriuContainerCompromiseGoal(Goal):
    id = "G23"
    cluster = "Container"
    label = "CRIU container-checkpoint memory forensics"
    description = (
        "Investigate a CRIU container checkpoint (raw memory pages + runc "
        "config) to identify a compromise: find the Pod/container, the C2 "
        "server used to fetch the payload, the malware's first sub-process, "
        "and any ransom/extortion message. Uses criu_mem_search to read the "
        "binary memory pages."
    )
    input_artifacts = ["B12"]
    tools = ["C16", "C17c", "C8", "C13", "A2"]
    icon = "cpu"

    def nodes(self) -> list[GoalNode]:
        return [
            GoalNode("triage", "Triage checkpoint evidence"),
            GoalNode("react_loop", "Agent memory investigation (ReAct)"),
            GoalNode("draft_report", "Draft report"),
            GoalNode("hitl_review", "Review (human)"),
            GoalNode("finalize", "Finalize"),
        ]

    async def run(self, *, investigation_id: str, case_id: str,
                  evidence_path: str, user_prompt: str, bus) -> None:
        out_dir = str(Path.home() / ".svetovid" / "cases" / case_id / investigation_id)
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        await self._set_node(bus, investigation_id, "triage", "running")
        triage = await self._triage(evidence_path)
        bus.publish(E.agent_thought(
            investigation_id,
            f"CRIU checkpoint triage: {triage}",
        ))
        await self._set_node(bus, investigation_id, "triage", "done")

        settings = load_settings()
        provider = settings.active()

        await self._set_node(bus, investigation_id, "react_loop", "running")
        final_answer = ""
        if provider and provider.is_configured() and provider.api_key:
            try:
                tools = [
                    CriuMemTool(),
                    K8sParseTool(),
                    ForensicSearchTool(),
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
                "No LLM provider configured; deterministic triage only.",
            ))
            final_answer = self._fallback(triage, user_prompt)

        await self._set_node(bus, investigation_id, "react_loop", "done")

        await self._set_node(bus, investigation_id, "draft_report", "running")
        bus.publish(E.report_section_added(
            investigation_id, "narrative", "Investigator narrative", final_answer,
        ))
        await self._set_node(bus, investigation_id, "draft_report", "done")

        await self._set_node(bus, investigation_id, "hitl_review", "running")
        if settings.hitl_report_release == "required":
            from ..agent.hitl import request_approval
            approved = await request_approval(
                investigation_id, bus,
                "Report drafted. Review before finalize.",
                {"preview": final_answer[:600]},
            )
            if not approved:
                bus.publish(E.investigation_end(investigation_id, "cancelled", "HITL rejected"))
                await self._set_node(bus, investigation_id, "hitl_review", "skipped")
                return
        await self._set_node(bus, investigation_id, "hitl_review", "done")

        await self._set_node(bus, investigation_id, "finalize", "running")
        bus.publish(E.report_section_added(
            investigation_id, "summary", "Summary",
            f"CRIU container-checkpoint investigation complete. Evidence: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _triage(self, root: str) -> str:
        import os
        criu_pages = 0
        has_spec = has_config = has_rootfs = False
        for dp, dns, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                if fn.startswith("pages-") and fl.endswith(".img"):
                    criu_pages += 1
                elif fl == "spec.dump":
                    has_spec = True
                elif fl == "config.dump":
                    has_config = True
                elif fl == "rootfs-diff.tar":
                    has_rootfs = True
        return (
            f"{criu_pages} CRIU pages-*.img, "
            f"spec.dump={'yes' if has_spec else 'no'}, "
            f"config.dump={'yes' if has_config else 'no'}, "
            f"rootfs-diff.tar={'yes' if has_rootfs else 'no'}"
        )

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"CRIU checkpoint evidence triaged. Found: {triage}.\n"
            f"Begin your investigation. User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## CRIU container-checkpoint (deterministic triage)\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one to enable the full ReAct investigation "
            "(criu_mem_search + k8s_parse + forensic_search + mitre_attack)."
        )


goal = CriuContainerCompromiseGoal()
