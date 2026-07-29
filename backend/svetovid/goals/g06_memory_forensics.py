"""G06 — Memory forensics / malware-in-RAM investigation.

The memory-focused goal. The agent is handed a memory image and a toolbelt
built around Volatility 3, and the ReAct loop decides which plugins to run
based on what it finds. Available tools:

  - volatility        — Volatility 3 plugin runner. The agent picks plugins:
                        pslist/psscan (process hiding), malfind (code
                        injection), netscan (C2), handles/dlllist (modules),
                        hashdump/lsadump (credentials), callbacks/modscan
                        (rootkits), svcscan (services).
  - yara_scan         — Scan extracted memory artifacts against malware YARA rules
  - mitre_attack      — Map behaviors / injections to ATT&CK techniques

The agent's job: hunt code injection, hidden processes, rootkit hooks, and
C2 channels in RAM, extract credentials, and produce an ATT&CK-mapped
report. The system prompt encodes the SANS FOR508 / Volatility memory-hunt
decision tree so the LLM follows forensic best practice without us
hard-coding the plugin call order.

Falls back to a deterministic summary if no LLM provider is configured
(matching G01/G02's contract).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.volatility import VolatilityTool
from ..tools.yara import YaraTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior memory-forensics analyst investigating a potential malware \
compromise captured in a RAM image. Your evidence is mounted read-only at \
/evidence (the agent wrappers translate that path for you automatically); \
the memory image is the *.raw / *.mem / *.vmem / *.lime / *.dmp file under \
/evidence (pass its subpath as image_subpath to the volatility tool).

## Your mission
1. Detect process hiding (DKOM): compare pslist (active EPROCESS list) \
against psscan (pool-scan) — processes in psscan but not pslist were \
hidden or terminated.
2. Detect code injection: malfind flags RWX pages containing MZ/PE headers \
— the hallmark of process hollowing, reflectivedll injection, and shellcode.
3. Detect C2 / network beaconing: netscan lists TCP/UDP endpoints and \
connections; correlate foreign IPs with suspicious processes.
4. Enumerate loaded modules per suspicious process (dlllist, handles) to \
spot injected DLLs, malicious handles, or backdoor files.
5. Hunt rootkits: callbacks (kernel callback routines — CmCallback, \
PsSetCreateProcessNotifyRoutine) and modscan (unloaded/hidden kernel \
modules) reveal hook-based rootkits.
6. Extract credentials: hashdump (NTLM hashes from LSASS) and lsadump \
(LSA secrets) for offline cred recovery.
7. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool).
8. Produce a clear Markdown report with: (a) process tree anomalies, (b) \
injection evidence, (c) network/C2 indicators, (d) rootkit hooks, (e) \
extracted credentials, (f) ATT&CK-mapped findings, (g) recommended \
remediation.

## Investigation strategy (memory-forensics decision tree)
- Start with pslist and psscan. Diff them: any EPROCESS present in \
psscan but absent from pslist is a DKOM-hidden (rootkit) or recently \
terminated process — investigate it.
- For each suspicious process, run malfind. RWX private memory pages \
containing a PE header (MZ) are strong evidence of code injection.
- Run netscan to map every network connection. Correlate each connection's \
owning PID back to the process tree — flag connections from injected/hidden \
processes as likely C2.
- For suspicious PIDs, run dlllist (loaded DLLs — look for unsigned / \
in-memory-only DLLs) and handles (open files, keys, mutexes — look for \
known-malware mutex names or access to credential stores).
- Run callbacks to enumerate kernel callback routines (rootkit hook \
detection) and modscan to find unloaded/hidden kernel modules.
- Run hashdump to recover NTLM hashes and lsadump for LSA secrets.
- Run yara_scan on any extracted injected payload or suspicious binary for \
malware family identification.
- Map every confirmed behavior to ATT&CK with the mitre_attack tool \
(technique_id lookup): T1055 (process injection), T1014 (rootkit), \
T1055.001 (DLL injection), T1055.012 (process hollowing), T1003.002 \
(SecurityDumper / SAM), T1071 (application layer protocol for C2), etc.

## Tool-use rules
- Always pass image_subpath as a relative path under /evidence to the \
volatility tool (the path to the memory image).
- Don't run the same plugin twice with identical args.
- Stop and write the report when you have covered the decision tree or hit \
the iteration cap.
"""


class MemoryForensicsGoal(Goal):
    id = "G06"
    cluster = "Memory"
    label = "Memory forensics & malware-in-RAM"
    description = (
        "Analyze a memory image with Volatility 3 to detect code injection, "
        "rootkits, hidden processes, network connections, and extract "
        "credentials. The agent picks which Vol3 plugins to run based on "
        "what it finds."
    )
    input_artifacts = ["B6"]
    tools = ["C13", "C13a", "C13b", "C13c", "C15", "A2"]
    icon = "memory-stick"

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
                    VolatilityTool(),
                    YaraTool(),
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
            f"Memory forensics hunt complete. Evidence: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _triage(self, root: str) -> str:
        import os
        counts = {
            "raw": 0, "mem": 0, "vmem": 0, "lime": 0, "dmp": 0,
            "hiberfil": 0, "pagefile": 0,
        }
        images: list[str] = []
        for dp, _, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                if fl.endswith(".raw"):
                    counts["raw"] += 1
                    images.append(fn)
                elif fl.endswith(".mem"):
                    counts["mem"] += 1
                    images.append(fn)
                elif fl.endswith(".vmem"):
                    counts["vmem"] += 1
                    images.append(fn)
                elif fl.endswith(".lime"):
                    counts["lime"] += 1
                    images.append(fn)
                elif fl.endswith(".dmp"):
                    counts["dmp"] += 1
                    images.append(fn)
                elif fl == "hiberfil.sys":
                    counts["hiberfil"] += 1
                    images.append(fn)
                elif fl == "pagefile.sys":
                    counts["pagefile"] += 1
                    images.append(fn)
        parts = [f"{v} {k}" for k, v in counts.items() if v]
        if not parts:
            return "no recognized memory artifacts (need *.raw/*.mem/*.vmem/*.lime/*.dmp/hiberfil.sys/pagefile.sys)"
        detail = f" (images: {', '.join(images[:3])}{'…' if len(images) > 3 else ''})" if images else ""
        return ", ".join(parts) + detail

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Evidence triage complete. Found: {triage}.\n"
            f"Begin your memory-forensics investigation. User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## Memory forensics (deterministic triage)\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "Volatility investigation (process hiding / DKOM detection, "
            "malfind code-injection hunting, netscan C2 mapping, callback "
            "rootkit detection, hashdump credential extraction, YARA "
            "scanning, and ATT&CK mapping).\n\n"
            "Once configured, re-run this goal for a complete report."
        )


goal = MemoryForensicsGoal()
