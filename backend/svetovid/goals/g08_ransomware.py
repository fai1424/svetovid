"""G08 — Ransomware investigation.

An agentic goal that hands the LLM a toolbelt and a mission: determine the
ransomware entry vector, build the encryption onset timeline, and identify
the ransomware family. Available tools:

  - chainsaw_hunt     — Sigma-rule hunt over .evtx for mass file modification
                        (4663 DELETE/RENAME bursts, Sysmon 11 file-create
                        bursts), entry-vector auth events, and lateral movement
  - hayabusa_timeline — Cross-validate Sigma findings + ATT&CK tags
  - volatility        — If a memory image is present, run pslist/malfind to
                        find the locker process and live encryption keys
  - yara_scan         — Identify the ransom binary against family YARA rules
  - mitre_attack      — Map behaviors to ATT&CK (T1486, T1490, T1087, ...)

The agent's job: reconstruct the attack, name the family/affiliate, and
assess recovery feasibility. The system prompt encodes the ransomware IR
decision tree so the LLM follows forensic best practice without us
hard-coding the call order.

Falls back to a deterministic summary if no LLM provider is configured
(matching G02's contract).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.chainsaw import ChainsawTool
from ..tools.hayabusa import HayabusaTool
from ..tools.volatility import VolatilityTool
from ..tools.yara import YaraTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior DFIR analyst investigating a ransomware incident. Your \
evidence is mounted read-only at /evidence (the agent wrappers translate \
that path for you automatically).

## Your mission
1. Determine the ransomware entry vector (phishing/macro, RDP brute-force, \
exploit of a public-facing app, stolen credentials, etc.).
2. Build the encryption onset timeline — when did mass file modification \
begin, and how fast did it spread.
3. Identify the ransom binary and the ransomware family / affiliate cluster.
4. If a memory image is present, find the locker process and any live \
encryption keys.
5. Assess recovery feasibility (shadow copies, backups, known decryptor).
6. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool).
7. Produce a clear Markdown report with: (a) entry vector, (b) encryption \
timeline, (c) family/affiliate identification, (d) recovery feasibility, \
(e) ATT&CK mapping, (f) recommended containment & remediation.

## Investigation strategy (ransomware IR decision tree)
- **Mass file modification / encryption onset:** hunt .evtx with chainsaw_hunt \
for event ID 4663 (object access) showing bursts of DELETE/RENAME on user \
documents, and Sysmon event ID 11 (FileCreate) bursts. The first sustained \
burst marks encryption onset. Walk the timeline backward from there to find \
the trigger process.
- **Identify the ransom binary:** run yara_scan on any extracted suspicious \
executables / dropped files against known ransomware-family rules. Check \
Prefetch (Sysmon EID 1 / 4688 process creation) and Amcache for execution \
proof of the locker. Note the ransom note filename and extension pattern \
(e.g. HOW_TO_DECRYPT.txt, README_RECOVER.txt, _README_.hta, .locked, \
.encrypted, family-specific extensions).
- **Entry vector:** distinguish between:
  - Phishing → macro execution: look for WINWORD/EXCEL → cmd/powershell → \
suspicious child process in 4688/Sysmon 1, plus macro-alarm events.
  - RDP brute-force: a run of 4625 (failed logon) followed by a 4624 \
(successful logon) with LogonType 10 from an external IP.
  - Exploit of public-facing app: web server / IIS logs (PCAP) showing \
suspicious requests immediately before the first malicious process.
  - Stolen creds / valid accounts: 4624 LogonType 3 (network) from an \
unexpected host, often followed by lateral movement.
- **Lateral movement:** look for 4624 LogonType 3 bursts, PsExec service \
creation (7045), SMB admin-share access (4663 on \\\\ADMIN$ / \\\\C$), and \
remote service/session creation. This tells you how far the encryption \
spread and how many hosts are impacted.
- **Memory (if a .raw/.vmem/.lime image is present):** run volatility pslist \
to enumerate the running locker process and malfind to detect injected \
code. For some families the encryption key (or the locker itself) is still \
resident in memory — note the PID and any key material for recovery.
- **Family & affiliate identification:** combine the YARA family hit, the \
ransom-note wording, the file-extension pattern, and any affiliate ID in \
the note to name both the ransomware family and the specific affiliate \
cluster (many families are operated as RaaS).
- **Recovery feasibility:** determine whether Volume Shadow Copies were \
deleted (vssadmin delete shadows → look for the process in 4688/Sysmon 1, \
and wbadmin/bcdedit manipulation). Note backup status. State whether a \
known free decryptor exists for the identified family (e.g. from the \
NoMoreRansom project) — but never promise decryption without the key.

## ATT&CK mapping (expected anchors)
- T1486 Data Encrypted for Impact (the encryption itself)
- T1490 Inhibit System Recovery (shadow-copy / backup deletion)
- T1489 Service Stop, T1496 Resource Hijacking (often seen alongside)
- T1087 Account Discovery, T1018 Remote System Discovery (targeting before \
encryption)
- T1021 Remote Services (SMB/RDP), T1570 Lateral Tool Transfer (spread)
- T1059 Command and Scripting Interpreter, T1105 Ingress Tool Transfer \
(locker delivery)

## Tool-use rules
- Always pass evidence_subpath as a relative path under /evidence.
- Don't call the same tool twice with identical args.
- Stop and write the report when you have established entry vector + \
encryption onset + family identification, or hit the iteration cap.
"""


# Ransom-note filenames / patterns commonly dropped by ransomware families.
RANSOM_NOTE_NAMES = {
    "how_to_decrypt.txt",
    "how_to_decrypt.html",
    "readme_recover.txt",
    "readme_recover.html",
    "_readme_.hta",
    "_readme_.txt",
    "readme.txt",
    "readme.html",
    "decrypt_my_files.txt",
    "decrypt_my_files.html",
    "restore_files.txt",
    "restore_files.html",
    "!!!restore!!!.txt",
    "!!!your_files_are_encrypted!!!.txt",
    "recovery+*.txt",
    "ransom.txt",
    "ransom.html",
    "info.txt",
    "info.hta",
    "your_files_are_encrypted.html",
    "de_crypt_readme.txt",
    "all_your_files_are_encrypted.txt",
}


class RansomwareGoal(Goal):
    id = "G08"
    cluster = "Ransomware"
    label = "Ransomware investigation"
    description = (
        "Determine ransomware entry vector, encryption onset timeline, and "
        "identify the ransomware family. Analyzes event logs for mass file "
        "modification, identifies the ransom binary via YARA, and checks "
        "memory for live encryption keys."
    )
    input_artifacts = ["B3", "B4", "B8", "B7", "B6"]
    tools = ["C12", "C17b", "C16", "C15", "C13", "A2"]
    icon = "file-lock-2"

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
                    ChainsawTool(),
                    HayabusaTool(),
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
            f"Ransomware investigation complete. Evidence: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _triage(self, root: str) -> str:
        import os
        import re
        counts = {
            "evtx": 0,
            "pcap": 0,
            "pf": 0,
            "memory": 0,
            "mft": 0,
            "e01": 0,
            "ransom_note": 0,
        }
        # Match ransom-note filenames; allow simple glob-style '+' (e.g. recovery+xxxx.txt)
        ransom_re = re.compile(
            r"^(recovery\+.*|.*how_to_decrypt.*|.*readme_recover.*|.*_readme_.*"
            r"|.*decrypt_my_files.*|.*restore_files.*|.*your_files_are_encrypted.*"
            r"|.*all_your_files_are_encrypted.*|.*de_crypt_readme.*"
            r"|!!!restore!!!|.*ransom\.(txt|html)|info\.(txt|hta|html))$",
            re.IGNORECASE,
        )
        for dp, _, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                if fl.endswith(".evtx"):
                    counts["evtx"] += 1
                elif fl.endswith((".pcap", ".pcapng", ".cap")):
                    counts["pcap"] += 1
                elif fl.endswith(".pf"):
                    counts["pf"] += 1
                elif fl.endswith((".raw", ".mem", ".vmem", ".lime", ".dmp")):
                    counts["memory"] += 1
                elif fl == "$mft" or fl == "mft":
                    counts["mft"] += 1
                elif fl.endswith((".e01", ".ex01")):
                    counts["e01"] += 1
                # ransom-note detection: exact name set or regex pattern
                elif fl in RANSOM_NOTE_NAMES or ransom_re.search(fl):
                    counts["ransom_note"] += 1
        parts = [f"{v} {k}" for k, v in counts.items() if v]
        return ", ".join(parts) if parts else "no recognized ransomware artifacts"

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Evidence triage complete. Found: {triage}.\n"
            f"Begin your ransomware investigation. User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## Ransomware investigation (deterministic triage)\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (mass-file-modification hunting, ransom-binary "
            "YARA identification, memory key recovery, and ATT&CK mapping).\n\n"
            "Once configured, re-run this goal for a complete report."
        )


goal = RansomwareGoal()
