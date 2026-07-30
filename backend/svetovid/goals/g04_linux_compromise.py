"""G04 — Linux server compromise investigation.

The first non-Windows agentic goal. Evidence is a mounted Linux filesystem
image or triage root (e.g. an E01 of a compromised server, or a directory of
copied log artifacts) read-only at /evidence. The agent drives the Linux
incident-response decision tree across the classic log artifacts:

  - linux_log_parse  — one tool, log_type selector, parses syslog/auth.log /
                       journal / wtmp / cron / shell_history / dpkg / systemd
                       units into structured rows
  - mitre_attack     — map observed behaviors (brute force, persistence,
                       command-and-scripting) to ATT&CK techniques

The system prompt encodes the standard Linux IR playbook (auth.log brute-force
& sudo, cron/systemd persistence, shell-history attacker commands, dpkg
installed backdoors, wtmp login patterns) so the LLM follows forensic best
practice without a hard-coded call order.

Falls back to a deterministic summary if no LLM provider is configured
(matching G01/G02/G03's contract).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.linux_logs import LinuxLogParseTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior Linux incident-response analyst investigating a potentially \
compromised server. Your evidence is a mounted read-only Linux filesystem or \
triage root at /evidence (the agent wrappers translate that path for you \
automatically). Standard Unix tools (journalctl, utmpdump, grep, awk) are \
available inside the sandbox.

## Your mission
1. Establish the initial access vector (brute-force sshd, valid accounts, \
exploit, supply-chain).
2. Find attacker persistence (cron jobs, systemd units, shell rc files, \
authorized_keys).
3. Recover attacker commands from shell history and reconstruct actions on \
objectives.
4. Identify installed backdoors / tooling via package logs (dpkg.log).
5. Reconstruct login/logout patterns from wtmp.
6. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool).
7. Produce a clear Markdown report with: (a) initial-access finding, \
(b) persistence inventory, (c) ATT&CK-ordered timeline, (d) IOCs (users, \
hosts, commands, packages), (e) recommended remediation.

## Investigation strategy (Linux IR decision tree)
- **auth.log first (log_type=auth)**: look for sshd brute-force (many \
`Failed password`), successful logins (`Accepted password`/`Accepted \
publickey`), sudo/su escalations, `useradd`/`usermod` account creation, and \
session openings. This usually reveals the initial-access vector and the \
attacker's user account.
- **wtmp (log_type=wtmp)**: reconstruct login patterns (who logged in, from \
where, when). Correlate IPs from auth.log with wtmp sessions.
- **cron (log_type=cron)**: persistence via crontab entries. Grep for curl/wget \
downloaders, reverse shells, and unknown scheduled scripts.
- **systemd_unit (log_type=systemd_unit)**: enumerate every .service/.timer in \
/etc/systemd/system. Flag any with ExecStart pointing at /tmp, /dev/shm, a \
python/perl one-liner, or an unknown binary.
- **shell_history (log_type=shell_history)**: read ~/.bash_history and \
~/.zsh_history for attacker commands (nmap, nc, curl|sh, base64 blobs, \
useradd, chmod +s, edits to /etc/rc.local or authorized_keys).
- **dpkg (log_type=dpkg)**: review /var/log/dpkg.log for newly installed \
packages around the compromise window — backdoors, tunneling tools \
(chisel, frp, ngrok), crypto miners, or webshells.
- **journal (log_type=journal)**: if .journal files exist, query them for \
service restarts, kernel messages, and process execution context not captured \
in syslog.

## Tool-use rules
- Always pass evidence_subpath as a relative path under /evidence (or omit it \
to let the parser discover the standard file, e.g. var/log/auth.log).
- Parse one log_type per call; pick the next based on what you found.
- Don't call the same (log_type, evidence_subpath) twice with identical args.
- For every notable finding, map it with mitre_attack (op=lookup or \
op=reverse_event) and cite the technique ID in your report.
- Stop and write the report when you have covered the decision-tree branches \
or hit the iteration cap.
"""


class LinuxCompromiseGoal(Goal):
    id = "G04"
    cluster = "Endpoint"
    label = "Linux server compromise"
    description = (
        "Investigate a compromised Linux server. The agent parses auth.log "
        "(brute-force/sudo), cron and systemd units (persistence), shell "
        "history (attacker commands), dpkg.log (installed backdoors), wtmp "
        "(login patterns), and the systemd journal, then maps findings to "
        "MITRE ATT&CK. Produces an ATT&CK-ordered compromise report."
    )
    input_artifacts = ["B4"]
    tools = ["C17c", "C16", "A2"]
    icon = "server"

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
                    LinuxLogParseTool(),
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
            f"Linux server compromise investigation complete. Evidence: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _triage(self, root: str) -> str:
        import os
        counts = {
            "auth": 0, "syslog": 0, "messages": 0, "journal": 0, "wtmp": 0,
            "btmp": 0, "cron_log": 0, "shell_history": 0, "dpkg": 0,
            "systemd_units": 0, "image": 0,
        }
        unit_exts = (".service", ".timer", ".socket", ".mount")
        hist_names = {".bash_history", ".zsh_history", ".sh_history", ".history"}
        for dp, _, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                if fl == "auth.log" or fl.startswith("auth.log"): counts["auth"] += 1
                elif fl == "syslog" or fl.startswith("syslog"): counts["syslog"] += 1
                elif fl == "messages" or fl.startswith("messages"): counts["messages"] += 1
                elif fl.endswith(".journal"): counts["journal"] += 1
                elif fl == "wtmp" or fl.startswith("wtmp"): counts["wtmp"] += 1
                elif fl == "btmp" or fl.startswith("btmp"): counts["btmp"] += 1
                elif fl in ("cron", "cron.log") or fl.startswith("cron.log"): counts["cron_log"] += 1
                elif fl == "dpkg.log" or fl.startswith("dpkg.log"): counts["dpkg"] += 1
                elif fn in hist_names: counts["shell_history"] += 1
                elif fl.endswith(unit_exts): counts["systemd_units"] += 1
                elif fl.endswith((".e01", ".ex01", ".raw", ".dd", ".001")): counts["image"] += 1
        parts = [f"{v} {k}" for k, v in counts.items() if v]
        return ", ".join(parts) if parts else "no recognized Linux artifacts"

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Evidence triage complete. Found: {triage}.\n"
            f"Begin your Linux compromise investigation. User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## Linux server compromise investigation (deterministic triage)\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (auth.log parsing, cron/systemd persistence hunt, "
            "shell-history recovery, dpkg backdoor detection, wtmp login "
            "correlation, ATT&CK mapping).\n\n"
            "Once configured, re-run this goal for a complete compromise report."
        )


goal = LinuxCompromiseGoal()
