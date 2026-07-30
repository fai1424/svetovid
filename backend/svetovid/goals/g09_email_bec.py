"""G09 — Email / BEC / phishing investigation.

The agentic email-compromise goal. Evidence is a mounted read-only copy of an
email corpus or messaging-cache at /evidence. The agent drives the email
investigation decision tree across the common artifact types:

  - email_parse  — one tool, format selector, parses .eml / .mbox / .msg /
                   .pst / .ost and Teams / Slack LevelDB caches into structured
                   rows (from/to/subject/date/body_preview/attachments and
                   SPF/DKIM/DMARC authentication results)
  - mitre_attack — map observed behaviors (phishing, internal spearphishing,
                   account takeover) to ATT&CK techniques

The system prompt encodes the SANS / NIST email-investigation playbook
(authentication-result triage, display-name spoofing, executable-attachment
flagging, BEC social-engineering indicators, cache-based exfiltration) so the
LLM follows forensic best practice without a hard-coded call order.

Falls back to a deterministic summary if no LLM provider is configured
(matching G01/G02/G03/G04/G05's contract).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.email_parse import EmailParseTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior email-forensics analyst investigating a potential email \
compromise: business email compromise (BEC), phishing, or account takeover. \
Your evidence is mounted read-only at /evidence (the agent wrappers translate \
that path for you automatically). The Python email/mailbox modules (and \
optional libpff/extract-msg) are available inside the sandbox.

## Your mission
1. Enumerate the mail store: parse every relevant artifact (email_parse) to \
extract message metadata and authentication results.
2. Triage authentication: flag any message where SPF=fail, DKIM=fail, or \
DMARC=fail/none — these are the primary phishing indicators.
3. Detect display-name spoofing (From: "CEO Name" <attacker@external-domain.com>).
4. Inventory attachments and flag executable / macro-bearing types (.exe, \
.dll, .js, .vbs, .jse, .wsf, .docm, .xlsm, .pptm, .hta, .scr, .lnk).
5. Score BEC / social-engineering indicators in the body (urgency language, \
wire-transfer / invoice / payment requests, gift-card scams, reply-to \
mismatch, lookalike domains).
6. For Teams / Slack caches, look for exfiltration (large outbound file \
shares) and social-engineering messages.
7. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool).
8. Produce a clear Markdown report with: (a) phishing/authentication \
findings, (b) impersonation / BEC inventory, (c) malicious-attachment list, \
(d) ATT&CK-mapped timeline, (e) recommended remediation.

## Investigation strategy (email investigation decision tree)
- **Start by parsing the mail store (email_parse).** Pick `format` by the \
artifact you triaged: eml (single messages), mbox (Unix mailbox), msg \
(Outlook .msg), pst/ost (Outlook stores), teams_db (Teams LevelDB cache), \
slack_cache (Slack desktop cache). Pass evidence_subpath as a relative path \
under /evidence, or omit it to let the parser discover matching files.
- **Authentication triage.** Every parsed message carries `auth_results` with \
`spf`, `dkim`, `dmarc`. SPF=fail, DKIM=fail, or DMARC=fail/none strongly \
suggests spoofing or an unauthenticated source. DMARC=none means the domain \
doesn't publish an enforcement policy — note it as a domain-weakness finding.
- **Display-name spoofing.** Compare the From display name against the From \
envelope address. A trusted name ("CEO Name", "IT Support", "Payroll") paired \
with an external or lookalike domain (ceo-name@company-accounts.com) is a \
classic BEC / spearphishing tell. Also check Reply-To vs From for mismatches.
- **Attachment triage.** Flag any attachment with a dangerous extension: \
.exe, .dll, .js, .jse, .vbs, .vbe, .wsf, .wsh, .ps1, .hta, .scr, .lnk, \
.docm, .xlsm, .pptm, .jar. Macro-enabled Office docs are the most common \
spearphishing-attachment vector.
- **BEC body-language signals.** Look for urgency ("urgent", "ASAP", "today"), \
secrecy ("wire transfer", "don't call", "confidential"), invoice / payment / \
gift-card language, and requests to change bank details or billing \
information. These often appear with a reply-to address on a different domain.
- **Lookalike domains.** Compare sender domains against the legitimate \
organization domain and flag homoglyph / plural / country-TLD variants \
(company-support.com, c0mpany.com, company-invoice.net).
- **Teams / Slack caches.** When format is teams_db or slack_cache, the rows \
are heuristic candidate indicators (emails, URLs, message fragments). Look \
for exfiltration (many outbound shares, sensitive keywords), social \
engineering, and credential-phishing links.
- **ATT&CK mapping.** Use the mitre_attack tool: T1566 Phishing, T1566.001 \
Spearphishing Attachment, T1566.002 Spearphishing Link, T1534 Internal \
Spearphishing (if the sender is an already-compromised internal mailbox), \
T1078 Valid Accounts (account takeover). Cite the technique ID in the report.

## Tool-use rules
- Always pass evidence_subpath as a relative path under /evidence.
- Parse one format per call; pick the next format based on what you found.
- Don't call the same (format, evidence_subpath) twice with identical args.
- For every notable finding, map it with mitre_attack (op=lookup) and cite \
the technique ID in your report.
- Stop and write the report when you have covered the artifact types or hit \
the iteration cap.
"""


class EmailBecGoal(Goal):
    id = "G09"
    cluster = "Email"
    label = "Email / BEC / phishing"
    description = (
        "Investigate email compromises: BEC, phishing, and account takeover. "
        "Parses PST/OST/MBOX/EML, checks SPF/DKIM/DMARC authentication, "
        "extracts attachments and URLs, and identifies sender impersonation."
    )
    input_artifacts = ["B9"]
    tools = ["C11a", "C12", "A2"]
    icon = "mail-warning"

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
                    EmailParseTool(),
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
            f"Email / BEC / phishing investigation complete. Evidence: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _triage(self, root: str) -> str:
        import os
        counts = {
            "eml": 0, "mbox": 0, "msg": 0, "pst": 0, "ost": 0,
            "teams_leveldb": 0, "slack_leveldb": 0,
        }
        for dp, dns, fns in os.walk(root):
            low_dir = dp.lower()
            # Teams stores its cache under IndexedDB/*indexeddb.leveldb dirs;
            # Slack under IndexedDB / Local Storage. Detect by dir-name hint.
            if "indexeddb" in low_dir and dp.lower().endswith(".leveldb"):
                counts["teams_leveldb"] += 1
            for fn in fns:
                fl = fn.lower()
                if fl.endswith(".eml"): counts["eml"] += 1
                elif fl.endswith(".mbox"): counts["mbox"] += 1
                elif fl.endswith(".msg"): counts["msg"] += 1
                elif fl.endswith(".pst"): counts["pst"] += 1
                elif fl.endswith(".ost"): counts["ost"] += 1
                elif fl.endswith(".ldb") or fl.endswith(".log"):
                    # coarse LevelDB file count; bucket by a path hint if present
                    if "slack" in low_dir:
                        counts["slack_leveldb"] += 1
                    elif "teams" in low_dir:
                        counts["teams_leveldb"] += 1
        parts = [f"{v} {k}" for k, v in counts.items() if v]
        return ", ".join(parts) if parts else "no recognized email artifacts"

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Evidence triage complete. Found: {triage}.\n"
            f"Begin your email / BEC / phishing investigation. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## Email / BEC / phishing investigation (deterministic triage)\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (mail-store parsing, SPF/DKIM/DMARC authentication "
            "triage, attachment and URL extraction, sender-impersonation "
            "detection, ATT&CK mapping).\n\n"
            "Once configured, re-run this goal for a complete email-compromise "
            "report."
        )


goal = EmailBecGoal()
