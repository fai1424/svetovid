"""G10 — iOS mobile device forensic examination.

The mobile analog of G02/G05. An iOS device examination walks the artifacts
that tell the device's "story": knowledgeC.db (app/device usage), sms.db
(iMessage + SMS), CallHistory (calls), keychain (credentials), Photos
(camera roll + geo), health (workouts/movement), Wallet passes, the
consolidated location cache (movement), app runtime telemetry, and Safari
history. Available tools:

  - ileapp_parse  — Parse any of the iOS forensic artifacts above into
                    structured rows (sqlite3/plistlib in the svetovid/base
                    image; opens each DB read-only via file:...?mode=ro)
  - mitre_attack  — Map observed behaviors to ATT&CK techniques

The agent's job: build a usage timeline, identify suspicious app activity,
surface comms + credentials + movement, and map everything to ATT&CK, then
produce a report. The system prompt encodes the iOS IR decision tree so the
LLM follows forensic best practice (knowledgeC → sms → keychain → location →
photos → browser → ATT&CK) without us hard-coding the call order.

Falls back to a deterministic summary if no LLM provider is configured
(matching G01/G02/G05's contract).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from ..agent.react import ReactConfig, build_react_graph
from ..config import load_settings
from ..tools.ileapp_parse import IleappTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are a senior mobile-forensics analyst examining an iOS device extraction \
(full file system or iTunes backup). Your evidence is mounted read-only at \
/evidence (the agent wrappers translate that path for you automatically).

## Your mission
1. Build a device/app usage timeline and identify anomalies (knowledgeC + \
app_usage).
2. Recover communications: SMS/iMessage threads and call history. Note any \
unknown contacts, odd hours, or deleted-message gaps.
3. Harvest credentials and identify sensitive apps (keychain: general + \
internet passwords).
4. Reconstruct movement and corroborate the timeline (location cache + \
Photos geo tags + health workouts).
5. Inventory media evidence (Photos / Wallet passes) and browsing activity \
(Safari history).
6. Map every finding to MITRE ATT&CK techniques (use the mitre_attack tool). \
On iOS the relevant platform is typically Mobile (TA-series), but data-theft \
behaviors map cleanly onto Enterprise techniques too.
7. Produce a clear Markdown report with: (a) usage timeline, (b) \
communications summary, (c) credentials of interest, (d) movement timeline, \
(e) media/browsing evidence, (f) suspicious app activity, (g) ATT&CK-mapped \
findings, (h) recommended follow-up.

## Investigation strategy (iOS IR decision tree)
- Anchor the timeline FIRST with knowledgec (knowledgeC.db): it covers every \
app launch, notification, and screen-on event and lets you pivot everything \
else onto a single clock.
- Then pull comms with sms (sms.db) and call_history (CallHistory.storedata). \
Cross-check contact/handle values against the usage timeline to spot burner \
apps or MDM-installed messengers.
- Go after credentials with keychain (Keychain DBs). Accounts / internet \
passwords reveal what the user (or malware) could reach. Flag grants to \
non-Apple apps.
- Reconstruct movement with location (consolidated/ated location cache), then \
corroborate with photos (geo tags on the camera roll) and health (workout \
start/stop). The three should agree; mismatches indicate deletion or \
anti-forensics.
- Check app_usage (runtime telemetry) to confirm whether a suspicious bundle \
actually executed and for how long — it is independent of knowledgeC and a \
strong execution indicator.
- Pull browser_history (Safari History.db) for the user's web activity; pivot \
suspicious URLs back through the usage timeline.
- Inventory wallet (Wallet passes) for payment/boarding/travel evidence — \
note relevant + expiration dates and embedded locations.
- Finally, map behaviors to ATT&CK (mitre_attack): e.g. T1430 (credential \
theft from keychain), T1630 (location data), T1437.001 (application layer \
protocol: web protocols / Safari), T1613 (container/cloud), T1518.001 \
(installed apps).

## Tool-use rules
- Always pass evidence_subpath as a relative path under /evidence. You may \
point at a directory — the parser resolves the right DB by name.
- Call ileapp_parse once per artifact_type — don't repeat a type with \
identical args.
- Stop and write the report when you have covered usage, comms, credentials, \
movement, and media/browsing, or hit the iteration cap.
"""


class IosForensicsGoal(Goal):
    id = "G10"
    cluster = "Mobile"
    label = "iOS device forensics"
    description = (
        "Parse iOS extractions for messages, calls, location, app usage, "
        "photos, and keychain credentials. Builds a usage timeline and "
        "identifies suspicious app activity."
    )
    input_artifacts = ["B10a"]
    tools = ["C12a", "A2"]
    icon = "smartphone"

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
                    IleappTool(),
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
            f"iOS device forensics examination complete. Evidence: {triage}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _triage(self, root: str) -> str:
        import os
        counts: dict[str, int] = {
            "knowledgec": 0, "sms": 0, "call_history": 0, "keychain": 0,
            "photos": 0, "health": 0, "wallet": 0, "location": 0,
            "app_usage": 0, "safari_history": 0, "manifest": 0, "files": 0,
        }
        for dp, _, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                counts["files"] += 1
                if fl == "knowledgec.db":
                    counts["knowledgec"] += 1
                elif fl == "sms.db":
                    counts["sms"] += 1
                elif fl == "callhistory.storedata":
                    counts["call_history"] += 1
                elif fl.endswith(".keychain") or fl in ("keychain.db", "keychain-db"):
                    counts["keychain"] += 1
                elif fl == "photos.sqlite":
                    counts["photos"] += 1
                elif fl == "healthdb_secure.sqlite":
                    counts["health"] += 1
                elif fl == "history.db" and "safari" in dp.lower():
                    counts["safari_history"] += 1
                elif fl == "manifest.db":
                    counts["manifest"] += 1
                elif fl in ("cache_encrypteda", "consolidated.db", "locationdb"):
                    counts["location"] += 1
                elif fl in ("runtime", "apprunnegptd", "appusage.db"):
                    counts["app_usage"] += 1
            # directory-name markers for Wallet passes
            if dp.lower().endswith(("passes", "wallet")):
                counts["wallet"] += sum(1 for f in fns if f.lower().endswith(".pkpass"))
        parts = [f"{v} {k}" for k, v in counts.items() if k != "files" and v]
        if counts["files"]:
            parts.append(f"{counts['files']} files total")
        return ", ".join(parts) if parts else "no recognized iOS artifacts"

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Evidence triage complete. Found: {triage}.\n"
            f"Begin your iOS forensic examination. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## iOS device forensics (deterministic triage)\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic analysis. "
            "Configure one on the Model screen to enable the full ReAct "
            "investigation (knowledgeC usage timeline, SMS/iMessage + call "
            "history recovery, keychain credential harvest, location/movement "
            "reconstruction, Photos/Wallet/Safari evidence, ATT&CK mapping).\n\n"
            "Once configured, re-run this goal for a complete report."
        )


goal = IosForensicsGoal()
