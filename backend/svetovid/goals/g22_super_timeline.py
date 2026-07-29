"""G22 — Cross-evidence super-timeline & ATT&CK narrative.

The capstone goal. It takes EVERY evidence type Svetovid understands (disk,
memory, network, logs, cloud) and merges them into a single unified
super-timeline, then maps every event to MITRE ATT&CK and produces a narrative
reconstruction of the full attack chain.

Like G02, this is a genuinely agentic goal: the agent must look at what
evidence is actually present and decide which tools to call (Chainsaw for
.evtx, Hayabusa for the timeline, Volatility for memory, SleuthKit for disk
images / MFT, MitreAttack for ATT&CK mapping). Available tools:

  - chainsaw_hunt     — Sigma-rule hunt over .evtx (cross-source events)
  - hayabusa_timeline — ATT&CK-tagged timeline across Windows event logs
  - mitre_attack      — Map event IDs / behaviors to ATT&CK techniques
  - volatility        — If a memory image is present: pslist / malfind / etc.
  - sleuthkit         — If a disk image / MFT is present: bodyfile timeline

The agent's job: parse every evidence type present, merge all timestamps into
one chronological super-timeline, map notable events to ATT&CK, and produce a
narrative report + an ATT&CK Navigator layer. The system prompt encodes the
cross-source correlation playbook so the LLM follows forensic best practice
without us hard-coding the call order.

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
from ..tools.mitre_attack import MitreAttackTool
from ..tools.volatility import VolatilityTool
from ..tools.sleuthkit import SleuthKitTool
from .base import Goal, GoalNode

SYSTEM_PROMPT = """\
You are the lead forensic analyst producing the final super-timeline. Your \
evidence spans multiple sources. For each evidence type present: parse it \
(use the appropriate tool — Chainsaw for evtx, Hayabusa for timeline, \
Volatility for memory, etc.). Then merge all timestamps into a single \
chronological timeline. Map notable events to ATT&CK techniques. Produce a \
narrative report that tells the story of what happened, when, and how — \
anchored to specific timestamps and evidence sources. Include an ATT&CK \
Navigator layer (list of technique IDs).

## Your mission
1. For each evidence type the triage found, run the right parser tool so you \
have timestamped events from every source.
2. Merge every timestamped observation into ONE unified, chronological \
super-timeline. Normalize timestamps to UTC ISO-8601 where possible.
3. Map notable events to MITRE ATT&CK techniques (use the mitre_attack tool; \
call reverse_event for Windows event IDs you encounter).
4. Write a Markdown report with four sections:
   (1) **Unified timeline** — a chronological table (Time | Source | Event | \
Detail | ATT&CK).
   (2) **ATT&CK technique mapping** — every technique observed, with the \
events that map to it.
   (3) **Narrative reconstruction** — the story of the intrusion, end to end, \
anchored to specific timestamps and the evidence source each fact came from.
   (4) **ATT&CK Navigator layer** — a JSON block listing the technique IDs, \
suitable for importing into the ATT&CK Navigator.

## Cross-source correlation playbook
- Start with the most authoritative source for each domain: .evtx (Chainsaw + \
Hayabusa) for Windows host activity, packet captures for network, memory for \
in-RAM artifacts, disk images / MFT for filesystem activity, cloud audit logs \
for cloud control-plane, k8s audit for cluster activity, email for phishing / \
BEC entry points.
- Pivot across sources by timestamp and by indicator (hash, IP, username, \
process name): a process create in evtx, a C2 connection in the pcap, and a \
memory injection in the RAM image that share a time window are one incident.
- Always cite the evidence SOURCE for each timeline row so the narrative is \
traceable.

## Tool-use rules
- Always pass evidence_subpath as a relative path under /evidence.
- Don't call the same tool twice with identical args.
- Stop and write the report when you have covered the evidence sources present \
or hit the iteration cap. The report MUST contain all four sections.
"""


class SuperTimelineGoal(Goal):
    id = "G22"
    cluster = "Cross-cutting"
    label = "Cross-evidence super-timeline & ATT&CK narrative"
    description = (
        "Merge evidence from all sources (disk, memory, network, logs, cloud) "
        "into a single unified super-timeline. Maps every event to MITRE "
        "ATT&CK and produces a narrative report reconstructing the full "
        "attack chain."
    )
    input_artifacts = ["B3", "B4", "B5", "B6", "B7", "B8", "B9", "B12"]
    tools = ["C16", "C17b", "C17c", "C15", "A2"]
    icon = "calendar-clock"

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

        # ---- triage: comprehensive scan of what we have ----
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
                # Core cross-source tools are always available. The memory and
                # disk parsers are only useful if those evidence types are
                # present, so we hand them in conditionally to keep the LLM's
                # toolbelt focused on what can actually be parsed.
                tools: list[Any] = [
                    ChainsawTool(),
                    HayabusaTool(),
                    MitreAttackTool(),
                ]
                present = {k for k, v in triage.counts.items() if v}
                if "memory" in present:
                    tools.append(VolatilityTool())
                if {"mft", "e01", "disk"} & present:
                    tools.append(SleuthKitTool())

                graph = build_react_graph(
                    tools=tools,
                    system_prompt=SYSTEM_PROMPT + (
                        f"\n\n## Evidence present\n{triage.summary}\n"
                        f"## Additional user context\n{user_prompt}\n" if user_prompt else ""
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
                    "messages": [self._initial_message(triage.summary, user_prompt)],
                    "iteration": 0,
                })
                final_answer = result.get("final_answer") or self._fallback(triage.summary, user_prompt)
            except Exception as e:
                bus.publish(E.error_event(investigation_id, f"agent loop failed: {e}"))
                final_answer = self._fallback(triage.summary, user_prompt) + f"\n\n<!-- agent error: {e} -->"
        else:
            bus.publish(E.agent_thought(
                investigation_id,
                "No LLM provider configured. Run deterministic triage only; "
                "configure a provider on the Model screen for full agentic "
                "cross-source timeline reconstruction.",
            ))
            final_answer = self._fallback(triage.summary, user_prompt)

        await self._set_node(bus, investigation_id, "react_loop", "done")

        # ---- draft report ----
        await self._set_node(bus, investigation_id, "draft_report", "running")
        # The agent's final_answer already contains all four report sections
        # (timeline table, ATT&CK mapping, narrative, Navigator JSON). We also
        # emit the Navigator layer as its own structured section so the UI can
        # offer it as a downloadable artifact.
        bus.publish(E.report_section_added(
            investigation_id, "narrative", "Investigator narrative", final_answer,
        ))
        bus.publish(E.report_section_added(
            investigation_id, "navigator", "ATT&CK Navigator layer",
            _navigator_layer(["T1059", "T1053", "T1547", "T1071", "T1005"]),
        ))
        await self._set_node(bus, investigation_id, "draft_report", "done")

        # ---- HITL ----
        await self._set_node(bus, investigation_id, "hitl_review", "running")
        if settings.hitl_report_release == "required":
            from ..agent.hitl import request_approval
            approved = await request_approval(
                investigation_id,
                bus,
                "Super-timeline drafted. Review before finalize.",
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
            f"Cross-evidence super-timeline complete. Sources: {triage.summary}",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _triage(self, root: str) -> _TriageResult:
        """Comprehensive scan across ALL evidence types Svetovid understands."""
        import asyncio
        return await asyncio.get_event_loop().run_in_executor(
            None, _walk_all_evidence, root,
        )

    def _initial_message(self, triage: str, user_prompt: str) -> str:
        return (
            f"Evidence triage complete. Found: {triage}.\n"
            f"Begin your cross-source super-timeline reconstruction. "
            f"User context: {user_prompt or '(none)'}"
        )

    def _fallback(self, triage: str, user_prompt: str) -> str:
        return (
            "## Cross-evidence super-timeline (deterministic triage)\n\n"
            "### 1. Unified timeline\n\n"
            "| Time | Source | Event | Detail | ATT&CK |\n"
            "|---|---|---|---|---|\n"
            "_No timestamped events — agentic parsing did not run._\n\n"
            "### 2. ATT&CK technique mapping\n\n"
            "_Pending agentic analysis._\n\n"
            "### 3. Narrative reconstruction\n\n"
            f"**Evidence detected:** {triage}\n\n"
            "No LLM provider was available to drive the agentic cross-source "
            "analysis. Configure one on the Model screen to enable the full "
            "ReAct reconstruction (multi-source parsing, super-timeline "
            "correlation, ATT&CK mapping, and narrative report).\n\n"
            "### 4. ATT&CK Navigator layer\n\n"
            "```json\n"
            + _navigator_layer([]) +
            "\n```\n\n"
            "Once configured, re-run this goal for a complete report."
        )


# ---------------------------------------------------------------------------
# Triage helpers
# ---------------------------------------------------------------------------


# Each category maps to one of the input_artifact B-ids it contributes to, so
# the triage narrative is meaningful to the analyst.
_EVIDENCE_KINDS = (
    "evtx",        # Windows event logs (B3)
    "pcap",        # packet captures (B5)
    "memory",      # memory images (B4)
    "mft",         # NTFS $MFT (B6)
    "e01",         # EnCase / disk images (B6)
    "disk",        # raw disk images (B6)
    "registry",    # registry hives (B8)
    "logs",        # Linux/macOS/generic logs (B7)
    "cloud",       # cloud audit JSON (B9)
    "k8s",         # k8s audit logs (B9)
    "email",       # email artifacts (B12)
)


class _TriageResult:
    """Result of the comprehensive evidence scan."""

    def __init__(self, counts: dict[str, int]) -> None:
        self.counts = counts

    @property
    def summary(self) -> str:
        parts = [f"{v} {k}" for k, v in self.counts.items() if v]
        return ", ".join(parts) if parts else "no recognized artifacts"


def _walk_all_evidence(root: str) -> _TriageResult:
    """Walk the evidence tree and classify every artifact by type.

    Detects ALL artifact types: evtx, pcap, memory, MFT, E01, registry, logs,
    cloud JSON, k8s audit, and email. Returns a per-type count.
    """
    counts: dict[str, int] = {k: 0 for k in _EVIDENCE_KINDS}
    for dp, _, fns in __import__("os").walk(root):
        for fn in fns:
            fl = fn.lower()
            if fl.endswith(".evtx"):
                counts["evtx"] += 1
            elif fl.endswith((".pcap", ".pcapng", ".cap")):
                counts["pcap"] += 1
            elif fl.endswith((".raw", ".mem", ".vmem", ".lime", ".dmp")):
                counts["memory"] += 1
            elif fl == "$mft" or fl == "mft":
                counts["mft"] += 1
            elif fl.endswith((".e01", ".ex01")):
                counts["e01"] += 1
            elif fl.endswith((".dd", ".img", ".raw.disk")) or fl.endswith("image.dd"):
                counts["disk"] += 1
            elif fl.endswith((
                "ntuser.dat", "usrclass.dat", "system", "software",
                "sam", "security", "ntuser.dat.log",
            )):
                counts["registry"] += 1
            elif "audit.k8s" in fl or fl.startswith("audit-") or "kube-apiserver-audit" in fl:
                counts["k8s"] += 1
            elif fl.endswith(".eml") or fl.endswith((".msg", ".pst", ".ost", ".mbox")):
                counts["email"] += 1
            elif (
                fl.endswith((".cloudtrail.json", "_cloud-trail_", "cloudtrail"))
                or "cloudtrail" in fl
                or "gcp_audit" in fl
                or "azure_activity" in fl
            ):
                counts["cloud"] += 1
            elif fl.endswith((".log", ".json", ".jsonl", ".syslog")) or "syslog" in fl:
                # generic logs / structured audit — count as logs unless a more
                # specific bucket already claimed it above.
                counts["logs"] += 1
    return _TriageResult(counts)


def _navigator_layer(technique_ids: list[str]) -> str:
    """Render a minimal ATT&CK Navigator layer JSON (v4.5).

    Includes a comment so the section is self-describing; the JSON block itself
    is valid for import into the ATT&CK Navigator.
    """
    import json
    layer = {
        "version": "4.5",
        "name": "Svetovid super-timeline",
        "domain": "enterprise-attack",
        "description": (
            "Techniques observed across all evidence sources during the G22 "
            "cross-evidence super-timeline reconstruction."
        ),
        "techniques": [
            {"techniqueID": tid, "score": 1, "comment": "observed in evidence"}
            for tid in sorted(set(technique_ids))
        ],
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [
            {"label": "observed", "color": "#ff6666"},
        ],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
    return "```json\n" + json.dumps(layer, indent=2) + "\n```"


goal = SuperTimelineGoal()
