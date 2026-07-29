"""Shared LangGraph state for every investigation.

``InvestigationState`` is the TypedDict that flows through every goal's graph
(per D20). Goals add their own fields via ``GoalState`` subclasses if needed,
but the common spine stays the same: evidence references, the agent's running
notes, tool outputs, and the assembled report. All fields are JSON-serializable
because the state snapshots into the case DB.
"""

from __future__ import annotations

from typing import Any, TypedDict


class EvidenceRef(TypedDict):
    """A pointer to one artifact discovered by the scanner."""

    artifact_id: str            # B-family id from research, e.g. "B3", "B8"
    family: str                 # human label, e.g. "Windows Event Logs"
    path: str                   # absolute path to the file/dir
    kind: str                   # detector name, e.g. "evtx", "pcap", "memory"
    size_bytes: int
    extra: dict[str, Any]       # detector-specific metadata (event count, etc.)


class ToolResult(TypedDict):
    """One completed tool call's output, kept in state for the LLM to cite."""

    call_id: str
    tool: str
    args: dict[str, Any]
    exit_code: int
    duration_s: float
    output_hash: str | None
    output_path: str | None     # sandbox-writable path the tool wrote to
    summary: str                # short natural-language summary the LLM sees
    data: Any                   # parsed structured payload (JSON-decodable)


class ReportSection(TypedDict):
    """Incremental report chunk streamed to the LiveReport pane."""

    section_id: str
    title: str
    markdown: str
    order: int


class TimelineEntry(TypedDict):
    """One row of the unified timeline (G22 super-timeline format)."""

    ts: str                     # ISO8601 UTC
    source: str                 # tool / artifact it came from
    actor: str | None           # user / host / process
    event: str                  # one-line description
    mitre_tactic: str | None    # TAxxxx
    mitre_technique: str | None # Txxxx
    raw: dict[str, Any]         # original record for drill-down


class IOC(TypedDict):
    """An indicator extracted during investigation."""

    type: str                   # hash | ip | domain | url | email | registry | file
    value: str
    context: str                # where / why it's suspicious
    confidence: str             # high | medium | low
    mitre_technique: str | None


class InvestigationState(TypedDict, total=False):
    """LangGraph state shared across all nodes of an investigation."""

    # --- identity ---
    case_id: str
    investigation_id: str
    goal_id: str

    # --- inputs ---
    evidence_path: str                  # the folder the user picked
    evidence: list[EvidenceRef]         # scanner output
    user_prompt: str                    # free-text goal refinement from the UI

    # --- agent working memory ---
    messages: list[dict[str, Any]]      # LangChain-style chat messages
    scratchpad: list[str]               # agent's own running notes (thoughts)
    tool_results: list[ToolResult]      # accumulated tool outputs

    # --- findings (assembled incrementally, streamed via events) ---
    timeline: list[TimelineEntry]
    iocs: list[IOC]
    report_sections: list[ReportSection]

    # --- governance ---
    hitl_pending: dict[str, Any] | None # in-flight HITL request, blocks graph
    audit_records: list[dict[str, Any]]

    # --- control ---
    error: str | None
    iterations: int
