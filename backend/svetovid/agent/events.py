"""Streaming event protocol: the contract between the agent and the UI.

A single WebSocket (``/ws``) carries a sequence of ``AgentEvent`` dicts
(serialized as JSON). The UI runs them through a reducer
(``frontend/src/lib/events.ts``) to update the three Investigation panes:
AgentTrace (left), StepProgress (middle), LiveReport (right).

Event shape::

    {
      "type": "<event_type>",
      "ts": "2026-07-27T17:01:23Z",     # ISO8601 UTC, server-set
      "case_id": "...",                  # investigation this event belongs to
      "investigation_id": "...",
      "node": "parse_evtx",              # LangGraph node this came from (or null)
      ...type-specific fields...
    }

Every event type is documented below. The UI MUST handle ``type == "error"``
gracefully even for unknown subtypes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Event type vocabulary
# ---------------------------------------------------------------------------

# Lifecycle / control
EVT_LIFECYCLE = Literal[
    "investigation.start",
    "investigation.end",
    "investigation.paused",
    "investigation.resumed",
    "investigation.cancelled",
]

# Scan (EvidenceSelect screen)
EVT_SCAN = Literal[
    "scan.start",
    "scan.progress",
    "scan.complete",
    "scan.error",
]

# Goal graph (GoalSelect + StepProgress)
EVT_GOAL = Literal[
    "goal.graph_loaded",   # sends the ordered node list for StepProgress
]

# Agent reasoning (AgentTrace left pane)
EVT_AGENT = Literal[
    "agent.thought",       # LLM thinking out loud
    "agent.action",        # decided to call a tool
    "agent.observation",   # tool result summarized back to the LLM
]

# Tool execution (ToolCallCard inside AgentTrace, plus tool.progress → StepProgress)
EVT_TOOL = Literal[
    "tool.start",
    "tool.stdout",
    "tool.stderr",
    "tool.progress",
    "tool.end",
    "tool.error",
]

# LangGraph node state changes (StepProgress middle pane)
EVT_NODE = Literal[
    "node.state_change",   # status: pending | running | done | failed | skipped
]

# Live report (LiveReport right pane)
EVT_REPORT = Literal[
    "report.section_added",
    "report.finding",
    "report.ioc",
    "report.timeline_entry",
]

# Governance: HITL gates + provenance ticker
EVT_GOV = Literal[
    "hitl.request",
    "hitl.response",
    "provenance.recorded",
]

# Errors (top-level)
EVT_ERR = Literal["error"]


EventType = (
    EVT_LIFECYCLE | EVT_SCAN | EVT_GOAL | EVT_AGENT | EVT_TOOL
    | EVT_NODE | EVT_REPORT | EVT_GOV | EVT_ERR
)


# ---------------------------------------------------------------------------
# Node + tool status enums
# ---------------------------------------------------------------------------

NodeStatus = Literal["pending", "running", "done", "failed", "skipped"]
ToolStatus = Literal["running", "ok", "error", "timeout", "cancelled"]

# Investigation end statuses — "done_llm_fallback" distinguishes cases where the
# agent ran but the LLM provider failed and the deterministic fallback was used
# (D8 fix: don't claim full success when the agent didn't actually reason).
InvestigationStatus = Literal["done", "failed", "cancelled", "paused", "done_llm_fallback"]


# ---------------------------------------------------------------------------
# Canonical event model
# ---------------------------------------------------------------------------


class AgentEvent(BaseModel):
    """One event on the WebSocket stream. All events share this envelope."""

    type: EventType
    ts: str = Field(default_factory=lambda: _now_iso())
    case_id: str | None = None
    investigation_id: str | None = None
    node: str | None = None                       # LangGraph node name
    data: dict[str, Any] = Field(default_factory=dict)

    def to_ws(self) -> dict[str, Any]:
        """Serialize for the WebSocket (flat dict, no extra wrappers)."""
        return self.model_dump()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Constructors — type-safe helpers so backend code never builds raw dicts.
# Each one returns an ``AgentEvent`` ready to emit.
# ---------------------------------------------------------------------------


def investigation_start(case_id: str, investigation_id: str, goal_id: str, nodes: list[str]) -> AgentEvent:
    return AgentEvent(
        type="investigation.start",
        case_id=case_id,
        investigation_id=investigation_id,
        data={"goal_id": goal_id, "nodes": nodes},
    )


def investigation_end(investigation_id: str, status: str, summary: str = "") -> AgentEvent:
    return AgentEvent(
        type="investigation.end",
        investigation_id=investigation_id,
        data={"status": status, "summary": summary},  # status: done | failed | cancelled
    )


def scan_start(path: str) -> AgentEvent:
    return AgentEvent(type="scan.start", data={"path": path})


def scan_progress(scanned: int, total: int | None, found: dict[str, int]) -> AgentEvent:
    return AgentEvent(
        type="scan.progress",
        data={"scanned": scanned, "total": total, "found": found},
    )


def scan_complete(artifacts: list[dict[str, Any]]) -> AgentEvent:
    return AgentEvent(type="scan.complete", data={"artifacts": artifacts})


def goal_graph_loaded(investigation_id: str, goal_id: str, nodes: list[dict[str, Any]]) -> AgentEvent:
    """``nodes`` is the ordered list for the StepProgress stepper:
    ``[{"id": "parse_evtx", "label": "Parse EVTX", "status": "pending"}, ...]``."""
    return AgentEvent(
        type="goal.graph_loaded",
        investigation_id=investigation_id,
        data={"goal_id": goal_id, "nodes": nodes},
    )


def agent_thought(investigation_id: str, text: str) -> AgentEvent:
    return AgentEvent(
        type="agent.thought",
        investigation_id=investigation_id,
        data={"text": text},
    )


def agent_action(investigation_id: str, tool: str, args: dict[str, Any], node: str | None = None) -> AgentEvent:
    return AgentEvent(
        type="agent.action",
        investigation_id=investigation_id,
        node=node,
        data={"tool": tool, "args": args},
    )


def agent_observation(investigation_id: str, tool: str, summary: str, node: str | None = None) -> AgentEvent:
    return AgentEvent(
        type="agent.observation",
        investigation_id=investigation_id,
        node=node,
        data={"tool": tool, "summary": summary},
    )


def tool_start(
    investigation_id: str,
    tool: str,
    args: dict[str, Any],
    sandboxed: bool,
    container_id: str | None = None,
    node: str | None = None,
) -> AgentEvent:
    return AgentEvent(
        type="tool.start",
        investigation_id=investigation_id,
        node=node,
        data={"tool": tool, "args": args, "sandboxed": sandboxed, "container_id": container_id},
    )


def tool_stdout(investigation_id: str, call_id: str, chunk: str) -> AgentEvent:
    return AgentEvent(
        type="tool.stdout",
        investigation_id=investigation_id,
        data={"call_id": call_id, "chunk": chunk},
    )


def tool_stderr(investigation_id: str, call_id: str, chunk: str) -> AgentEvent:
    return AgentEvent(
        type="tool.stderr",
        investigation_id=investigation_id,
        data={"call_id": call_id, "chunk": chunk},
    )


def tool_progress(investigation_id: str, call_id: str, pct: float, msg: str = "") -> AgentEvent:
    return AgentEvent(
        type="tool.progress",
        investigation_id=investigation_id,
        data={"call_id": call_id, "pct": max(0.0, min(1.0, pct)), "msg": msg},
    )


def tool_end(
    investigation_id: str,
    call_id: str,
    exit_code: int,
    duration_s: float,
    output_hash: str | None,
    node: str | None = None,
) -> AgentEvent:
    return AgentEvent(
        type="tool.end",
        investigation_id=investigation_id,
        node=node,
        data={
            "call_id": call_id,
            "exit_code": exit_code,
            "duration_s": round(duration_s, 3),
            "output_hash": output_hash,
            "ok": exit_code == 0,
        },
    )


def node_state_change(investigation_id: str, node: str, status: NodeStatus, detail: str = "") -> AgentEvent:
    return AgentEvent(
        type="node.state_change",
        investigation_id=investigation_id,
        node=node,
        data={"status": status, "detail": detail},
    )


def report_section_added(investigation_id: str, section_id: str, title: str, markdown: str) -> AgentEvent:
    return AgentEvent(
        type="report.section_added",
        investigation_id=investigation_id,
        data={"section_id": section_id, "title": title, "markdown": markdown},
    )


def report_timeline_entry(
    investigation_id: str,
    ts: str,
    source: str,
    event: str,
    *,
    actor: str | None = None,
    description: str | None = None,
    mitre_tactic: str | None = None,
    mitre_technique: str | None = None,
    mitre_tags: list[str] | None = None,
) -> AgentEvent:
    """One timestamped host/agent event for the Timeline tab.

    ``ts`` is the event's own wall-clock timestamp (not the publish time). The
    frontend ``TimelineView`` sorts by it. ``source`` is the producing tool or
    host (e.g. ``"chainsaw"``), ``event`` a short human-readable description
    (e.g. the matched rule name). ATT&CK context is carried in
    ``mitre_technique`` (single id) and/or ``mitre_tags`` (list, for heatmap).
    """
    tags = list(mitre_tags) if mitre_tags else []
    if mitre_technique and mitre_technique not in tags:
        tags.append(mitre_technique)
    data: dict[str, Any] = {
        "timestamp": ts,
        "ts": ts,
        "source": source,
        "event": event,
    }
    if actor is not None:
        data["actor"] = actor
    if description is not None:
        data["description"] = description
    if mitre_tactic is not None:
        data["mitre_tactic"] = mitre_tactic
    if mitre_technique is not None:
        data["mitre_technique"] = mitre_technique
    if tags:
        data["mitre_tags"] = tags
    return AgentEvent(
        type="report.timeline_entry",
        investigation_id=investigation_id,
        data=data,
    )


def report_ioc(
    investigation_id: str,
    ioc_type: str,
    value: str,
    context: str = "",
    *,
    confidence: float = 0.0,
    description: str | None = None,
    mitre_technique: str | None = None,
    mitre_tags: list[str] | None = None,
) -> AgentEvent:
    """One indicator of compromise for the IoC tab + STIX export.

    ``ioc_type`` is free-form (``hash|ip|domain|url|email|mutex|...``) and
    normalized downstream by ``governance.ioc_store``. ``value`` is the
    indicator string. Carries both ``type``/``value`` (frontend shape) and
    ``ioc_type``/``ioc`` (ioc_store shape) so every reducer sees its keys.
    """
    tags = list(mitre_tags) if mitre_tags else []
    if mitre_technique and mitre_technique not in tags:
        tags.append(mitre_technique)
    data: dict[str, Any] = {
        "type": ioc_type,
        "ioc_type": ioc_type,
        "value": value,
        "ioc": value,
        "context": context,
        "confidence": float(confidence or 0.0),
    }
    if description is not None:
        data["description"] = description
    if mitre_technique is not None:
        data["mitre_technique"] = mitre_technique
    if tags:
        data["mitre_tags"] = tags
    return AgentEvent(
        type="report.ioc",
        investigation_id=investigation_id,
        data=data,
    )


def report_finding(
    investigation_id: str,
    title: str,
    *,
    severity: str = "info",
    description: str = "",
    mitre_technique: str | None = None,
    mitre_tags: list[str] | None = None,
    evidence: list[dict[str, Any]] | None = None,
) -> AgentEvent:
    """One structured finding for the report (summary + ATT&CK context).

    Findings are the analyst-facing conclusions; goals/tools emit these to
    surface a notable result beyond a raw timeline entry or IOC.
    """
    tags = list(mitre_tags) if mitre_tags else []
    if mitre_technique and mitre_technique not in tags:
        tags.append(mitre_technique)
    data: dict[str, Any] = {
        "title": title,
        "severity": severity,
        "description": description,
    }
    if mitre_technique is not None:
        data["mitre_technique"] = mitre_technique
    if tags:
        data["mitre_tags"] = tags
    if evidence:
        data["evidence"] = evidence
    return AgentEvent(
        type="report.finding",
        investigation_id=investigation_id,
        data=data,
    )


def hitl_request(investigation_id: str, reason: str, payload: dict[str, Any]) -> AgentEvent:
    return AgentEvent(
        type="hitl.request",
        investigation_id=investigation_id,
        data={"reason": reason, "payload": payload},
    )


def hitl_response(investigation_id: str, approved: bool, detail: str = "") -> AgentEvent:
    """The human's decision on a ``hitl.request`` gate.

    ``approved=True`` clears the paused state and lets the goal finalize;
    ``approved=False`` (or a timeout) cancels the report release. ``detail``
    is the human-readable outcome ("approved" / "rejected" / "timeout after Ns").
    """
    return AgentEvent(
        type="hitl.response",
        investigation_id=investigation_id,
        data={"approved": approved, "detail": detail},
    )


def provenance_recorded(investigation_id: str, record: dict[str, Any]) -> AgentEvent:
    return AgentEvent(
        type="provenance.recorded",
        investigation_id=investigation_id,
        data={"record": record},
    )


def error_event(investigation_id: str | None, message: str, *, fatal: bool = False, recovery: str = "") -> AgentEvent:
    return AgentEvent(
        type="error",
        investigation_id=investigation_id,
        data={"message": message, "fatal": fatal, "recovery": recovery},
    )


# ---------------------------------------------------------------------------
# In-process event bus: agents publish, the WS layer subscribes per client.
# ---------------------------------------------------------------------------


class EventBus:
    """A small pub/sub for AgentEvent dicts.

    Each WebSocket client gets its own asyncio.Queue. Any code that holds a
    reference to the bus can ``publish`` an event, and every connected client
    receives it. Clients filter by ``investigation_id`` on the receive side.
    """

    def __init__(self) -> None:
        self._subscribers: list = []

    def subscribe(self):
        import asyncio
        q: "asyncio.Queue[dict[str, Any]]" = asyncio.Queue(maxsize=1000)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q) -> None:
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    def publish(self, event: "AgentEvent | dict[str, Any]") -> None:
        if isinstance(event, AgentEvent):
            event = event.to_ws()
        import asyncio
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Slow client — drop oldest to keep stream live.
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    pass
