"""EventBus subscriber that accumulates per-investigation metrics.

The ``TelemetryCollector`` subscribes to the in-process ``EventBus`` and
watches every streamed event. It is **privacy-first**: it only ever extracts
aggregate operational counters and never touches evidence content, file
paths, command arguments, prompts, or API keys (see ``_PII_FIELDS`` below for
the allowlist it *does* read, everything else is ignored).

When an investigation ends it serializes the accumulated metrics as one
``investigation.complete`` record and appends it to the local SQLite queue
(``~/.svetovid/telemetry_queue.db``). The queue is drained by
``uploader.Uploader`` on a timer; the collector never talks to the network.

The SQLite queue is intentionally a plain ``sqlite3`` file (not aiosqlite):
writes happen at most once per investigation and the uploader reads from the
same thread/loop, so a single connection guarded by a lock is plenty.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..agent.events import EventBus
from ..config import APP_DIR, load_settings

logger = logging.getLogger("svetovid.telemetry")

# Local on-disk queue. The uploader drains this; a failed upload leaves rows
# here for the next cycle.
QUEUE_DB_PATH: Path = APP_DIR / "telemetry_queue.db"

# Lock guarding the single shared sqlite connection (same-thread writes from
# the event loop, but the lock makes concurrent API-endpoint writes safe too).
_QUEUE_LOCK = threading.Lock()
_queue_conn: sqlite3.Connection | None = None


QUEUE_SCHEMA = """
CREATE TABLE IF NOT EXISTS queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    event TEXT NOT NULL,
    ts TEXT NOT NULL,
    props_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queue_ts ON queue(ts);
"""


def _get_queue_conn() -> sqlite3.Connection:
    """Return the singleton sqlite connection, initializing the schema once."""
    global _queue_conn
    if _queue_conn is None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(QUEUE_DB_PATH), check_same_thread=False)
        conn.executescript(QUEUE_SCHEMA)
        conn.commit()
        _queue_conn = conn
    return _queue_conn


def enqueue_record(client_id: str, event: str, ts: str, props: dict[str, Any]) -> int:
    """Append one telemetry record to the local queue. Returns its row id.

    Used both by the collector (investigation records) and by the
    ``POST /api/telemetry/rate`` endpoint (user rating records).
    """
    with _QUEUE_LOCK:
        conn = _get_queue_conn()
        cur = conn.execute(
            "INSERT INTO queue (client_id, event, ts, props_json) VALUES (?, ?, ?, ?)",
            (client_id, event, ts, json.dumps(props, default=str)),
        )
        conn.commit()
        return int(cur.lastrowid)


def queue_count() -> int:
    """Number of records waiting in the local queue."""
    with _QUEUE_LOCK:
        conn = _get_queue_conn()
        cur = conn.execute("SELECT COUNT(*) FROM queue")
        return int(cur.fetchone()[0])


def drain_queue(limit: int = 500) -> list[dict[str, Any]]:
    """Return up to ``limit`` queued records (oldest first) and remove them."""
    with _QUEUE_LOCK:
        conn = _get_queue_conn()
        cur = conn.execute(
            "SELECT id, client_id, event, ts, props_json FROM queue ORDER BY id ASC LIMIT ?",
            (limit,),
        )
        rows = cur.fetchall()
        if not rows:
            return []
        ids = [r[0] for r in rows]
        # delete the exact rows we read
        placeholders = ",".join("?" * len(ids))
        conn.execute(f"DELETE FROM queue WHERE id IN ({placeholders})", ids)
        conn.commit()
        return [
            {"client_id": r[1], "event": r[2], "ts": r[3], "props": json.loads(r[4])}
            for r in rows
        ]


# ---------------------------------------------------------------------------
# Per-investigation accumulator
# ---------------------------------------------------------------------------


@dataclass
class _InvState:
    """Mutable metric accumulator for one in-flight investigation."""

    investigation_id: str
    goal_id: str | None = None
    start_ts: str | None = None
    end_ts: str | None = None
    # node -> timestamp when it entered "running"
    node_running_since: dict[str, str] = field(default_factory=dict)
    # node -> seconds spent running
    node_durations: dict[str, float] = field(default_factory=dict)
    # FIFO of tool names awaiting a matching tool.end (agent loop is sequential)
    pending_tools: deque[str] = field(default_factory=deque)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    iteration_count: int = 0
    hitl_reached: bool = False
    error_count: int = 0


# Fields we deliberately extract from event.data. Everything else is treated
# as PII and discarded. This list is the auditable privacy allowlist.
_EVENT_ALLOWLIST = {
    "investigation.start": {"goal_id", "nodes"},
    "investigation.end": {"status", "summary"},
    "node.state_change": {"status"},
    "tool.start": {"tool"},
    "tool.end": {"call_id", "exit_code", "duration_s", "ok"},
    "agent.action": set(),
    "hitl.request": set(),
    "error": {"fatal"},
    "scan.complete": set(),   # artifacts are read but only counted by family
}


def _parse_ts(ts: str | None) -> datetime | None:
    """Parse an event ``ts`` (ISO8601 UTC, may end in 'Z') to an aware datetime."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _duration_s(start_ts: str | None, end_ts: str | None) -> float | None:
    a = _parse_ts(start_ts)
    b = _parse_ts(end_ts)
    if a is None or b is None:
        return None
    return round((b - a).total_seconds(), 3)


def _count_evidence_families(artifacts: list[Any]) -> dict[str, int]:
    """Aggregate artifact family counts from a scan.complete payload.

    Returns ``{family: count}``. Defensive: only counts string families and
    never copies artifact content, paths, or extra metadata.
    """
    counts: dict[str, int] = defaultdict(int)
    for art in artifacts:
        if not isinstance(art, dict):
            continue
        family = art.get("family")
        if isinstance(family, str) and family:
            counts[family] += 1
    return dict(counts)


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class TelemetryCollector:
    """Subscribes to the EventBus and accumulates per-investigation metrics.

    Lifecycle:
      collector = TelemetryCollector(bus)
      await collector.start()   # spawns the background drain loop
      ...
      await collector.stop()    # cancels the loop, releases the subscription

    Even when telemetry is disabled the collector still subscribes (cheap) but
    discards everything without writing — see ``is_enabled``.
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._queue: asyncio.Queue | None = None
        self._task: asyncio.Task | None = None
        self._state: dict[str, _InvState] = {}
        # Most recent scan results, attached to the next investigation.end.
        self._pending_evidence: dict[str, int] = {}

    # ---- public ----

    @property
    def is_enabled(self) -> bool:
        """Whether telemetry collection is on (reads ``settings.telemetry_enabled``)."""
        try:
            return bool(load_settings().telemetry_enabled)
        except Exception:
            # If settings can't be read, fail safe and disable.
            return False

    async def start(self) -> None:
        """Subscribe to the bus and launch the background drain loop."""
        if self._task is not None:
            return
        self._queue = self._bus.subscribe()
        self._task = asyncio.create_task(self._run(), name="telemetry-collector")
        logger.info("TelemetryCollector started (enabled=%s)", self.is_enabled)

    async def stop(self) -> None:
        """Cancel the drain loop and unsubscribe. Safe to call if never started."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        if self._queue is not None:
            self._bus.unsubscribe(self._queue)
            self._queue = None

    # ---- internals ----

    async def _run(self) -> None:
        """Drain the subscription queue and accumulate per-investigation state."""
        assert self._queue is not None
        try:
            while True:
                event = await self._queue.get()
                try:
                    self._handle(event)
                except Exception:
                    # Telemetry must never break the app — log and continue.
                    logger.exception("telemetry: failed to handle event %s",
                                     event.get("type") if isinstance(event, dict) else "?")
        except asyncio.CancelledError:
            return

    def _handle(self, event: dict[str, Any]) -> None:
        """Dispatch one event to the accumulator. Discards everything on disable."""
        if not self.is_enabled:
            return

        etype = event.get("type")
        if etype not in _EVENT_ALLOWLIST:
            return  # unknown / out-of-scope event — ignore

        data = event.get("data") or {}
        inv_id = event.get("investigation_id")
        ts = event.get("ts")

        # scan.complete carries evidence family counts; not tied to an inv,
        # so we stash them for the next investigation.end.
        if etype == "scan.complete":
            self._pending_evidence = _count_evidence_families(data.get("artifacts") or [])
            return

        if etype == "error":
            if inv_id and inv_id in self._state:
                self._state[inv_id].error_count += 1
            return

        if not inv_id:
            return

        state = self._state.get(inv_id)
        if etype == "investigation.start":
            state = _InvState(
                investigation_id=inv_id,
                goal_id=data.get("goal_id"),
                start_ts=ts,
            )
            self._state[inv_id] = state
            return

        if state is None:
            # Saw events before the start event (rare) — lazily create.
            state = _InvState(investigation_id=inv_id)
            self._state[inv_id] = state

        if etype == "node.state_change":
            node = event.get("node") or data.get("node")
            status = data.get("status")
            if node and status == "running":
                state.node_running_since[node] = ts
            elif node and status in ("done", "failed", "skipped"):
                started = state.node_running_since.pop(node, None)
                dur = _duration_s(started, ts)
                if dur is not None:
                    state.node_durations[node] = dur
        elif etype == "tool.start":
            tool = data.get("tool")
            if isinstance(tool, str):
                state.pending_tools.append(tool)
        elif etype == "tool.end":
            exit_code = data.get("exit_code")
            duration_s = data.get("duration_s")
            # Pair with the oldest unmatched tool.start (sequential agent loop).
            if state.pending_tools:
                tool = state.pending_tools.popleft()
            else:
                tool = None
            state.tool_calls.append({
                "tool": tool,
                "exit_code": exit_code,
                "duration_s": duration_s,
            })
        elif etype == "agent.action":
            state.iteration_count += 1
        elif etype == "hitl.request":
            state.hitl_reached = True
        elif etype == "investigation.end":
            state.end_ts = ts
            self._flush(state)
            self._state.pop(inv_id, None)

    def _flush(self, state: _InvState) -> None:
        """Serialize accumulated metrics and enqueue one investigation.complete record."""
        from .client_id import get_client_id

        provider_id = None
        model = None
        try:
            active = load_settings().active()
            if active is not None:
                provider_id = active.id
                model = active.model
        except Exception:
            pass

        props: dict[str, Any] = {
            "investigation_id": state.investigation_id,
            "goal_id": state.goal_id,
            "duration_s": _duration_s(state.start_ts, state.end_ts),
            "node_durations": state.node_durations,
            "tool_calls": state.tool_calls,
            "iteration_count": state.iteration_count,
            "provider": provider_id,
            "model": model,
            "hitl_approved": state.hitl_reached,
            "error_count": state.error_count,
            "user_rating": None,                      # filled later by the rating endpoint
            "evidence_types": dict(self._pending_evidence),
            "svetovid_version": _version(),
        }

        try:
            client_id = get_client_id()
            enqueue_record(
                client_id=client_id,
                event="investigation.complete",
                ts=state.end_ts or _now_iso(),
                props=props,
            )
        except Exception:
            logger.exception("telemetry: failed to enqueue investigation record")

    # ---- rating injection (called from the /api/telemetry/rate endpoint) ----

    def attach_rating(self, investigation_id: str, rating: int,
                      feedback: str | None = None) -> bool:
        """Enqueue a standalone rating record for a finished investigation.

        Returns True if a record was enqueued. The collection server joins
        this to the investigation.complete record by ``investigation_id``.
        """
        if not self.is_enabled:
            return False
        if not isinstance(rating, int) or not (1 <= rating <= 5):
            return False
        try:
            from .client_id import get_client_id
            enqueue_record(
                client_id=get_client_id(),
                event="user.rating",
                ts=_now_iso(),
                props={
                    "investigation_id": investigation_id,
                    "rating": rating,
                    "feedback": (feedback or "")[:1000] or None,
                },
            )
            return True
        except Exception:
            logger.exception("telemetry: failed to enqueue rating record")
            return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _version() -> str:
    try:
        from .. import __version__
        return __version__
    except Exception:
        return "unknown"
