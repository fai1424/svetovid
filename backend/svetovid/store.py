"""Case database — persistent storage for investigations, events, and tool calls.

Uses aiosqlite (already a declared dependency). The DB lives at
``~/.svetovid/svetovid.db``. On first access the schema is auto-created.

This replaces the in-memory EventBus as the source of truth — the EventBus
remains for real-time streaming, but the DB persists everything so
investigations survive app restarts and are queryable from the Cases screen.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiosqlite

from .config import APP_DIR

DB_PATH = APP_DIR / "svetovid.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT 'Default Case',
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL DEFAULT 'default',
    goal_id TEXT NOT NULL,
    evidence_path TEXT NOT NULL,
    user_prompt TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'running',
    started_at TEXT NOT NULL,
    ended_at TEXT,
    report_markdown TEXT DEFAULT '',
    error TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE TABLE IF NOT EXISTS tool_calls (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    args_json TEXT,
    exit_code INTEGER,
    duration_s REAL,
    output_hash TEXT,
    ts TEXT NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT,
    type TEXT NOT NULL,
    ts TEXT NOT NULL,
    node TEXT,
    data_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_inv ON events(investigation_id);
CREATE INDEX IF NOT EXISTS idx_toolcalls_inv ON tool_calls(investigation_id);

CREATE TABLE IF NOT EXISTS evidence_items (
    id TEXT PRIMARY KEY,
    case_id TEXT,
    path TEXT,
    sha256 TEXT,
    md5 TEXT,
    size_bytes INTEGER,
    artifact_id TEXT,
    family TEXT,
    collected_at TEXT,
    collector TEXT
);

CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence_items(case_id);

CREATE TABLE IF NOT EXISTS iocs (
    id TEXT PRIMARY KEY,
    investigation_id TEXT,
    ioc_type TEXT,
    value TEXT,
    context TEXT DEFAULT '',
    confidence REAL DEFAULT 0.0,
    mitre_technique TEXT,
    ts TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_iocs_inv ON iocs(investigation_id);
"""


class CaseDB:
    """Async wrapper around the SQLite case database."""

    def __init__(self, path: Path = DB_PATH) -> None:
        self._path = path
        self._db: aiosqlite.Connection | None = None

    async def init(self) -> None:
        """Open the connection and create the schema if needed."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._path))
        await self._db.executescript(SCHEMA)
        await self._db.commit()
        # Ensure a default case exists
        await self._db.execute(
            "INSERT OR IGNORE INTO cases (id, name, created_at, status) VALUES (?, ?, ?, ?)",
            ("default", "Default Case", _now(), "active"),
        )
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    # ---- investigations ----

    async def create_investigation(
        self, inv_id: str, case_id: str, goal_id: str,
        evidence_path: str, user_prompt: str = "",
    ) -> None:
        await self._db.execute(
            "INSERT INTO investigations (id, case_id, goal_id, evidence_path, "
            "user_prompt, status, started_at) VALUES (?, ?, ?, ?, ?, 'running', ?)",
            (inv_id, case_id, goal_id, evidence_path, user_prompt, _now()),
        )
        await self._db.commit()

    async def finish_investigation(
        self, inv_id: str, status: str, error: str | None = None,
    ) -> None:
        await self._db.execute(
            "UPDATE investigations SET status = ?, ended_at = ?, error = ? WHERE id = ?",
            (status, _now(), error, inv_id),
        )
        await self._db.commit()

    async def update_report(self, inv_id: str, markdown: str) -> None:
        await self._db.execute(
            "UPDATE investigations SET report_markdown = ? WHERE id = ?",
            (markdown, inv_id),
        )
        await self._db.commit()

    async def list_investigations(self) -> list[dict[str, Any]]:
        cursor = await self._db.execute(
            "SELECT id, case_id, goal_id, status, started_at, ended_at "
            "FROM investigations ORDER BY started_at DESC LIMIT 200"
        )
        rows = await cursor.fetchall()
        return [
            {"id": r[0], "case_id": r[1], "goal_id": r[2], "status": r[3],
             "started_at": r[4], "ended_at": r[5]}
            for r in rows
        ]

    async def get_investigation(self, inv_id: str) -> dict[str, Any] | None:
        cursor = await self._db.execute(
            "SELECT id, case_id, goal_id, evidence_path, user_prompt, status, "
            "started_at, ended_at, report_markdown, error "
            "FROM investigations WHERE id = ?",
            (inv_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "id": row[0], "case_id": row[1], "goal_id": row[2],
            "evidence_path": row[3], "user_prompt": row[4], "status": row[5],
            "started_at": row[6], "ended_at": row[7],
            "report_markdown": row[8], "error": row[9],
        }

    # ---- tool calls ----

    async def record_tool_call(
        self, call_id: str, inv_id: str, tool: str, args: dict,
        exit_code: int, duration_s: float, output_hash: str | None,
    ) -> None:
        await self._db.execute(
            "INSERT INTO tool_calls (id, investigation_id, tool, args_json, "
            "exit_code, duration_s, output_hash, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (call_id, inv_id, tool, json.dumps(args), exit_code, duration_s,
             output_hash, _now()),
        )
        await self._db.commit()

    async def list_tool_calls(self, inv_id: str) -> list[dict[str, Any]]:
        cursor = await self._db.execute(
            "SELECT tool, args_json, exit_code, duration_s, output_hash, ts "
            "FROM tool_calls WHERE investigation_id = ? ORDER BY ts",
            (inv_id,),
        )
        rows = await cursor.fetchall()
        return [
            {"tool": r[0], "args": json.loads(r[1]) if r[1] else {},
             "exit_code": r[2], "duration_s": r[3], "output_hash": r[4], "ts": r[5]}
            for r in rows
        ]

    # ---- events ----

    async def record_event(self, event: dict[str, Any]) -> None:
        await self._db.execute(
            "INSERT INTO events (investigation_id, type, ts, node, data_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (event.get("investigation_id"), event.get("type"),
             event.get("ts", _now()), event.get("node"),
             json.dumps(event.get("data", {}), default=str)),
        )
        await self._db.commit()

    async def list_events(self, inv_id: str) -> list[dict[str, Any]]:
        """Return all events for an investigation, oldest first.

        Reconstructs the wire shape of ``AgentEvent`` (``type``, ``ts``,
        ``node``, ``data``) so callers can replay them as if they were
        arriving live over the WebSocket.
        """
        cursor = await self._db.execute(
            "SELECT id, investigation_id, type, ts, node, data_json "
            "FROM events WHERE investigation_id = ? ORDER BY id",
            (inv_id,),
        )
        rows = await cursor.fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            try:
                data = json.loads(r[5]) if r[5] else {}
            except Exception:
                data = {}
            out.append({
                "id": r[0],
                "investigation_id": r[1],
                "type": r[2],
                "ts": r[3],
                "node": r[4],
                "data": data,
            })
        return out

    # ---- evidence items (governance: hashed intake + chain of custody) ----

    async def record_evidence_item(
        self,
        item_id: str,
        case_id: str,
        path: str,
        sha256: str | None,
        md5: str | None,
        size_bytes: int,
        artifact_id: str | None = None,
        family: str | None = None,
        collector: str | None = None,
    ) -> None:
        """Persist one hashed evidence item (idempotent on item_id)."""
        await self._db.execute(
            "INSERT OR REPLACE INTO evidence_items "
            "(id, case_id, path, sha256, md5, size_bytes, artifact_id, family, "
            "collected_at, collector) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (item_id, case_id, path, sha256, md5, int(size_bytes or 0),
             artifact_id, family, _now(), collector),
        )
        await self._db.commit()

    async def list_evidence_items(self, case_id: str) -> list[dict[str, Any]]:
        cursor = await self._db.execute(
            "SELECT id, case_id, path, sha256, md5, size_bytes, artifact_id, "
            "family, collected_at, collector "
            "FROM evidence_items WHERE case_id = ? ORDER BY collected_at",
            (case_id,),
        )
        rows = await cursor.fetchall()
        return [
            {"id": r[0], "case_id": r[1], "path": r[2], "sha256": r[3],
             "md5": r[4], "size_bytes": r[5], "artifact_id": r[6],
             "family": r[7], "collected_at": r[8], "collector": r[9]}
            for r in rows
        ]

    # ---- IOCs (threat intelligence) ----

    async def record_ioc(
        self,
        ioc_id: str,
        investigation_id: str,
        ioc_type: str,
        value: str,
        context: str = "",
        confidence: float = 0.0,
        mitre_technique: str | None = None,
    ) -> None:
        """Persist one IOC observation tied to an investigation."""
        await self._db.execute(
            "INSERT INTO iocs (id, investigation_id, ioc_type, value, context, "
            "confidence, mitre_technique, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ioc_id, investigation_id, ioc_type, value, context,
             float(confidence or 0.0), mitre_technique, _now()),
        )
        await self._db.commit()

    async def list_iocs(self, investigation_id: str) -> list[dict[str, Any]]:
        cursor = await self._db.execute(
            "SELECT id, investigation_id, ioc_type, value, context, confidence, "
            "mitre_technique, ts FROM iocs WHERE investigation_id = ? "
            "ORDER BY ts",
            (investigation_id,),
        )
        rows = await cursor.fetchall()
        return [
            {"id": r[0], "investigation_id": r[1], "ioc_type": r[2],
             "value": r[3], "context": r[4], "confidence": r[5],
             "mitre_technique": r[6], "ts": r[7]}
            for r in rows
        ]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_db: CaseDB | None = None


async def get_db() -> CaseDB:
    global _db
    if _db is None:
        _db = CaseDB()
        await _db.init()
    return _db


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
