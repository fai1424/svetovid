"""Reference telemetry collection server (standalone FastAPI app).

This is the server you deploy internally to receive data from every Svetovid
installation. It is intentionally separate from the Svetovid backend — run it
on its own host behind your own auth/ingress::

    python -m svetovid.telemetry.server            # uvicorn on :7430
    SVETOVID_ANALYTICS_DB=/data/analytics.db \\
    python -m svetovid.telemetry.server --port 8443

Endpoints:
    POST /api/v1/telemetry            accept a JSON array of records
    GET  /api/v1/analytics/summary    aggregate stats (duration / tools / goals / ratings)
    GET  /api/v1/analytics/investigations   paginated raw records

The DB is a single SQLite file (``~/.svetovid/analytics.db`` by default, or
``$SVETOVID_ANALYTICS_DB``). For a real deployment you'd swap SQLite for
Postgres and add auth/rate-limiting, but this is enough to develop and demo
the analytics surface against.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query

logger = logging.getLogger("svetovid.analytics")

DEFAULT_DB_PATH = Path.home() / ".svetovid" / "analytics.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    event TEXT NOT NULL,
    ts TEXT NOT NULL,
    received_at TEXT NOT NULL,
    props_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_event ON records(event);
CREATE INDEX IF NOT EXISTS idx_records_client ON records(client_id);
CREATE INDEX IF NOT EXISTS idx_records_ts ON records(ts);
"""


def _db_path() -> Path:
    return Path(os.environ.get("SVETOVID_ANALYTICS_DB", str(DEFAULT_DB_PATH)))


def _connect() -> sqlite3.Connection:
    p = _db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def create_app() -> FastAPI:
    """Build the FastAPI app with its own DB connection (for TestClient use)."""
    app = FastAPI(title="Svetovid telemetry collection server", version="1.0")
    app.state.db = _connect()

    # ---------- POST /api/v1/telemetry ----------
    @app.post("/api/v1/telemetry")
    def ingest(payload: list[Any]) -> dict[str, Any]:
        """Accept a JSON array of telemetry records.

        Each record is ``{"client_id", "event", "ts", "props"}``. Unknown /
        malformed rows are skipped (counted in ``rejected``) so one bad client
        can't poison the batch — the endpoint validates per-row rather than
        rejecting the whole batch.
        """
        if not isinstance(payload, list):
            raise HTTPException(400, "expected a JSON array")
        conn: sqlite3.Connection = app.state.db
        accepted = 0
        rejected = 0
        now = _now_iso()
        for rec in payload:
            if not isinstance(rec, dict):
                rejected += 1
                continue
            try:
                client_id = str(rec["client_id"])
                event = str(rec["event"])
                ts = str(rec.get("ts") or now)
                props = rec.get("props") or {}
                conn.execute(
                    "INSERT INTO records (client_id, event, ts, received_at, props_json) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (client_id, event, ts, now, json.dumps(props, default=str)),
                )
                accepted += 1
            except Exception:
                rejected += 1
                continue
        conn.commit()
        return {"accepted": accepted, "rejected": rejected}

    # ---------- GET /api/v1/analytics/summary ----------
    @app.get("/api/v1/analytics/summary")
    def summary() -> dict[str, Any]:
        """Aggregate stats across all received records.

        Returns:
          - ``avg_duration_by_goal``: {goal_id: avg_seconds}
          - ``tool_success_rate``: {tool: {success, total, rate}}
          - ``goal_popularity``: {goal_id: count}  (investigations run)
          - ``avg_user_rating``: mean of all 1-5 ratings
          - ``totals``: {investigations, tool_calls, ratings, errors}
        """
        conn: sqlite3.Connection = app.state.db

        # investigations: join investigation.complete records with their props
        rows = conn.execute(
            "SELECT props_json FROM records WHERE event = 'investigation.complete'"
        ).fetchall()
        durations: dict[str, list[float]] = defaultdict(list)
        popularity: dict[str, int] = defaultdict(int)
        tool_totals: dict[str, dict[str, int]] = defaultdict(
            lambda: {"success": 0, "total": 0}
        )
        errors_total = 0
        iterations: list[int] = []

        for r in rows:
            try:
                props = json.loads(r["props_json"])
            except Exception:
                continue
            goal = props.get("goal_id") or "unknown"
            popularity[goal] += 1
            dur = props.get("duration_s")
            if isinstance(dur, (int, float)):
                durations[goal].append(float(dur))
            it = props.get("iteration_count")
            if isinstance(it, int):
                iterations.append(it)
            err = props.get("error_count")
            if isinstance(err, int):
                errors_total += err
            for call in props.get("tool_calls") or []:
                if not isinstance(call, dict):
                    continue
                tool = call.get("tool") or "unknown"
                tool_totals[tool]["total"] += 1
                exit_code = call.get("exit_code")
                if exit_code == 0:
                    tool_totals[tool]["success"] += 1

        avg_duration_by_goal = {
            g: round(sum(v) / len(v), 3) for g, v in durations.items() if v
        }
        tool_success_rate = {
            t: {
                "success": d["success"],
                "total": d["total"],
                "rate": round(d["success"] / d["total"], 4) if d["total"] else 0.0,
            }
            for t, d in tool_totals.items()
        }

        # ratings
        rating_rows = conn.execute(
            "SELECT props_json FROM records WHERE event = 'user.rating'"
        ).fetchall()
        ratings: list[int] = []
        for r in rating_rows:
            try:
                props = json.loads(r["props_json"])
                rating = props.get("rating")
                if isinstance(rating, int) and 1 <= rating <= 5:
                    ratings.append(rating)
            except Exception:
                continue

        avg_rating = round(sum(ratings) / len(ratings), 3) if ratings else None

        return {
            "avg_duration_by_goal": avg_duration_by_goal,
            "tool_success_rate": tool_success_rate,
            "goal_popularity": dict(popularity),
            "avg_user_rating": avg_rating,
            "rating_count": len(ratings),
            "totals": {
                "investigations": len(rows),
                "tool_calls": sum(d["total"] for d in tool_totals.values()),
                "ratings": len(ratings),
                "errors": errors_total,
            },
            "avg_iterations": (
                round(sum(iterations) / len(iterations), 3) if iterations else None
            ),
        }

    # ---------- GET /api/v1/analytics/investigations ----------
    @app.get("/api/v1/analytics/investigations")
    def investigations(
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        client_id: str | None = None,
    ) -> dict[str, Any]:
        """Paginated list of raw records (newest first)."""
        conn: sqlite3.Connection = app.state.db
        params: list[Any] = []
        where = ""
        if client_id:
            where = "WHERE client_id = ?"
            params.append(client_id)
        params.extend([limit, offset])
        cur = conn.execute(
            f"SELECT id, client_id, event, ts, received_at, props_json "
            f"FROM records {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params,
        )
        rows = cur.fetchall()
        total_cur = conn.execute(
            f"SELECT COUNT(*) FROM records {where}",
            params[:1] if client_id else [],
        )
        total = int(total_cur.fetchone()[0])
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "records": [
                {
                    "id": r["id"],
                    "client_id": r["client_id"],
                    "event": r["event"],
                    "ts": r["ts"],
                    "received_at": r["received_at"],
                    "props": json.loads(r["props_json"]),
                }
                for r in rows
            ],
        }

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "db": str(_db_path())}

    return app


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Module-level app so ``uvicorn svetovid.telemetry.server:app`` works.
app = create_app()


def run() -> None:
    parser = argparse.ArgumentParser(description="Svetovid telemetry collection server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7430)
    args = parser.parse_args()
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    run()
