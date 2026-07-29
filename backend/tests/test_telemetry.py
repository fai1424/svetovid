"""Tests for the telemetry system: client_id, collector, uploader, server,
and the main.py /api/telemetry/* endpoints + the settings round-trip for the
telemetry toggle.

Run with::

    cd backend && pytest -q tests/test_telemetry.py

Privacy is the headline guarantee, so several tests assert that NO PII
(file paths, args, evidence content, prompts, keys) ever makes it into a
queued or uploaded record.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys

import pytest


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    """Run every test against a throwaway ~/.svetovid + fresh telemetry module state."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]
    yield fake_home


# ---------------------------------------------------------------------------
# client_id
# ---------------------------------------------------------------------------


def test_client_id_is_stable_uuid(isolated_home):
    from svetovid.telemetry import client_id as cid_mod
    from svetovid.config import APP_DIR

    a = cid_mod.get_client_id()
    b = cid_mod.get_client_id()
    assert a == b, "client_id must be stable across calls"
    # canonical UUID v4 form
    assert len(a) == 36
    assert a[8] == "-" and a[13] == "-" and a[18] == "-"
    # persisted on disk
    assert (APP_DIR / "client_id.txt").read_text().strip() == a


def test_client_id_regenerates_on_corruption(isolated_home, monkeypatch):
    from svetovid.config import APP_DIR
    from svetovid.telemetry import client_id as cid_mod

    # write garbage where the id should be
    cid_mod.CLIENT_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
    cid_mod.CLIENT_ID_FILE.write_text("not-a-uuid\n")
    new = cid_mod.get_client_id()
    assert new != "not-a-uuid"
    # now valid + persisted
    assert cid_mod.get_client_id() == new


# ---------------------------------------------------------------------------
# collector queue helpers
# ---------------------------------------------------------------------------


def test_queue_enqueue_drain_and_count(isolated_home):
    from svetovid.telemetry import collector

    assert collector.queue_count() == 0
    collector.enqueue_record("cid", "investigation.complete", "2026-07-27T00:00:00Z",
                             {"goal_id": "G01", "duration_s": 12.3})
    collector.enqueue_record("cid", "user.rating", "2026-07-27T00:00:01Z",
                             {"rating": 4})
    assert collector.queue_count() == 2

    drained = collector.drain_queue(limit=10)
    assert len(drained) == 2
    assert drained[0]["event"] == "investigation.complete"
    assert drained[0]["props"]["goal_id"] == "G01"
    assert drained[1]["props"]["rating"] == 4
    # draining empties the queue
    assert collector.queue_count() == 0
    assert collector.drain_queue() == []


def test_queue_drain_respects_limit(isolated_home):
    from svetovid.telemetry import collector

    for i in range(5):
        collector.enqueue_record("cid", "e", f"ts{i}", {"i": i})
    first = collector.drain_queue(limit=2)
    assert [r["props"]["i"] for r in first] == [0, 1]
    assert collector.queue_count() == 3


# ---------------------------------------------------------------------------
# TelemetryCollector event accumulation
# ---------------------------------------------------------------------------


def _iso(base: str, add_seconds: float = 0) -> str:
    from datetime import datetime, timedelta, timezone
    d = datetime.fromisoformat(base.replace("Z", "+00:00"))
    d = d + timedelta(seconds=add_seconds)
    return d.isoformat(timespec="milliseconds").replace("+00:00", "Z")


async def _publish_investigation(bus, inv_id: str = "inv_test"):
    """Publish a realistic event sequence to the bus and return the start ts."""
    from svetovid.agent import events as E

    t0 = "2026-07-27T12:00:00.000Z"
    bus.publish(E.investigation_start("case1", inv_id, "G01", ["n1", "n2"]))
    bus.publish(E.node_state_change(inv_id, "n1", "running"))
    bus.publish(E.scan_complete([
        {"family": "windows_event_logs", "kind": "evtx", "path": "/secret/case/Security.evtx"},
        {"family": "windows_event_logs", "kind": "evtx"},
        {"family": "pcap", "kind": "pcap"},
    ]))
    bus.publish(E.agent_action(inv_id, "chainsaw_hunt", {"rules": "/secret/path"}))
    bus.publish(E.tool_start(inv_id, "chainsaw_hunt", {"evidence": "/secret/path"}, True))
    bus.publish(E.tool_end(inv_id, "call_1", 0, 1.5, "sha256:abc"))
    bus.publish(E.node_state_change(inv_id, "n1", "done"))
    bus.publish(E.node_state_change(inv_id, "n2", "running"))
    bus.publish(E.error_event(inv_id, "transient blip"))
    bus.publish(E.hitl_request(inv_id, "review findings", {"report": "SECRET REPORT CONTENT"}))
    bus.publish(E.investigation_end(inv_id, "done"))
    return t0


def test_collector_accumulates_metrics_on_investigation_end(isolated_home):
    from svetovid.agent.events import EventBus
    from svetovid.telemetry.collector import TelemetryCollector, drain_queue

    async def run():
        bus = EventBus()
        col = TelemetryCollector(bus)
        await col.start()
        try:
            await _publish_investigation(bus)
            # let the drain loop process
            for _ in range(20):
                await asyncio.sleep(0.01)
        finally:
            await col.stop()

        rows = drain_queue(limit=10)
        assert len(rows) == 1
        rec = rows[0]
        assert rec["event"] == "investigation.complete"
        props = rec["props"]
        assert props["goal_id"] == "G01"
        assert props["hitl_approved"] is True
        assert props["error_count"] == 1
        assert props["iteration_count"] == 1   # one agent.action
        assert props["user_rating"] is None
        # tool calls recorded with exit code + duration
        assert props["tool_calls"] == [
            {"tool": "chainsaw_hunt", "exit_code": 0, "duration_s": 1.5}
        ]
        # node durations captured for the node that finished
        assert "n1" in props["node_durations"]
        # evidence families aggregated, not the raw artifact dicts
        assert props["evidence_types"] == {"windows_event_logs": 2, "pcap": 1}

    asyncio.run(run())


def test_collector_never_records_pii(isolated_home):
    """The headline privacy guarantee: no paths, args, content, prompts leak."""
    from svetovid.agent.events import EventBus
    from svetovid.telemetry.collector import TelemetryCollector, drain_queue

    secret_path = "/secret/case/Security.evtx"
    secret_arg = {"evidence": secret_path, "api_key": "sk-LEAKED"}
    secret_report = "TOP SECRET FINDINGS"

    async def run():
        bus = EventBus()
        col = TelemetryCollector(bus)
        await col.start()
        try:
            from svetovid.agent import events as E
            bus.publish(E.investigation_start("c", "inv_pii", "G07", ["n"]))
            bus.publish(E.scan_complete([{"family": "evtx", "path": secret_path}]))
            bus.publish(E.agent_action("inv_pii", "tool", secret_arg))
            bus.publish(E.tool_start("inv_pii", "tool", secret_arg, True))
            bus.publish(E.hitl_request("inv_pii", "r", {"report": secret_report}))
            bus.publish(E.investigation_end("inv_pii", "done"))
            for _ in range(20):
                await asyncio.sleep(0.01)
        finally:
            await col.stop()

        rows = drain_queue()
        assert len(rows) == 1
        blob = json.dumps(rows[0])
        # none of these may appear anywhere in the queued record
        assert secret_path not in blob
        assert "sk-LEAKED" not in blob
        assert "api_key" not in blob
        assert secret_report not in blob

    asyncio.run(run())


def test_collector_respects_is_enabled_toggle(isolated_home, monkeypatch):
    from svetovid.agent.events import EventBus
    from svetovid.config import load_settings, save_settings
    from svetovid.telemetry.collector import TelemetryCollector, drain_queue

    s = load_settings()
    s.telemetry_enabled = False
    save_settings(s)

    async def run():
        bus = EventBus()
        col = TelemetryCollector(bus)
        assert col.is_enabled is False
        await col.start()
        try:
            await _publish_investigation(bus)
            for _ in range(10):
                await asyncio.sleep(0.01)
        finally:
            await col.stop()
        # nothing queued while disabled
        assert drain_queue() == []

    asyncio.run(run())


def test_collector_attach_rating_validates_and_enqueues(isolated_home):
    from svetovid.agent.events import EventBus
    from svetovid.telemetry.collector import TelemetryCollector, drain_queue

    async def run():
        bus = EventBus()
        col = TelemetryCollector(bus)
        await col.start()
        try:
            assert col.attach_rating("inv1", 3, "good") is True
            assert col.attach_rating("inv1", 0, "bad") is False     # out of range
            assert col.attach_rating("inv1", 6, "bad") is False     # out of range
        finally:
            await col.stop()
        rows = drain_queue()
        assert len(rows) == 1
        assert rows[0]["event"] == "user.rating"
        assert rows[0]["props"]["rating"] == 3
        assert rows[0]["props"]["feedback"] == "good"

    asyncio.run(run())


def test_collector_graceful_without_start_event(isolated_home):
    """Events arriving before investigation.start should not crash the loop."""
    from svetovid.agent.events import EventBus
    from svetovid.agent import events as E
    from svetovid.telemetry.collector import TelemetryCollector, drain_queue

    async def run():
        bus = EventBus()
        col = TelemetryCollector(bus)
        await col.start()
        try:
            # node state before start event
            bus.publish(E.node_state_change("inv_late", "n", "running"))
            bus.publish(E.investigation_start("c", "inv_late", "G01", ["n"]))
            bus.publish(E.node_state_change("inv_late", "n", "done"))
            bus.publish(E.investigation_end("inv_late", "done"))
            for _ in range(20):
                await asyncio.sleep(0.01)
        finally:
            await col.stop()
        rows = drain_queue()
        assert len(rows) == 1
        assert rows[0]["props"]["goal_id"] == "G01"

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Uploader
# ---------------------------------------------------------------------------


def test_uploader_does_nothing_when_endpoint_empty(isolated_home):
    from svetovid.telemetry import collector
    from svetovid.telemetry.uploader import Uploader

    collector.enqueue_record("cid", "e", "ts", {"k": "v"})
    up = Uploader(interval_s=1)

    async def run():
        up.start()
        await asyncio.sleep(0.2)
        await up.stop()

    asyncio.run(run())
    # record still queued (no endpoint → never drained)
    assert collector.queue_count() == 1


def test_uploader_does_nothing_when_disabled(isolated_home, monkeypatch):
    from svetovid.config import load_settings, save_settings
    from svetovid.telemetry import collector
    from svetovid.telemetry.uploader import Uploader

    s = load_settings()
    s.telemetry_enabled = False
    s.telemetry_endpoint = "https://example.invalid/api/v1/telemetry"
    save_settings(s)

    collector.enqueue_record("cid", "e", "ts", {})

    async def run():
        up = Uploader(interval_s=1)
        up.start()
        await asyncio.sleep(0.2)
        await up.stop()

    asyncio.run(run())
    assert collector.queue_count() == 1


def test_uploader_uploads_on_success_and_clears_queue(isolated_home):
    """A successful upload POSTs the batch and clears the local queue."""
    import httpx
    from svetovid.telemetry import collector
    from svetovid.telemetry.uploader import Uploader

    received: list[list[dict]] = []

    def good_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        received.append(body)
        return httpx.Response(200, json={"accepted": len(body)})

    transport = httpx.MockTransport(good_handler)
    monkeypatch_post(transport)

    collector.enqueue_record("cid", "investigation.complete", "ts", {"goal_id": "G01"})

    # point endpoint at something so enabled() returns True
    from svetovid.config import load_settings, save_settings
    s = load_settings()
    s.telemetry_endpoint = "https://analytics.test/api/v1/telemetry"
    save_settings(s)

    async def run():
        up = Uploader(interval_s=1)
        up.start()
        # give the loop time to wake (wait_for(stop) timeout is 1s)
        for _ in range(30):
            await asyncio.sleep(0.05)
            if collector.queue_count() == 0:
                break
        await up.stop()

    asyncio.run(run())
    assert collector.queue_count() == 0
    assert received and received[0][0]["event"] == "investigation.complete"


def test_uploader_retains_queue_on_failure(isolated_home):
    """A failed upload (non-2xx) must re-enqueue every drained record."""
    import httpx
    from svetovid.config import load_settings, save_settings
    from svetovid.telemetry import collector
    from svetovid.telemetry.uploader import Uploader

    def fail_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    monkeypatch_post(httpx.MockTransport(fail_handler))

    s = load_settings()
    s.telemetry_endpoint = "https://analytics.test/api/v1/telemetry"
    save_settings(s)

    collector.enqueue_record("cid", "e1", "ts1", {"a": 1})
    collector.enqueue_record("cid", "e2", "ts2", {"b": 2})
    before = collector.queue_count()

    async def run():
        up = Uploader(interval_s=1)
        up.start()
        for _ in range(30):
            await asyncio.sleep(0.05)
        await up.stop()

    asyncio.run(run())
    # all records retained after the failed upload
    after = collector.queue_count()
    assert after == before, f"records lost on failure: before={before} after={after}"


def monkeypatch_post(transport):
    """Replace uploader._post with one bound to the given MockTransport."""
    import httpx
    from svetovid.telemetry import uploader

    async def fake_post(endpoint, batch):
        async with httpx.AsyncClient(transport=transport) as client:
            resp = await client.post(endpoint, json=batch)
            resp.raise_for_status()

    uploader._post = fake_post


# ---------------------------------------------------------------------------
# Reference server
# ---------------------------------------------------------------------------


def test_server_round_trip_and_analytics():
    """Ingest records, then read back aggregate analytics."""
    from fastapi.testclient import TestClient
    from svetovid.telemetry.server import create_app

    app = create_app()
    client = TestClient(app)

    payload = [
        {
            "client_id": "c1", "event": "investigation.complete",
            "ts": "2026-07-27T10:00:00Z",
            "props": {
                "investigation_id": "inv_1", "goal_id": "G01", "duration_s": 120.0,
                "tool_calls": [
                    {"tool": "chainsaw_hunt", "exit_code": 0, "duration_s": 1.5},
                    {"tool": "chainsaw_hunt", "exit_code": 1, "duration_s": 0.5},
                    {"tool": "volatility_pslist", "exit_code": 0, "duration_s": 9.0},
                ],
                "iteration_count": 5, "error_count": 0, "hitl_approved": True,
                "user_rating": None, "node_durations": {}, "evidence_types": {},
                "provider": "ollama", "model": "llama3.1:8b",
            },
        },
        {
            "client_id": "c2", "event": "investigation.complete",
            "ts": "2026-07-27T11:00:00Z",
            "props": {
                "investigation_id": "inv_2", "goal_id": "G01", "duration_s": 80.0,
                "tool_calls": [
                    {"tool": "chainsaw_hunt", "exit_code": 0, "duration_s": 2.0},
                ],
                "iteration_count": 3, "error_count": 1, "hitl_approved": False,
                "user_rating": None, "node_durations": {}, "evidence_types": {},
                "provider": "glm", "model": "glm-4-flash",
            },
        },
        {
            "client_id": "c1", "event": "user.rating",
            "ts": "2026-07-27T10:05:00Z",
            "props": {"investigation_id": "inv_1", "rating": 4, "feedback": None},
        },
    ]
    r = client.post("/api/v1/telemetry", json=payload)
    assert r.status_code == 200
    assert r.json() == {"accepted": 3, "rejected": 0}

    summary = client.get("/api/v1/analytics/summary").json()
    # two G01 investigations averaging (120+80)/2 = 100s
    assert summary["avg_duration_by_goal"] == {"G01": 100.0}
    assert summary["goal_popularity"] == {"G01": 2}
    # chainsaw: 2 success / 3 total = 0.6667; volatility: 1/1
    assert summary["tool_success_rate"]["chainsaw_hunt"]["rate"] == pytest.approx(2 / 3, abs=1e-3)
    assert summary["tool_success_rate"]["volatility_pslist"]["rate"] == 1.0
    # one rating of 4
    assert summary["avg_user_rating"] == 4
    assert summary["totals"]["investigations"] == 2
    assert summary["totals"]["tool_calls"] == 4
    assert summary["totals"]["ratings"] == 1
    assert summary["totals"]["errors"] == 1
    # average iterations (5+3)/2 = 4
    assert summary["avg_iterations"] == 4.0

    # paginated list
    listing = client.get("/api/v1/analytics/investigations?limit=2").json()
    assert listing["total"] == 3
    assert len(listing["records"]) == 2
    # newest first
    assert listing["records"][0]["event"] == "user.rating"


def test_server_rejects_malformed_rows_but_keeps_good_ones():
    from fastapi.testclient import TestClient
    from svetovid.telemetry.server import create_app

    client = TestClient(create_app())
    payload = [
        {"client_id": "c", "event": "e", "ts": "t", "props": {}},   # good
        "not-a-dict",                                                  # bad
        {"event": "no-client"},                                        # bad (missing client_id)
    ]
    r = client.post("/api/v1/telemetry", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] == 1
    assert body["rejected"] == 2


def test_server_investigations_filter_by_client():
    from fastapi.testclient import TestClient
    from svetovid.telemetry.server import create_app

    client = TestClient(create_app())
    client.post("/api/v1/telemetry", json=[
        {"client_id": "alice", "event": "e", "ts": "t", "props": {}},
        {"client_id": "bob", "event": "e", "ts": "t", "props": {}},
    ])
    r = client.get("/api/v1/analytics/investigations?client_id=alice").json()
    assert r["total"] == 1
    assert r["records"][0]["client_id"] == "alice"


# ---------------------------------------------------------------------------
# main.py endpoints
# ---------------------------------------------------------------------------


def test_main_rate_endpoint_enqueues_rating(isolated_home, monkeypatch):
    from fastapi.testclient import TestClient
    from svetovid.main import app, AUTH_TOKEN
    from svetovid.telemetry import collector

    client = TestClient(app)
    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

    r = client.post("/api/telemetry/rate", json={
        "investigation_id": "inv_abc", "rating": 5, "feedback": "great",
    }, headers=headers)
    assert r.status_code == 200
    assert r.json() == {"ok": True}

    rows = collector.drain_queue()
    assert len(rows) == 1
    assert rows[0]["event"] == "user.rating"
    assert rows[0]["props"]["rating"] == 5


def test_main_rate_rejects_out_of_range(isolated_home, monkeypatch):
    from fastapi.testclient import TestClient
    from svetovid.main import app, AUTH_TOKEN

    client = TestClient(app)
    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    r = client.post("/api/telemetry/rate", json={
        "investigation_id": "inv", "rating": 9,
    }, headers=headers)
    assert r.status_code == 400


def test_main_status_endpoint(isolated_home, monkeypatch):
    from fastapi.testclient import TestClient
    from svetovid.main import app, AUTH_TOKEN
    from svetovid.telemetry import collector

    collector.enqueue_record("cid", "e", "ts", {})

    client = TestClient(app)
    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    r = client.get("/api/telemetry/status", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True         # default opt-in
    assert body["endpoint"] == ""          # default empty
    assert body["queued_count"] == 1


def test_main_rate_requires_auth(isolated_home):
    from fastapi.testclient import TestClient
    from svetovid.main import app

    client = TestClient(app)
    r = client.post("/api/telemetry/rate", json={
        "investigation_id": "x", "rating": 3,
    })
    assert r.status_code == 401


def test_settings_round_trip_persists_telemetry_endpoint(isolated_home):
    from svetovid.config import load_settings, save_settings

    s = load_settings()
    s.telemetry_enabled = False
    s.telemetry_endpoint = "https://analytics.internal/api/v1/telemetry"
    save_settings(s)

    s2 = load_settings()
    assert s2.telemetry_enabled is False
    assert s2.telemetry_endpoint == "https://analytics.internal/api/v1/telemetry"


def test_put_settings_accepts_telemetry_fields(isolated_home):
    """The PUT /api/settings handler must persist telemetry_endpoint + toggle."""
    from fastapi.testclient import TestClient
    from svetovid.main import app, AUTH_TOKEN

    client = TestClient(app)
    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

    r = client.put("/api/settings", json={
        "telemetry_enabled": False,
        "telemetry_endpoint": "https://x.test/t",
    }, headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["telemetry_enabled"] is False
    assert body["telemetry_endpoint"] == "https://x.test/t"
