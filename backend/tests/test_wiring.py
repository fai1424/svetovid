"""Wiring tests: prove the "built but not connected" gaps are closed (Q1 + Q2).

These verify the two critical audit findings are fixed end-to-end:

  Q2 — EventBus → case DB persistence.
       A published event must land in the case DB's ``events`` table (and, for
       ``report.ioc``, in the ``iocs`` table). Previously ``record_event`` /
       ``record_tool_call`` / ``record_evidence_item`` / ``record_ioc`` were
       never called from the live path, so exports read from empty tables.

  Q1 — IoC / timeline / finding events are actually emitted from tools.
       The Chainsaw tool wrapper must publish ``report.timeline_entry`` for
       each parsed hit and ``report.ioc`` for IP/domain/hash indicators found
       in the hit details. Previously no code emitted these, leaving the IoC
       tab, Timeline tab, and ATT&CK heatmap permanently empty.

We exercise the real code paths (the lifespan ``_db_persister`` task and the
Chainsaw ``invoke`` emission) — not mocks of the units under test. The Docker
sandbox runner IS mocked because there's no Docker / chainsaw binary in CI; the
mock returns a canned Chainsaw JSON payload so the parsing + emission logic
runs against realistic vendor output.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Fixtures — mirror test_smoke / test_integration (hermetic HOME, fail keyring).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    """Run against a throwaway ``~/.svetovid`` + fail keyring backend.

    Also clears cached svetovid singletons so each test re-initializes the
    case DB against the fresh HOME (the DB is a module-level singleton).
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]
    yield fake_home


class _RecordingBus:
    """Minimal EventBus stand-in that records every published event as a dict.

    Mirrors the helper in test_integration, but typed to match what the tool
    wrappers need (``bus.publish(event)`` accepting AgentEvent or dict).
    """

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def publish(self, event) -> None:
        if hasattr(event, "to_ws"):
            event = event.to_ws()
        self.events.append(event)

    # The lifespan persister calls subscribe/unsubscribe on a real EventBus;
    # this stub is only used for the tool-path tests where no subscription is
    # needed, so these are no-ops.
    def subscribe(self):  # pragma: no cover - not used in these tests
        raise NotImplementedError

    def unsubscribe(self, _q) -> None:  # pragma: no cover - not used
        pass


# ===========================================================================
# Q2: EventBus → case DB persistence
# ===========================================================================


def test_published_event_is_persisted_to_db(isolated_home):
    """The lifespan DB persister writes every published event into ``events``.

    This drives the real ``_db_persister`` task against a real CaseDB and a
    real EventBus (no mocks of the unit under test): we publish, give the task
    a beat to drain its subscription queue, then cancel it and assert the row
    landed in the DB. This is the exact wiring the lifespan installs.
    """
    from svetovid.agent.events import EventBus, investigation_start
    from svetovid.main import _db_persister
    from svetovid.store import get_db

    async def run():
        bus = EventBus()
        db = await get_db()
        # Seed the investigation row first so the persisted event's FK-like
        # investigation_id has a home (record_event itself doesn't enforce FK,
        # but list_events is keyed on it).
        await db.create_investigation("inv_persist_1", "default", "G01", "/e", "")

        task = asyncio.create_task(_db_persister(bus, db))
        # Let the persister reach its bus.subscribe() before we publish.
        await asyncio.sleep(0)
        try:
            bus.publish(investigation_start("default", "inv_persist_1", "G01", ["n1"]))
            # Drain: the persister polls a queue with a 5s timeout; give the
            # event loop a few cycles for it to land in the DB.
            for _ in range(50):
                await asyncio.sleep(0.02)
                evts = await db.list_events("inv_persist_1")
                if evts:
                    break
            events = await db.list_events("inv_persist_1")
            assert events, "published event was not persisted to the DB"
            assert events[0]["type"] == "investigation.start"
            assert events[0]["investigation_id"] == "inv_persist_1"
            assert events[0]["data"]["goal_id"] == "G01"
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            await db.close()

    asyncio.run(run())


def test_published_ioc_event_is_persisted_to_iocs_table(isolated_home):
    """``report.ioc`` events fold into the IOCs table via the persister.

    This exercises the ``_persist_ioc_event`` branch of ``_db_persister``: a
    tool emits a ``report.ioc`` on the bus, and it must land in the IOCs table
    (so the IoC tab / STIX export read real data even when no tool calls
    ``record_ioc`` directly).
    """
    from svetovid.agent.events import EventBus, report_ioc
    from svetovid.main import _db_persister
    from svetovid.store import get_db

    async def run():
        bus = EventBus()
        db = await get_db()
        await db.create_investigation("inv_ioc_1", "default", "G01", "/e", "")

        task = asyncio.create_task(_db_persister(bus, db))
        await asyncio.sleep(0)  # let the persister subscribe before publish
        try:
            bus.publish(report_ioc(
                "inv_ioc_1", "ip", "203.0.113.9", "c2 beacon",
                confidence=0.9, mitre_technique="T1071",
            ))
            for _ in range(50):
                await asyncio.sleep(0.02)
                iocs = await db.list_iocs("inv_ioc_1")
                if iocs:
                    break
            iocs = await db.list_iocs("inv_ioc_1")
            assert iocs, "report.ioc event was not persisted to iocs table"
            assert iocs[0]["value"] == "203.0.113.9"
            assert iocs[0]["ioc_type"] == "ip"
            assert iocs[0]["confidence"] == pytest.approx(0.9)
            assert iocs[0]["mitre_technique"] == "T1071"
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            await db.close()

    asyncio.run(run())


def test_scan_endpoint_persists_evidence_items(isolated_home, tmp_path):
    """``/api/scan`` records every scanned artifact as a hashed evidence item.

    Drives the real ``scan`` endpoint via FastAPI's TestClient against a temp
    folder of fixtures. The evidence_items table must be populated afterward
    (previously record_evidence_item was never called, so chain-of-custody was
    empty).
    """
    from fastapi.testclient import TestClient
    from svetovid.main import app, AUTH_TOKEN
    from svetovid.store import get_db

    # Build a tiny evidence tree the scanner will classify.
    (tmp_path / "Security.evtx").write_bytes(b"ElfFile\x00fake")

    with TestClient(app) as client:
        r = client.post(
            "/api/scan",
            json={"path": str(tmp_path)},
            headers={"Authorization": f"Bearer {AUTH_TOKEN}"},
        )
        assert r.status_code == 200, r.text
        artifacts = r.json()["artifacts"]
        assert any(a["kind"] == "evtx" for a in artifacts), artifacts

        # The endpoint must have persisted evidence rows for the default case.
        async def check():
            db = await get_db()
            items = await db.list_evidence_items("default")
            await db.close()
            return items

        items = asyncio.run(check())
        assert items, "scan produced artifacts but recorded zero evidence items"
        paths = {it["path"] for it in items}
        assert any(p.endswith("Security.evtx") for p in paths), \
            "evtx artifact not recorded as evidence"


# ===========================================================================
# Q1: Chainsaw emits timeline + IOC events
# ===========================================================================


def _fake_chainsaw_payload() -> list[dict[str, Any]]:
    """Canned Chainsaw JSON output with timeline + IOC-bearing hits.

    Mirrors the real Chainsaw ``--json`` shape (a list of groups, each with a
    ``hits`` list). The hits include:
      - a clean timeline hit (no IOC),
      - a hit with an IP + domain in details (→ IOC),
      - a hit with a SHA-256 in details (→ hash IOC).
    """
    return [
        {
            "hits": [
                {
                    "time": "2026-07-20T08:14:02Z",
                    "event_id": 4688,
                    "computer": "DC01",
                    "name": "Suspicious PowerShell Execution",
                    "level": "high",
                    "status": "experimental",
                    "tags": ["attack.execution", "attack.t1059.001"],
                    "details": {"CommandLine": "powershell -enc SGVsbG8="},
                },
                {
                    "time": "2026-07-20T08:15:30Z",
                    "event_id": 3,
                    "computer": "WS02",
                    "name": "Network Connection To Known C2",
                    "level": "critical",
                    "status": "stable",
                    "tags": ["attack.t1071.001"],
                    "details": {
                        "DestinationIp": "203.0.113.66",
                        "DestinationHostname": "evil-c2.example.ru",
                    },
                },
                {
                    "time": "2026-07-20T08:16:01Z",
                    "event_id": 11,
                    "computer": "WS02",
                    "name": "Dropped Binary",
                    "level": "high",
                    "status": "stable",
                    "tags": ["attack.t1027"],
                    "details": {
                        "TargetFilename": "C:\\Users\\pub\\app.exe",
                        "Hashes": "SHA256=d077f0643ec0bdbe5e2a5b5e8d1f9c3a2b8e6f4d9c7b6a5e4d3c2b1a0f9e8d7c",
                    },
                },
            ]
        }
    ]


def test_chainsaw_emits_timeline_entries_for_hits(isolated_home, tmp_path):
    """The Chainsaw wrapper publishes ``report.timeline_entry`` per parsed hit.

    We mock ``run_in_sandbox`` (no Docker / chainsaw binary in CI) to drop the
    canned JSON payload into the output dir and return exit 0. The real
    parsing + emission code then runs over it. Every hit must become a
    timeline entry carrying the rule name and ATT&CK tag.
    """
    from svetovid.tools import chainsaw as chainsaw_mod
    from svetovid.tools.base import ToolContext

    payload = _fake_chainsaw_payload()
    output_dir = tmp_path / "work"
    output_dir.mkdir()

    async def fake_run_in_sandbox(**kwargs):
        from svetovid.sandbox.docker_runner import RunResult
        # Write the canned chainsaw output where the tool expects it.
        (output_dir / "chainsaw_hits.json").write_text(json.dumps(payload))
        return RunResult(exit_code=0, duration_s=0.42,
                         container_id=None, output_dir=str(output_dir))

    # Patch the runner where the tool imports it (module-local import).
    import svetovid.sandbox.docker_runner as runner_mod
    original = runner_mod.run_in_sandbox
    runner_mod.run_in_sandbox = fake_run_in_sandbox  # type: ignore[assignment]
    try:
        bus = _RecordingBus()
        ctx = ToolContext(
            investigation_id="inv_chain_1", case_id="default", bus=bus,  # type: ignore[arg-type]
            evidence_path=str(tmp_path), output_dir=str(output_dir),
        )
        result = asyncio.run(chainsaw_mod.ChainsawTool().invoke(
            {"min_level": "medium"}, ctx,
        ))
    finally:
        runner_mod.run_in_sandbox = original  # type: ignore[assignment]

    assert result.exit_code == 0
    timeline_events = [e for e in bus.events if e.get("type") == "report.timeline_entry"]
    # One timeline entry per hit (3 hits in the canned payload).
    assert len(timeline_events) == 3, \
        f"expected 3 timeline entries, got {len(timeline_events)}: {timeline_events}"
    # Spot-check the C2 hit: rule name + ATT&CK technique ride along.
    c2 = next(e for e in timeline_events if "C2" in e["data"]["event"])
    c2_data = c2["data"]
    assert c2_data["source"] == "chainsaw"
    assert "Network Connection To Known C2" in c2_data["event"]
    assert c2_data["mitre_technique"] == "T1071.001"
    assert "T1071.001" in (c2_data.get("mitre_tags") or [])


def test_chainsaw_emits_iocs_for_ip_and_domain_hits(isolated_home, tmp_path):
    """Chainsaw emits ``report.ioc`` for IP / domain / hash indicators in hits.

    Same harness as the timeline test; we assert the C2 hit produced both an
    IP IOC and a domain IOC, and the drop-binary hit produced a hash IOC.
    Loopback / private IPs and bare hostnames are deliberately NOT emitted.
    """
    from svetovid.tools import chainsaw as chainsaw_mod
    from svetovid.tools.base import ToolContext

    payload = _fake_chainsaw_payload()
    output_dir = tmp_path / "work"
    output_dir.mkdir()

    async def fake_run_in_sandbox(**kwargs):
        from svetovid.sandbox.docker_runner import RunResult
        (output_dir / "chainsaw_hits.json").write_text(json.dumps(payload))
        return RunResult(exit_code=0, duration_s=0.42,
                         container_id=None, output_dir=str(output_dir))

    import svetovid.sandbox.docker_runner as runner_mod
    original = runner_mod.run_in_sandbox
    runner_mod.run_in_sandbox = fake_run_in_sandbox  # type: ignore[assignment]
    try:
        bus = _RecordingBus()
        ctx = ToolContext(
            investigation_id="inv_chain_2", case_id="default", bus=bus,  # type: ignore[arg-type]
            evidence_path=str(tmp_path), output_dir=str(output_dir),
        )
        asyncio.run(chainsaw_mod.ChainsawTool().invoke({"min_level": "medium"}, ctx))
    finally:
        runner_mod.run_in_sandbox = original  # type: ignore[assignment]

    ioc_events = [e for e in bus.events if e.get("type") == "report.ioc"]
    values = {(e["data"]["type"], e["data"]["value"]) for e in ioc_events}
    # The C2 hit carries a public IP + a malicious domain → both become IOCs.
    assert ("ip", "203.0.113.66") in values, f"missing IP IOC; got {values}"
    assert ("domain", "evil-c2.example.ru") in values, f"missing domain IOC; got {values}"
    # The drop-binary hit carries a SHA-256 → hash IOC.
    assert any(t == "hash" for t, _ in values), f"missing hash IOC; got {values}"
    # Confidence + context are populated (not empty defaults).
    an_ioc = ioc_events[0]["data"]
    assert an_ioc["confidence"] > 0.0
    assert an_ioc["context"]


def test_chainsaw_persists_tool_call_to_db(isolated_home, tmp_path):
    """Chainsaw records its invocation in the tool_calls table (Q2)."""
    from svetovid.tools import chainsaw as chainsaw_mod
    from svetovid.tools.base import ToolContext
    from svetovid.store import get_db

    payload = _fake_chainsaw_payload()
    output_dir = tmp_path / "work"
    output_dir.mkdir()

    async def fake_run_in_sandbox(**kwargs):
        from svetovid.sandbox.docker_runner import RunResult
        (output_dir / "chainsaw_hits.json").write_text(json.dumps(payload))
        return RunResult(exit_code=0, duration_s=0.42,
                         container_id=None, output_dir=str(output_dir))

    import svetovid.sandbox.docker_runner as runner_mod
    original = runner_mod.run_in_sandbox
    runner_mod.run_in_sandbox = fake_run_in_sandbox  # type: ignore[assignment]
    try:
        bus = _RecordingBus()
        ctx = ToolContext(
            investigation_id="inv_chain_tc", case_id="default", bus=bus,  # type: ignore[arg-type]
            evidence_path=str(tmp_path), output_dir=str(output_dir),
        )
        asyncio.run(chainsaw_mod.ChainsawTool().invoke({"min_level": "high"}, ctx))
    finally:
        runner_mod.run_in_sandbox = original  # type: ignore[assignment]

    async def check():
        db = await get_db()
        calls = await db.list_tool_calls("inv_chain_tc")
        await db.close()
        return calls

    calls = asyncio.run(check())
    assert calls, "chainsaw tool call was not persisted to tool_calls table"
    assert calls[0]["tool"] == "chainsaw_hunt"
    assert calls[0]["exit_code"] == 0
    assert calls[0]["duration_s"] == pytest.approx(0.42)


# ===========================================================================
# Supporting: IOC extraction sanity (used by all the tool emitters)
# ===========================================================================


def test_extract_iocs_from_text_finds_ips_domains_hashes():
    from svetovid.governance.ioc_store import extract_iocs_from_text
    text = (
        "beacon to 203.0.113.55 then evil-c2.example.com "
        "sha256 d077f0643ec0bdbe5e2a5b5e8d1f9c3a2b8e6f4d9c7b6a5e4d3c2b1a0f9e8d7c "
        "from 127.0.0.1 and 10.0.0.5 md5 abcdef0123456789abcdef0123456789"
    )
    found = extract_iocs_from_text(text)
    types_values = {(d["ioc_type"], d["value"]) for d in found}
    assert ("ip", "203.0.113.55") in types_values
    assert ("domain", "evil-c2.example.com") in types_values
    assert ("hash", "d077f0643ec0bdbe5e2a5b5e8d1f9c3a2b8e6f4d9c7b6a5e4d3c2b1a0f9e8d7c") in types_values
    assert ("hash", "abcdef0123456789abcdef0123456789") in types_values
    # Loopback must be filtered out (would flood the IoC tab with noise).
    assert not any(v == "127.0.0.1" for _, v in types_values), \
        "loopback IP leaked into IOCs"
