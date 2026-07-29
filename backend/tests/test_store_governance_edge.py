"""Comprehensive edge-case tests for the database store + governance modules.

Covers the seams the happy-path modules don't stress:

  * CaseDB lifecycle: double-init safety, close semantics, post-close errors.
  * Investigation / tool-call / event / evidence / IOC CRUD edge cases.
  * Hashing: empty file, missing file, oversize file (>cap), batch progress.
  * Chain-of-custody tamper detection across every sealed field + the seal.
  * IOC extraction from free-form text (IPs / domains / hashes / loopback filter).

Hermetic like ``test_governance.py``: throwaway HOME, fail-keyring, fresh
module cache, DBs rooted under ``tmp_path``. No network.
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Hermetic isolation — throwaway HOME + fail keyring + fresh module cache.
# Mirrors the pattern in test_governance.py so config/store singletons never
# leak across tests.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]
    yield fake_home


# Helper: a fresh, initialized CaseDB rooted at a tmp_path file.
async def _fresh_db(tmp_path, filename: str = "t.db"):
    from svetovid.store import CaseDB
    db = CaseDB(path=tmp_path / filename)
    await db.init()
    return db


# ===========================================================================
# 1. CaseDB lifecycle
# ===========================================================================


def test_init_creates_schema_and_default_case(tmp_path):
    """init() creates the cases table and seeds the default case."""
    async def run():
        from svetovid.store import CaseDB
        db_path = tmp_path / "lifecycle.db"
        assert not db_path.exists()  # nothing on disk yet
        db = CaseDB(path=db_path)
        await db.init()
        assert db_path.exists()  # DB file materialized
        # default case seeded by init — verify against a fresh connection.
        import aiosqlite
        async with aiosqlite.connect(str(db_path)) as conn:
            cur = await conn.execute("SELECT id, name, status FROM cases WHERE id = 'default'")
            row = await cur.fetchone()
        assert row is not None
        assert row[0] == "default"
        assert row[1] == "Default Case"
        assert row[2] == "active"
        await db.close()

    asyncio.run(run())


def test_double_init_is_safe(tmp_path):
    """Calling init() twice must not raise (IF NOT EXISTS + INSERT OR IGNORE)."""
    async def run():
        from svetovid.store import CaseDB
        db_path = tmp_path / "double.db"
        db = CaseDB(path=db_path)
        await db.init()
        # Re-init on the same connection — schema is idempotent, default case
        # uses INSERT OR IGNORE so the duplicate-PK path is exercised.
        await db.init()
        await db.close()
        # And re-init on a brand-new CaseDB instance pointing at the same file.
        db2 = CaseDB(path=db_path)
        await db2.init()
        await db2.close()

    asyncio.run(run())


def test_close_releases_connection(tmp_path):
    """After close(), the internal connection handle is cleared."""
    async def run():
        db = await _fresh_db(tmp_path, "close.db")
        assert db._db is not None
        await db.close()
        assert db._db is None
        # close() is idempotent — a second call is a no-op, not an error.
        await db.close()

    asyncio.run(run())


def test_operations_after_close_raise_gracefully(tmp_path):
    """A query issued after close() must raise a clear error, not silently pass."""
    async def run():
        db = await _fresh_db(tmp_path, "afterclose.db")
        await db.create_investigation("inv_z", "default", "g1", "/evidence")
        await db.close()
        # _db is None after close → list_investigations dereferences None.
        with pytest.raises(AttributeError):
            await db.list_investigations()
        with pytest.raises(AttributeError):
            await db.get_investigation("inv_z")

    asyncio.run(run())


# ===========================================================================
# 2. Investigation CRUD
# ===========================================================================


def test_investigation_create_then_list(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "inv.db")
        await db.create_investigation("inv_a", "default", "G01", "/evidence/a",
                                      user_prompt="find persistence")
        listed = await db.list_investigations()
        assert len(listed) == 1
        assert listed[0]["id"] == "inv_a"
        assert listed[0]["case_id"] == "default"
        assert listed[0]["goal_id"] == "G01"
        assert listed[0]["status"] == "running"
        await db.close()

    asyncio.run(run())


def test_finish_investigation_updates_status(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "finish.db")
        await db.create_investigation("inv_f", "default", "G01", "/evidence")
        await db.finish_investigation("inv_f", "complete", error=None)
        got = await db.get_investigation("inv_f")
        assert got is not None
        assert got["status"] == "complete"
        assert got["ended_at"] is not None  # timestamp set on finish
        assert got["error"] is None
        await db.close()

    asyncio.run(run())


def test_finish_investigation_records_error(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "finish_err.db")
        await db.create_investigation("inv_e", "default", "G01", "/evidence")
        await db.finish_investigation("inv_e", "error", error="boom")
        got = await db.get_investigation("inv_e")
        assert got["status"] == "error"
        assert got["error"] == "boom"
        await db.close()

    asyncio.run(run())


def test_get_nonexistent_investigation_returns_none(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "ghost.db")
        assert await db.get_investigation("does_not_exist") is None
        await db.close()

    asyncio.run(run())


def test_update_report_persists_markdown(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "report.db")
        await db.create_investigation("inv_r", "default", "G01", "/evidence")
        # before update, report defaults to empty string
        assert (await db.get_investigation("inv_r"))["report_markdown"] == ""
        await db.update_report("inv_r", "# Findings\n\nLateral movement detected.")
        got = await db.get_investigation("inv_r")
        assert "Lateral movement detected" in got["report_markdown"]
        await db.close()

    asyncio.run(run())


def test_list_investigations_ordered_by_started_at_desc(tmp_path):
    """Newest investigations must come first (ORDER BY started_at DESC)."""
    async def run():
        db = await _fresh_db(tmp_path, "order.db")
        # started_at is second-resolution ISO; insert sequentially so their
        # timestamps are strictly increasing (sleep at least 1s between).
        import time
        for i, iid in enumerate(["inv_old", "inv_mid", "inv_new"]):
            await db.create_investigation(iid, "default", "G01", f"/e/{iid}")
            if i < 2:
                time.sleep(1.1)  # ensure distinct second-resolution timestamps
        listed = await db.list_investigations()
        assert [r["id"] for r in listed] == ["inv_new", "inv_mid", "inv_old"]
        await db.close()

    asyncio.run(run())


# ===========================================================================
# 3. Tool call storage
# ===========================================================================


def test_tool_call_record_and_list(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "tool.db")
        await db.create_investigation("inv_t", "default", "G01", "/evidence")
        await db.record_tool_call("call_1", "inv_t", "run_chainsaw",
                                  {"path": "/e/Security.evtx", "rules": "all"},
                                  exit_code=0, duration_s=1.23,
                                  output_hash="sha256:abc")
        calls = await db.list_tool_calls("inv_t")
        assert len(calls) == 1
        c = calls[0]
        assert c["tool"] == "run_chainsaw"
        assert c["args"] == {"path": "/e/Security.evtx", "rules": "all"}
        assert c["exit_code"] == 0
        assert c["duration_s"] == pytest.approx(1.23)
        assert c["output_hash"] == "sha256:abc"
        await db.close()

    asyncio.run(run())


def test_tool_call_with_none_args_json(tmp_path):
    """A tool call with empty args dict round-trips to an empty dict."""
    async def run():
        db = await _fresh_db(tmp_path, "tool_none.db")
        await db.create_investigation("inv_na", "default", "G01", "/evidence")
        # record_tool_call always json.dumps(args); {} serializes fine.
        await db.record_tool_call("call_na", "inv_na", "noop", {},
                                  exit_code=0, duration_s=0.0,
                                  output_hash=None)
        calls = await db.list_tool_calls("inv_na")
        assert calls[0]["args"] == {}
        await db.close()

    asyncio.run(run())


def test_tool_call_with_none_output_hash(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "tool_hash.db")
        await db.create_investigation("inv_nh", "default", "G01", "/evidence")
        await db.record_tool_call("call_nh", "inv_nh", "raw_subprocess",
                                  {"cmd": "ls"}, exit_code=1, duration_s=0.5,
                                  output_hash=None)
        calls = await db.list_tool_calls("inv_nh")
        assert calls[0]["output_hash"] is None
        assert calls[0]["exit_code"] == 1
        await db.close()

    asyncio.run(run())


def test_tool_calls_scoped_to_investigation(tmp_path):
    """list_tool_calls returns only the calls for the given investigation."""
    async def run():
        db = await _fresh_db(tmp_path, "tool_scope.db")
        await db.create_investigation("inv_x", "default", "G01", "/evidence")
        await db.create_investigation("inv_y", "default", "G01", "/evidence")
        await db.record_tool_call("c1", "inv_x", "t1", {}, 0, 0.1, "h1")
        await db.record_tool_call("c2", "inv_y", "t2", {}, 0, 0.1, "h2")
        assert [c["tool"] for c in await db.list_tool_calls("inv_x")] == ["t1"]
        assert [c["tool"] for c in await db.list_tool_calls("inv_y")] == ["t2"]
        await db.close()

    asyncio.run(run())


# ===========================================================================
# 4. Event storage
# ===========================================================================


def test_record_event_with_all_fields(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "event.db")
        await db.create_investigation("inv_ev", "default", "G01", "/evidence")
        await db.record_event({
            "investigation_id": "inv_ev",
            "type": "agent.thought",
            "ts": "2026-07-27T12:00:00Z",
            "node": "reasoner",
            "data": {"thought": "checking persistence", "step": 3},
        })
        events = await db.list_events("inv_ev")
        assert len(events) == 1
        e = events[0]
        assert e["investigation_id"] == "inv_ev"
        assert e["type"] == "agent.thought"
        assert e["ts"] == "2026-07-27T12:00:00Z"
        assert e["node"] == "reasoner"
        assert e["data"]["thought"] == "checking persistence"
        assert e["data"]["step"] == 3
        # id is an autoincrement integer PK
        assert isinstance(e["id"], int)
        await db.close()

    asyncio.run(run())


def test_record_event_with_minimal_fields(tmp_path):
    """An event with no investigation_id / node / data still persists."""
    async def run():
        db = await _fresh_db(tmp_path, "event_min.db")
        await db.record_event({"type": "investigation.start"})
        events = await db.list_events("inv_anything")  # filter by inv_id = None rows
        # The event had investigation_id=None; list_events filters by a given id,
        # so passing a concrete id returns nothing.
        assert events == []
        # But the row exists in the table (verify directly).
        cur = await db._db.execute("SELECT type, investigation_id, node FROM events")
        row = await cur.fetchone()
        assert row[0] == "investigation.start"
        assert row[1] is None  # investigation_id nullable
        assert row[2] is None  # node nullable
        await db.close()

    asyncio.run(run())


def test_list_events_returns_investigation_events_oldest_first(tmp_path):
    """list_events orders by id ascending → oldest-first replay order."""
    async def run():
        db = await _fresh_db(tmp_path, "event_order.db")
        await db.create_investigation("inv_o", "default", "G01", "/evidence")
        for i in range(4):
            await db.record_event({"investigation_id": "inv_o",
                                   "type": "step", "data": {"n": i}})
        events = await db.list_events("inv_o")
        assert [e["data"]["n"] for e in events] == [0, 1, 2, 3]
        await db.close()

    asyncio.run(run())


# ===========================================================================
# 5. Evidence items
# ===========================================================================


def test_evidence_item_round_trip(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "ev.db")
        await db.record_evidence_item(
            "ev_1", "case_1", "/evidence/a.evtx", "sha256:aaa", "md5:bbb",
            1024, artifact_id="B8", family="Windows Event Logs",
            collector="alice",
        )
        items = await db.list_evidence_items("case_1")
        assert len(items) == 1
        it = items[0]
        assert it["id"] == "ev_1"
        assert it["sha256"] == "sha256:aaa"
        assert it["md5"] == "md5:bbb"
        assert it["size_bytes"] == 1024
        assert it["family"] == "Windows Event Logs"
        assert it["collector"] == "alice"
        await db.close()

    asyncio.run(run())


def test_evidence_items_multiple_same_case(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "ev_multi.db")
        for i in range(3):
            await db.record_evidence_item(
                f"ev_{i}", "case_multi", f"/e/f{i}", f"sha256:{i}", f"md5:{i}",
                (i + 1) * 100,
            )
        items = await db.list_evidence_items("case_multi")
        assert len(items) == 3
        assert {it["id"] for it in items} == {"ev_0", "ev_1", "ev_2"}
        # other case is empty
        assert await db.list_evidence_items("other_case") == []
        await db.close()

    asyncio.run(run())


def test_evidence_item_with_none_sha256(tmp_path):
    """An item whose hash failed to compute (e.g. oversize) stores None."""
    async def run():
        db = await _fresh_db(tmp_path, "ev_none.db")
        await db.record_evidence_item("ev_big", "case_n", "/disk.img",
                                      None, None, 5_000_000_000)
        it = (await db.list_evidence_items("case_n"))[0]
        assert it["sha256"] is None
        assert it["md5"] is None
        assert it["size_bytes"] == 5_000_000_000
        await db.close()

    asyncio.run(run())


# ===========================================================================
# 6. IOC storage (DB-level)
# ===========================================================================


def test_ioc_record_and_list(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "ioc.db")
        await db.record_ioc("ioc_1", "inv_9", "hash", "abc123",
                            context="yara hit", confidence=0.9,
                            mitre_technique="T1027")
        iocs = await db.list_iocs("inv_9")
        assert len(iocs) == 1
        i = iocs[0]
        assert i["ioc_type"] == "hash"
        assert i["value"] == "abc123"
        assert i["context"] == "yara hit"
        assert i["confidence"] == pytest.approx(0.9)
        assert i["mitre_technique"] == "T1027"
        await db.close()

    asyncio.run(run())


def test_ioc_multiple_types(tmp_path):
    """All canonical IOC types persist and round-trip."""
    async def run():
        db = await _fresh_db(tmp_path, "ioc_types.db")
        samples = [
            ("ioc_h", "hash", "a" * 64),
            ("ioc_ip", "ip", "203.0.113.9"),
            ("ioc_d", "domain", "evil.example.com"),
            ("ioc_u", "url", "http://evil.example.com/payload"),
        ]
        for ioc_id, t, v in samples:
            await db.record_ioc(ioc_id, "inv_multi", t, v)
        iocs = await db.list_iocs("inv_multi")
        assert len(iocs) == 4
        by_type = {i["ioc_type"]: i["value"] for i in iocs}
        assert by_type["hash"] == "a" * 64
        assert by_type["ip"] == "203.0.113.9"
        assert by_type["domain"] == "evil.example.com"
        assert by_type["url"] == "http://evil.example.com/payload"
        await db.close()

    asyncio.run(run())


def test_ioc_with_none_mitre_technique(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path, "ioc_mitre.db")
        await db.record_ioc("ioc_nm", "inv_nm", "ip", "198.51.100.7",
                            mitre_technique=None)
        i = (await db.list_iocs("inv_nm"))[0]
        assert i["mitre_technique"] is None
        assert i["confidence"] == 0.0  # default
        await db.close()

    asyncio.run(run())


# ===========================================================================
# 7. Hashing
# ===========================================================================


def test_hash_file_real_temp_file(tmp_path):
    """hash_file returns sha256 + md5 + size matching an independent recompute."""
    from svetovid.governance.hashing import hash_file
    payload = b"forensic-evidence-bytes" * 16
    p = tmp_path / "sample.bin"
    p.write_bytes(payload)

    rec = hash_file(p)
    assert rec["sha256"] == hashlib.sha256(payload).hexdigest()
    assert rec["md5"] == hashlib.md5(payload).hexdigest()
    assert rec["size"] == len(payload)
    assert rec["path"] == str(p)
    assert "error" not in rec


def test_hash_file_missing_returns_no_crash(tmp_path):
    """A missing file yields a record with an error field, never raises."""
    from svetovid.governance.hashing import hash_file
    rec = hash_file(tmp_path / "does_not_exist.bin")
    assert rec["sha256"] is None
    assert rec["md5"] is None
    assert rec["size"] == 0
    assert "error" in rec
    assert "stat_failed" in rec["error"]


def test_hash_file_empty_file(tmp_path):
    """Empty file hashes to the canonical empty-string digests."""
    from svetovid.governance.hashing import hash_file
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    rec = hash_file(p)
    # sha256("") = e3b0c4..., md5("") = d41d8c...
    assert rec["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert rec["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert rec["size"] == 0


def test_hash_file_above_size_cap_skips_hashing(tmp_path):
    """A file larger than the cap records size only with hash_skipped."""
    from svetovid.governance.hashing import hash_file, DEFAULT_SIZE_CAP
    # Use a tiny cap rather than creating a >2GiB file (too slow/expensive).
    p = tmp_path / "big.bin"
    p.write_bytes(b"x" * 100)
    rec = hash_file(p, size_cap=10)  # 100 bytes > 10-byte cap
    assert rec["size"] == 100
    assert rec["sha256"] is None
    assert rec["md5"] is None
    assert rec["hash_skipped"] == "too_large"
    # Sanity: the production default cap is 2 GiB.
    assert DEFAULT_SIZE_CAP == 2 * 1024 * 1024 * 1024


def test_hash_evidence_batch_progress_callback(tmp_path):
    """on_progress fires once per file with monotonic (done, total) counts."""
    from svetovid.governance.hashing import hash_evidence_batch
    paths = []
    for i in range(3):
        p = tmp_path / f"f{i}.bin"
        p.write_bytes(f"payload-{i}".encode())
        paths.append(p)

    seen: list[tuple[int, int, dict]] = []
    results = hash_evidence_batch(paths, on_progress=lambda d, t, r: seen.append((d, t, r)))
    assert len(results) == 3
    assert [d for d, _, _ in seen] == [1, 2, 3]
    assert all(t == 3 for _, t, _ in seen)
    # the record passed to the callback is the same one returned
    assert seen[0][2] is results[0]
    for rec, p in zip(results, paths):
        assert rec["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()


def test_hash_evidence_batch_empty_input():
    """An empty batch returns an empty list and never calls the callback."""
    from svetovid.governance.hashing import hash_evidence_batch
    called = []
    assert hash_evidence_batch([], on_progress=lambda *a: called.append(a)) == []
    assert called == []


# ===========================================================================
# 8. Chain of custody
# ===========================================================================


def _custody_artifacts(tmp_path) -> list[dict]:
    """Two realistic scanner-shaped artifacts with full hashes."""
    p1 = tmp_path / "Security.evtx"
    p1.write_bytes(b"ElfFile\x00fake")
    p2 = tmp_path / "capture.pcap"
    p2.write_bytes(b"\xd4\xc3\xb2\xa1fake")
    return [
        {"artifact_id": "B8", "family": "Windows Event Logs", "kind": "evtx",
         "path": str(p1), "size_bytes": p1.stat().st_size,
         "extra": {"sha256": hashlib.sha256(p1.read_bytes()).hexdigest(),
                   "md5": hashlib.md5(p1.read_bytes()).hexdigest()}},
        {"artifact_id": "B7", "family": "Packet Captures", "kind": "pcap",
         "path": str(p2), "size_bytes": p2.stat().st_size,
         "extra": {"sha256": hashlib.sha256(p2.read_bytes()).hexdigest(),
                   "md5": hashlib.md5(p2.read_bytes()).hexdigest()}},
    ]


def test_custody_form_shape_and_seal(tmp_path):
    """create_custody_form produces a well-formed, sealed, JSON-able document."""
    from svetovid.governance.custody import create_custody_form
    form = create_custody_form("case_1", _custody_artifacts(tmp_path), "analyst@svetovid")
    assert form["case_id"] == "case_1"
    assert form["collector_name"] == "analyst@svetovid"
    assert form["item_count"] == 2
    assert len(form["items"]) == 2
    # required structural keys
    for k in ("case_id", "items", "integrity_seal", "sealed_at", "collected_at"):
        assert k in form, f"missing key {k}"
    assert form["integrity_seal"].startswith("sha256:")
    assert form["sealed_at"]  # non-empty ISO timestamp
    # sealed item fields present + 1-indexed chain sequence
    assert [it["chain_sequence"] for it in form["items"]] == [1, 2]
    for it in form["items"]:
        assert it["sha256"] and it["md5"]
        assert it["collector_name"] == "analyst@svetovid"
    # the whole form is JSON-serializable (custody forms are persisted as JSON)
    import json
    json.dumps(form)


def test_verify_custody_form_untampered_is_true(tmp_path):
    from svetovid.governance.custody import create_custody_form, verify_custody_form
    form = create_custody_form("case_1", _custody_artifacts(tmp_path), "alice")
    assert verify_custody_form(form) is True


def test_verify_custody_form_tampered_hash_is_false(tmp_path):
    """Changing a sealed sha256 must break the seal."""
    from svetovid.governance.custody import create_custody_form, verify_custody_form
    form = create_custody_form("case_1", _custody_artifacts(tmp_path), "alice")
    tampered = {**form, "items": [dict(it) for it in form["items"]]}
    tampered["items"][0]["sha256"] = "deadbeef" * 8
    assert verify_custody_form(tampered) is False


def test_verify_custody_form_tampered_path_is_false(tmp_path):
    """Changing a sealed source_location must break the seal."""
    from svetovid.governance.custody import create_custody_form, verify_custody_form
    form = create_custody_form("case_1", _custody_artifacts(tmp_path), "alice")
    tampered = {**form, "items": [dict(it) for it in form["items"]]}
    tampered["items"][0]["source_location"] = "/totally/different/path.bin"
    assert verify_custody_form(tampered) is False


def test_verify_custody_form_tampered_seal_is_false(tmp_path):
    """A mutated integrity_seal string must fail verification."""
    from svetovid.governance.custody import create_custody_form, verify_custody_form
    form = create_custody_form("case_1", _custody_artifacts(tmp_path), "alice")
    tampered = {**form, "integrity_seal": "sha256:" + "0" * 64}
    assert verify_custody_form(tampered) is False


def test_verify_custody_form_missing_seal_is_false(tmp_path):
    """No seal at all → not verified (not an exception)."""
    from svetovid.governance.custody import create_custody_form, verify_custody_form
    form = create_custody_form("case_1", _custody_artifacts(tmp_path), "alice")
    noseal = {k: v for k, v in form.items() if k != "integrity_seal"}
    assert verify_custody_form(noseal) is False


def test_verify_custody_form_dropped_item_is_false(tmp_path):
    """Removing an item after sealing must break the seal."""
    from svetovid.governance.custody import create_custody_form, verify_custody_form
    form = create_custody_form("case_1", _custody_artifacts(tmp_path), "alice")
    tampered = {**form, "items": form["items"][:1], "item_count": 1}
    assert verify_custody_form(tampered) is False


# ===========================================================================
# 9. IOC extraction from free-form text
# ===========================================================================


def test_extract_iocs_finds_ipv4():
    from svetovid.governance.ioc_store import extract_iocs_from_text
    out = extract_iocs_from_text("C2 beacon to 203.0.113.9 and 198.51.100.23")
    ips = [r for r in out if r["ioc_type"] == "ip"]
    assert {r["value"] for r in ips} == {"203.0.113.9", "198.51.100.23"}


def test_extract_iocs_finds_domains():
    from svetovid.governance.ioc_store import extract_iocs_from_text
    out = extract_iocs_from_text("phish at evil.example.com and bad.tld.xyz")
    domains = {r["value"] for r in out if r["ioc_type"] == "domain"}
    assert "evil.example.com" in domains
    assert "bad.tld.xyz" in domains


def test_extract_iocs_finds_sha256():
    from svetovid.governance.ioc_store import extract_iocs_from_text
    sha = "a" * 64
    out = extract_iocs_from_text(f"dropper hash {sha} seen on host")
    hashes = [r for r in out if r["ioc_type"] == "hash"]
    assert any(r["value"] == sha for r in hashes)
    # A 64-hex string must not be double-counted as md5 (32) or sha1 (40).
    assert sum(1 for r in hashes if r["value"] == sha) == 1


def test_extract_iocs_filters_loopback_ips():
    """127.x and 0.x must be filtered out (not useful IOCs)."""
    from svetovid.governance.ioc_store import extract_iocs_from_text
    out = extract_iocs_from_text("local 127.0.0.1 and bad 0.0.0.0 plus real 203.0.113.5")
    ips = {r["value"] for r in out if r["ioc_type"] == "ip"}
    assert "127.0.0.1" not in ips
    assert "0.0.0.0" not in ips
    assert "203.0.113.5" in ips


def test_extract_iocs_empty_text():
    from svetovid.governance.ioc_store import extract_iocs_from_text
    assert extract_iocs_from_text("") == []
    assert extract_iocs_from_text(None) == []  # type: ignore[arg-type]


def test_extract_iocs_no_indicators():
    """Plain prose with no indicator shapes returns an empty list."""
    from svetovid.governance.ioc_store import extract_iocs_from_text
    assert extract_iocs_from_text(
        "The analyst reviewed the logs and found nothing of note today.") == []


def test_extract_iocs_dedupes():
    """The same indicator repeated several times appears once."""
    from svetovid.governance.ioc_store import extract_iocs_from_text
    out = extract_iocs_from_text("hit 203.0.113.9 then 203.0.113.9 again 203.0.113.9")
    ips = [r for r in out if r["ioc_type"] == "ip" and r["value"] == "203.0.113.9"]
    assert len(ips) == 1
