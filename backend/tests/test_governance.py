"""Tests for the governance module (Gap 1 + Gap 3): evidence intake hashing,
chain-of-custody forms, and the threat-intel / IOC plumbing.

These run hermetically (throwaway HOME + fail keyring, same pattern as the
other test modules) and never hit the network — the threat-intel tool is
exercised against a stubbed httpx transport so the lookups are deterministic
and offline.
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    """Throwaway HOME + no-op keyring + fresh module cache per test."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]
    yield fake_home


# ---------------------------------------------------------------------------
# hashing
# ---------------------------------------------------------------------------


def test_hash_file_returns_sha256_and_md5(tmp_path):
    from svetovid.governance.hashing import hash_file

    payload = b"forensic-evidence-bytes" * 16
    p = tmp_path / "sample.bin"
    p.write_bytes(payload)

    rec = hash_file(p)

    assert rec["sha256"] == hashlib.sha256(payload).hexdigest()
    assert rec["md5"] == hashlib.md5(payload).hexdigest()
    assert rec["size"] == len(payload)
    assert rec["path"] == str(p)


def test_hash_file_skips_files_above_size_cap(tmp_path):
    from svetovid.governance.hashing import hash_file

    p = tmp_path / "big.bin"
    p.write_bytes(b"x")
    # Force a tiny cap so the 1-byte file is "too large".
    rec = hash_file(p, size_cap=0)
    assert rec["size"] == 1
    assert rec["sha256"] is None
    assert rec["md5"] is None
    assert rec["hash_skipped"] == "too_large"


def test_hash_file_never_raises_on_missing_file():
    from svetovid.governance.hashing import hash_file

    rec = hash_file(Path("/no/such/file/here.bin"))
    assert rec["sha256"] is None
    assert "error" in rec


def test_hash_evidence_batch_progress(tmp_path):
    from svetovid.governance.hashing import hash_evidence_batch

    paths = []
    for i in range(3):
        p = tmp_path / f"f{i}.bin"
        p.write_bytes(f"payload-{i}".encode())
        paths.append(p)

    seen: list[tuple[int, int]] = []

    def on_progress(done, total, record):
        seen.append((done, total))

    results = hash_evidence_batch(paths, on_progress=on_progress)

    assert len(results) == 3
    # progress callback fired once per file with monotonic done counts
    assert [d for d, _ in seen] == [1, 2, 3]
    assert all(t == 3 for _, t in seen)
    # every result carries the right size and a real sha256
    for rec, p in zip(results, paths):
        assert rec["size"] == p.stat().st_size
        assert rec["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()


def test_hash_evidence_batch_continues_past_bad_file(tmp_path):
    from svetovid.governance.hashing import hash_evidence_batch

    good = tmp_path / "good.bin"
    good.write_bytes(b"ok")
    results = hash_evidence_batch([good, Path("/no/such/missing.bin")])
    assert len(results) == 2
    assert results[0]["sha256"] is not None
    assert results[1]["sha256"] is None
    assert "error" in results[1]


# ---------------------------------------------------------------------------
# chain of custody
# ---------------------------------------------------------------------------


def _sample_artifacts(tmp_path) -> list[dict]:
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


def test_custody_form_has_integrity_seal(tmp_path):
    from svetovid.governance.custody import create_custody_form, verify_custody_form

    artifacts = _sample_artifacts(tmp_path)
    form = create_custody_form("case_1", artifacts, "analyst@svetovid")

    assert form["case_id"] == "case_1"
    assert form["collector_name"] == "analyst@svetovid"
    assert form["item_count"] == 2
    assert form["integrity_seal"].startswith("sha256:")
    assert len(form["items"]) == 2
    # chain sequence is 1-indexed and ordered
    assert [it["chain_sequence"] for it in form["items"]] == [1, 2]
    # the sealed fields are present on every item
    for it in form["items"]:
        assert it["sha256"] and it["md5"]
        assert it["size_bytes"] > 0
        assert it["collector_name"] == "analyst@svetovid"
    # a freshly created form verifies
    assert verify_custody_form(form) is True


def test_verify_custody_form_tamper_detection(tmp_path):
    from svetovid.governance.custody import create_custody_form, verify_custody_form

    form = create_custody_form("case_1", _sample_artifacts(tmp_path), "alice")
    assert verify_custody_form(form) is True

    # 1) mutate a sealed field (sha256) on an item
    tampered = {**form, "items": [dict(form["items"][0]) for _ in form["items"]]}
    tampered["items"][0]["sha256"] = "deadbeef" * 8
    assert verify_custody_form(tampered) is False

    # 2) mutate the collector identity (a sealed field)
    tampered2 = {**form, "items": [dict(it) for it in form["items"]]}
    tampered2["items"][0]["collector_name"] = "mallory"
    assert verify_custody_form(tampered2) is False

    # 3) drop an item
    tampered3 = {**form, "items": form["items"][:1]}
    assert verify_custody_form(tampered3) is False

    # 4) strip the seal entirely
    noseal = {k: v for k, v in form.items() if k != "integrity_seal"}
    assert verify_custody_form(noseal) is False


# ---------------------------------------------------------------------------
# scanner includes hashes
# ---------------------------------------------------------------------------


def test_scanner_includes_hashes(tmp_path):
    from svetovid.evidence.scanner import scan_folder

    (tmp_path / "Security.evtx").write_bytes(b"ElfFile\x00fake")
    (tmp_path / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1fake")

    arts = asyncio.run(scan_folder(str(tmp_path)))

    # both evtx + pcap should be classified and carry hashes in extra
    assert len(arts) == 2
    for a in arts:
        extra = a.get("extra") or {}
        assert extra.get("sha256"), f"missing sha256 on {a['path']}"
        assert extra.get("md5"), f"missing md5 on {a['path']}"
        # hash matches a fresh recompute
        assert extra["sha256"] == hashlib.sha256(Path(a["path"]).read_bytes()).hexdigest()


def test_scanner_hash_evidence_can_be_disabled(tmp_path):
    from svetovid.evidence.scanner import scan_folder

    (tmp_path / "Security.evtx").write_bytes(b"ElfFile\x00fake")
    arts = asyncio.run(scan_folder(str(tmp_path), hash_evidence=False))
    assert len(arts) == 1
    assert not (arts[0].get("extra") or {}).get("sha256")


# ---------------------------------------------------------------------------
# DB store: evidence_items + iocs
# ---------------------------------------------------------------------------


async def _fresh_db(tmp_path):
    from svetovid.store import CaseDB
    db = CaseDB(path=tmp_path / "t.db")
    await db.init()
    return db


def test_db_evidence_items_round_trip(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path)
        await db.record_evidence_item(
            "ev_1", "case_1", "/evidence/a.evtx", "sha256:aaa", "md5:bbb",
            1024, artifact_id="B8", family="Windows Event Logs",
            collector="alice",
        )
        await db.record_evidence_item(
            "ev_2", "case_1", "/evidence/b.pcap", None, None, 4096,
            artifact_id="B7", family="Packet Captures",
        )
        items = await db.list_evidence_items("case_1")
        assert len(items) == 2
        by_id = {it["id"]: it for it in items}
        assert by_id["ev_1"]["sha256"] == "sha256:aaa"
        assert by_id["ev_1"]["collector"] == "alice"
        assert by_id["ev_2"]["sha256"] is None
        await db.close()

    asyncio.run(run())


def test_db_iocs_round_trip(tmp_path):
    async def run():
        db = await _fresh_db(tmp_path)
        await db.record_ioc("ioc_1", "inv_9", "hash", "abc123",
                            context="yara hit", confidence=0.9,
                            mitre_technique="T1027")
        await db.record_ioc("ioc_2", "inv_9", "ip", "203.0.113.9")
        iocs = await db.list_iocs("inv_9")
        assert len(iocs) == 2
        assert iocs[0]["ioc_type"] == "hash"
        assert iocs[0]["value"] == "abc123"
        assert iocs[0]["mitre_technique"] == "T1027"
        assert iocs[1]["ioc_type"] == "ip"
        await db.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# IOC store helpers
# ---------------------------------------------------------------------------


def test_ioc_store_record_and_list(tmp_path, monkeypatch):
    async def run():
        # Point the singleton DB at a temp file so record_ioc/list_iocs persist.
        from svetovid import store as store_mod
        db = store_mod.CaseDB(path=tmp_path / "s.db")
        await db.init()
        monkeypatch.setattr(store_mod, "_db", db)

        from svetovid.governance.ioc_store import record_ioc, list_iocs, ioc_from_event
        ioc_id = await record_ioc("inv_x", "sha256", "deadbeef" * 8,
                                  context="amcache", confidence=0.8,
                                  mitre_technique="T1027")
        assert ioc_id.startswith("ioc_")
        listed = await list_iocs("inv_x")
        assert len(listed) == 1
        assert listed[0]["value"] == "deadbeef" * 8
        assert listed[0]["ioc_type"] == "hash"

        # ioc_from_event normalizes report.ioc payloads
        parsed = ioc_from_event({"data": {"value": "1.2.3.4", "type": "ipv4",
                                          "confidence": 0.5}})
        assert parsed["value"] == "1.2.3.4"
        assert parsed["ioc_type"] == "ipv4"  # alias kept as-is for storage
        await db.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# threat-intel tool (offline: stubbed httpx transport)
# ---------------------------------------------------------------------------


def _stub_transport(routes):
    """Build a httpx MockTransport from a {method+url: response} mapping.

    Responses are (status, json) tuples; a missing route yields 404 so VT's
    "no report" path is exercised naturally.
    """
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.method, request.url.path)
        for (method, path_prefix), resp in routes.items():
            if request.method == method and request.url.path.startswith(path_prefix):
                status, body = resp
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={"data": None})

    return httpx.MockTransport(handler)


def test_threat_intel_schema_is_flat():
    from svetovid.tools.threat_intel import ThreatIntelTool
    schema = ThreatIntelTool().schema()
    assert schema["type"] == "object"
    for name, prop in schema["properties"].items():
        assert prop["type"] in ("string", "number", "boolean", "array"), \
            f"{name}: non-primitive type {prop['type']}"
    # required args present
    assert "indicator_type" in schema["required"]
    assert "indicator_value" in schema["required"]


def test_threat_intel_lookup_aggregates_sources(monkeypatch):
    import asyncio
    from svetovid.tools.threat_intel import ThreatIntelTool
    from svetovid.tools.base import ToolContext
    from svetovid.agent.events import EventBus

    # Stub every outbound request the tool makes.
    routes = {
        ("GET", "/api/v3/files/"): (200, {
            "data": {"attributes": {
                "last_analysis_stats": {
                    "malicious": 41, "suspicious": 2, "undetected": 10,
                    "harmless": 0,
                },
                "reputation": -3,
            }},
        }),
        ("POST", "/api/v1/"): (200, {
            "query_status": "ok",
            "data": [{
                "tags": ["CobaltStrike", "exe"],
                "malware_printable": "Cobalt Strike",
                "confidence_level": 100,
            }],
        }),
    }

    real_asyncclient = None
    import httpx

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = _stub_transport(routes)
            super().__init__(*args, **kwargs)

    # Patch httpx at the module level — the tool imports it locally in invoke().
    monkeypatch.setattr(httpx, "AsyncClient", _PatchedClient)
    monkeypatch.setenv("VT_API_KEY", "fake-vt-key")

    class FakeBus(EventBus):
        def publish(self, *a, **k):
            pass  # swallow — we assert on the ToolResult, not events

    ctx = ToolContext(
        investigation_id="inv_t", case_id="case_t", bus=FakeBus(),
        evidence_path="/tmp", output_dir="/tmp",
    )
    res = asyncio.run(ThreatIntelTool().invoke(
        {"indicator_type": "hash",
         "indicator_value": "a" * 64,
         "sources": ["virustotal", "abuse_ch", "mip"]},
        ctx,
    ))

    assert res.exit_code == 0
    src = res.data["sources"]
    assert src["virustotal"]["status"] == "ok"
    assert src["virustotal"]["malicious"] == 41
    assert src["virustotal"]["total"] == 53
    assert src["virustotal"]["permalink"].startswith("https://www.virustotal.com/")
    assert src["abuse_ch"]["status"] == "ok"
    assert "CobaltStrike" in src["abuse_ch"]["tags"]
    # MalwareBazaar route wasn't stubbed → not_found, but lookup still succeeds.
    assert src["mip"]["status"] in ("not_found", "ok")
    assert "VT" in res.summary


def test_threat_intel_skips_vt_without_key(monkeypatch):
    import asyncio
    from svetovid.tools.threat_intel import ThreatIntelTool
    from svetovid.tools.base import ToolContext
    from svetovid.agent.events import EventBus

    # No VT_API_KEY set.
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("HOME", str(__import__("pathlib").Path("/tmp")))

    import httpx

    called = {"vt": False}

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = _stub_transport({})
            super().__init__(*args, **kwargs)

        async def get(self, url, **kwargs):
            if "virustotal" in url:
                called["vt"] = True
            return await super().get(url, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _PatchedClient)

    class FakeBus(EventBus):
        def publish(self, *a, **k):
            pass

    ctx = ToolContext(
        investigation_id="inv_t2", case_id="case_t", bus=FakeBus(),
        evidence_path="/tmp", output_dir="/tmp",
    )
    res = asyncio.run(ThreatIntelTool().invoke(
        {"indicator_type": "ip", "indicator_value": "203.0.113.10",
         "sources": ["virustotal"]}, ctx,
    ))
    assert res.exit_code == 0
    assert res.data["sources"]["virustotal"]["status"] == "skipped"
    assert "VT_API_KEY" in res.data["sources"]["virustotal"]["reason"]
    assert called["vt"] is False  # never even attempted the GET


def test_threat_intel_validates_indicator_type():
    import asyncio
    from svetovid.tools.threat_intel import ThreatIntelTool
    from svetovid.tools.base import ToolContext
    from svetovid.agent.events import EventBus

    class FakeBus(EventBus):
        def publish(self, *a, **k):
            pass

    ctx = ToolContext(
        investigation_id="inv_v", case_id="c", bus=FakeBus(),
        evidence_path="/tmp", output_dir="/tmp",
    )
    res = asyncio.run(ThreatIntelTool().invoke(
        {"indicator_type": "bogus", "indicator_value": "x"}, ctx,
    ))
    assert res.exit_code == 1
    assert "unsupported" in res.summary.lower()
