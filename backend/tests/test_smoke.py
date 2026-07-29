"""Smoke tests for the M0 backend.

Run with::

    cd backend && pytest -q

These cover the pieces of M0 most likely to regress when the agent code
grows: settings persistence (and the api-key masking round-trip), evidence
signatures, scanner output shape, the goal registry, and the streaming
event constructors. They run against a temp ``HOME`` so they never touch the
real ``~/.svetovid``.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    """Run every test against a throwaway ~/.svetovid.

    Also force ``keyring`` to use its no-op fail backend so tests never block
    on the macOS Keychain GUI permission dialog (which would otherwise hang
    the entire pytest session).
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    # clear any cached singletons from previous tests
    import sys
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]
    yield fake_home


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def test_first_run_seeds_three_providers(isolated_home):
    from svetovid.config import load_settings
    s = load_settings()
    assert set(s.providers) == {"ollama", "glm", "kimi"}
    assert s.providers["glm"].base_url.startswith("https://open.bigmodel.cn")
    assert s.providers["kimi"].base_url == "https://api.moonshot.cn/v1"
    assert s.active_provider is None  # user must pick on ApiKeySetup


def test_settings_round_trip_strips_api_key(isolated_home):
    from svetovid.config import Provider, load_settings, save_settings
    s = load_settings()
    s.providers["glm"].api_key = "test-secret-key"
    s.active_provider = "glm"
    save_settings(s)

    # The on-disk JSON file MUST NOT contain the key.
    cfg = json.loads((isolated_home / ".svetovid" / "config.json").read_text())
    assert cfg["providers"]["glm"].get("api_key") in (None, "", "***"), \
        "API key leaked into config.json"

    # Reloading re-hydrates the key from keyring/fallback.
    s2 = load_settings()
    assert s2.providers["glm"].api_key == "test-secret-key"
    assert s2.active_provider == "glm"


def test_provider_defaults_carry_correct_models(isolated_home):
    from svetovid.config import load_settings
    s = load_settings()
    assert s.providers["ollama"].model.startswith("llama3.1")
    assert s.providers["glm"].model.startswith("glm-5")  # GLM-5.2
    assert s.providers["kimi"].model.startswith("moonshot-v1")


# ---------------------------------------------------------------------------
# evidence signatures + scanner
# ---------------------------------------------------------------------------


def test_signatures_detect_evtx_by_magic_and_extension():
    from svetovid.evidence.signatures import detect
    sigs = detect("Security.evtx", b"ElfFile\x00rest", 100)
    assert any(s.id == "evtx" for s in sigs)
    sigs = detect("foo.evtx", b"\x00" * 16, 100)
    assert any(s.id == "evtx" for s in sigs)


def test_signatures_detect_pcap_pcapng():
    from svetovid.evidence.signatures import detect
    # pcap LE
    assert any(s.id == "pcap" for s in detect("a", b"\xd4\xc3\xb2\xa1rest", 10))
    # pcapng SHB
    assert any(s.id == "pcap" for s in detect("a", b"\x0a\x0d\x0d\x0a", 10))


def test_signatures_detect_mft_by_filename():
    from svetovid.evidence.signatures import detect
    assert any(s.id == "mft" for s in detect("$MFT", b"FILE0rest", 1024))


def test_scanner_walks_folder_and_classifies(tmp_path):
    from svetovid.evidence.scanner import scan_folder

    (tmp_path / "Security.evtx").write_bytes(b"ElfFile\x00fake")
    (tmp_path / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1fake")
    (tmp_path / "README.txt").write_text("not evidence")
    sub = tmp_path / "Logs"
    sub.mkdir()
    (sub / "System.evtx").write_bytes(b"ElfFile\x00fake2")

    import asyncio
    arts = asyncio.run(scan_folder(str(tmp_path)))

    kinds = sorted(a["kind"] for a in arts)
    assert kinds == ["evtx", "evtx", "pcap"], f"unexpected kinds: {kinds}"
    # every artifact carries goal hints for the UI
    for a in arts:
        assert a["artifact_id"].startswith("B")
        assert isinstance(a["goals"], list) and a["goals"]


def test_scanner_handles_missing_path():
    from svetovid.evidence.scanner import scan_folder
    import asyncio
    with pytest.raises(FileNotFoundError):
        asyncio.run(scan_folder("/no/such/path/here"))


# ---------------------------------------------------------------------------
# goal registry
# ---------------------------------------------------------------------------


def test_registry_loads_g01():
    from svetovid.goals.registry import registry
    g = registry.get("G01")
    assert g is not None
    assert g.label == "Windows attack timeline"
    nodes = g.nodes()
    assert [n.id for n in nodes] == [
        "triage", "sigma_hunt", "enrich_attack", "correlate",
        "draft_report", "hitl_review", "finalize",
    ]
    assert "B3" in g.input_artifacts and "B8" in g.input_artifacts


def test_goal_manifest_round_trip_is_json_serializable():
    from svetovid.goals.registry import registry
    g = registry.get("G01")
    m = g.manifest()
    # must serialize cleanly (it goes over the wire to the UI)
    s = json.dumps(m)
    m2 = json.loads(s)
    assert m2["id"] == "G01"
    assert len(m2["nodes"]) == 7


def test_goal_detect_scores_evidence_overlap():
    from svetovid.goals.registry import registry
    g = registry.get("G01")
    # B3 + B8 present → score should be 1.0
    ev = [{"artifact_id": "B3"}, {"artifact_id": "B8"}]
    assert g.detect(ev) == 1.0
    # neither present → 0
    assert g.detect([{"artifact_id": "B6"}]) == 0.0


# ---------------------------------------------------------------------------
# event protocol
# ---------------------------------------------------------------------------


def test_event_constructors_produce_ws_serializable_dicts():
    from svetovid.agent import events as E
    for ev in [
        E.investigation_start("c1", "i1", "G01", ["a", "b"]),
        E.scan_progress(10, 100, {"evtx": 5}),
        E.tool_start("i1", "chainsaw_hunt", {"min_level": "medium"}, True),
        E.tool_end("i1", "call_1", 0, 1.23, "sha256:abc"),
        E.node_state_change("i1", "triage", "running"),
        E.report_section_added("i1", "s1", "Title", "## body"),
        E.error_event("i1", "boom", fatal=True),
    ]:
        d = ev.to_ws()
        assert d["type"]
        assert d["ts"]
        json.dumps(d)  # must not raise


def test_event_bus_publish_subscribe_roundtrip():
    import asyncio
    from svetovid.agent.events import EventBus, investigation_start

    async def run():
        bus = EventBus()
        q = bus.subscribe()
        bus.publish(investigation_start("c", "i", "G01", ["n"]))
        got = await asyncio.wait_for(q.get(), timeout=1)
        assert got["type"] == "investigation.start"
        assert got["case_id"] == "c"
        bus.unsubscribe(q)

    asyncio.run(run())


# ---------------------------------------------------------------------------
# tool wrappers (no Docker needed)
# ---------------------------------------------------------------------------


def test_chainsaw_schema_is_flat_and_llm_friendly():
    from svetovid.tools.chainsaw import ChainsawTool
    schema = ChainsawTool().schema()
    assert schema["type"] == "object"
    # only primitive types — no nested objects, keeps GLM/KIMI tool-calling reliable
    for prop in schema["properties"].values():
        assert prop["type"] in ("string", "number", "boolean", "array"), prop


def test_mitre_reverse_event_returns_known_technique():
    import asyncio
    from svetovid.tools.mitre_attack import MitreAttackTool
    from svetovid.tools.base import ToolContext
    from svetovid.agent.events import EventBus

    class FakeBus(EventBus):
        def publish(self, *a, **k):
            pass  # swallow

    ctx = ToolContext(
        investigation_id="i",
        case_id="c",
        bus=FakeBus(),
        evidence_path="/tmp",
        output_dir="/tmp",
    )

    res = asyncio.run(MitreAttackTool().invoke(
        {"op": "reverse_event", "event_id": "4688"}, ctx
    ))
    candidates = res.data["candidates"]
    ids = [c["id"] for c in candidates]
    assert "T1059" in ids  # process creation → command interpreter
