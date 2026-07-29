"""Phase-3 integration test: end-to-end scan → detection → G01 investigation.

This is the NEW test added as part of Phase-3 deployment hardening. It does
NOT modify the existing smoke/react/goals tests; it sits alongside them and
exercises the realistic happy-path a user hits on first run:

  1. ``scan_folder`` walks ``tests/fixtures/`` and classifies the synthetic
     ``security.evtx`` and ``capture.pcap`` that ``generate_fixtures.py``
     produced (REAL artifacts with valid magic bytes, not stubs).
  2. We assert the scanner reports exactly one EVTX (``kind == "evtx"``) and
     one PCAP (``kind == "pcap"``) with the correct research B-ids and goal
     hints — proving detection works on real file headers, not just extensions.
  3. We cross-check the G01 ``detect()`` score against the scanned evidence.
  4. We drive ``G01.run()`` to completion with a ``FakeBus`` (an ``EventBus``
     subclass that swallows publishes, like the helper in ``test_smoke``).
     The goal shells out to Chainsaw via the sandbox runner; with no Docker
     and no host ``chainsaw`` binary, the ``host_fallback`` path returns a
     non-zero exit and the goal marks ``sigma_hunt`` failed with zero hits —
     the remaining nodes must still complete gracefully (no exception). We
     verify at least one event was published, every one of the 7 nodes
     reached a terminal status, and ``run()`` returned without raising.

The test is hermetic: it runs against a throwaway ``HOME`` (so it never
touches the real ``~/.svetovid``) and forces the no-op keyring backend so
the macOS Keychain dialog can't hang the session.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    """Run against a throwaway ``~/.svetovid`` + fail keyring backend.

    Mirrors the ``isolated_home`` fixture in ``test_smoke`` so every test here
    is hermetic and never blocks on the macOS Keychain GUI dialog.
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    # Clear cached svetovid singletons from sibling test modules.
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]
    yield fake_home


class _FakeBus:
    """A minimal stand-in for ``agent.events.EventBus`` that records every
    published event instead of queueing it for a WebSocket subscriber.

    The G01 goal only needs ``bus.publish(event)``; it never subscribes, so we
    avoid pulling in the asyncio.Queue machinery (which needs a running loop).
    """

    def __init__(self) -> None:
        self.events: list[dict] = []

    def publish(self, event) -> None:
        # Accept either an AgentEvent (has ``to_ws``) or a raw dict.
        if hasattr(event, "to_ws"):
            event = event.to_ws()
        self.events.append(event)


def _ensure_fixtures() -> None:
    """Regenerate the EVTX + PCAP fixtures if they're missing on disk.

    Lets the integration test be self-sufficient on a fresh clone. The
    generator script is loaded by path (the fixtures dir is a data folder,
    not an importable package) so we don't depend on ``sys.path`` hacks.
    """
    evtx = FIXTURES_DIR / "security.evtx"
    pcap = FIXTURES_DIR / "capture.pcap"
    if evtx.exists() and pcap.exists():
        return
    gen = FIXTURES_DIR / "generate_fixtures.py"
    assert gen.exists(), f"fixture generator missing: {gen}"
    spec = importlib.util.spec_from_file_location("_gen_fixtures", gen)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    module.main(["--out", str(FIXTURES_DIR)])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_fixtures_are_real_and_valid():
    """The EVTX/PCAP fixtures exist with correct magic bytes (not stubs).

    This guards against someone committing a zero-byte placeholder: a real
    EVTX starts with ``ElfFile\\x00`` and a libpcap capture starts with one
    of the documented pcap magic byte sequences.
    """
    _ensure_fixtures()
    evtx = FIXTURES_DIR / "security.evtx"
    pcap = FIXTURES_DIR / "capture.pcap"
    assert evtx.exists() and evtx.stat().st_size > 4096, "EVTX missing or empty"
    assert pcap.exists() and pcap.stat().st_size > 0, "PCAP missing or empty"
    assert evtx.read_bytes()[:8] == b"ElfFile\x00", "bad EVTX magic"
    # libpcap little-endian microsecond magic (the variant generate_fixtures emits).
    assert pcap.read_bytes()[:4] in (
        b"\xd4\xc3\xb2\xa1",  # pcap LE microsecond
        b"\xa1\xb2\xc3\xd4",  # pcap BE microsecond
        b"\x4d\x3c\xb2\xa1",  # pcap LE nanosecond
        b"\xa1\xb2\x3c\x4d",  # pcap BE nanosecond
        b"\x0a\x0d\x0d\x0a",  # pcapng SHB
    ), "bad PCAP magic"


def test_scan_folder_detects_evtx_and_pcap():
    """``scan_folder`` classifies the real fixtures by magic byte + extension.

    Must find exactly one ``evtx`` (B8, feeds G01/G02/G08) and one ``pcap``
    (B7, feeds G07/G08), each carrying a non-empty ``goals`` hint list.
    """
    _ensure_fixtures()
    from svetovid.evidence.scanner import scan_folder

    artifacts = asyncio.run(scan_folder(str(FIXTURES_DIR)))

    kinds = sorted(a["kind"] for a in artifacts)
    assert kinds == ["evtx", "pcap"], f"unexpected kinds: {kinds}"

    by_kind = {a["kind"]: a for a in artifacts}
    evtx = by_kind["evtx"]
    pcap = by_kind["pcap"]

    # Correct research B-family ids (see signatures.py).
    assert evtx["artifact_id"] == "B8"
    assert pcap["artifact_id"] == "B7"
    # Every artifact carries goal hints for the UI GoalSelect screen.
    assert isinstance(evtx["goals"], list) and evtx["goals"]
    assert isinstance(pcap["goals"], list) and pcap["goals"]
    # EVTX feeds G01 (attack timeline); this is what we run next.
    assert "G01" in evtx["goals"]
    # Paths point at the real fixture files, not temp stubs.
    assert evtx["path"].endswith("security.evtx")
    assert pcap["path"].endswith("capture.pcap")


def test_g01_detect_scores_scanned_evidence():
    """The G01 goal's ``detect()`` matches the scanned evidence overlap.

    With B3 + B8 in ``input_artifacts`` and B8 (EVTX) present in the scan,
    the score must be > 0. (We don't assert == 1.0 since the fixture set has
    no B3 image; that's the correct, honest signal.)
    """
    _ensure_fixtures()
    from svetovid.evidence.scanner import scan_folder
    from svetovid.goals.registry import registry

    g = registry.get("G01")
    assert g is not None
    artifacts = asyncio.run(scan_folder(str(FIXTURES_DIR)))
    score = g.detect(artifacts)
    assert 0.0 < score <= 1.0, f"G01 detect score should be positive, got {score}"


def test_g01_investigation_streams_events_without_crashing():
    """Drive ``G01.run()`` to completion and assert it streams + doesn't crash.

    With no Docker and no host ``chainsaw`` binary, the sandbox runner takes
    the ``host_fallback`` path: Chainsaw exits non-zero, the goal marks
    ``sigma_hunt`` failed with zero hits, and the remaining nodes (enrich,
    correlate, draft_report, hitl_review, finalize) complete on the empty
    timeline. The LLM narrative path falls back deterministically because no
    provider is configured in the isolated HOME. We assert:

      * ``run()`` returns without raising (no crash),
      * at least one event was published to the bus (the stream is live),
      * every one of the 7 nodes reaches a terminal status (done|failed|skipped).
    """
    _ensure_fixtures()
    from svetovid.goals.registry import registry

    g = registry.get("G01")
    assert g is not None

    node_ids = [n.id for n in g.nodes()]
    assert node_ids == [
        "triage", "sigma_hunt", "enrich_attack", "correlate",
        "draft_report", "hitl_review", "finalize",
    ]

    bus = _FakeBus()

    async def drive() -> None:
        await g.run(
            investigation_id="inv_test_1",
            case_id="case_test_1",
            evidence_path=str(FIXTURES_DIR),
            user_prompt="Reconstruct the attack timeline from the fixtures.",
            bus=bus,  # type: ignore[arg-type]
        )

    # Must not raise — the goal is responsible for degrading gracefully when
    # its sandboxed tools are unavailable (host_fallback returns non-zero,
    # not an exception).
    asyncio.run(drive())

    events = bus.events
    assert len(events) >= 1, "G01 run() produced no events (stream is dead)"

    # Collect the terminal status reached per node from node.state_change events.
    terminal = {"done", "failed", "skipped"}
    last_status: dict[str, str] = {}
    for ev in events:
        if ev.get("type") == "node.state_change":
            data = ev.get("data") or {}
            node = ev.get("node")
            status = data.get("status")
            if node and status:
                last_status[node] = status

    # Every declared node must have been driven to a terminal state. A node
    # that's stuck "pending" or "running" would indicate a control-flow bug.
    unfinished = [nid for nid in node_ids if last_status.get(nid) not in terminal]
    assert not unfinished, (
        f"nodes never reached a terminal state: {unfinished} "
        f"(statuses: {last_status})"
    )

    # The triage node always succeeds (we DO have .evtx files in the fixture
    # dir), so it must be "done" — not failed. This proves evidence discovery
    # ran against the real fixtures.
    assert last_status.get("triage") == "done", (
        f"triage should be done (EVTX fixtures present), got "
        f"{last_status.get('triage')!r}"
    )

    # At least one report section should be emitted (the timeline section is
    # always written, even on zero hits).
    report_sections = [e for e in events
                       if e.get("type") == "report.section_added"]
    assert report_sections, "no report.section_added events emitted"
