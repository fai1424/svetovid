"""Edge-case tests for the report exporters and the telemetry system.

This module is deliberately *complementary* to ``test_report.py`` and
``test_telemetry.py``: it targets the boundary / degenerate inputs and the
public contracts of:

  * ``svetovid.report.exporters``  — export_markdown / export_stix /
    export_case_uco / export_json
  * ``svetovid.report.pdf_renderer`` — render_pdf / is_pdf
  * ``svetovid.report.templates`` — render_template
  * ``svetovid.telemetry.client_id`` — get_client_id
  * ``svetovid.telemetry.collector`` — TelemetryCollector (metrics shape,
    privacy filtering, settings toggle)
  * ``svetovid.telemetry.uploader`` — Uploader (no-op, drain, retain, batch)
  * ``svetovid.telemetry.server`` — standalone FastAPI collection server

Run with::

    cd backend && PYTHON_KEYRING_BACKEND=keyring.backends.fail.Keyring \\
        SVETOVID_HITL_AUTO_APPROVE=1 pytest -q tests/test_export_telemetry_edge.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid

import pytest


# ---------------------------------------------------------------------------
# Shared isolation: throwaway HOME + fail-keyring + fresh module state.
# The config module caches ``APP_DIR`` at import time, so any test that reads
# settings or the client_id file must run against re-imported modules.
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


# ---------------------------------------------------------------------------
# A realistic gathered-data blob used by the exporter tests.
# ---------------------------------------------------------------------------


def _sample_data() -> dict:
    """Two sections, two IOCs, two timeline rows, one finding, two techniques,
    two tool calls — the shape ``gather_investigation_data`` returns."""
    return {
        "investigation": {
            "id": "inv_edge_1",
            "case_id": "default",
            "goal_id": "G07",
            "evidence_path": "/cases/default/inv_edge_1/evidence",
            "user_prompt": "Find the C2 channel and reconstruct beaconing.",
            "status": "done",
            "started_at": "2026-07-27T10:00:00Z",
            "ended_at": "2026-07-27T10:42:00Z",
        },
        "tool_calls": [
            {
                "tool": "chainsaw_hunt",
                "args": {"path": "/cases/default/inv_edge_1/evidence", "min_level": "high"},
                "exit_code": 0, "duration_s": 9.5,
                "output_hash": "sha256:cafef00d", "ts": "2026-07-27T10:01:00Z",
            },
        ],
        "events": [],
        "report_sections": [
            {"section_id": "summary", "title": "Executive Summary",
             "markdown": "Initial access via spear-phish, then **T1059.001**.",
             "order": 0, "ts": "2026-07-27T10:40:00Z", "node": "finalize"},
            {"section_id": "narrative", "title": "Technical Narrative",
             "markdown": "Detailed walkthrough of the beacon.", "order": 1,
             "ts": "2026-07-27T10:41:00Z", "node": "draft"},
        ],
        "iocs": [
            {"type": "ipv4", "value": "198.51.100.7", "description": "C2 server",
             "mitre_tags": ["T1071.001"], "ts": "2026-07-27T10:30:00Z"},
            {"type": "sha256", "value": "b" * 64, "description": "beacon implant",
             "ts": "2026-07-27T10:31:00Z"},
        ],
        "timeline": [
            {"timestamp": "2026-07-27T10:05:00Z", "source": "Chainsaw",
             "actor": "WIN-DEV", "event": "powershell.exe spawned",
             "mitre_tags": ["T1059.001"], "ts": "2026-07-27T10:05:00Z"},
            {"timestamp": "2026-07-27T10:06:00Z", "source": "Zeek",
             "actor": "WIN-DEV", "event": "DNS query for evil.test",
             "mitre_tags": ["T1071.004"], "ts": "2026-07-27T10:06:00Z"},
        ],
        "findings": [
            {"title": "Beacon beaconing every 60s", "description": "...",
             "ts": "2026-07-27T10:35:00Z"},
        ],
        "attack_techniques": ["T1059.001", "T1071.001"],
    }


# ===========================================================================
# 1. Markdown export
# ===========================================================================


def test_export_markdown_empty_investigation_still_has_title():
    """A completely empty ``investigation_data`` must still render a header."""
    from svetovid.report.exporters import export_markdown

    md = export_markdown({})
    assert isinstance(md, str) and md.strip()
    # The title line is always emitted so the doc is never blank.
    assert "# Svetovid Investigation Report" in md
    # Placeholder note appears when there are no sections.
    assert "No report sections" in md
    # No IOC / timeline tables when those lists are absent.
    assert "Indicators of Compromise" not in md
    assert "Timeline" not in md


def test_export_markdown_sections_render_in_declared_order():
    """Sections given out of order are sorted by ``order`` before concat."""
    from svetovid.report.exporters import export_markdown

    data = _sample_data()
    # Reverse the stored order to force the sort path.
    data["report_sections"] = list(reversed(data["report_sections"]))
    md = export_markdown(data)
    assert md.index("## Executive Summary") < md.index("## Technical Narrative")


def test_export_markdown_includes_ioc_table():
    from svetovid.report.exporters import export_markdown

    md = export_markdown(_sample_data())
    assert "## Indicators of Compromise" in md
    # Both IOC values and their descriptions appear.
    assert "198.51.100.7" in md
    assert "C2 server" in md
    assert ("b" * 64) in md
    assert "ipv4" in md and "sha256" in md
    # Pipe characters in descriptions must not break the table.
    pipey = {"type": "url", "value": "http://x.test/p|q",
             "description": "a|b|c", "ts": "2026-07-27T10:30:00Z"}
    data = _sample_data()
    data["iocs"] = [pipey]
    md2 = export_markdown(data)
    # The escaped description replaces pipes with slashes inside the row.
    assert "a/b/c" in md2


def test_export_markdown_includes_timeline_entries():
    from svetovid.report.exporters import export_markdown

    md = export_markdown(_sample_data())
    assert "## Timeline" in md
    assert "powershell.exe spawned" in md
    assert "DNS query for evil.test" in md
    # The actor + source columns are populated.
    assert "WIN-DEV" in md
    assert "Chainsaw" in md and "Zeek" in md
    # ATT&CK tags column is filled from mitre_tags.
    assert "T1059.001" in md


# ===========================================================================
# 2. STIX 2.1 export
# ===========================================================================


def test_export_stix_bundle_structure_is_valid():
    """Top-level envelope is ``{"type": "bundle", "id": "bundle--uuid"}``."""
    from svetovid.report.exporters import export_stix

    bundle = export_stix(_sample_data())
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert isinstance(bundle["objects"], list) and bundle["objects"]
    # Must round-trip through JSON (it crosses the wire).
    json.dumps(bundle)


def test_export_stix_each_known_ioc_becomes_indicator_with_pattern():
    """Every IOC whose type maps to a STIX pattern becomes an Indicator SDO
    carrying a valid ``[prop = 'value']`` pattern string."""
    from svetovid.report.exporters import export_stix

    bundle = export_stix(_sample_data())
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 2  # ipv4 + sha256 both map

    for ind in indicators:
        assert ind["spec_version"] == "2.1"
        assert ind["pattern_type"] == "stix"
        assert ind["indicator_types"] == ["malicious-activity"]
        pat = ind["pattern"]
        assert pat.startswith("[") and pat.endswith("]")
        assert " = '" in pat

    # ipv4 IOC uses the ipv4-addr pattern; sha256 uses file:hashes.SHA-256.
    patterns = {i["pattern"] for i in indicators}
    assert any("ipv4-addr:value" in p and "198.51.100.7" in p for p in patterns)
    assert any("file:hashes.SHA-256" in p for p in patterns)


def test_export_stix_empty_iocs_yields_identity_and_report_only():
    """No IOCs and no techniques → bundle still has identity + report, nothing else."""
    from svetovid.report.exporters import export_stix

    data = _sample_data()
    data["iocs"] = []
    data["attack_techniques"] = []
    bundle = export_stix(data)
    types = [o["type"] for o in bundle["objects"]]
    assert types == ["identity", "report"]
    # The report references nothing.
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert report["object_refs"] == []


def test_export_stix_attack_techniques_become_attack_pattern_sdos():
    """Each ATT&CK technique id is an attack-pattern with a mitre-attack ref."""
    from svetovid.report.exporters import export_stix

    bundle = export_stix(_sample_data())
    aps = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    assert len(aps) == 2
    ext_ids = set()
    for ap in aps:
        for ref in ap.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_ids.add(ref["external_id"])
                assert ref["url"].startswith("https://attack.mitre.org/techniques/")
    assert {"T1059.001", "T1071.001"} <= ext_ids
    # Relationships link the report → each attack-pattern via "uses".
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert len(rels) == 2 and all(r["relationship_type"] == "uses" for r in rels)


def test_export_stix_ids_follow_type_dash_uuid_format():
    """Every STIX id is ``{type}--{rfc4122 uuid}`` and deterministic."""
    import re
    from svetovid.report.exporters import export_stix

    data = _sample_data()
    b1 = export_stix(data)
    b2 = export_stix(data)  # second run over identical data

    id_re = re.compile(r"^[a-z-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    for o in b1["objects"]:
        assert id_re.match(o["id"]), o["id"]
        # the uuid portion parses and is version 4
        uuid.UUID(o["id"].split("--", 1)[1])

    # Deterministic: same data → identical ids (stable diffs, no UUID churn).
    assert [o["id"] for o in b1["objects"]] == [o["id"] for o in b2["objects"]]


# ===========================================================================
# 3. CASE (UCO) export
# ===========================================================================


def test_export_case_uco_context_includes_uco_namespace_and_has_case():
    """The JSON-LD ``@context`` carries the UCO namespace and the bundle has a
    Bundle (Case) typed node."""
    from svetovid.report.exporters import export_case_uco

    case = export_case_uco(_sample_data())
    ctx = case["@context"]
    assert "uco" in ctx and ctx["uco"].startswith("https://ontology.unifiedcyberontology.org")
    assert "uco-core" in ctx and "uco-observable" in ctx
    # @graph is a non-empty list of JSON-LD nodes.
    assert isinstance(case["@graph"], list) and case["@graph"]
    types = {n.get("@type") for n in case["@graph"]}
    # The Case (Bundle) node + the instrument are both present.
    assert "uco-core:Bundle" in types
    assert "uco-action:Instrument" in types


def test_export_case_uco_empty_data_is_minimal_valid_bundle():
    """Completely empty input still yields a valid JSON-LD bundle envelope."""
    from svetovid.report.exporters import export_case_uco

    case = export_case_uco({})
    assert "@context" in case and "@graph" in case
    assert case["@type"] == "uco-core:Bundle"
    # The case node and instrument node always exist.
    types = [n.get("@type") for n in case["@graph"]]
    assert "uco-core:Bundle" in types
    # No evidence / iocs → Bundle.uco-core:object is an empty list, not missing.
    bundle_node = next(n for n in case["@graph"] if n.get("@type") == "uco-core:Bundle")
    assert bundle_node["uco-core:object"] == []
    json.dumps(case)  # serializable


def test_export_case_uco_evidence_items_carry_hash_facets():
    """Evidence paths touched by a tool call with an output_hash get a
    ContentData facet carrying the SHA-256 hash."""
    from svetovid.report.exporters import export_case_uco

    case = export_case_uco(_sample_data())
    observables = [n for n in case["@graph"]
                   if n.get("@type") == "uco-observable:ObservableObject"]
    assert observables, "expected at least one evidence observable"

    found_hash = False
    found_file_path = False
    for obs in observables:
        for facet in obs.get("uco-core:hasFacet", []):
            if facet.get("@type") == "uco-observable:File":
                assert facet["uco-observable:filePath"] == "/cases/default/inv_edge_1/evidence"
                found_file_path = True
            if facet.get("@type") == "uco-observable:ContentData":
                for h in facet.get("uco-observable:hash", []):
                    if h.get("uco-types:hashValue") == "sha256:cafef00d":
                        found_hash = True
    assert found_file_path
    assert found_hash, "the evidence item should carry the tool call's hash facet"


# ===========================================================================
# 4. JSON export
# ===========================================================================


def test_export_json_includes_all_metadata_and_sub_blobs():
    """export_json carries investigation metadata plus every sub-blob through
    verbatim, sorted where order matters."""
    from svetovid.report.exporters import export_json

    blob = export_json(_sample_data())
    assert blob["schema"] == "svetovid.investigation.v1"
    assert "exported_at" in blob

    # Investigation metadata.
    assert blob["investigation"]["id"] == "inv_edge_1"
    assert blob["investigation"]["goal_id"] == "G07"
    assert blob["investigation"]["status"] == "done"

    # tool_calls carried through unchanged.
    assert len(blob["tool_calls"]) == 1
    assert blob["tool_calls"][0]["tool"] == "chainsaw_hunt"

    # IOCs.
    assert [i["value"] for i in blob["iocs"]] == ["198.51.100.7", "b" * 64]

    # Timeline.
    assert len(blob["timeline"]) == 2
    assert blob["timeline"][0]["source"] == "Chainsaw"

    # Report sections sorted by order.
    assert [s["section_id"] for s in blob["report_sections"]] == ["summary", "narrative"]
    assert blob["report_sections"][0]["order"] == 0

    # findings + techniques + events present.
    assert blob["findings"][0]["title"] == "Beacon beaconing every 60s"
    assert blob["attack_techniques"] == ["T1059.001", "T1071.001"]
    assert blob["events"] == []
    json.dumps(blob)


def test_export_json_empty_input_does_not_crash():
    """Empty input yields a well-formed envelope with empty sub-blobs."""
    from svetovid.report.exporters import export_json

    blob = export_json({})
    assert blob["schema"] == "svetovid.investigation.v1"
    assert blob["investigation"] == {}
    for key in ("tool_calls", "iocs", "timeline", "findings",
                "report_sections", "attack_techniques", "events"):
        assert blob[key] == [], key


# ===========================================================================
# 5. PDF renderer
# ===========================================================================


def test_render_pdf_returns_nonempty_bytes():
    from svetovid.report.pdf_renderer import render_pdf

    blob = render_pdf("# Heading\n\nbody", _sample_data())
    assert isinstance(blob, bytes) and len(blob) > 0


def test_is_pdf_correctly_identifies_format():
    """is_pdf is True only for the %PDF- magic, false for HTML / empty / other."""
    from svetovid.report.pdf_renderer import is_pdf

    assert is_pdf(b"%PDF-1.4\n...binary...")
    assert not is_pdf(b"<!DOCTYPE html><html>...")
    assert not is_pdf(b"")
    assert not is_pdf(b"%POSTSCRIPT-")
    # weasyprint isn't installed in this env → render_pdf returns HTML
    from svetovid.report.pdf_renderer import render_pdf
    assert not is_pdf(render_pdf("# t", _sample_data()))


def test_render_pdf_empty_markdown_still_produces_output():
    """An empty narrative still yields a printable artifact (title page etc.)."""
    from svetovid.report.pdf_renderer import render_pdf, is_pdf

    blob = render_pdf("", {})
    assert isinstance(blob, bytes) and len(blob) > 0
    # In this env it's the HTML fallback, never a bare empty string.
    assert not is_pdf(blob)
    assert b"<html" in blob[:300].lower()


# ===========================================================================
# 6. Templates
# ===========================================================================


def test_render_template_executive_summary_nonempty_with_counts():
    from svetovid.report.templates import render_template

    out = render_template("executive_summary", _sample_data())
    assert isinstance(out, str) and out.strip()
    assert "G07" in out
    # Counts appear in the prose.
    assert "1" in out  # one tool call
    # Findings section lists the recorded finding title.
    assert "Beacon beaconing every 60s" in out


def test_render_template_ioc_table_empty_iocs_handled_gracefully():
    """An empty IOC list renders the placeholder row, not an exception."""
    from svetovid.report.templates import render_template

    out = render_template("ioc_table", {"iocs": []})
    assert isinstance(out, str)
    # The table header is always present...
    assert "| Type | Value |" in out
    # ...and the {% else %} placeholder row is rendered.
    assert "no indicators recorded" in out


def test_render_template_unknown_name_raises_keyerror():
    from svetovid.report.templates import render_template

    with pytest.raises(KeyError):
        render_template("does_not_exist", _sample_data())


# ===========================================================================
# 7. Telemetry client_id
# ===========================================================================


def test_client_id_first_call_generates_valid_uuid_v4():
    from svetovid.telemetry import client_id as cid_mod

    cid = cid_mod.get_client_id()
    parsed = uuid.UUID(cid)          # raises if not a UUID
    assert parsed.version == 4
    assert cid == str(parsed)        # canonical lowercase form


def test_client_id_stable_across_calls_and_persisted():
    from svetovid.config import APP_DIR
    from svetovid.telemetry import client_id as cid_mod

    a = cid_mod.get_client_id()
    b = cid_mod.get_client_id()
    assert a == b
    assert (APP_DIR / "client_id.txt").read_text().strip() == a


def test_client_id_corrupt_file_is_regenerated():
    from svetovid.telemetry import client_id as cid_mod

    cid_mod.CLIENT_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
    cid_mod.CLIENT_ID_FILE.write_text("definitely-not-a-uuid\n")
    new = cid_mod.get_client_id()
    assert new != "definitely-not-a-uuid"
    assert uuid.UUID(new).version == 4
    # Subsequent reads reuse the regenerated id.
    assert cid_mod.get_client_id() == new


# ===========================================================================
# 8. Telemetry collector
# ===========================================================================


def _iso(base: str, add_seconds: float = 0) -> str:
    from datetime import datetime, timedelta, timezone
    d = datetime.fromisoformat(base.replace("Z", "+00:00"))
    return (d + timedelta(seconds=add_seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _publish_full_run(bus, inv_id: str = "inv_metrics") -> str:
    """Push a realistic event stream; returns the start timestamp."""
    from svetovid.agent import events as E

    bus.publish(E.investigation_start("case1", inv_id, "G07", ["n1", "n2"]))
    bus.publish(E.node_state_change(inv_id, "n1", "running"))
    bus.publish(E.scan_complete([
        {"family": "windows_event_logs", "kind": "evtx", "path": "/secret/Security.evtx"},
        {"family": "windows_event_logs", "kind": "evtx"},
        {"family": "pcap", "kind": "pcap"},
    ]))
    bus.publish(E.agent_action(inv_id, "chainsaw_hunt",
                               {"rules": "/secret/path", "api_key": "sk-LEAKED"}))
    bus.publish(E.tool_start(inv_id, "chainsaw_hunt",
                             {"evidence": "/secret/path", "token": "hush"}, True))
    bus.publish(E.tool_end(inv_id, "call_1", 0, 2.25, "sha256:abc"))
    bus.publish(E.node_state_change(inv_id, "n1", "done"))
    bus.publish(E.error_event(inv_id, "transient blip"))
    bus.publish(E.hitl_request(inv_id, "review", {"report": "TOP SECRET"}))
    bus.publish(E.investigation_end(inv_id, "done"))
    return "2026-07-27T12:00:00.000Z"


def test_collector_is_enabled_reads_settings_default_true():
    """With default settings, telemetry_enabled is True → is_enabled is True."""
    from svetovid.agent.events import EventBus
    from svetovid.telemetry.collector import TelemetryCollector

    col = TelemetryCollector(EventBus())
    assert col.is_enabled is True


def test_collector_is_enabled_false_when_disabled_in_settings():
    from svetovid.agent.events import EventBus
    from svetovid.config import load_settings, save_settings
    from svetovid.telemetry.collector import TelemetryCollector

    s = load_settings()
    s.telemetry_enabled = False
    save_settings(s)

    col = TelemetryCollector(EventBus())
    assert col.is_enabled is False


def test_collector_correct_metrics_shape_on_investigation_end():
    """investigation.end flushes one record with the documented metric shape."""
    from svetovid.agent.events import EventBus
    from svetovid.telemetry.collector import TelemetryCollector, drain_queue

    async def run():
        bus = EventBus()
        col = TelemetryCollector(bus)
        await col.start()
        try:
            _publish_full_run(bus)
            for _ in range(20):
                await asyncio.sleep(0.01)
        finally:
            await col.stop()
        rows = drain_queue(limit=10)
        assert len(rows) == 1
        rec = rows[0]
        assert rec["event"] == "investigation.complete"
        return rec

    rec = asyncio.run(run())
    props = rec["props"]
    # Required keys are all present with the expected types.
    assert props["investigation_id"] == "inv_metrics"
    assert props["goal_id"] == "G07"
    assert props["hitl_approved"] is True
    assert props["error_count"] == 1
    assert props["iteration_count"] == 1
    assert props["user_rating"] is None
    assert isinstance(props["duration_s"], (int, float))
    assert isinstance(props["node_durations"], dict)
    assert "n1" in props["node_durations"]
    # Tool calls recorded with exit code + duration (paired by FIFO).
    assert props["tool_calls"] == [
        {"tool": "chainsaw_hunt", "exit_code": 0, "duration_s": 2.25}
    ]
    # Evidence families are aggregated counts, not raw artifact dicts.
    assert props["evidence_types"] == {"windows_event_logs": 2, "pcap": 1}
    assert isinstance(props["svetovid_version"], str)


def test_collector_filters_out_all_pii():
    """Headline privacy guarantee: paths, args, keys, report content never leak."""
    from svetovid.agent.events import EventBus
    from svetovid.telemetry.collector import TelemetryCollector, drain_queue

    secret_path = "/secret/case/Security.evtx"
    secret_key = "sk-LEAKED"
    secret_token = "hush"
    secret_report = "TOP SECRET"

    async def run():
        bus = EventBus()
        col = TelemetryCollector(bus)
        await col.start()
        try:
            _publish_full_run(bus)
            for _ in range(20):
                await asyncio.sleep(0.01)
        finally:
            await col.stop()
        return drain_queue()

    rows = asyncio.run(run())
    blob = json.dumps(rows)
    for needle in (secret_path, secret_key, secret_token, secret_report, "api_key"):
        assert needle not in blob, f"PII leaked into telemetry: {needle!r}"


# ===========================================================================
# 9. Telemetry uploader (httpx MockTransport)
# ===========================================================================


def _monkeypatch_post(transport) -> None:
    """Redirect ``uploader._post`` through the given httpx MockTransport."""
    import httpx
    from svetovid.telemetry import uploader

    async def fake_post(endpoint, batch):
        async with httpx.AsyncClient(transport=transport) as client:
            resp = await client.post(endpoint, json=batch)
            resp.raise_for_status()

    uploader._post = fake_post


def _enable_endpoint(url: str) -> None:
    from svetovid.config import load_settings, save_settings
    s = load_settings()
    s.telemetry_enabled = True
    s.telemetry_endpoint = url
    save_settings(s)


def test_uploader_noop_when_telemetry_disabled():
    from svetovid.config import load_settings, save_settings
    from svetovid.telemetry import collector
    from svetovid.telemetry.uploader import Uploader

    s = load_settings()
    s.telemetry_enabled = False
    s.telemetry_endpoint = "https://analytics.test/api/v1/telemetry"
    save_settings(s)

    collector.enqueue_record("cid", "e", "ts", {"k": "v"})

    up = Uploader(interval_s=1)

    async def run():
        up.start()
        await asyncio.sleep(0.25)
        await up.stop()

    asyncio.run(run())
    # Disabled → records retained, never drained.
    assert collector.queue_count() == 1


def test_uploader_noop_when_endpoint_empty():
    from svetovid.telemetry import collector
    from svetovid.telemetry.uploader import Uploader

    # Default endpoint is "".
    collector.enqueue_record("cid", "e", "ts", {"k": "v"})

    up = Uploader(interval_s=1)

    async def run():
        up.start()
        await asyncio.sleep(0.25)
        await up.stop()

    asyncio.run(run())
    assert collector.queue_count() == 1


def test_uploader_success_drains_queue():
    import httpx
    from svetovid.telemetry import collector
    from svetovid.telemetry.uploader import Uploader

    received: list[list[dict]] = []

    def good_handler(request: httpx.Request) -> httpx.Response:
        received.append(json.loads(request.content.decode()))
        return httpx.Response(200, json={"ok": True})

    _monkeypatch_post(httpx.MockTransport(good_handler))
    _enable_endpoint("https://analytics.test/api/v1/telemetry")
    collector.enqueue_record("cid", "investigation.complete", "ts", {"goal_id": "G07"})

    up = Uploader(interval_s=1)

    async def run():
        up.start()
        for _ in range(30):
            await asyncio.sleep(0.05)
            if collector.queue_count() == 0:
                break
        await up.stop()

    asyncio.run(run())
    assert collector.queue_count() == 0
    assert received and received[0][0]["event"] == "investigation.complete"


def test_uploader_failure_retains_all_records():
    import httpx
    from svetovid.telemetry import collector
    from svetovid.telemetry.uploader import Uploader

    def fail_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    _monkeypatch_post(httpx.MockTransport(fail_handler))
    _enable_endpoint("https://analytics.test/api/v1/telemetry")

    collector.enqueue_record("cid", "e1", "ts1", {"a": 1})
    collector.enqueue_record("cid", "e2", "ts2", {"b": 2})
    before = collector.queue_count()
    assert before == 2

    up = Uploader(interval_s=1)

    async def run():
        up.start()
        for _ in range(30):
            await asyncio.sleep(0.05)
        await up.stop()

    asyncio.run(run())
    # Failed upload re-enqueues everything → nothing lost.
    assert collector.queue_count() == before


def test_uploader_respects_batch_limit():
    """A small batch_limit caps records per POST; extra records are uploaded
    on subsequent ticks and the queue still ends empty."""
    import httpx
    from svetovid.telemetry import collector
    from svetovid.telemetry.uploader import Uploader

    batch_sizes: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        batch = json.loads(request.content.decode())
        batch_sizes.append(len(batch))
        return httpx.Response(200, json={"ok": True})

    _monkeypatch_post(httpx.MockTransport(handler))
    _enable_endpoint("https://analytics.test/api/v1/telemetry")

    for i in range(3):
        collector.enqueue_record("cid", "e", f"ts{i}", {"i": i})

    up = Uploader(interval_s=1, batch_limit=2)

    async def run():
        up.start()
        for _ in range(40):
            await asyncio.sleep(0.05)
            if collector.queue_count() == 0:
                break
        await up.stop()

    asyncio.run(run())
    assert collector.queue_count() == 0
    assert batch_sizes, "no batches were uploaded"
    # No single batch exceeded the limit.
    assert all(n <= 2 for n in batch_sizes), batch_sizes
    # All three records were delivered across the batches.
    assert sum(batch_sizes) == 3


# ===========================================================================
# 10. Telemetry server (TestClient)
# ===========================================================================


def test_server_ingest_then_summary_aggregates(tmp_path, monkeypatch):
    """The standalone server accepts a batch and aggregates analytics."""
    from fastapi.testclient import TestClient
    from svetovid.telemetry.server import create_app

    # Point the analytics DB at a throwaway path so multiple test runs don't
    # collide on the shared default ~/.svetovid/analytics.db.
    monkeypatch.setenv("SVETOVID_ANALYTICS_DB", str(tmp_path / "analytics.db"))
    client = TestClient(create_app())

    # health check
    h = client.get("/health")
    assert h.status_code == 200 and h.json()["ok"] is True

    payload = [
        {"client_id": "c1", "event": "investigation.complete", "ts": "2026-07-27T10:00:00Z",
         "props": {"investigation_id": "i1", "goal_id": "G07", "duration_s": 100.0,
                   "tool_calls": [{"tool": "chainsaw_hunt", "exit_code": 0, "duration_s": 1.0}],
                   "iteration_count": 4, "error_count": 0}},
        {"client_id": "c1", "event": "user.rating", "ts": "2026-07-27T10:05:00Z",
         "props": {"investigation_id": "i1", "rating": 5, "feedback": None}},
    ]
    r = client.post("/api/v1/telemetry", json=payload)
    assert r.status_code == 200
    assert r.json() == {"accepted": 2, "rejected": 0}

    summary = client.get("/api/v1/analytics/summary").json()
    assert summary["avg_duration_by_goal"] == {"G07": 100.0}
    assert summary["goal_popularity"] == {"G07": 1}
    assert summary["tool_success_rate"]["chainsaw_hunt"]["rate"] == 1.0
    assert summary["avg_user_rating"] == 5
    assert summary["totals"]["investigations"] == 1
    assert summary["avg_iterations"] == 4.0


def test_server_rejects_non_array_payload(tmp_path, monkeypatch):
    """A non-array body is rejected by FastAPI (422) before the handler runs.

    Note: the handler raises ``HTTPException(400)`` on a non-list payload, but
    the ``payload: list[Any]`` signature makes pydantic validate the request
    body shape first, so the client sees a 422 (Unprocessable Entity) rather
    than the 400 the handler intends — the manual isinstance branch is
    effectively unreachable for a structurally-wrong body. Either way the
    endpoint never 500s and never ingests garbage.
    """
    from fastapi.testclient import TestClient
    from svetovid.telemetry.server import create_app

    monkeypatch.setenv("SVETOVID_ANALYTICS_DB", str(tmp_path / "analytics.db"))
    client = TestClient(create_app())
    r = client.post("/api/v1/telemetry", json={"not": "an array"})
    assert r.status_code in (400, 422)
    # Nothing was ingested.
    assert client.get("/api/v1/analytics/summary").json()["totals"]["investigations"] == 0
