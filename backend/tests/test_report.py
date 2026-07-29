"""Tests for the report export pipeline (Gap 2/4/8).

Covers the four core exporters: ``export_markdown``,
``export_stix``, ``export_case_uco``, ``export_json``. The exporters are
pure functions on plain dicts, so we feed them a realistic
``investigation_data`` fixture and assert the structural contracts:

  * Markdown concatenates sections in order with a header table.
  * STIX bundle is a valid ``{"type": "bundle", ...}`` with Indicator +
    attack-pattern + Report objects, and Indicator ``pattern`` strings.
  * CASE bundle is JSON-LD with the required UCO ``@type`` nodes (Case,
    ObservableObject, Action, Relationship).
  * JSON includes every sub-blob (investigation, tool_calls, iocs,
    timeline, findings, report_sections, attack_techniques, events).

These tests do NOT touch the DB or the FastAPI app — they exercise the
exporters directly so they run hermetically alongside the existing suite.
"""

from __future__ import annotations

import json
import sys

import pytest


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    """Mirror the smoke-test isolation: throwaway HOME + fail keyring."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]
    yield fake_home


def _sample_investigation_data() -> dict:
    """A realistic gathered-data blob (the shape ``gather_investigation_data``
    returns). Two report sections, two IOCs, two timeline entries, one
    finding, two ATT&CK techniques, two tool calls."""
    return {
        "investigation": {
            "id": "inv_abc123",
            "case_id": "default",
            "goal_id": "G01",
            "evidence_path": "/cases/default/inv_abc123/evidence",
            "user_prompt": "Reconstruct the attack timeline.",
            "status": "done",
            "started_at": "2026-07-27T10:00:00Z",
            "ended_at": "2026-07-27T10:42:00Z",
            "report_markdown": "",
            "error": None,
        },
        "tool_calls": [
            {
                "tool": "chainsaw_hunt",
                "args": {"min_level": "medium",
                         "path": "/cases/default/inv_abc123/evidence"},
                "exit_code": 0, "duration_s": 12.3,
                "output_hash": "sha256:deadbeef", "ts": "2026-07-27T10:01:00Z",
            },
            {
                "tool": "mitre_attack", "args": {"op": "reverse_event", "event_id": "4688"},
                "exit_code": 0, "duration_s": 0.1, "output_hash": None,
                "ts": "2026-07-27T10:02:00Z",
            },
        ],
        "events": [],
        "report_sections": [
            {
                "section_id": "summary", "title": "Summary",
                "markdown": "## Summary\n2 ATT&CK-mapped events.",
                "order": 0, "ts": "2026-07-27T10:42:00Z", "node": "finalize",
            },
            {
                "section_id": "narrative", "title": "Investigator narrative",
                "markdown": "## Narrative\nThe attacker used **T1059.001** PowerShell.",
                "order": 1, "ts": "2026-07-27T10:40:00Z", "node": "draft_report",
            },
        ],
        "iocs": [
            {"type": "ipv4", "value": "203.0.113.5", "description": "C2 callback",
             "mitre_tags": ["T1071"], "ts": "2026-07-27T10:30:00Z"},
            {"type": "sha256", "value": "a" * 64, "description": "dropper binary",
             "ts": "2026-07-27T10:31:00Z"},
        ],
        "timeline": [
            {"timestamp": "2026-07-27T10:05:00Z", "source": "Chainsaw",
             "actor": "WIN-DEV", "event": "powershell.exe launched",
             "mitre_tags": ["T1059.001"], "ts": "2026-07-27T10:05:00Z"},
            {"timestamp": "2026-07-27T10:06:00Z", "source": "Chainsaw",
             "actor": "WIN-DEV", "event": "network connection to 203.0.113.5",
             "mitre_tags": ["T1071"], "ts": "2026-07-27T10:06:00Z"},
        ],
        "findings": [
            {"title": "PowerShell abuse", "description": "attacker ran powershell",
             "ts": "2026-07-27T10:35:00Z"},
        ],
        "attack_techniques": ["T1059.001", "T1071"],
    }


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def test_export_markdown_concatenates_sections():
    from svetovid.report.exporters import export_markdown
    data = _sample_investigation_data()
    md = export_markdown(data)

    # Header table is present and self-describing.
    assert "Svetovid Investigation Report" in md
    assert "inv_abc123" in md
    assert "G01" in md
    assert "/cases/default/inv_abc123/evidence" in md

    # Sections appear in declared order (summary before narrative).
    assert md.index("## Summary") < md.index("## Investigator narrative")
    # The narrative body is concatenated verbatim.
    assert "T1059.001" in md

    # IOCs and timeline tables are appended.
    assert "Indicators of Compromise" in md
    assert "203.0.113.5" in md
    assert "Timeline" in md
    assert "powershell.exe launched" in md


def test_export_markdown_handles_empty_sections():
    from svetovid.report.exporters import export_markdown
    data = _sample_investigation_data()
    data["report_sections"] = []
    data["iocs"] = []
    data["timeline"] = []
    md = export_markdown(data)
    # No sections → a placeholder note, but the header still renders.
    assert "Svetovid Investigation Report" in md
    assert "No report sections" in md


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------


def test_export_stix_produces_valid_bundle():
    from svetovid.report.exporters import export_stix
    data = _sample_investigation_data()
    bundle = export_stix(data)

    # Top-level bundle shape.
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert isinstance(bundle["objects"], list)
    assert len(bundle["objects"]) >= 4

    # Every object conforms to the STIX shape (type + spec_version + id).
    for obj in bundle["objects"]:
        assert "type" in obj
        assert obj.get("spec_version") == "2.1"
        assert obj["id"].startswith(obj["type"] + "--")

    # An identity (the tool) and a Report SDO are present.
    identities = [o for o in bundle["objects"] if o["type"] == "identity"]
    assert identities and identities[0]["name"] == "Svetovid"

    reports = [o for o in bundle["objects"] if o["type"] == "report"]
    assert len(reports) == 1
    report = reports[0]
    assert report["report_types"] == ["investigation"]
    assert "investigation" in report["report_types"]

    # Each IOC with a known type becomes an Indicator with a STIX pattern.
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 2
    patterns = [i["pattern"] for i in indicators]
    assert any("ipv4-addr:value" in p and "203.0.113.5" in p for p in patterns), patterns
    assert any("SHA-256" in p for p in patterns), patterns
    for ind in indicators:
        assert ind["pattern_type"] == "stix"
        assert ind["indicator_types"] == ["malicious-activity"]

    # Each ATT&CK technique is an attack-pattern with a mitre-attack external ref.
    aps = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    assert len(aps) == 2
    external_ids = {
        ref["external_id"]
        for ap in aps
        for ref in ap.get("external_references", [])
        if ref.get("source_name") == "mitre-attack"
    }
    assert {"T1059.001", "T1071"} <= external_ids

    # Relationships link the report to each attack-pattern via "uses".
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert rels and all(r["relationship_type"] == "uses" for r in rels)

    # Must be JSON-serializable (it goes over the wire).
    json.dumps(bundle)


def test_export_stix_handles_no_iocs():
    from svetovid.report.exporters import export_stix
    data = _sample_investigation_data()
    data["iocs"] = []
    data["attack_techniques"] = []
    bundle = export_stix(data)
    # Still a valid bundle with identity + report, just no indicators/aps.
    assert bundle["type"] == "bundle"
    types = {o["type"] for o in bundle["objects"]}
    assert "identity" in types
    assert "report" in types
    assert "indicator" not in types


# ---------------------------------------------------------------------------
# CASE (UCO)
# ---------------------------------------------------------------------------


def test_export_case_uco_has_required_types():
    from svetovid.report.exporters import export_case_uco
    data = _sample_investigation_data()
    case = export_case_uco(data)

    # JSON-LD envelope.
    assert "@context" in case
    assert "@graph" in case
    assert case["@type"] == "uco-core:Bundle"
    assert "uco" in case["@context"]

    types = [n.get("@type") for n in case["@graph"]]

    # The Case (Bundle) node.
    assert any(t == "uco-core:Bundle" for t in types), types
    # Evidence items as ObservableObjects.
    assert any(t == "uco-observable:ObservableObject" for t in types), types
    # Tool calls as Actions.
    assert any(t == "uco-action:Action" for t in types), types
    # IOC relationships as Relationships.
    assert any(t == "uco-core:Relationship" for t in types), types
    # The instrument (Svetovid) is present.
    assert any(t == "uco-action:Instrument" for t in types), types

    # The Bundle references all other nodes via uco-core:object.
    bundle_nodes = [n for n in case["@graph"] if n.get("@type") == "uco-core:Bundle"]
    assert bundle_nodes
    obj_refs = bundle_nodes[0].get("uco-core:object")
    assert isinstance(obj_refs, list) and len(obj_refs) >= 4, "Bundle must link its objects"

    # Must be JSON-LD serializable.
    json.dumps(case)


def test_export_case_uco_attaches_hash_facet():
    from svetovid.report.exporters import export_case_uco
    data = _sample_investigation_data()
    case = export_case_uco(data)

    # The evidence observable for /cases/.../evidence should carry a SHA-256
    # facet (the chainsaw tool call touched it and has an output_hash).
    obs = [n for n in case["@graph"]
           if n.get("@type") == "uco-observable:ObservableObject"]
    has_hash = False
    for o in obs:
        for facet in o.get("uco-core:hasFacet", []):
            if facet.get("@type") == "uco-observable:ContentData":
                for h in facet.get("uco-observable:hash", []):
                    if h.get("uco-types:hashValue") == "sha256:deadbeef":
                        has_hash = True
    assert has_hash, "expected a SHA-256 hash facet anchored to the tool call"


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def test_export_json_includes_all_data():
    from svetovid.report.exporters import export_json
    data = _sample_investigation_data()
    blob = export_json(data)

    assert blob["schema"] == "svetovid.investigation.v1"
    assert "exported_at" in blob

    # Every sub-blob is carried through verbatim.
    assert blob["investigation"]["id"] == "inv_abc123"
    assert blob["investigation"]["goal_id"] == "G01"
    assert len(blob["tool_calls"]) == 2
    assert blob["tool_calls"][0]["tool"] == "chainsaw_hunt"
    assert [s["section_id"] for s in blob["report_sections"]] == ["summary", "narrative"]
    assert blob["report_sections"][0]["order"] == 0
    assert blob["report_sections"][1]["order"] == 1
    assert [i["value"] for i in blob["iocs"]] == ["203.0.113.5", "a" * 64]
    assert len(blob["timeline"]) == 2
    assert blob["timeline"][0]["source"] == "Chainsaw"
    assert blob["findings"][0]["title"] == "PowerShell abuse"
    assert blob["attack_techniques"] == ["T1059.001", "T1071"]
    assert blob["events"] == []

    # Round-trip JSON.
    json.dumps(blob)


# ---------------------------------------------------------------------------
# Endpoint wiring — exercises /api/investigations/{id}/export through TestClient
# ---------------------------------------------------------------------------


def _seed_inv_for_export(db_path):
    """Create an investigation + some events directly in the SQLite DB so the
    export endpoint has real data to gather."""
    import aiosqlite
    import asyncio

    async def seed():
        async with aiosqlite.connect(str(db_path)) as conn:
            await conn.executescript(
                """
                INSERT OR IGNORE INTO cases (id, name, created_at, status)
                VALUES ('default', 'Default Case', '2026-07-27T00:00:00Z', 'active');

                INSERT OR REPLACE INTO investigations
                  (id, case_id, goal_id, evidence_path, user_prompt, status,
                   started_at, ended_at, report_markdown, error)
                VALUES
                  ('inv_export_test', 'default', 'G01', '/evidence', 'objective',
                   'done', '2026-07-27T10:00:00Z', '2026-07-27T10:30:00Z', '', NULL);

                INSERT OR REPLACE INTO tool_calls
                  (id, investigation_id, tool, args_json, exit_code, duration_s,
                   output_hash, ts)
                VALUES
                  ('call_1', 'inv_export_test', 'chainsaw_hunt',
                   '{"min_level":"medium"}', 0, 1.2, 'sha256:abc',
                   '2026-07-27T10:01:00Z');

                INSERT INTO events (investigation_id, type, ts, node, data_json) VALUES
                  ('inv_export_test', 'report.section_added',
                   '2026-07-27T10:30:00Z', 'finalize',
                   '{"section_id":"summary","title":"Summary","markdown":"## ok"}'),
                  ('inv_export_test', 'report.ioc',
                   '2026-07-27T10:30:00Z', 'sigma_hunt',
                   '{"type":"ipv4","value":"203.0.113.9","mitre_tags":["T1071"]}'),
                  ('inv_export_test', 'report.timeline_entry',
                   '2026-07-27T10:05:00Z', 'sigma_hunt',
                   '{"timestamp":"2026-07-27T10:05:00Z","source":"Chainsaw","event":"x","mitre_tags":["T1059.001"]}');
                """
            )
            await conn.commit()

    asyncio.run(seed())


def test_export_endpoint_returns_all_formats(tmp_path, monkeypatch):
    """The /export endpoint dispatches by ``format`` and is auth-protected."""
    # Isolate HOME so the app DB lives in tmp_path. (The autouse
    # ``isolated_home`` fixture already sets HOME + keyring for this module;
    # we additionally re-point HOME at a dir we control so the seeded DB
    # lands in a known place. ``exist_ok`` avoids colliding with the
    # autouse fixture's own tmp dir.)
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]

    # The lifespan inits the DB schema; seed rows after init.
    db_file = fake_home / ".svetovid" / "svetovid.db"

    from fastapi.testclient import TestClient
    from svetovid.main import app, AUTH_TOKEN

    with TestClient(app) as client:
        assert db_file.exists(), "lifespan should have created the DB"
        _seed_inv_for_export(db_file)

        auth = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        # 401 without auth.
        no_auth = client.get("/api/investigations/inv_export_test/export?format=json")
        assert no_auth.status_code == 401

        # markdown
        r = client.get("/api/investigations/inv_export_test/export?format=markdown",
                       headers=auth)
        assert r.status_code == 200, r.text
        assert "inv_export_test" in r.text
        assert "203.0.113.9" in r.text

        # json
        r = client.get("/api/investigations/inv_export_test/export?format=json",
                       headers=auth)
        assert r.status_code == 200
        body = r.json()
        assert body["investigation"]["id"] == "inv_export_test"
        assert len(body["iocs"]) == 1
        assert body["iocs"][0]["value"] == "203.0.113.9"
        assert "T1059.001" in body["attack_techniques"]

        # stix
        r = client.get("/api/investigations/inv_export_test/export?format=stix",
                       headers=auth)
        assert r.status_code == 200
        bundle = r.json()
        assert bundle["type"] == "bundle"
        types = {o["type"] for o in bundle["objects"]}
        assert {"identity", "report", "indicator"} <= types

        # case
        r = client.get("/api/investigations/inv_export_test/export?format=case",
                       headers=auth)
        assert r.status_code == 200
        case = r.json()
        assert "@graph" in case
        ctypes = {n.get("@type") for n in case["@graph"]}
        assert "uco-observable:ObservableObject" in ctypes

        # pdf (falls back to HTML since weasyprint isn't installed here)
        r = client.get("/api/investigations/inv_export_test/export?format=pdf",
                       headers=auth)
        assert r.status_code == 200
        body_bytes = r.content
        # Either real PDF or printable HTML — both are valid fallbacks.
        assert body_bytes[:5] == b"%PDF-" or b"<html" in body_bytes[:200].lower()

        # 404 for unknown investigation.
        r = client.get("/api/investigations/does_not_exist/export?format=json",
                       headers=auth)
        assert r.status_code == 404

        # 400 for bad format.
        r = client.get("/api/investigations/inv_export_test/export?format=docx",
                       headers=auth)
        assert r.status_code == 400


def test_pdf_renderer_returns_pdf_or_html_fallback():
    """``render_pdf`` works without weasyprint (returns printable HTML)."""
    from svetovid.report.pdf_renderer import is_pdf, render_pdf

    md = "# Title\n\nA short narrative."
    data = {
        "investigation": {"id": "i", "case_id": "c", "goal_id": "G01",
                          "status": "done", "started_at": "t0", "ended_at": "t1",
                          "evidence_path": "/e"},
        "report_sections": [],
        "iocs": [],
        "attack_techniques": [],
        "tool_calls": [],
    }
    blob = render_pdf(md, data)
    assert isinstance(blob, bytes) and len(blob) > 0
    # In this env weasyprint isn't installed → HTML fallback (not is_pdf).
    assert not is_pdf(blob)
    assert b"<html" in blob[:200].lower()
    assert b"Svetovid Investigation Report" in blob


def test_templates_render_known_names():
    """The Jinja2 templates render against an investigation_data context."""
    from svetovid.report.templates import render_template

    data = _sample_investigation_data()
    summary = render_template("executive_summary", data)
    assert "G01" in summary
    assert "indicator" in summary.lower()

    technical = render_template("technical_report", data)
    assert "Technical Report" in technical
    assert "T1059.001" in technical

    ioc_tbl = render_template("ioc_table", data)
    assert "203.0.113.5" in ioc_tbl

    tl_tbl = render_template("timeline_table", data)
    assert "powershell.exe launched" in tl_tbl

    # Unknown name → KeyError.
    with pytest.raises(KeyError):
        render_template("nope", data)
