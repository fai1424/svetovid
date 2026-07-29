"""Tests for the EnScript-equivalent tool wrappers (research item — Step 3).

These cover the eight tools that fill the EnCase EnScript gaps the OSS world
hadn't covered: PII scanning, timeline gap/tampering detection, USB history
correlation, Authenticode validation, ransomware decryptor lookup, evidence
relationship graphing, registry MRU/ShellBag/UserAssist interpretation, and
forensic Boolean search.

Strategy (mirroring ``test_tools_edge.py``):
  - Schema / contract checks run against each module-level ``tool`` instance.
  - The detection logic is exercised through the host-testable helpers each
    module exposes (regexes, gap stats, join logic, PE parser, decoders, query
    evaluator) so no Docker is required.
  - A few ``invoke`` paths run end-to-end against temp evidence dirs. Those
    go through ``run_in_sandbox``; because every ``svetovid/base`` wrapper
    sets ``host_fallback=True`` and the embedded parser is stdlib-only, the
    parser actually executes on the host in this environment, so we assert on
    real parsed output.
"""

from __future__ import annotations

import asyncio
import json
import struct
from pathlib import Path
from typing import Any

import pytest

from svetovid.tools import (
    decryptor_lookup,
    evidence_graph,
    forensic_search,
    pii_scanner,
    registry_mru,
    sigcheck,
    timeline_gap,
    usb_history,
)
from svetovid.tools.base import Tool, ToolContext

# The eight new wrappers, as module-level instances.
ALL_ENSCRIPT_TOOLS = [
    pii_scanner.tool,
    timeline_gap.tool,
    usb_history.tool,
    sigcheck.tool,
    decryptor_lookup.tool,
    evidence_graph.tool,
    registry_mru.tool,
    forensic_search.tool,
]

# Primitive JSON-schema types a flat tool schema may use.
_PRIMITIVE_TYPES = {"string", "number", "integer", "boolean", "array"}


# ---------------------------------------------------------------------------
# Fixtures / helpers (mirror test_tools_edge.py)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Keep the case DB / keyring hermetic: redirect HOME + disable keyring."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    import svetovid.store as _store
    monkeypatch.setattr(_store, "_db", None)
    yield


class _FakeBus:
    """Swallow every publish — tests assert on ToolResult, not events."""

    def publish(self, *args, **kwargs):
        return None


def _ctx(tmp_path) -> ToolContext:
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    (tmp_path / "evidence").mkdir(parents=True, exist_ok=True)
    return ToolContext(
        investigation_id="inv_enscript",
        case_id="case_enscript",
        bus=_FakeBus(),
        evidence_path=str(tmp_path / "evidence"),
        output_dir=str(out),
    )


# ---------------------------------------------------------------------------
# 0. Schema validation — every tool exposes a flat object schema
# ---------------------------------------------------------------------------

def _assert_flat_object_schema(schema: dict[str, Any]) -> None:
    assert schema["type"] == "object", f"schema type must be object, got {schema.get('type')!r}"
    props = schema.get("properties")
    assert isinstance(props, dict) and props, "schema must declare properties"
    for name, prop in props.items():
        assert isinstance(prop, dict), f"property {name!r} is not a dict"
        ptype = prop.get("type")
        assert ptype in _PRIMITIVE_TYPES, (
            f"property {name!r} has non-primitive type {ptype!r}; nested objects forbidden"
        )
        if ptype == "array":
            items = prop.get("items", {})
            itype = items.get("type") if isinstance(items, dict) else None
            assert itype in _PRIMITIVE_TYPES, (
                f"array property {name!r} items must be primitive, got {itype!r}"
            )
    if "required" in schema:
        assert isinstance(schema["required"], list)
        assert all(isinstance(r, str) for r in schema["required"])
        assert set(schema["required"]).issubset(props.keys())


@pytest.mark.parametrize("tool", ALL_ENSCRIPT_TOOLS, ids=lambda t: t.name)
def test_schema_is_flat_object(tool):
    _assert_flat_object_schema(tool.schema())


@pytest.mark.parametrize("tool", ALL_ENSCRIPT_TOOLS, ids=lambda t: t.name)
def test_instance_satisfies_tool_contract(tool):
    assert isinstance(tool, Tool)
    assert isinstance(tool.name, str) and tool.name
    assert isinstance(tool.description, str) and tool.description
    assert callable(tool.schema)
    assert isinstance(tool.schema(), dict)
    assert tool.image is None or isinstance(tool.image, str)


def test_tool_names_and_export():
    """Each module exports a ``tool`` with the expected canonical name."""
    expected = {
        pii_scanner: "pii_scan",
        timeline_gap: "timeline_gap_analysis",
        usb_history: "usb_history_correlate",
        sigcheck: "signature_check",
        decryptor_lookup: "ransomware_decryptor_check",
        evidence_graph: "evidence_correlate",
        registry_mru: "registry_mru_analyze",
        forensic_search: "forensic_keyword_search",
    }
    for module, name in expected.items():
        assert module.tool.name == name, f"{module.__name__}: expected {name!r}"


def test_decryptor_lookup_is_host_tool():
    """The decryptor lookup is API-based (no Docker image)."""
    assert decryptor_lookup.tool.image is None


def test_docker_tools_target_svetovid_base():
    """Seven of the eight tools run inside the svetovid/base image."""
    for t in (pii_scanner.tool, timeline_gap.tool, usb_history.tool,
              sigcheck.tool, evidence_graph.tool, registry_mru.tool,
              forensic_search.tool):
        assert t.image == "svetovid/base"


# ---------------------------------------------------------------------------
# 1. PII scanner
# ---------------------------------------------------------------------------

def test_pii_scanner_finds_ssn(tmp_path):
    f = tmp_path / "evidence" / "note.txt"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("employee ssn 123-45-6789 on file\n")
    res = asyncio.run(pii_scanner.tool.invoke(
        {"evidence_subpath": "", "patterns": ["ssn"]}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    ssn_hits = [h for h in res.data["hits"] if h["pattern_type"] == "ssn"]
    assert ssn_hits, "expected at least one SSN hit"
    assert ssn_hits[0]["match"] == "123-45-6789"
    assert ssn_hits[0]["line_number"] == 1


def test_pii_scanner_skips_invalid_ssn(tmp_path):
    """000-00-0000 must be rejected by the SSN validity rules."""
    hits = pii_scanner.scan_text("junk 000-00-0000 more junk", ["ssn"])
    assert hits == [], "invalid SSN (all-zero groups) must not be reported"


def test_pii_scanner_finds_api_key(tmp_path):
    f = tmp_path / "evidence" / "config.txt"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("aws key AKIAIOSFODNN7EXAMPLE deployed\n")
    res = asyncio.run(pii_scanner.tool.invoke(
        {"evidence_subpath": "", "patterns": ["api_key"]}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    api_hits = [h for h in res.data["hits"]
                if h["pattern_type"].startswith("api_key")]
    assert api_hits, "expected an AWS access-key hit"
    assert api_hits[0]["match"] == "AKIAIOSFODNN7EXAMPLE"


def test_pii_scanner_luhn_validates_credit_card(tmp_path):
    f = tmp_path / "evidence" / "card.txt"
    f.parent.mkdir(parents=True, exist_ok=True)
    # 4111 1111 1111 1111 is a canonical Luhn-valid test card;
    # 1234567890123456 is Luhn-invalid.
    f.write_text("valid 4111 1111 1111 1111 invalid 1234567890123456\n")
    res = asyncio.run(pii_scanner.tool.invoke(
        {"evidence_subpath": "", "patterns": ["credit_card"]}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    cc_hits = [h["match"] for h in res.data["hits"]
               if h["pattern_type"] == "credit_card"]
    assert "4111 1111 1111 1111" in cc_hits
    assert "1234567890123456" not in cc_hits


def test_pii_scanner_luhn_helper():
    assert pii_scanner.luhn_valid("4111111111111111") is True
    assert pii_scanner.luhn_valid("1234567890123456") is False
    assert pii_scanner.valid_ssn("123-45-6789") is True
    assert pii_scanner.valid_ssn("000-00-0000") is False
    assert pii_scanner.valid_ssn("900-12-3456") is False  # 900 area invalid


# ---------------------------------------------------------------------------
# 2. Timeline gap / tampering detector
# ---------------------------------------------------------------------------

def test_timeline_gap_detects_large_gap():
    """A 48-hour hole in an otherwise-hourly series is flagged."""
    base = 1_700_000_000.0
    hourly = [base + i * 3600 for i in range(20)]
    # 48-hour gap, then resume hourly.
    resume = base + 20 * 3600 + 48 * 3600
    hourly += [resume + j * 3600 for j in range(5)]
    gaps = timeline_gap.detect_gaps(hourly, sensitivity=2.0,
                                    expected_interval_hours=1.0)
    assert gaps, "expected at least one detected gap"
    big = max(gaps, key=lambda g: g["duration_hours"])
    assert big["duration_hours"] >= 48.0
    assert big["expected_events"] >= 48  # ~48 hourly events swallowed


def test_timeline_gap_no_gap_on_regular_series():
    """A perfectly regular series has no gaps above the threshold."""
    base = 1_700_000_000.0
    regular = [base + i * 3600 for i in range(50)]
    gaps = timeline_gap.detect_gaps(regular, sensitivity=2.0)
    assert gaps == []


def test_timeline_gap_timestomp_detection():
    rows = [
        {"file": "evil.exe", "si_time": 1_700_000_000.0,
         "fn_time": 1_700_000_000.0 - 86400 * 400},  # 400 days newer
        {"file": "normal.exe", "si_time": 1_700_000_000.0,
         "fn_time": 1_700_000_000.0},  # no delta
    ]
    suspects = timeline_gap.detect_timestomps(rows)
    assert len(suspects) == 1
    assert suspects[0]["file"] == "evil.exe"
    assert suspects[0]["delta_seconds"] >= 3600


def test_timeline_gap_invoke_text_logs(tmp_path):
    """End-to-end: a text log with a 48h hole produces a gap via invoke."""
    ev = tmp_path / "evidence" / "sec.log"
    ev.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    import datetime as _dt
    start = _dt.datetime(2026, 1, 1, 0, 0, 0, tzinfo=_dt.timezone.utc)
    for i in range(12):
        lines.append((start + _dt.timedelta(hours=i)).isoformat()
                     + " 4624 login")
    # 48h gap
    for i in range(12, 24):
        lines.append((start + _dt.timedelta(hours=i + 48)).isoformat()
                     + " 4624 login")
    ev.write_text("\n".join(lines) + "\n")
    res = asyncio.run(timeline_gap.tool.invoke(
        {"evidence_subpath": "", "expected_frequency": "hourly",
         "sensitivity": 2.0}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.data["gaps"], "expected a detected gap from the text log"


# ---------------------------------------------------------------------------
# 3. USB history correlator
# ---------------------------------------------------------------------------

def test_usb_history_parses_usbstor():
    """The correlate join merges per-source records by serial number."""
    usbstor = [{
        "serial": "0013729813B01F9B", "ven": "Kingston",
        "prod": "DataTraveler", "first_seen": "2026-06-01T00:00:00Z",
        "last_seen": "2026-06-10T00:00:00Z",
    }]
    usb = [{"serial": "0013729813B01F9B", "vid": "0951", "pid": "1666",
            "last_seen": "2026-06-10T00:00:00Z"}]
    mounted = [{"serial": "0013729813B01F9B", "mount_point": "E:"}]
    setupapi = [{"serial": "0013729813B01F9B",
                 "timestamp": "2026-05-01T00:00:00Z"}]
    ntuser = [{"serial": "0013729813B01F9B", "user": "alice",
               "last_seen": "2026-06-10T00:00:00Z"}]
    devices = usb_history.correlate_devices(usbstor, usb, mounted,
                                            setupapi, ntuser)
    assert len(devices) == 1
    d = devices[0]
    assert d["serial"] == "0013729813B01F9B"
    assert d["make"] == "Kingston"
    assert d["model"] == "DataTraveler"
    assert d["vid"] == "0951" and d["pid"] == "1666"
    assert d["first_seen"] == "2026-05-01T00:00:00Z"  # earliest from SetupAPI
    assert d["mounted_as"] == ["E:"]
    assert d["users_who_connected"] == ["alice"]


def test_usb_history_correlate_handles_missing_sources():
    """A device seen only in USBSTOR still surfaces (others empty)."""
    devices = usb_history.correlate_devices(
        [{"serial": "ABC", "ven": "SanDisk", "prod": "Cruzer"}],
        [], [], [], [],
    )
    assert len(devices) == 1
    assert devices[0]["make"] == "SanDisk"
    assert devices[0]["users_who_connected"] == []


def test_usb_history_invoke_no_hives(tmp_path):
    """No hives present -> the tool runs cleanly and reports zero devices."""
    ev = tmp_path / "evidence" / "empty"
    ev.mkdir(parents=True)
    res = asyncio.run(usb_history.tool.invoke(
        {"evidence_subpath": ""}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.data["devices"] == []


def test_usb_history_setupapi_log(tmp_path):
    """A SetupAPI.dev.log is parsed into install records via invoke."""
    ev = tmp_path / "evidence" / "Windows" / "inf"
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "setupapi.dev.log").write_text(
        ">>>  [Device Install (Hardware initiated)]\n"
        ">>>  Section: USBSTOR\\DiskVen_Kingston&Prod_DataTraveler#0013729813B01F9B\n"
        ">>>  start 2026-05-01 13:45:01.000\n"
    )
    res = asyncio.run(usb_history.tool.invoke(
        {"evidence_subpath": ""}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.data["devices"], "expected the SetupAPI-only device to surface"
    assert res.data["devices"][0]["serial"] == "0013729813B01F9B"


# ---------------------------------------------------------------------------
# 4. Signature check (Authenticode)
# ---------------------------------------------------------------------------

def _build_pe(signed: bool = False) -> bytes:
    """Build a minimal PE32. If ``signed``, append a fake WIN_CERTIFICATE."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    pe_sig_off = 64
    dos[0x3C:0x40] = struct.pack("<I", pe_sig_off)
    buf = bytearray(dos)
    buf += b"PE\x00\x00"
    opt_size = 224  # PE32: 96 base + 16 data dirs * 8
    buf += struct.pack("<HHIIIHH", 0x14C, 0, 0, 0, 0, opt_size, 0)
    opt_start = len(buf)
    buf += struct.pack("<H", 0x10B)            # PE32 magic
    buf += bytearray(opt_size - 2)            # rest zeroed
    sec_dir_off = opt_start + 96 + 4 * 8      # data dirs base + 4 entries
    if signed:
        # Append a fake WIN_CERTIFICATE after the headers and point the
        # security directory at it.
        cert_off = len(buf)
        fake_cert = (struct.pack("<IHH", 40, 0x0200, 2)  # dwLength, rev, type=PKCS#7
                     + b"\x30" + b"\x00" * 31)
        buf += fake_cert
        struct.pack_into("<II", buf, sec_dir_off, cert_off, len(fake_cert))
    else:
        struct.pack_into("<II", buf, sec_dir_off, 0, 0)
    return bytes(buf)


def test_signature_check_pe_unsigned(tmp_path):
    pe = _build_pe(signed=False)
    f = tmp_path / "evidence" / "tool.exe"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(pe)
    res = asyncio.run(sigcheck.tool.invoke(
        {"evidence_subpath": "", "check_type": "all"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    results = res.data["results"]
    assert len(results) == 1
    assert results[0]["is_pe"] is True
    assert results[0]["is_signed"] is False


def test_signature_check_pe_signed(tmp_path):
    pe = _build_pe(signed=True)
    f = tmp_path / "evidence" / "signed.dll"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(pe)
    res = asyncio.run(sigcheck.tool.invoke(
        {"evidence_subpath": "", "check_type": "authenticode"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    results = res.data["results"]
    assert results[0]["is_signed"] is True
    assert results[0]["thumbprint"]  # SHA-1 of the cert blob


def test_signature_check_skips_non_pe(tmp_path):
    ev = tmp_path / "evidence" / "readme.txt"
    ev.parent.mkdir(parents=True, exist_ok=True)
    ev.write_text("not a binary\n")
    res = asyncio.run(sigcheck.tool.invoke(
        {"evidence_subpath": "", "check_type": "all"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.data["results"] == []  # .txt is skipped


def test_signature_check_helper_rejects_non_pe():
    info = sigcheck.inspect_pe_bytes(b"not a PE file at all")
    assert info["is_pe"] is False
    assert info["is_signed"] is False


# ---------------------------------------------------------------------------
# 5. Ransomware decryptor lookup
# ---------------------------------------------------------------------------

def test_decryptor_lookup_known_family(tmp_path):
    res = asyncio.run(decryptor_lookup.tool.invoke(
        {"ransomware_family": "WannaCry"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.data["family"] == "wannacry"
    assert res.data["decryptor_available"] is True
    assert res.data["decryptor_url"]
    assert res.data["recovery_probability"] > 0.5


def test_decryptor_lookup_unknown_family(tmp_path):
    res = asyncio.run(decryptor_lookup.tool.invoke(
        {"ransomware_family": "TotallyUnknownRansom"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.data["decryptor_available"] is False
    assert res.data["recovery_probability"] == 0.0


def test_decryptor_lookup_extension_hint():
    """An encrypted extension resolves to a family even without a name."""
    assert decryptor_lookup.match_family(None, None, ".wcry") == "wannacry"
    assert decryptor_lookup.match_family(None, None, "WCry") == "wannacry"


def test_decryptor_lookup_note_keyword():
    note = "Your files have been encrypted by GandCrab. Pay now."
    assert decryptor_lookup.match_family(None, note, None) == "gandcrab"


def test_decryptor_lookup_no_input_errors(tmp_path):
    res = asyncio.run(decryptor_lookup.tool.invoke({}, _ctx(tmp_path)))
    assert res.exit_code == 1
    assert "no family" in res.data.get("error", "").lower()


def test_decryptor_lookup_offline_does_not_call_network(monkeypatch, tmp_path):
    """With httpx patched to raise, the static DB still answers."""
    import httpx

    async def _boom(self, *a, **kw):
        raise httpx.HTTPError("offline")

    monkeypatch.setattr(httpx.AsyncClient, "get", _boom)
    monkeypatch.setattr(httpx.AsyncClient, "post", _boom)
    res = asyncio.run(decryptor_lookup.tool.invoke(
        {"ransomware_family": "WannaCry"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.data["decryptor_available"] is True  # static DB answered


# ---------------------------------------------------------------------------
# 6. Evidence relationship grapher
# ---------------------------------------------------------------------------

def test_evidence_graph_same_hash():
    items = [
        {"file": "/host1/dropped.exe", "sha256": "deadbeefcafe"},
        {"file": "/host2/dropped.exe", "sha256": "deadbeefcafe"},
    ]
    rels = evidence_graph.find_relationships(items)
    same_hash = [r for r in rels if r["type"] == "same_hash"]
    assert len(same_hash) == 1
    assert same_hash[0]["source_item"] == "/host1/dropped.exe"
    assert same_hash[0]["target_item"] == "/host2/dropped.exe"
    assert same_hash[0]["confidence"] >= 0.9


def test_evidence_graph_same_actor():
    items = [
        {"file": "/a/log1", "user": "admin"},
        {"file": "/b/log2", "user": "admin"},
        {"file": "/c/log3", "user": "guest"},
    ]
    rels = evidence_graph.find_relationships(items)
    actor_rels = [r for r in rels if r["type"] == "same_actor"]
    assert len(actor_rels) == 1
    assert "admin" in actor_rels[0]["detail"]


def test_evidence_graph_process_tree():
    items = [{"parent_process": "powershell.exe", "process": "cmd.exe"}]
    rels = evidence_graph.find_relationships(items)
    tree = [r for r in rels if r["type"] == "process_tree"]
    assert len(tree) == 1
    assert tree[0]["source_item"] == "powershell.exe"
    assert tree[0]["target_item"] == "cmd.exe"


def test_evidence_graph_invoke(tmp_path):
    ctx_str = json.dumps([
        {"file": "/a/x", "sha256": "aaa"},
        {"file": "/b/y", "sha256": "aaa"},
    ])
    res = asyncio.run(evidence_graph.tool.invoke(
        {"investigation_context": ctx_str}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert any(r["type"] == "same_hash" for r in res.data["relationships"])


# ---------------------------------------------------------------------------
# 7. Registry MRU / ShellBag / UserAssist deep analyzer
# ---------------------------------------------------------------------------

def test_registry_mru_rot13():
    assert registry_mru.rot13("cmd.exe") == "pzq.rkr"
    assert registry_mru.rot13(registry_mru.rot13("anything")) == "anything"


def test_registry_mru_shellbags_path():
    path = registry_mru.reconstruct_shellbag_path(
        ["C:", "Users", "alice", "Documents", ""])
    assert path == "C:\\Users\\alice\\Documents"


def test_registry_mru_mrulist_order():
    ordered = registry_mru.parse_mrulist("ba", {"a": "foo.txt", "b": "bar.txt"})
    assert ordered == ["bar.txt", "foo.txt"]


def test_registry_mru_userassist_decode():
    # Win7 layout: 60 bytes min, run_count at offset 4, FILETIME at offset 60.
    data = bytearray(68)
    struct.pack_into("<I", data, 4, 7)  # run count = 7
    # A FILETIME ~ 2020-01-01 = 132223104000000000
    struct.pack_into("<Q", data, 60, 132223104000000000)
    decoded = registry_mru.decode_userassist_value("pzq.rkr", bytes(data))
    assert decoded["application"] == "cmd.exe"  # ROT13 reversed
    assert decoded["run_count"] == 7
    assert decoded["last_execution"] is not None


def test_registry_mru_unknown_key_type(tmp_path):
    res = asyncio.run(registry_mru.tool.invoke(
        {"key_path": "not_a_real_type"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 2


def test_registry_mru_filetime_helper():
    assert registry_mru.filetime_to_iso(0) is None
    iso = registry_mru.filetime_to_iso(132223104000000000)
    assert iso is not None
    assert iso.startswith("2020-")


# ---------------------------------------------------------------------------
# 8. Forensic keyword search
# ---------------------------------------------------------------------------

def test_forensic_search_finds_keyword(tmp_path):
    f = tmp_path / "evidence" / "secret.txt"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("the admin password is hunter2 do not share\n")
    res = asyncio.run(forensic_search.tool.invoke(
        {"evidence_subpath": "", "query": "hunter2",
         "context_chars": 12}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    results = res.data["results"]
    assert len(results) == 1
    r = results[0]
    assert r["match"] == "hunter2"
    assert r["line_number"] == 1
    assert "password" in r["context_before"]  # context before the match


def test_forensic_search_boolean(tmp_path):
    """'password AND admin' matches only files containing both terms."""
    both = tmp_path / "evidence" / "both.txt"
    only_pw = tmp_path / "evidence" / "pw.txt"
    both.parent.mkdir(parents=True, exist_ok=True)
    both.write_text("password admin combo\n")
    only_pw.write_text("password only here\n")
    res = asyncio.run(forensic_search.tool.invoke(
        {"evidence_subpath": "", "query": "password AND admin"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    files = {Path(r["file"]).name for r in res.data["results"]}
    assert files == {"both.txt"}  # pw.txt lacks 'admin'


def test_forensic_search_boolean_not():
    q = forensic_search.compile_query("password AND admin NOT test")
    assert forensic_search.evaluate_query(q, "the password is admin here") is True
    assert forensic_search.evaluate_query(q, "password test admin") is False


def test_forensic_search_phrase():
    q = forensic_search.compile_query('"secret key"')
    assert forensic_search.evaluate_query(q, "the secret key is here") is True
    assert forensic_search.evaluate_query(q, "secret other key") is False


def test_forensic_search_requires_query(tmp_path):
    res = asyncio.run(forensic_search.tool.invoke(
        {"query": ""}, _ctx(tmp_path),
    ))
    assert res.exit_code == 2


def test_forensic_search_skips_binary(tmp_path):
    """A .exe (binary) is skipped even if it contains the term as text."""
    ev = tmp_path / "evidence" / "malware.exe"
    ev.parent.mkdir(parents=True, exist_ok=True)
    ev.write_bytes(b"MZ\x90\x00\x03password\x00binary\xff")
    res = asyncio.run(forensic_search.tool.invoke(
        {"evidence_subpath": "", "query": "password"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.data["results"] == []
