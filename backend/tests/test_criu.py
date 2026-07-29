"""Tests for the CRIU checkpoint parser tool and signature.

Exercises:
  - The pure-Python protobuf wire-format helpers (varint, length-delimited,
    32/64-bit, packed arrays).
  - The per-message interpreters (pstree / core / vma / creds / inetsk /
    regfile).
  - The .img framing reader (magic → img_version handling → PB entries).
  - The tool wrapper's flat-schema contract and graceful failure modes.
  - The CRIU checkpoint signature (directory detection by marker files).
  - An end-to-end synthetic CRIU dump: build inventory.img + pstree.img on
    disk, run the embedded subprocess parser, and verify the process tree
    comes back correctly.

The synthetic-dump helpers (``encode_pb_varint`` / ``encode_pb_field`` /
``write_img_file``) build minimal valid .img files without any protobuf
library — they emit the exact wire bytes the parser reads back.
"""

from __future__ import annotations

import asyncio
import json
import struct
from pathlib import Path

import pytest

from svetovid.tools import criu_parse
from svetovid.tools.base import ToolContext
from svetovid.tools.criu_parse import (
    CriuParseTool,
    ANALYSIS_TYPES,
    _parse_pb_fields,
    _read_img_file,
    _interpret_pstree,
    _interpret_vma,
    _interpret_creds,
    _interpret_inetsk,
    _interpret_regfile,
    _decode_varint,
)


# ---------------------------------------------------------------------------
# Isolation fixture — hermetic HOME + disabled keyring (mirrors test_smoke).
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    import svetovid.store as _store
    monkeypatch.setattr(_store, "_db", None)
    yield


class _FakeBus:
    """Swallow every publish — we assert on ToolResult, not events."""

    def publish(self, *args, **kwargs):
        return None


def _ctx(tmp_path) -> ToolContext:
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    (tmp_path / "evidence").mkdir(parents=True, exist_ok=True)
    return ToolContext(
        investigation_id="inv_criu",
        case_id="case_criu",
        bus=_FakeBus(),
        evidence_path=str(tmp_path / "evidence"),
        output_dir=str(out),
    )


# ---------------------------------------------------------------------------
# Protobuf wire-format encoder helpers (build the bytes the parser reads).
# ---------------------------------------------------------------------------

def encode_pb_varint(value: int) -> bytes:
    """Encode an unsigned int as a base-128 varint."""
    if value < 0:
        value &= (1 << 64) - 1
    result = b""
    while value > 0x7F:
        result += bytes([0x80 | (value & 0x7F)])
        value >>= 7
    return result + bytes([value])


def encode_pb_field(field_number: int, wire_type: int, value) -> bytes:
    """Encode one protobuf tag+value pair."""
    tag = encode_pb_varint((field_number << 3) | wire_type)
    if wire_type == 0:  # varint
        return tag + encode_pb_varint(value)
    if wire_type == 2:  # length-delimited (str | bytes)
        if isinstance(value, str):
            value = value.encode("utf-8")
        return tag + encode_pb_varint(len(value)) + value
    if wire_type == 5:  # 32-bit fixed
        return tag + struct.pack("<I", value)
    if wire_type == 1:  # 64-bit fixed
        return tag + struct.pack("<Q", value)
    raise ValueError(f"unsupported wire_type {wire_type}")


def write_img_file(path, magic: int, entries, img_version: int = 2) -> None:
    """Write a minimal .img file: [u32 magic][?u64 legacy addr][u32 len][payload]..."""
    data = struct.pack("<I", magic)
    if img_version == 1:
        data += struct.pack("<Q", 0)  # legacy addr
    for entry in entries:
        data += struct.pack("<I", len(entry))
        data += entry
    Path(path).write_bytes(data)


# CRIU magic numbers (must match the parser's MAGIC table).
MAGIC_INVENTORY = 0x58311116
MAGIC_PSTREE = 0x50273030
MAGIC_CORE = 0x55053847


# ===========================================================================
# 1. .img header + framing parser
# ===========================================================================

def test_criu_img_header_parser(tmp_path):
    """A minimal .img file with one PB entry is framed and parsed correctly."""
    # inventory.img with img_version=2 (field 1 = varint 2)
    payload = encode_pb_field(1, 0, 2)  # img_version = 2
    p = tmp_path / "inventory.img"
    write_img_file(p, MAGIC_INVENTORY, [payload], img_version=2)

    rec = _read_img_file(str(p), img_version=2)
    assert rec["magic"] == MAGIC_INVENTORY
    assert rec["raw"] is False
    assert len(rec["entries"]) == 1
    # Field 1 of the first (and only) entry is the img_version.
    assert rec["entries"][0][1] == 2


def test_read_img_file_skips_raw_images(tmp_path):
    """magic == 0 → raw image (pages/pipes); returns raw=True with no entries."""
    p = tmp_path / "pages-1.img"
    p.write_bytes(struct.pack("<I", 0) + b"\x00" * 64)
    rec = _read_img_file(str(p), img_version=2)
    assert rec["raw"] is True
    assert rec["entries"] == []


def test_read_img_file_legacy_v1_addr_consumed(tmp_path):
    """img_version 1 has an 8-byte legacy addr after the magic; entries still parse."""
    payload = encode_pb_field(1, 0, 1)
    p = tmp_path / "inventory.img"
    write_img_file(p, MAGIC_INVENTORY, [payload], img_version=1)
    rec = _read_img_file(str(p), img_version=1)
    assert rec["entries"][0][1] == 1


# ===========================================================================
# 2-3. Protobuf wire primitives
# ===========================================================================

def test_parse_pb_varint():
    """Varint encoding/decoding round-trips for small and multi-byte values."""
    # single byte
    assert _decode_varint(encode_pb_varint(0), 0) == (0, 1)
    assert _decode_varint(encode_pb_varint(1), 0)[0] == 1
    # multi-byte (300 = 0xAC 0x02)
    raw = encode_pb_varint(300)
    assert raw == b"\xac\x02"
    assert _decode_varint(raw, 0) == (300, 2)
    # large value crossing several bytes
    big = 0x3FFFFFFFFFFFFFFF
    val, new_pos = _decode_varint(encode_pb_varint(big), 0)
    assert val == big
    assert new_pos == len(encode_pb_varint(big))

    # Inside a message: field 1 = varint 300
    pb = encode_pb_field(1, 0, 300)
    fields = _parse_pb_fields(pb)
    assert fields[1] == 300


def test_parse_pb_length_delimited():
    """String/bytes (wire type 2) fields extract correctly, including embedded."""
    # string field
    pb = encode_pb_field(6, 2, "nginx")
    fields = _parse_pb_fields(pb)
    assert fields[6] == b"nginx"

    # bytes field (raw)
    pb = encode_pb_field(11, 2, b"\x7f\x00\x00\x01")
    fields = _parse_pb_fields(pb)
    assert fields[11] == b"\x7f\x00\x00\x01"

    # multiple distinct fields in one payload
    pb = encode_pb_field(1, 0, 42) + encode_pb_field(6, 2, "comm")
    fields = _parse_pb_fields(pb)
    assert fields[1] == 42
    assert fields[6] == b"comm"

    # repeated field accumulates into a list
    pb = encode_pb_field(5, 2, b"a") + encode_pb_field(5, 2, b"b")
    fields = _parse_pb_fields(pb)
    assert fields[5] == [b"a", b"b"]


def test_parse_pb_fixed32_and_fixed64():
    """32-bit and 64-bit wire types decode as little-endian ints."""
    pb = encode_pb_field(7, 5, 0x1234)  # src_port as u16-ish
    assert _parse_pb_fields(pb)[7] == 0x1234
    pb = encode_pb_field(1, 1, 0xDEADBEEFCAFEBABE)  # start addr as u64
    assert _parse_pb_fields(pb)[1] == 0xDEADBEEFCAFEBABE


# ===========================================================================
# 4. interpret_pstree
# ===========================================================================

def test_interpret_pstree():
    """Mock PB fields → correct pid/ppid/pgid/sid; packed threads decoded."""
    # pstree_entry: pid=1234, ppid=1, pgid=1234, sid=1234, threads=[1234,1235]
    threads_packed = struct.pack("<II", 1234, 1235)
    pb = (encode_pb_field(1, 0, 1234) + encode_pb_field(2, 0, 1) +
          encode_pb_field(3, 0, 1234) + encode_pb_field(4, 0, 1234) +
          encode_pb_field(5, 2, threads_packed))
    row = _interpret_pstree(_parse_pb_fields(pb))
    assert row == {"pid": 1234, "ppid": 1, "pgid": 1234, "sid": 1234,
                   "threads": [1234, 1235]}

    # without threads field → empty list
    pb = encode_pb_field(1, 0, 7) + encode_pb_field(2, 0, 0)
    row = _interpret_pstree(_parse_pb_fields(pb))
    assert row["pid"] == 7 and row["threads"] == []


# ===========================================================================
# 5. interpret_vma detects anonymous RWX (code injection)
# ===========================================================================

def test_interpret_vma_detects_rwx():
    """Anonymous VMA with PROT_READ|PROT_WRITE|PROT_EXEC → is_anon_rwx=True."""
    # prot=7 (RWX), status=2 (ANON)
    pb = (encode_pb_field(1, 1, 0x1000) + encode_pb_field(2, 1, 0x3000) +
          encode_pb_field(5, 5, 7) + encode_pb_field(7, 5, 2))
    vma = _interpret_vma(_parse_pb_fields(pb))
    assert vma["is_anon"] is True
    assert vma["is_rwx"] is True
    assert vma["is_anon_rwx"] is True
    assert vma["prot_str"] == "rwx"
    assert vma["size"] == 0x2000


def test_interpret_vma_regular_rw_not_flagged():
    """A regular file-backed RW (not X) VMA is NOT code injection."""
    # prot=3 (RW), status=1|4 (REGULAR|FILE)
    pb = encode_pb_field(5, 5, 3) + encode_pb_field(7, 5, 1 | 4)
    vma = _interpret_vma(_parse_pb_fields(pb))
    assert vma["is_anon_rwx"] is False
    assert vma["is_rwx"] is False
    assert vma["prot_str"] == "rw-"


# ===========================================================================
# 6. interpret_creds detects CAP_SYS_ADMIN
# ===========================================================================

def test_interpret_creds_detects_sys_admin():
    """cap_eff with bit 21 (CAP_SYS_ADMIN) set → has_sys_admin=True."""
    # bit 21 → word 0, mask 1<<21
    cap_eff = struct.pack("<I", 1 << 21)
    pb = (encode_pb_field(1, 0, 1000) +   # uid
          encode_pb_field(2, 0, 1000) +   # gid
          encode_pb_field(3, 0, 0) +      # euid=0 (root)
          encode_pb_field(4, 0, 0) +      # egid=0
          encode_pb_field(11, 2, cap_eff))
    c = _interpret_creds(_parse_pb_fields(pb))
    assert c["has_sys_admin"] is True
    assert "CAP_SYS_ADMIN" in c["capabilities"]
    # uid != euid == 0 → setuid-root
    assert c["setuid_root"] is True
    assert c["running_as_root"] is True


def test_interpret_creds_no_caps_clean():
    """A plain unprivileged process has no dangerous caps."""
    pb = (encode_pb_field(1, 0, 1000) + encode_pb_field(3, 0, 1000) +
          encode_pb_field(11, 2, struct.pack("<I", 0)))
    c = _interpret_creds(_parse_pb_fields(pb))
    assert c["has_sys_admin"] is False
    assert c["capabilities"] == []
    assert c["setuid_root"] is False


# ===========================================================================
# 7. interpret_inetsk parses a 5-tuple
# ===========================================================================

def test_interpret_inetsk_parses_5tuple():
    """Mock fields → correct src/dst IP:port, protocol, state extraction."""
    # IPv4 src=10.0.0.5:44330, dst=203.0.113.9:443, tcp (proto=6), ESTABLISHED
    pb = (encode_pb_field(3, 5, 2) +          # family = AF_INET
          encode_pb_field(4, 5, 1) +          # type = SOCK_STREAM
          encode_pb_field(5, 5, 6) +          # proto = tcp
          encode_pb_field(6, 5, 1) +          # state = ESTABLISHED
          encode_pb_field(7, 5, 44330) +      # src_port
          encode_pb_field(8, 5, 443) +        # dst_port
          encode_pb_field(11, 2, bytes([10, 0, 0, 5])) +
          encode_pb_field(12, 2, bytes([203, 0, 113, 9])))
    sk = _interpret_inetsk(_parse_pb_fields(pb))
    assert sk["src_addr"] == "10.0.0.5"
    assert sk["src_port"] == 44330
    assert sk["dst_addr"] == "203.0.113.9"
    assert sk["dst_port"] == 443
    assert sk["proto_str"] == "tcp"
    assert sk["state_str"] == "ESTABLISHED"
    assert "203.0.113.9:443" in sk["5tuple"]


# ===========================================================================
# 8. reg-file interpret (bonus coverage)
# ===========================================================================

def test_interpret_regfile():
    pb = (encode_pb_field(1, 1, 0xA) +              # id
          encode_pb_field(6, 2, "/bin/bash") +      # name
          encode_pb_field(8, 1, 1234567) +          # size
          encode_pb_field(10, 5, 0o100755))         # mode
    rf = _interpret_regfile(_parse_pb_fields(pb))
    assert rf["id"] == 0xA
    assert rf["name"] == "/bin/bash"
    assert rf["size"] == 1234567
    assert rf["mode"] == 0o100755
    assert rf["mode_str"].startswith("-rwxr-xr-x")


# ===========================================================================
# 9. Tool wrapper — flat schema contract
# ===========================================================================

def test_criu_tool_schema_is_flat():
    """The criu_parse tool exposes a flat object schema (no nested objects)."""
    t = CriuParseTool()
    assert t.name == "criu_parse"
    assert t.image == "svetovid/base"
    schema = t.schema()
    assert schema["type"] == "object"
    props = schema["properties"]
    assert set(props) == {"evidence_subpath", "analysis_type"}
    assert props["evidence_subpath"]["type"] == "string"
    assert props["analysis_type"]["type"] == "string"
    assert set(props["analysis_type"]["enum"]) == set(ANALYSIS_TYPES)
    # required references real props
    assert set(schema["required"]) == {"evidence_subpath", "analysis_type"}
    # flat: no nested object types anywhere
    for name, prop in props.items():
        assert prop["type"] in {"string", "number", "integer", "boolean", "array"}, \
            f"property {name!r} has non-primitive type {prop['type']!r}"


def test_criu_tool_unknown_analysis_type_rejected(tmp_path):
    """An unknown analysis_type returns exit_code 2 without touching Docker."""
    res = asyncio.run(criu_parse.tool.invoke(
        {"analysis_type": "bogus", "evidence_subpath": "dump"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 2
    assert "unknown" in res.summary.lower()


def test_criu_tool_missing_subpath_rejected(tmp_path):
    """No evidence_subpath → exit_code 2 (the dump dir is mandatory)."""
    res = asyncio.run(criu_parse.tool.invoke(
        {"analysis_type": "full", "evidence_subpath": ""}, _ctx(tmp_path),
    ))
    assert res.exit_code == 2
    assert "evidence_subpath" in res.summary.lower()


# ===========================================================================
# 10. CRIU checkpoint signature — directory detection
# ===========================================================================

def test_criu_checkpoint_signature_detects_directory():
    """A directory path ending in inventory.img / pstree.img is detected."""
    from svetovid.evidence.signatures import detect, CRIUCheckpointSig

    # Directory path whose basename is a marker (scanner passes dir paths).
    sigs = detect("/evidence/compromised/inventory.img", b"", 0)
    assert any(isinstance(s, CRIUCheckpointSig) for s in sigs)
    s = next(x for x in sigs if isinstance(x, CRIUCheckpointSig))
    assert s.artifact_id == "B12"
    assert s.family == "CRIU checkpoint"
    assert "G19" in s.goals

    # pstree.img marker too
    assert any(isinstance(s, CRIUCheckpointSig)
               for s in detect("/dump/pstree.img", b"", 0))

    # A known CRIU .img file stem (core-1234.img) also matches at file level.
    assert any(isinstance(s, CRIUCheckpointSig)
               for s in detect("core-1234.img", b"", 0))
    # pages-1.img (raw image) is recognized as a CRIU image too.
    assert any(isinstance(s, CRIUCheckpointSig)
               for s in detect("pages-1.img", b"", 0))

    # A random unrelated .img file is NOT matched (avoid false positives).
    assert not any(isinstance(s, CRIUCheckpointSig)
                   for s in detect("screenshot.img", b"", 0))

    # A plain directory with no marker and no .img files is not matched.
    assert not any(isinstance(s, CRIUCheckpointSig)
                   for s in detect("/evidence/random_dir", b"", 0))


def test_scanner_classifies_criu_dump_directory(tmp_path):
    """End-to-end: the scanner turns a CRIU dump dir into one artifact."""
    from svetovid.evidence.scanner import scan_folder

    dump = tmp_path / "checkpoint"
    dump.mkdir()
    # Minimal valid inventory.img + pstree.img on disk.
    write_img_file(dump / "inventory.img", MAGIC_INVENTORY,
                   [encode_pb_field(1, 0, 2)])
    write_img_file(dump / "pstree.img", MAGIC_PSTREE,
                   [encode_pb_field(1, 0, 1)])

    arts = asyncio.run(scan_folder(str(tmp_path)))
    # The directory-level signature fires on the marker paths; the .img files
    # also classify individually. At least one criu_checkpoint artifact exists.
    assert any(a["kind"] == "criu_checkpoint" for a in arts), \
        f"scanner missed CRIU dump: {[a['kind'] for a in arts]}"
    criu = next(a for a in arts if a["kind"] == "criu_checkpoint")
    assert criu["artifact_id"] == "B12"
    assert "G19" in criu["goals"]


# ===========================================================================
# 11. End-to-end synthetic CRIU dump — inventory + pstree → process tree
# ===========================================================================

def test_synthetic_criu_dump_parses_process_tree(tmp_path):
    """Build inventory.img + pstree.img on disk, run the embedded parser,
    verify the process tree and img_version come back correctly.

    This exercises the full _PARSER subprocess program (the same string the
    tool ships to svetovid/base) via host fallback, so the wire-format
    framing, magic handling, and JSONL output are all covered end to end.
    """
    # The dump directory under /evidence/<sub>.
    ev_root = tmp_path / "evidence"
    dump = ev_root / "criu_dump"
    dump.mkdir(parents=True)

    # inventory.img: img_version = 2
    write_img_file(dump / "inventory.img", MAGIC_INVENTORY,
                   [encode_pb_field(1, 0, 2)])
    # pstree.img: one process — pid=1, ppid=0, pgid=1, sid=1
    pstree_entry = (encode_pb_field(1, 0, 1) + encode_pb_field(2, 0, 0) +
                    encode_pb_field(3, 0, 1) + encode_pb_field(4, 0, 1))
    write_img_file(dump / "pstree.img", MAGIC_PSTREE, [pstree_entry])

    # Run the embedded parser directly (it is the source of truth the tool
    # ships to the sandbox). argv: <analysis> <dump_dir>.
    import subprocess, sys
    proc = subprocess.run(
        [sys.executable, "-c", criu_parse._PARSER, "process_tree", str(dump)],
        capture_output=True, text=True, check=True,
    )
    rows = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]

    # One process_tree row + one _meta row.
    pt_rows = [r for r in rows if r.get("artifact_type") == "process_tree"]
    assert len(pt_rows) == 1
    proc_row = pt_rows[0]
    assert proc_row["pid"] == 1
    assert proc_row["ppid"] == 0
    assert proc_row["pgid"] == 1
    assert proc_row["sid"] == 1

    meta = next(r for r in rows if r.get("artifact_type") == "_meta")
    assert meta["img_version"] == 2
    assert meta["analysis"] == "process_tree"
    assert meta["process_count"] == 1


def test_criu_tool_invoke_full_run_on_host(tmp_path):
    """Full tool.invoke() against a synthetic dump via host fallback.

    Docker is unavailable in CI, so host_fallback=True runs the embedded
    parser on the host. We assert the ToolResult carries parsed rows and a
    provenance output file.
    """
    ev = tmp_path / "evidence"
    dump = ev / "checkpoint"
    dump.mkdir(parents=True)
    write_img_file(dump / "inventory.img", MAGIC_INVENTORY,
                   [encode_pb_field(1, 0, 2)])
    write_img_file(dump / "pstree.img", MAGIC_PSTREE,
                   [encode_pb_field(1, 0, 100) + encode_pb_field(2, 0, 1)])

    res = asyncio.run(criu_parse.tool.invoke(
        {"analysis_type": "process_tree", "evidence_subpath": "checkpoint"},
        _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.tool == "criu_parse"
    assert res.data["analysis_type"] == "process_tree"
    pids = [r["pid"] for r in res.data["rows"]
            if r.get("artifact_type") == "process_tree"]
    assert 100 in pids
    # Provenance copy persisted.
    assert res.output_path and Path(res.output_path).exists()
    assert res.output_hash and res.output_hash.startswith("sha256:")
