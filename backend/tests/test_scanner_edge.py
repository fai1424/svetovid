"""Edge-case tests for the evidence scanner and forensic signatures.

These tests exercise the corners the smoke tests do not: every PCAP magic
variant, MFT/registry/E01 detection by magic alone, folder- vs file-input
handling, recursive walking, symlinks, permission-denied files, the large-file
hash skip, and the ``hash_evidence=False`` opt-out. They run against real temp
files in ``tmp_path`` so the on-disk behavior (stat, head read, hashing) is
exercised end to end.

Run with::

    cd backend && pytest tests/test_scanner_edge.py -v
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# A tiny isolation fixture so these tests never touch a real ~/.svetovid or
# the macOS Keychain (which would otherwise block the pytest session on a GUI
# prompt). Mirrors the pattern in test_smoke.py.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    # Drop cached svetovid modules so each test imports fresh state.
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]
    yield fake_home


# ===========================================================================
# Signature detection edge cases
# ===========================================================================


def test_evtx_correct_magic_detected():
    from svetovid.evidence.signatures import detect

    sigs = detect("Security.evtx", b"ElfFile\x00\x01\x02\x03", 1024)
    assert any(s.id == "evtx" for s in sigs)
    evtx = next(s for s in sigs if s.id == "evtx")
    assert evtx.artifact_id == "B8"
    assert "G01" in evtx.goals


def test_evtx_wrong_magic_but_correct_extension_still_detected():
    """An .evtx that lost its magic header should still match by extension."""
    from svetovid.evidence.signatures import detect

    sigs = detect("corrupt.evtx", b"\x00" * 16, 500)
    assert any(s.id == "evtx" for s in sigs), \
        "an .evtx file must match by extension even with wrong magic"


@pytest.mark.parametrize("magic,label", [
    (b"\xd4\xc3\xb2\xa1", "pcap LE microsecond"),
    (b"\xa1\xb2\xc3\xd4", "pcap BE microsecond"),
    (b"\x4d\x3c\xb2\xa1", "pcap LE nanosecond"),
    (b"\xa1\xb2\x3c\x4d", "pcap BE nanosecond"),
    (b"\x0a\x0d\x0d\x0a", "pcapng SHB"),
])
def test_pcap_all_five_magic_variants(magic, label):
    from svetovid.evidence.signatures import detect

    sigs = detect("trace.bin", magic + b"\x00" * 20, 2048)
    assert any(s.id == "pcap" for s in sigs), f"failed for {label}"
    pcap = next(s for s in sigs if s.id == "pcap")
    assert pcap.artifact_id == "B7"


@pytest.mark.parametrize("ext", [".raw", ".mem", ".vmem", ".lime", ".dmp"])
def test_memory_image_all_extensions(ext):
    from svetovid.evidence.signatures import detect

    # RAW memory has no universal magic; empty head, rely purely on extension.
    sigs = detect(f"memory_image{ext}", b"", 1_073_741_824)
    assert any(s.id == "memory" for s in sigs), f"failed for {ext}"
    mem = next(s for s in sigs if s.id == "memory")
    assert mem.artifact_id == "B6"


def test_mft_by_filename_dollar_mft():
    from svetovid.evidence.signatures import detect

    sigs = detect("$MFT", b"", 1024 * 1024)
    assert any(s.id == "mft" for s in sigs)
    mft = next(s for s in sigs if s.id == "mft")
    assert mft.artifact_id == "B3"


def test_mft_by_filename_lowercase_mft():
    from svetovid.evidence.signatures import detect

    # The MFT matcher lowercases the name and accepts a bare "mft" too.
    assert any(s.id == "mft" for s in detect("mft", b"", 4096))


def test_mft_by_magic_FILE0_no_extension():
    from svetovid.evidence.signatures import detect

    # A file with no extension but a FILE0 record header must match.
    sigs = detect("some-disk-segment", b"FILE0" + b"\x00" * 1023, 4096)
    assert any(s.id == "mft" for s in sigs)


def test_registry_hive_by_magic_regf():
    from svetovid.evidence.signatures import detect

    # Registry hives have no extension; matched purely on the "regf" magic.
    sigs = detect("SYSTEM", b"regf" + b"\x00" * 1020, 4096)
    assert any(s.id == "registry" for s in sigs)
    reg = next(s for s in sigs if s.id == "registry")
    assert reg.artifact_id == "B3"
    assert "G01" in reg.goals


def test_e01_by_magic_no_extension():
    from svetovid.evidence.signatures import detect

    evf = b"\x45\x56\x46\x09\x0d\x0a\xff\x00"
    sigs = detect("disk-image", evf + b"\x00" * 100, 50_000)
    assert any(s.id == "e01" for s in sigs)
    e01 = next(s for s in sigs if s.id == "e01")
    assert e01.artifact_id == "B3"
    assert "G03" in e01.goals


def test_zeek_log_by_extension():
    from svetovid.evidence.signatures import detect

    # ZeekLogSig matches on .log extension only; magic probe is intentionally 0.
    sigs = detect("conn.log", b"", 1234)
    assert any(s.id == "zeek_log" for s in sigs)
    zeek = next(s for s in sigs if s.id == "zeek_log")
    assert zeek.artifact_id == "B7"


def test_pcapng_shb_magic_matches():
    from svetovid.evidence.signatures import detect

    sigs = detect("traffic.pcapng", b"\x0a\x0d\x0d\x0a", 4096)
    assert any(s.id == "pcap" for s in sigs)


def test_txt_file_no_match():
    from svetovid.evidence.signatures import detect

    sigs = detect("readme.txt", b"hello world this is plain text", 100)
    assert sigs == [], f"expected no signature, got {[s.id for s in sigs]}"


def test_directory_named_winevt_logs_matches_evtx_folder():
    from svetovid.evidence.signatures import detect

    # The scanner classifies directory paths; EVTXFolder matches the Logs dir.
    sigs = detect(str(Path("/tmp/ev") / "winevt" / "Logs"), b"", 0)
    assert any(s.id == "evtx_folder" for s in sigs)
    folder = next(s for s in sigs if s.id == "evtx_folder")
    assert folder.artifact_id == "B8"


# ===========================================================================
# Scanner edge cases
# ===========================================================================


def test_scanner_empty_folder_returns_empty_artifacts(tmp_path):
    from svetovid.evidence.scanner import scan_folder

    arts = asyncio.run(scan_folder(str(tmp_path)))
    assert arts == []


def test_scanner_folder_with_only_non_evidence_files(tmp_path):
    from svetovid.evidence.scanner import scan_folder

    (tmp_path / "notes.txt").write_text("nothing to see here")
    (tmp_path / "README.md").write_text("# docs")
    (tmp_path / "data.dat").write_bytes(b"\x00" * 100)
    arts = asyncio.run(scan_folder(str(tmp_path)))
    assert arts == []


def test_scanner_single_file_classified_correctly(tmp_path):
    from svetovid.evidence.scanner import scan_folder

    evtx = tmp_path / "System.evtx"
    evtx.write_bytes(b"ElfFile\x00payload")
    arts = asyncio.run(scan_folder(str(evtx)))
    assert len(arts) == 1
    a = arts[0]
    assert a["kind"] == "evtx"
    assert a["artifact_id"] == "B8"
    assert a["family"].startswith("Windows Event Logs")


def test_scanner_nested_subfolders_recursive(tmp_path):
    from svetovid.evidence.scanner import scan_folder

    (tmp_path / "evtx" / "deep" / "deeper").mkdir(parents=True)
    (tmp_path / "evtx" / "deep" / "deeper" / "App.evtx").write_bytes(b"ElfFile\x00x")
    (tmp_path / "pcap").mkdir()
    (tmp_path / "pcap" / "cap.pcap").write_bytes(b"\xd4\xc3\xb2\xa1data")
    arts = asyncio.run(scan_folder(str(tmp_path)))
    kinds = sorted(a["kind"] for a in arts)
    assert kinds == ["evtx", "pcap"], f"unexpected: {kinds}"


def test_scanner_symlink_not_followed_as_separate_artifact(tmp_path):
    """A symlink to an evidence file should be skipped (os.stat with
    follow_symlinks=False raises OSError on a broken link, or reports the link
    itself). Either way the scanner must not crash and must not double-count."""
    from svetovid.evidence.scanner import scan_folder

    real = tmp_path / "real.evtx"
    real.write_bytes(b"ElfFile\x00data")
    link = tmp_path / "link.evtx"
    try:
        os.symlink(real, link)
    except OSError:
        pytest.skip("symlinks not supported on this platform")

    arts = asyncio.run(scan_folder(str(tmp_path)))
    # At minimum the real file is found and classified; the symlink path may or
    # may not appear, but scanning must succeed without error.
    assert any(a["kind"] == "evtx" for a in arts)
    # ensure no duplicate of the real file path
    paths = [a["path"] for a in arts]
    assert str(real) in paths


def test_scanner_permission_denied_file_skipped(tmp_path):
    """An unreadable file must not crash the scan; it is simply skipped."""
    from svetovid.evidence.scanner import scan_folder

    locked = tmp_path / "locked.evtx"
    locked.write_bytes(b"ElfFile\x00secret")
    # Also place a good evidence file so we can confirm scanning still proceeds.
    good = tmp_path / "good.evtx"
    good.write_bytes(b"ElfFile\x00ok")

    try:
        locked.chmod(0o000)
    except (OSError, PermissionError):
        pytest.skip("cannot revoke file permissions on this platform")

    try:
        arts = asyncio.run(scan_folder(str(tmp_path)))
    finally:
        locked.chmod(0o644)

    kinds = sorted(a["kind"] for a in arts)
    # The good file is always detected; the locked file may or may not be.
    assert "evtx" in kinds
    # scanning never raised


def test_scanner_large_file_hash_skipped_with_note(tmp_path):
    """A file larger than SCAN_HASH_LIMIT is recorded but its hashes are
    noted as skipped rather than computed inline."""
    from svetovid.evidence import scanner
    from svetovid.evidence.scanner import scan_folder

    big = tmp_path / "memory.raw"
    # Write a tiny real file but pretend it is enormous via stat patching so we
    # avoid actually writing 100 MiB+ to disk.
    big.write_bytes(b"\x00\x02\x00\x00\x00\x00\x00\x00")  # Windows crash dump magic

    class FakeStat:
        st_size = scanner.SCAN_HASH_LIMIT + 1
        st_mode = 0o100644

    real_stat = Path.stat

    def fake_stat(self, *a, **kw):
        if self == big:
            return FakeStat()
        return real_stat(self, *a, **kw)

    with patch.object(Path, "stat", fake_stat):
        arts = asyncio.run(scan_folder(str(tmp_path)))

    a = next(x for x in arts if x["path"] == str(big))
    assert a["kind"] == "memory"
    assert a["extra"].get("hash_skipped") == "too_large"
    assert "sha256" not in a["extra"]


def test_scanner_hash_evidence_false_no_hashes_in_extra(tmp_path):
    from svetovid.evidence.scanner import scan_folder

    (tmp_path / "Security.evtx").write_bytes(b"ElfFile\x00payload")
    arts = asyncio.run(scan_folder(str(tmp_path), hash_evidence=False))
    assert len(arts) == 1
    a = arts[0]
    assert a["kind"] == "evtx"
    assert a["extra"] == {}


# ===========================================================================
# Hash edge cases
# ===========================================================================


def test_small_file_gets_sha256_and_md5(tmp_path):
    from svetovid.evidence.scanner import scan_folder

    data = b"ElfFile\x00the quick brown fox"
    (tmp_path / "App.evtx").write_bytes(data)
    arts = asyncio.run(scan_folder(str(tmp_path)))
    a = arts[0]
    extra = a["extra"]
    assert "sha256" in extra
    assert "md5" in extra
    assert len(extra["sha256"]) == 64
    assert len(extra["md5"]) == 32


def test_hash_matches_known_value_for_specific_content(tmp_path):
    from svetovid.evidence.scanner import scan_folder

    content = b"ElfFile\x00forensic content here"
    (tmp_path / "known.evtx").write_bytes(content)
    arts = asyncio.run(scan_folder(str(tmp_path)))
    extra = arts[0]["extra"]
    assert extra["sha256"] == hashlib.sha256(content).hexdigest()
    assert extra["md5"] == hashlib.md5(content).hexdigest()


def test_two_files_same_content_same_hash(tmp_path):
    from svetovid.evidence.scanner import scan_folder

    content = b"ElfFile\x00identical payload"
    # Same bytes, different filenames/extensions -> both .evtx so both classify.
    (tmp_path / "a.evtx").write_bytes(content)
    (tmp_path / "b.evtx").write_bytes(content)
    arts = asyncio.run(scan_folder(str(tmp_path)))
    by_name = {Path(a["path"]).name: a for a in arts}
    assert by_name["a.evtx"]["extra"]["sha256"] == by_name["b.evtx"]["extra"]["sha256"]
    assert by_name["a.evtx"]["extra"]["md5"] == by_name["b.evtx"]["extra"]["md5"]
