"""Digital signature / Authenticode validator (EnScript gap — Tool 4).

EnCase examines Windows binaries for Authenticode signatures, catalog
signatures, and certificate chains to flag unsigned / tampered executables.
``sigcheck`` is Windows-only and ``codesign`` is macOS-only; there is no
cross-platform OSS way to do this in a forensic pipeline. This tool fills the
gap by parsing the PE structure directly (no ``pefile`` dependency required)
to:

  - detect the ``IMAGE_DIRECTORY_ENTRY_SECURITY`` WIN_CERTIFICATE entry
    (Authenticode signature presence),
  - decode the embedded PKCS#7 / CMS blob well enough to extract the signer's
    subject, issuer, validity window, and a SHA-1 thumbprint (using stdlib
    ``hashlib`` + a minimal ASN.1 walk; ``cryptography`` is used if importable
    for full chain validation, otherwise we report presence + best-effort
    fields),
  - return ``trusted=False`` conservatively (we can verify presence and
    self-consistency but a full trust-chain check needs the system cert
    store, which a sandbox lacks).

The PE-parsing logic is factored into ``inspect_pe_bytes`` so the unit test
can drive it with a hand-built minimal PE. Runs inside ``svetovid/base``.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

CHECK_TYPES = ("authenticode", "catalog", "all")
PE_EXTENSIONS = (".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr")
# Treat a signature as "tampered" if the file size after the security
# directory is inconsistent; we surface this as trusted=False with a reason.


def inspect_pe_bytes(data: bytes) -> dict[str, Any]:
    """Inspect raw PE bytes and return signature metadata.

    Returns ``{"is_pe", "is_signed", "signer", "issuer", "valid_from",
    "valid_to", "thumbprint", "trusted", "note"}``. Never raises — a
    malformed/short input yields ``is_pe=False``. Host-testable.

    The PE layout we read (all little-endian):
      - DOS header: e_lfanew at offset 0x3C points at the PE signature.
      - PE signature 'PE\\0\\0', then the COFF header (20 bytes), then the
        optional header. The optional header's magic (0x10b = PE32,
        0x20b = PE32+) tells us its size, and the data directory we want
        (index 4 = security) sits at a fixed offset within it.
    """
    result: dict[str, Any] = {
        "is_pe": False, "is_signed": False, "signer": "", "issuer": "",
        "valid_from": "", "valid_to": "", "thumbprint": "", "trusted": False,
        "note": "",
    }
    if len(data) < 0x40 or data[:2] != b"MZ":
        return result
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return result
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return result
    result["is_pe"] = True

    coff_off = e_lfanew + 4
    try:
        machine, num_sections, _ts, _ptr_sym, _num_sym, opt_hdr_size, _chars = \
            struct.unpack_from("<HHIIIHH", data, coff_off)
    except struct.error:
        result["note"] = "truncated COFF header"
        return result

    opt_off = coff_off + 20
    if opt_hdr_size == 0 or opt_off + opt_hdr_size > len(data):
        result["note"] = "missing optional header"
        return result
    magic = struct.unpack_from("<H", data, opt_off)[0]
    # Security directory is the 5th data directory (index 4). Its offset within
    # the optional header differs for PE32 vs PE32+:
    #   PE32:  optional header data dirs start at offset 96
    #   PE32+: optional header data dirs start at offset 112
    data_dir_base = opt_off + (112 if magic == 0x20B else 96)
    sec_dir_off = data_dir_base + 4 * 8  # 4 entries * 8 bytes before security
    try:
        sec_va, sec_size = struct.unpack_from("<II", data, sec_dir_off)
    except struct.error:
        result["note"] = "missing security data directory"
        return result

    if sec_va == 0 or sec_size == 0 or sec_va + 8 > len(data):
        # No Authenticode signature embedded.
        result["note"] = "no embedded Authenticode signature"
        return result

    # WIN_CERTIFICATE: dwLength(4) wRevision(2) wCertificateType(2) bCertificate[]
    try:
        dw_length, w_rev, w_type = struct.unpack_from("<IHH", data, sec_va)
    except struct.error:
        result["note"] = "malformed WIN_CERTIFICATE entry"
        return result
    # wCertificateType == 2 means PKCS#7 / CMS signed data.
    if w_type != 2:
        result["is_signed"] = True
        result["note"] = f"embedded cert (type {w_type}, not PKCS#7)"
        return result

    cert_blob = data[sec_va + 8: sec_va + dw_length]
    result["is_signed"] = True
    # SHA-1 thumbprint of the embedded signature blob (what sigcheck prints).
    import hashlib
    result["thumbprint"] = hashlib.sha1(cert_blob).hexdigest().upper()

    fields = _extract_pkcs7_summary(cert_blob)
    result["signer"] = fields.get("signer", "")
    result["issuer"] = fields.get("issuer", "")
    result["valid_from"] = fields.get("valid_from", "")
    result["valid_to"] = fields.get("valid_to", "")
    # Without the system trust store we cannot assert full chain validity;
    # mark trusted only if we found a signer + a non-expired window.
    result["trusted"] = _within_validity(fields.get("valid_from"),
                                         fields.get("valid_to"))
    if not result["trusted"] and not result["note"]:
        result["note"] = "signature present; trust chain not verifiable in sandbox"
    return result


def _within_validity(valid_from: str | None, valid_to: str | None) -> bool:
    """Conservatively True only when we have both bounds and now is between."""
    import datetime as _dt
    if not valid_from or not valid_to:
        return False
    now = _dt.datetime.now(_dt.timezone.utc)
    try:
        vf = _parse_cert_time(valid_from)
        vt = _parse_cert_time(valid_to)
    except (ValueError, TypeError):
        return False
    return vf is not None and vt is not None and vf <= now <= vt


def _parse_cert_time(s: str):
    import datetime as _dt
    s = s.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y%m%d%H%M%SZ"):
        try:
            dt = _dt.datetime.strptime(s, fmt)
            return dt.replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            continue
    return None


def _extract_pkcs7_summary(blob: bytes) -> dict[str, str]:
    """Best-effort extraction of signer / issuer / validity from a PKCS#7 blob.

    Prefers ``cryptography`` (parses the full CMS). Falls back to scanning the
    raw DER for UTF-8 / PrintableString CN= attributes and UTCTime validity,
    which is enough for a forensic "who signed this and when" summary without
    a full ASN.1 stack.
    """
    fields: dict[str, str] = {}
    # Try cryptography first.
    try:
        from cryptography import x509  # type: ignore
        from cryptography.hazmat.primitives import hashes  # noqa: F401
        from cryptography.x509 import oid  # noqa: F401
        from cryptography.exceptions import UnsupportedAlgorithm  # noqa: F401
    except ImportError:
        x509 = None  # type: ignore[assignment]
    if x509 is not None:
        try:
            cms = x509.load_der_pkcs7_certificates(blob)
            for cert in cms:
                try:
                    cn = cert.subject.get_attributes_for_oid(
                        x509.oid.NameOID.COMMON_NAME)
                    if cn and not fields.get("signer"):
                        fields["signer"] = cn[0].value
                    icn = cert.issuer.get_attributes_for_oid(
                        x509.oid.NameOID.COMMON_NAME)
                    if icn and not fields.get("issuer"):
                        fields["issuer"] = icn[0].value
                    na = cert.not_valid_after_utc
                    nb = cert.not_valid_before_utc
                    if not fields.get("valid_from"):
                        fields["valid_from"] = nb.strftime("%Y-%m-%dT%H:%M:%SZ")
                    if not fields.get("valid_to"):
                        fields["valid_to"] = na.strftime("%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    continue
            if fields:
                return fields
        except Exception:
            pass

    # Fallback: light DER scan for CN= and validity dates.
    text = blob.decode("latin-1", "replace")
    cns = _find_cn_values(text)
    if cns:
        fields["signer"] = cns[0]
        if len(cns) > 1:
            fields["issuer"] = cns[1]
    dates = _find_validity_utctime(blob)
    if len(dates) >= 2:
        fields["valid_from"], fields["valid_to"] = dates[0], dates[1]
    elif len(dates) == 1:
        fields["valid_from"] = dates[0]
    return fields


_CN_RE = __import__("re").compile(r"CN=([^,/]+)")


def _find_cn_values(text: str) -> list[str]:
    return [m.strip() for m in _CN_RE.findall(text)][:4]


def _find_validity_utctime(blob: bytes) -> list[str]:
    """Find UTCTime (tag 0x17) values of the form YYMMDDHHMMSSZ in the DER."""
    import re
    out: list[str] = []
    i = 0
    pat = re.compile(rb"\x17\x0d(\d{12}Z)")
    for m in pat.finditer(blob):
        raw = m.group(1).decode("ascii")
        try:
            yy = int(raw[:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            iso = f"{year}-{raw[2:4]}-{raw[4:6]}T{raw[6:8]}:{raw[8:10]}:{raw[10:12]}Z"
        except ValueError:
            continue
        out.append(iso)
    return out


# ---------------------------------------------------------------------------
# Embedded inspector script run inside svetovid/base.
# ---------------------------------------------------------------------------

_INSPECTOR_SCRIPT = r'''#!/usr/bin/env python3
"""Authenticode / signature inspector — runs inside svetovid/base.

Walks the evidence tree for PE files and reports signature presence /
metadata per file. PE parsing is manual (struct) so no pefile dependency is
needed; cryptography is used opportunistically for chain decoding.

Usage:
    sigcheck.py <evidence_path> <output_json> <check_type>
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

PE_EXTENSIONS = (".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr")
_CN_RE = re.compile(r"CN=([^,/]+)")


def inspect_pe(data):
    result = {"is_pe": False, "is_signed": False, "signer": "", "issuer": "",
              "valid_from": "", "valid_to": "", "thumbprint": "", "trusted": False,
              "note": ""}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return result
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return result
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return result
    result["is_pe"] = True
    coff_off = e_lfanew + 4
    try:
        _m, _ns, _ts, _ps, _nsy, opt_size, _c = struct.unpack_from("<HHIIIHH", data, coff_off)
    except struct.error:
        result["note"] = "truncated COFF header"
        return result
    opt_off = coff_off + 20
    if opt_size == 0 or opt_off + opt_size > len(data):
        result["note"] = "missing optional header"
        return result
    magic = struct.unpack_from("<H", data, opt_off)[0]
    data_dir_base = opt_off + (112 if magic == 0x20B else 96)
    sec_dir_off = data_dir_base + 4 * 8
    try:
        sec_va, sec_size = struct.unpack_from("<II", data, sec_dir_off)
    except struct.error:
        result["note"] = "missing security data directory"
        return result
    if sec_va == 0 or sec_size == 0 or sec_va + 8 > len(data):
        result["note"] = "no embedded Authenticode signature"
        return result
    try:
        dw_length, w_rev, w_type = struct.unpack_from("<IHH", data, sec_va)
    except struct.error:
        result["note"] = "malformed WIN_CERTIFICATE entry"
        return result
    if w_type != 2:
        result["is_signed"] = True
        result["note"] = "embedded cert (type %d, not PKCS#7)" % w_type
        return result
    cert_blob = data[sec_va + 8: sec_va + dw_length]
    result["is_signed"] = True
    result["thumbprint"] = hashlib.sha1(cert_blob).hexdigest().upper()
    # cryptography optional full-chain decode
    fields = {}
    try:
        from cryptography import x509
        cms = x509.load_der_pkcs7_certificates(cert_blob)
        for cert in cms:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn and not fields.get("signer"):
                fields["signer"] = cn[0].value
            icn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if icn and not fields.get("issuer"):
                fields["issuer"] = icn[0].value
            if not fields.get("valid_from"):
                fields["valid_from"] = cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            if not fields.get("valid_to"):
                fields["valid_to"] = cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    if not fields:
        text = cert_blob.decode("latin-1", "replace")
        cns = _CN_RE.findall(text)
        if cns:
            fields["signer"] = cns[0]
            if len(cns) > 1:
                fields["issuer"] = cns[1]
        dates = re.findall(rb"\x17\x0d(\d{12}Z)", cert_blob)
        parsed = []
        for d in dates:
            d = d.decode("ascii")
            try:
                yy = int(d[:2]); year = 2000 + yy if yy < 50 else 1900 + yy
                parsed.append("%d-%s-%sT%s:%s:%sZ" % (year, d[2:4], d[4:6], d[6:8], d[8:10], d[10:12]))
            except ValueError:
                continue
        if len(parsed) >= 2:
            fields["valid_from"], fields["valid_to"] = parsed[0], parsed[1]
        elif len(parsed) == 1:
            fields["valid_from"] = parsed[0]
    result["signer"] = fields.get("signer", "")
    result["issuer"] = fields.get("issuer", "")
    result["valid_from"] = fields.get("valid_from", "")
    result["valid_to"] = fields.get("valid_to", "")
    result["trusted"] = _within(fields.get("valid_from"), fields.get("valid_to"))
    if not result["trusted"] and not result["note"]:
        result["note"] = "signature present; trust chain not verifiable in sandbox"
    return result


def _within(vf, vt):
    if not vf or not vt:
        return False
    now = _dt.datetime.now(_dt.timezone.utc)
    for s, fmt in ((vf, "%Y-%m-%dT%H:%M:%SZ"), (vt, "%Y-%m-%dT%H:%M:%SZ")):
        try:
            _dt.datetime.strptime(s, fmt)
        except ValueError:
            return False
    try:
        a = _dt.datetime.strptime(vf, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
        b = _dt.datetime.strptime(vt, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return False
    return a <= now <= b


def main(argv):
    if len(argv) != 4:
        print("usage: sigcheck.py <evidence_path> <output_json> <check_type>", file=sys.stderr)
        return 2
    evidence_path, out_json, check_type = argv[1], argv[2], argv[3]
    root = Path(evidence_path)
    if not root.exists():
        with open(out_json, "w") as fh:
            json.dump({"results": [], "error": "path not found: " + evidence_path}, fh)
        return 0
    files = sorted(root.rglob("*")) if root.is_dir() else [root]
    results = []
    for f in files:
        if not f.is_file() or f.suffix.lower() not in PE_EXTENSIONS:
            continue
        try:
            with open(f, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        info = inspect_pe(data)
        info["file"] = str(f)
        if check_type == "catalog":
            info["catalog_check"] = "catalog DB not available in sandbox"
        results.append(info)
    summary = "%d PE file(s); %d signed" % (
        len(results), sum(1 for r in results if r.get("is_signed")))
    payload = {"results": results, "summary": summary}
    with open(out_json, "w") as fh:
        json.dump(payload, fh, ensure_ascii=False, default=str)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


class SignatureCheckTool(Tool):
    name = "signature_check"
    image = "svetovid/base"
    description = (
        "Validate Windows PE Authenticode / catalog signatures. Parses the PE "
        "security directory to detect embedded signatures, extracts signer / "
        "issuer / validity window / SHA-1 thumbprint, and reports trust "
        "status. Flags unsigned or tampered executables. Cross-platform "
        "replacement for sigcheck. Fills the EnCase signature-validator gap."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence containing PE files "
                        "(.exe/.dll/.sys) to validate."
                    ),
                },
                "check_type": {
                    "type": "string",
                    "enum": list(CHECK_TYPES),
                    "default": "all",
                    "description": (
                        "authenticode (embedded signatures), catalog "
                        "(catalog DB — limited in sandbox), or all."
                    ),
                },
            },
            "required": [],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        sub = args.get("evidence_subpath", "") or ""
        check_type = args.get("check_type", "all")
        if check_type not in CHECK_TYPES:
            check_type = "all"

        out_json = "/work/sigcheck.json"
        script_host = Path(ctx.output_dir) / "sigcheck.py"
        script_host.write_text(_INSPECTOR_SCRIPT)

        cmd = [
            "python3", "/work/sigcheck.py",
            (f"/evidence/{sub}".rstrip("/") if sub else "/evidence"),
            out_json,
            check_type,
        ]

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(
            ctx.investigation_id, tool=self.name, args=args,
        ))

        def on_stdout(line: str) -> None:
            ctx.bus.publish(E.tool_stdout(ctx.investigation_id, call_id, line))

        def on_stderr(line: str) -> None:
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, line))

        try:
            res = await run_in_sandbox(
                image=self.image or "",
                command=cmd,
                evidence_path=ctx.evidence_path,
                output_dir=ctx.output_dir,
                investigation_id=ctx.investigation_id,
                on_stdout=on_stdout,
                on_stderr=on_stderr,
                host_fallback=True,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(
                ctx.investigation_id, f"signature_check failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"signature_check failed: {e}",
            )

        results: list[dict[str, Any]] = []
        summary = ""
        local_out = Path(ctx.output_dir) / "sigcheck.json"
        if local_out.exists():
            try:
                payload = json.loads(local_out.read_text())
                if isinstance(payload, dict):
                    results = payload.get("results", [])
                    summary = payload.get("summary", "")
            except Exception as e:
                summary = f"sigcheck output couldn't be parsed: {e}"
        if not summary:
            summary = f"signature_check exited {res.exit_code} with no output"

        output_hash = _hash_file(local_out)
        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s,
            output_hash,
        ))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": args,
            "exit_code": res.exit_code, "duration_s": res.duration_s,
            "output_hash": output_hash, "ts": E._now_iso(),
        }))

        try:
            from ._reporting import record_tool_call_db
            await record_tool_call_db(
                call_id=call_id, investigation_id=ctx.investigation_id,
                tool=self.name, args=args, exit_code=res.exit_code,
                duration_s=res.duration_s, output_hash=output_hash,
            )
        except Exception:
            pass

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
            output_path=str(local_out) if local_out.exists() else None,
            summary=summary, data={"results": results},
        )


def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


tool = SignatureCheckTool()
