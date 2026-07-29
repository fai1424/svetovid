"""PII / sensitive-data scanner (EnScript gap — Tool 1).

EnCase ships EnScripts that sweep disk images for personally identifiable
information and secrets: SSNs, credit-card numbers, passport numbers, phone
numbers, email addresses, IBANs, Bitcoin addresses, and API keys/tokens.
Bulk Extractor covers emails / URLs / CCNs but not SSNs, passports, IBANs,
Bitcoin, or cloud API keys. This tool fills that gap.

Runs inside the ``svetovid/base`` Docker image (python3 + stdlib only). We
ship an embedded scanner script that walks the evidence tree line-by-line,
runs well-tested regexes, and Luhn-validates credit-card candidates before
reporting them. Output is a JSON hits document written to ``/work``.

The regexes and validators are factored as importable, host-testable helpers
(``PATTERNS``, ``luhn_valid``, ``valid_ssn``) so the unit tests can exercise
the detection logic directly without Docker.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

# Pattern types the agent can select. Each maps to a compiled regex + an
# optional post-validator (e.g. Luhn for credit cards, area/group rules for
# SSNs). Order matters only for the enum exposed to the agent.
PATTERN_TYPES = (
    "ssn", "credit_card", "passport", "phone", "email",
    "api_key", "iban", "bitcoin",
)

# Maximum hits retained per pattern type (per the spec). Keeps the result set
# bounded so a single 1GB text file can't flood the agent.
MAX_HITS_PER_PATTERN = 500

# ---------------------------------------------------------------------------
# Regex catalogue.
#
# Each entry: (regex, post_validator_or_None). The validator is a callable
# taking the matched string and returning True if it should be reported. This
# is how we apply Luhn checks (credit cards) and SSN invalid-area rules
# without polluting the regex itself.
# ---------------------------------------------------------------------------

import re as _re

_RE_SSN = _re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")
_RE_CC = _re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_RE_PASSPORT = _re.compile(
    r"\b(?:US\s?\d{9}|[A-Z]{1,2}\d{6,9})\b"
)
# International phone: optional + then 7+ digits with separators.
_RE_PHONE = _re.compile(r"\+?\d[\d\s\-()]{7,}\d")
# RFC 5322 simplified (good enough for forensic triage, not for arbitrary
# RFC compliance).
_RE_EMAIL = _re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)
_RE_IBAN = _re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
# Bitcoin: bech32 (bc1...) and legacy (1... / 3...), base58 alphabet.
_RE_BTC_BECH32 = _re.compile(r"\bbc1[ac-hj-np-z02-9]{6,87}\b")
_RE_BTC_LEGACY = _re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{24,33}\b")
# API key / token signatures for common cloud/SaaS providers + generic JWTs.
_RE_API_PATTERNS = {
    "aws_access_key": _re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret": _re.compile(r"(?i)\baws.{0,20}(?:secret|sk).{0,10}([A-Za-z0-9/+=]{40})\b"),
    "google_api": _re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "github_pat": _re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "github_old": _re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "slack_token": _re.compile(r"\bxox[bp]a-[0-9A-Za-z]{10,48}\b"),
    "slack_webhook": _re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    "stripe": _re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b"),
    "generic_jwt": _re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
}


def luhn_valid(number: str) -> bool:
    """Return True if ``number`` passes the Luhn checksum.

    Used to validate credit-card candidates after regex extraction. Strips
    spaces and dashes first (cards are often written grouped).
    """
    digits = [c for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        n = int(d)
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def valid_ssn(match: str) -> bool:
    """Apply the SSN invalidity rules (no 000/666/900-999 area, no 00 group,
    no 0000 serial) to a ``###-##-####`` candidate."""
    m = _RE_SSN.fullmatch(match.strip())
    if not m:
        return False
    area, group, serial = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0 or serial == 0:
        return False
    return True


# Single source of truth the embedded script also re-implements (kept
# duplicated on purpose so the script is self-contained inside the container).
def build_scan_table(types: list[str]) -> list[tuple[str, "_re.Pattern[str]", Any]]:
    """Return ``[(label, regex, validator_or_None), ...]`` for the requested
    pattern types."""
    table: list[tuple[str, "_re.Pattern[str]", Any]] = []
    for t in types:
        if t == "ssn":
            table.append(("ssn", _RE_SSN, valid_ssn))
        elif t == "credit_card":
            table.append(("credit_card", _RE_CC, luhn_valid))
        elif t == "passport":
            table.append(("passport", _RE_PASSPORT, None))
        elif t == "phone":
            table.append(("phone", _RE_PHONE, None))
        elif t == "email":
            table.append(("email", _RE_EMAIL, None))
        elif t == "api_key":
            # One pseudo-entry per provider so we report which key type.
            for label, rx in _RE_API_PATTERNS.items():
                table.append((f"api_key:{label}", rx, None))
        elif t == "iban":
            table.append(("iban", _RE_IBAN, None))
        elif t == "bitcoin":
            table.append(("bitcoin:bech32", _RE_BTC_BECH32, None))
            table.append(("bitcoin:legacy", _RE_BTC_LEGACY, None))
    return table


def scan_text(text: str, types: list[str], cap: int = MAX_HITS_PER_PATTERN) -> list[dict[str, Any]]:
    """Scan a single text blob and return hits (host-testable).

    Each hit is ``{"pattern_type", "match", "offset"}`` (offset is the
    character index within ``text``). The caller is responsible for adding
    file/line/context. Capped at ``cap`` per pattern type.
    """
    hits: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for label, rx, validator in build_scan_table(types):
        if counts.get(label, 0) >= cap:
            continue
        for m in rx.finditer(text):
            candidate = m.group(0)
            if validator is not None and not validator(candidate):
                continue
            if counts.get(label, 0) >= cap:
                break
            hits.append({
                "pattern_type": label,
                "match": candidate,
                "offset": m.start(),
            })
            counts[label] = counts.get(label, 0) + 1
    return hits


# ---------------------------------------------------------------------------
# Embedded scanner script run inside svetovid/base.
# ---------------------------------------------------------------------------

_SCANNER_SCRIPT = r'''#!/usr/bin/env python3
"""PII / sensitive-data scanner — runs inside svetovid/base.

Walks an evidence path, reads each text-readable file line by line, and
reports regex matches for the requested pattern types. Writes JSON to the
output path. Self-contained (stdlib only) so it runs on the host fallback too.

Usage:
    pii_scan.py <evidence_path> <output_json> <patterns_csv> <max_hits>
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

_RE_SSN = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")
_RE_CC = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_RE_PASSPORT = re.compile(r"\b(?:US\s?\d{9}|[A-Z]{1,2}\d{6,9})\b")
_RE_PHONE = re.compile(r"\+?\d[\d\s\-()]{7,}\d")
_RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_RE_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_RE_BTC_BECH32 = re.compile(r"\bbc1[ac-hj-np-z02-9]{6,87}\b")
_RE_BTC_LEGACY = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{24,33}\b")
_RE_API = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google_api": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "github_pat": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "slack_token": re.compile(r"\bxox[bp]a-[0-9A-Za-z]{10,48}\b"),
    "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    "stripe": re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b"),
    "generic_jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
}


def luhn_valid(number):
    digits = [c for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        n = int(d)
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def valid_ssn(match):
    m = _RE_SSN.fullmatch(match.strip())
    if not m:
        return False
    area, group, serial = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0 or serial == 0:
        return False
    return True


def build_table(types):
    table = []
    for t in types:
        if t == "ssn":
            table.append(("ssn", _RE_SSN, valid_ssn))
        elif t == "credit_card":
            table.append(("credit_card", _RE_CC, luhn_valid))
        elif t == "passport":
            table.append(("passport", _RE_PASSPORT, None))
        elif t == "phone":
            table.append(("phone", _RE_PHONE, None))
        elif t == "email":
            table.append(("email", _RE_EMAIL, None))
        elif t == "api_key":
            for label, rx in _RE_API.items():
                table.append(("api_key:" + label, rx, None))
        elif t == "iban":
            table.append(("iban", _RE_IBAN, None))
        elif t == "bitcoin":
            table.append(("bitcoin:bech32", _RE_BTC_BECH32, None))
            table.append(("bitcoin:legacy", _RE_BTC_LEGACY, None))
    return table


# Files we skip outright (binary / archive formats that would produce noise).
_SKIP_EXT = {
    ".exe", ".dll", ".sys", ".so", ".dylib", ".bin", ".dat", ".db", ".sqlite",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".ico",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flv",
    ".zip", ".gz", ".tar", ".7z", ".rar", ".bz2", ".xz",
    ".evtx", ".pf", ".pdf",
}
# Magic bytes that indicate a binary (non-text) file. We read the first 2KB
# and reject if it contains a NUL byte or too many non-printable chars.
_MAGIC_BIN_PREFIXES = (
    b"MZ", b"\x7fELF", b"\xfe\xed\xfa", b"\xcf\x84\x01", b"PE\x00\x00",
    b"\x1f\x8b", b"PK\x03\x04", b"Rar!", b"\x42\x5a\x68",
)


def _looks_textual(path, head):
    if head.startswith(_MAGIC_BIN_PREFIXES):
        return False
    if b"\x00" in head:
        return False
    # Allow common text; reject if >10% non-text control chars.
    if not head:
        return True
    non_text = sum(1 for b in head if b < 9 or (13 < b < 32))
    return non_text / max(1, len(head)) < 0.10


def main(argv):
    if len(argv) != 5:
        print("usage: pii_scan.py <evidence_path> <output_json> <patterns_csv> <max_hits>",
              file=sys.stderr)
        return 2
    evidence_path, out_json, patterns_csv, max_hits_s = argv[1:5]
    types = [t.strip() for t in patterns_csv.split(",") if t.strip()]
    if not types:
        types = ["ssn", "credit_card", "passport", "phone", "email",
                 "api_key", "iban", "bitcoin"]
    try:
        max_hits = int(max_hits_s)
    except ValueError:
        max_hits = 500
    table = build_table(types)

    root = Path(evidence_path)
    if not root.exists():
        payload = {"hits": [], "files_scanned": 0, "error": "path not found: " + evidence_path}
        with open(out_json, "w") as fh:
            json.dump(payload, fh, ensure_ascii=False, default=str)
        print("path not found: " + evidence_path, file=sys.stderr)
        return 0

    files = sorted(root.rglob("*")) if root.is_dir() else [root]
    hits = []
    counts = {}
    files_scanned = 0
    context_chars = 40
    for f in files:
        if not f.is_file():
            continue
        if f.suffix.lower() in _SKIP_EXT:
            continue
        try:
            with open(f, "rb") as fh:
                head = fh.read(2048)
            if not _looks_textual(f, head):
                continue
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        files_scanned += 1
        for lineno, line in enumerate(lines, start=1):
            for label, rx, validator in table:
                if counts.get(label, 0) >= max_hits:
                    continue
                for m in rx.finditer(line):
                    candidate = m.group(0)
                    if validator is not None and not validator(candidate):
                        continue
                    if counts.get(label, 0) >= max_hits:
                        break
                    start = max(0, m.start() - context_chars)
                    end = min(len(line), m.end() + context_chars)
                    context = line[start:end].strip()
                    hits.append({
                        "file": str(f),
                        "line_number": lineno,
                        "pattern_type": label,
                        "match": candidate,
                        "context": context,
                    })
                    counts[label] = counts.get(label, 0) + 1
    payload = {"hits": hits, "files_scanned": files_scanned,
               "counts": counts, "summary": str(len(hits)) + " hit(s) across "
               + str(files_scanned) + " file(s)"}
    with open(out_json, "w") as fh:
        json.dump(payload, fh, ensure_ascii=False, default=str)
    print(payload["summary"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


class PIIScannerTool(Tool):
    name = "pii_scan"
    image = "svetovid/base"
    description = (
        "Scan evidence files for PII / sensitive data: SSNs, credit-card "
        "numbers (Luhn-validated), passport numbers, phone numbers, emails, "
        "IBANs, Bitcoin addresses, and API keys/tokens (AWS, Google, GitHub, "
        "Slack, Stripe, JWTs). Returns structured hits with line numbers and "
        "surrounding context. Skips binary files. Fills the EnCase "
        "PII-scanner EnScript gap."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence to scan (file or directory). "
                        "Defaults to the whole evidence tree."
                    ),
                },
                "patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Pattern types to scan for. Subset of "
                        "['ssn','credit_card','passport','phone','email',"
                        "'api_key','iban','bitcoin']. Defaults to all."
                    ),
                },
                "max_hits_per_pattern": {
                    "type": "number",
                    "default": MAX_HITS_PER_PATTERN,
                    "description": "Cap on hits retained per pattern type.",
                },
            },
            "required": [],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        sub = args.get("evidence_subpath", "") or ""
        patterns = args.get("patterns") or list(PATTERN_TYPES)
        # Validate requested pattern types; drop unknowns rather than failing.
        patterns = [p for p in patterns if p in PATTERN_TYPES] or list(PATTERN_TYPES)
        max_hits = int(args.get("max_hits_per_pattern", MAX_HITS_PER_PATTERN))

        out_json = "/work/pii_hits.json"
        script_host = Path(ctx.output_dir) / "pii_scan.py"
        script_host.write_text(_SCANNER_SCRIPT)

        cmd = [
            "python3", "/work/pii_scan.py",
            (f"/evidence/{sub}".rstrip("/") if sub else "/evidence"),
            out_json,
            ",".join(patterns),
            str(max_hits),
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
                ctx.investigation_id, f"pii_scan failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"pii_scan failed: {e}",
            )

        hits: list[dict[str, Any]] = []
        summary = ""
        files_scanned = 0
        local_out = Path(ctx.output_dir) / "pii_hits.json"
        if local_out.exists():
            try:
                payload = json.loads(local_out.read_text())
                hits = payload.get("hits", []) if isinstance(payload, dict) else []
                summary = payload.get("summary", "") if isinstance(payload, dict) else ""
                files_scanned = payload.get("files_scanned", 0) if isinstance(payload, dict) else 0
            except Exception as e:
                summary = f"pii_scan output couldn't be parsed: {e}"
        if not summary:
            summary = f"pii_scan exited {res.exit_code} with no usable output"

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

        # Persist to the case DB (best-effort) so the Cases screen records it.
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
            summary=summary,
            data={"hits": hits, "files_scanned": files_scanned},
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


# Module-level instance the registry picks up like the other tools.
tool = PIIScannerTool()
