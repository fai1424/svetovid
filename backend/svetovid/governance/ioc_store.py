"""IOC store: accumulate + persist indicators of compromise (governance).

During an investigation the agent emits ``report.ioc`` events as it discovers
indicators (file hashes, IPs, domains, URLs). This module turns those events
into a durable per-investigation IOC list persisted in the case DB so the UI's
IoC tab (and the threat-intel enrichment tool) can read and enrich them.

The store is intentionally source-agnostic: callers can pass an event dict, a
flat set of fields, or call the underlying ``CaseDB.record_ioc`` directly.
"""

from __future__ import annotations

import re
from typing import Any

from ..agent.events import new_id
from ..store import CaseDB, get_db

# IOC type vocabulary — mirrors the ``indicator_type`` enum on the threat-intel
# tool so a recorded IOC can be enriched without translation.
VALID_IOC_TYPES = {"hash", "ip", "domain", "url", "email", "mutex", "registry", "other"}


def _normalize_type(ioc_type: str | None) -> str:
    """Map free-form type strings onto the canonical vocabulary."""
    if not ioc_type:
        return "other"
    t = str(ioc_type).strip().lower()
    # Common aliases seen in tool output / event payloads.
    aliases = {
        "sha256": "hash", "sha1": "hash", "md5": "hash",
        "ipv4": "ip", "ipv6": "ip", "ipaddr": "ip",
        "hostname": "domain", "fqdn": "domain",
        "uri": "url",
    }
    t = aliases.get(t, t)
    return t if t in VALID_IOC_TYPES else "other"


async def record_ioc(
    investigation_id: str,
    ioc_type: str,
    value: str,
    context: str = "",
    confidence: float = 0.0,
    mitre_technique: str | None = None,
    *,
    db: CaseDB | None = None,
) -> str:
    """Persist one IOC observation, returning the new IOC id.

    ``db`` is fetched from the singleton when not supplied.
    """
    db = db or await get_db()
    ioc_id = new_id("ioc")
    await db.record_ioc(
        ioc_id=ioc_id,
        investigation_id=investigation_id,
        ioc_type=_normalize_type(ioc_type),
        value=str(value),
        context=context or "",
        confidence=float(confidence or 0.0),
        mitre_technique=mitre_technique,
    )
    return ioc_id


async def list_iocs(investigation_id: str, *, db: CaseDB | None = None) -> list[dict[str, Any]]:
    """Return all IOCs recorded for ``investigation_id`` (oldest first)."""
    db = db or await get_db()
    return await db.list_iocs(investigation_id)


def ioc_from_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Extract the IOC fields from a ``report.ioc`` event payload.

    A ``report.ioc`` event's ``data`` carries one or more indicators; this
    returns a flat kwargs dict suitable for ``record_ioc``. Returns ``None``
    when the event doesn't carry a usable indicator.
    """
    data = event.get("data") if isinstance(event, dict) else None
    if not isinstance(data, dict):
        return None
    value = data.get("value") or data.get("ioc") or data.get("indicator")
    if not value:
        return None
    ioc_type = data.get("type") or data.get("ioc_type") or data.get("indicator_type")
    return {
        "ioc_type": ioc_type,
        "value": str(value),
        "context": str(data.get("context") or data.get("description") or ""),
        "confidence": float(data.get("confidence") or 0.0),
        "mitre_technique": data.get("mitre_technique") or data.get("mitre") or None,
    }


# ---------------------------------------------------------------------------
# Best-effort IOC extraction from free-form tool output text.
# ---------------------------------------------------------------------------
#
# Tools like Chainsaw/Hayabusa emit a "details" blob of arbitrary text. We scan
# it for the high-signal indicator shapes (IPs, domains, hashes) so a hit
# automatically feeds the IoC tab without the agent having to hand-curate each
# one. Deliberately conservative: we'd rather miss a noisy indicator than flood
# the IoC tab with false positives (e.g. local MAC addrs, build paths).

# IPv4 — exclude the loopback / link-local ranges tools log internally; those
# are not useful IOCs and would dominate the IoC tab. We keep private ranges
# (10/172.16-31/192.168) because lateral movement to internal IPs is signal.
_IPV4_RE = re.compile(
    r"\b(?!127\.|0\.)(25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
)
# Domain — host.label.tld, anchored on a word boundary, requiring a real TLD-
# looking suffix. Skips single-label hostnames and anything that's clearly a
# Windows filename/path (no slashes) to avoid matching local paths.
_DOMAIN_RE = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|co|ai|me|us|uk|de|fr|nl|pw))"
)
# Hashes — sha256 / sha1 / md5. Matched by length + hex.
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

def extract_iocs_from_text(text: str) -> list[dict[str, str]]:
    """Scan free-form text for IP / domain / hash indicators.

    Returns a list of ``{"ioc_type": ..., "value": ...}`` dicts (no duplicates).
    Hashes are checked longest-first so a SHA-256 isn't misread as an MD5.
    """
    if not text or not isinstance(text, str):
        return []
    text = str(text)
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []

    def _add(t: str, v: str) -> None:
        key = (t, v.lower())
        if key not in seen:
            seen.add(key)
            out.append({"ioc_type": t, "value": v})

    # Hashes first (longest → shortest) so we don't substring-match inside one.
    for m in _SHA256_RE.findall(text):
        _add("hash", m.lower())
    for m in _SHA1_RE.findall(text):
        _add("hash", m.lower())
    for m in _MD5_RE.findall(text):
        # Avoid double-counting a sha1/sha256 prefix as md5.
        if ("hash", m.lower()) not in seen:
            _add("hash", m.lower())
    # Domains before IPs so an IP-in-a-domain isn't grabbed by the IP regex.
    for m in _DOMAIN_RE.findall(text):
        _add("domain", m.lower())
    # finditer (not findall) on the grouped IPv4 regex so we get the whole match.
    for m in _IPV4_RE.finditer(text):
        _add("ip", m.group(0))

    return out


__all__ = [
    "VALID_IOC_TYPES",
    "record_ioc",
    "list_iocs",
    "ioc_from_event",
    "extract_iocs_from_text",
]
