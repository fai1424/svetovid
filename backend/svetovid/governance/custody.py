"""Chain-of-custody forms (governance).

A chain-of-custody form documents who collected each piece of evidence, when,
where it came from, and (critically) the cryptographic fingerprint that lets a
court verify the evidence has not been altered since collection.

This module produces a structured custody document (JSON-serializable) from a
list of evidence artifacts and seals it with a tamper-evident SHA-256
integrity seal computed over the canonical concatenation of the per-item
records. ``verify_custody_form`` recomputes that seal and reports whether the
form (or any item) has been modified after sealing.

The seal is *not* a signature — it proves integrity, not origin. The collector
identity + collection timestamp are part of the sealed record, so a form that
re-uses an old seal with a changed collector is detected.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .hashing import canonical_record, sha256_of_bytes

# Field order used when building the per-item string that the seal is hashed
# over. Keeping it explicit (rather than dict order) makes the seal stable
# across Python versions and json-sort implementations.
SEALED_ITEM_FIELDS = (
    "chain_sequence",
    "item_id",
    "description",
    "source_location",
    "sha256",
    "md5",
    "size_bytes",
    "collector_name",
    "collected_at",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class ChainOfCustodyEntry:
    """One evidence item in a chain-of-custody form."""

    case_id: str
    item_id: str
    description: str
    collector_name: str
    collected_at: str
    source_location: str
    sha256: str | None
    md5: str | None
    size_bytes: int
    chain_sequence: int = 0

    def to_record(self) -> dict[str, Any]:
        """Flat dict form suitable for sealing + JSON serialization."""
        return {
            "case_id": self.case_id,
            "item_id": self.item_id,
            "description": self.description,
            "collector_name": self.collector_name,
            "collected_at": self.collected_at,
            "source_location": self.source_location,
            "sha256": self.sha256,
            "md5": self.md5,
            "size_bytes": self.size_bytes,
            "chain_sequence": self.chain_sequence,
        }


def _entries_from_artifacts(
    case_id: str,
    artifacts: list[dict[str, Any]],
    collector_name: str,
    collected_at: str,
) -> list[ChainOfCustodyEntry]:
    """Build custody entries from scanner artifact dicts (best-effort)."""
    entries: list[ChainOfCustodyEntry] = []
    for seq, art in enumerate(artifacts, start=1):
        extra = art.get("extra") or {}
        sha256 = extra.get("sha256") or art.get("sha256")
        md5 = extra.get("md5") or art.get("md5")
        entries.append(ChainOfCustodyEntry(
            case_id=case_id,
            item_id=str(art.get("artifact_id") or art.get("kind") or "?"),
            description=str(art.get("family") or art.get("kind") or art.get("path") or ""),
            collector_name=collector_name,
            collected_at=collected_at,
            source_location=str(art.get("path") or ""),
            sha256=sha256,
            md5=md5,
            size_bytes=int(art.get("size_bytes") or 0),
            chain_sequence=seq,
        ))
    return entries


def _compute_seal(records: list[dict[str, Any]]) -> str:
    """SHA-256 over the canonical concatenation of the per-item sealed fields."""
    parts: list[bytes] = []
    for rec in records:
        sub = {k: rec.get(k) for k in SEALED_ITEM_FIELDS}
        parts.append(canonical_record(sub))
    blob = b"\n".join(parts)
    return "sha256:" + sha256_of_bytes(blob)


def create_custody_form(
    case_id: str,
    artifacts: list[dict[str, Any]],
    collector_name: str,
) -> dict[str, Any]:
    """Produce a structured chain-of-custody document for ``artifacts``.

    ``artifacts`` is a list of dicts shaped like scanner output (fields
    ``path``, ``size_bytes``, ``family``/``kind``, optional ``extra.sha256`` /
    ``extra.md5``). The returned document has the per-item entries, collection
    metadata, and an ``integrity_seal`` computed over the canonical
    concatenation of the per-item records.
    """
    collected_at = _now_iso()
    entries = _entries_from_artifacts(case_id, artifacts, collector_name, collected_at)
    records = [e.to_record() for e in entries]
    seal = _compute_seal(records)

    return {
        "case_id": case_id,
        "collector_name": collector_name,
        "collected_at": collected_at,
        "form_version": "1.0",
        "items": records,
        "item_count": len(records),
        "integrity_seal": seal,
        "sealed_at": _now_iso(),
    }


def verify_custody_form(form: dict[str, Any]) -> bool:
    """Return True iff the form's integrity seal matches its current contents.

    The seal is recomputed from the per-item records exactly as
    ``create_custody_form`` produced it; any change to an item's sealed fields
    (hash, size, description, collector, timestamp, sequence) — or to the item
    list itself — makes this return False. A missing or malformed seal is
    treated as not-verified.
    """
    try:
        records = form.get("items") or []
        if not isinstance(records, list):
            return False
        expected = _compute_seal([dict(r) for r in records])
        stored = form.get("integrity_seal")
        if not isinstance(stored, str) or not stored:
            return False
        return _consttime_eq(expected, stored)
    except Exception:
        return False


def _consttime_eq(a: str, b: str) -> bool:
    """Constant-time string comparison (defends against timing oracles)."""
    import hmac
    return hmac.compare_digest(a, b)


__all__ = [
    "ChainOfCustodyEntry",
    "create_custody_form",
    "verify_custody_form",
]
