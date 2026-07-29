"""Evidence intake hashing (governance).

Every commercial forensic tool fingerprints evidence on intake so its
integrity can be verified later in court. This module provides:

  - ``hash_file(path)``         : SHA-256 + MD5 + size for a single file,
                                  read in 64KB chunks. Files larger than the
                                  configured cap (default 2 GiB) are recorded
                                  by size only with ``hash_skipped: too_large``
                                  so intake never stalls on a disk image.
  - ``hash_evidence_batch(...)``: hash many files, calling a progress callback
                                  after each one (used by the scanner / UI).

Both functions are synchronous and best-effort: a single unreadable file is
recorded with an ``error`` field and never raises — evidence intake must not
abort because one of 200k files is locked.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable

# Read files in 64 KiB chunks — big enough to amortize syscall overhead on
# spinning rust, small enough to keep memory flat on a 4 GiB memory image.
CHUNK_SIZE = 64 * 1024

# Skip hashing anything larger than 2 GiB by default. These are almost always
# raw disk/memory images; hashing them inline would block intake for minutes.
# The size is still recorded so custody is complete; the skip is explicit.
DEFAULT_SIZE_CAP = 2 * 1024 * 1024 * 1024  # 2 GiB

ProgressCb = Callable[[int, int, dict[str, Any]], None]


def hash_file(path: Path, *, size_cap: int = DEFAULT_SIZE_CAP) -> dict[str, Any]:
    """Return ``{sha256, md5, size}`` for ``path``.

    Files larger than ``size_cap`` are recorded by size only with
    ``hash_skipped: "too_large"`` (and ``sha256``/``md5`` set to ``None``) so
    the caller can still build a complete evidence inventory without stalling.

    If the file cannot be read at all (permission, missing, etc.), the result
    carries ``error`` instead of hashes and never raises.
    """
    path = Path(path)
    try:
        st = path.stat()
        size = st.st_size
    except OSError as e:
        return {"path": str(path), "sha256": None, "md5": None, "size": 0,
                "error": f"stat_failed: {e}"}

    result: dict[str, Any] = {"path": str(path), "sha256": None, "md5": None, "size": size}

    if size > size_cap:
        result["hash_skipped"] = "too_large"
        return result

    sha = hashlib.sha256()
    md5 = hashlib.md5()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha.update(chunk)
                md5.update(chunk)
    except OSError as e:
        result["error"] = f"read_failed: {e}"
        return result

    result["sha256"] = sha.hexdigest()
    result["md5"] = md5.hexdigest()
    return result


def hash_evidence_batch(
    paths: list[Path],
    *,
    on_progress: ProgressCb | None = None,
    size_cap: int = DEFAULT_SIZE_CAP,
) -> list[dict[str, Any]]:
    """Hash every path in ``paths`` in order, returning one record per file.

    ``on_progress(done, total, record)`` is invoked after each file (including
    failures and skips) so callers can stream progress to the UI. The batch
    itself never raises on a single bad file — each record is self-describing.
    """
    results: list[dict[str, Any]] = []
    total = len(paths)
    for i, p in enumerate(paths, start=1):
        record = hash_file(p, size_cap=size_cap)
        results.append(record)
        if on_progress is not None:
            on_progress(i, total, record)
    return results


def sha256_of_bytes(data: bytes) -> str:
    """Hex SHA-256 of an in-memory blob (used by the custody integrity seal)."""
    return hashlib.sha256(data).hexdigest()


def canonical_record(record: dict[str, Any]) -> bytes:
    """Serialize a dict deterministically (sorted keys, no spaces) for sealing."""
    import json
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
