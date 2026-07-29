"""Periodic batch uploader: drains the local SQLite queue to an HTTPS endpoint.

The uploader runs a background asyncio task that wakes every
``settings.telemetry_upload_interval_s`` seconds (default 300 = 5 min), pulls
all queued records via ``collector.drain_queue()``, and POSTs them as a JSON
array to ``settings.telemetry_endpoint``.

Fail-safe rules:
  - If telemetry is disabled → the task sleeps (it does NOT drain, so records
    accumulate locally until the user re-enables; this preserves data the user
    opted into).
  - If ``telemetry_endpoint`` is empty → same: sleep, keep records.
  - If the upload raises (network, non-2xx, timeout) → records are put back
    into the queue and retried next cycle. ``drain_queue`` removes rows from
    the DB; on failure we re-enqueue them with ``enqueue_record``.
  - Never blocks app startup/shutdown; never propagates exceptions out of the
    loop.

Uses ``httpx`` (already a dependency for the cloud tool wrappers).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from ..config import load_settings
from . import collector

logger = logging.getLogger("svetovid.telemetry")

# How often the uploader wakes up, in seconds.
DEFAULT_INTERVAL_S = 300
# Per-batch cap on records; the loop just runs again next tick if more remain.
DEFAULT_BATCH_LIMIT = 500
# HTTP timeout (connect + read). Telemetry must never stall the app.
HTTP_TIMEOUT_S = 15.0
# Maximum payload size (bytes) before we split into smaller POSTs.
MAX_PAYLOAD_BYTES = 1_000_000


class Uploader:
    """Background loop that flushes the local telemetry queue to a server."""

    def __init__(
        self,
        interval_s: int = DEFAULT_INTERVAL_S,
        batch_limit: int = DEFAULT_BATCH_LIMIT,
    ) -> None:
        self._interval_s = interval_s
        self._batch_limit = batch_limit
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    # ---- lifecycle ----

    def start(self) -> None:
        """Launch the background upload loop (no-op if already running)."""
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run(), name="telemetry-uploader")
        logger.info("Telemetry uploader started (interval=%ss)", self._interval_s)

    async def stop(self) -> None:
        """Signal the loop to stop and wait for it to wind down."""
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    # ---- internals ----

    @staticmethod
    def _enabled() -> bool:
        """Telemetry is on AND an endpoint is configured."""
        try:
            s = load_settings()
        except Exception:
            return False
        endpoint = (s.telemetry_endpoint or "").strip()
        return bool(s.telemetry_enabled and endpoint)

    @staticmethod
    def _endpoint() -> str:
        try:
            return (load_settings().telemetry_endpoint or "").strip()
        except Exception:
            return ""

    async def _run(self) -> None:
        """Main loop: wake on an interval, flush if enabled, retry on failure."""
        try:
            while not self._stop.is_set():
                try:
                    if self._enabled():
                        await self._flush_once()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # Any unexpected error is logged but never fatal.
                    logger.exception("telemetry uploader: flush failed")
                # Sleep cooperatively so cancel() is responsive.
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval_s)
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            return

    async def _flush_once(self) -> None:
        """Drain the queue and upload in batches. Re-enqueues on failure."""
        records = collector.drain_queue(limit=self._batch_limit)
        if not records:
            return

        endpoint = self._endpoint()
        client_id = records[0].get("client_id", "")
        try:
            batch: list[dict[str, Any]] = []
            batch_bytes = 2  # "[]"
            for rec in records:
                batch.append(rec)
                batch_bytes += len(_to_json(rec)) + 1
                if batch_bytes >= MAX_PAYLOAD_BYTES:
                    await _post(endpoint, batch)
                    batch = []
                    batch_bytes = 2
            if batch:
                await _post(endpoint, batch)
            logger.info("telemetry: uploaded %d record(s)", len(records))
        except Exception:
            # Upload failed — re-enqueue everything we drained so it survives.
            logger.warning("telemetry: upload failed, retaining %d record(s)", len(records))
            for rec in records:
                collector.enqueue_record(
                    client_id=rec.get("client_id", client_id),
                    event=rec.get("event", "unknown"),
                    ts=rec.get("ts", ""),
                    props=rec.get("props", {}),
                )
            raise


async def _post(endpoint: str, batch: list[dict[str, Any]]) -> None:
    """POST one JSON-array batch to the endpoint. Raises on non-2xx."""
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S) as client:
        resp = await client.post(endpoint, json=batch)
        resp.raise_for_status()


def _to_json(rec: dict[str, Any]) -> str:
    import json
    return json.dumps(rec, default=str)
