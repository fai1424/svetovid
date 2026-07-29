"""Human-in-the-loop (HITL) approval gate.

The headline governance feature of Svetovid. Before a goal finalizes its
report (when ``settings.hitl_report_release == "required"``), the agent MUST
wait for a human to approve or reject the drafted report. This module turns
what used to be a ``bus.publish(hitl_request); await asyncio.sleep(1)``
no-op into a real blocking gate.

Design:

  * ``request_approval`` publishes the ``hitl.request`` event (so the UI flips
    to the "paused" state and shows the Approve/Reject buttons), then awaits
    an ``asyncio.Future`` stored in a module-level dict keyed by
    ``investigation_id``.
  * ``resolve_approval`` is called by the ``POST /api/investigations/{id}/hitl``
    endpoint when the human clicks Approve/Reject. It resolves the Future,
    unblocking (or cancelling) the goal.
  * A timeout (default 300s) guards against a human walking away — a timeout
    counts as a rejection (returns ``False``) so the goal never hangs
    indefinitely.

Only ONE pending approval per investigation_id at a time. If a second
``request_approval`` arrives for the same id while the first is in flight,
the first is cancelled (rejected) and replaced.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from . import events as E

logger = logging.getLogger("svetovid.hitl")

# Module-level registry of pending approvals, keyed by investigation_id.
# Each value is the asyncio.Future the goal coroutine is awaiting.
_pending: "dict[str, asyncio.Future[bool]]" = {}

# Per-investigation outcome ledger: once a gate resolves (approve/reject/
# timeout) the decision is recorded here so the investigation runner can tell
# whether the goal self-cancelled and persist the right terminal status.
# Keyed by investigation_id (NOT by goal singleton), so there's no cross-
# investigation state pollution.
_outcomes: "dict[str, bool]" = {}

# Default timeout for an approval gate, in seconds (5 minutes). A human who
# hasn't decided in 5 minutes is treated as a rejection so the investigation
# never wedges. Overridable per-call by ``request_approval(timeout=...)``.
DEFAULT_TIMEOUT = 300


def get_outcome(investigation_id: str) -> bool | None:
    """Return the recorded gate outcome for an investigation, or ``None``.

    ``None`` means no gate ran (or hasn't resolved). ``True`` = approved,
    ``False`` = rejected/timed-out. Used by ``_run_goal`` to decide whether
    the goal self-cancelled.
    """
    return _outcomes.get(investigation_id)


def reset_outcome(investigation_id: str) -> None:
    """Clear the recorded outcome for an investigation (housekeeping)."""
    _outcomes.pop(investigation_id, None)


def _new_future() -> "asyncio.Future[bool]":
    """Create a Future bound to the currently running event loop."""
    return asyncio.get_event_loop().create_future()


def resolve_approval(investigation_id: str, approved: bool) -> bool:
    """Resolve a pending approval gate.

    Called by the HITL REST endpoint when the human approves or rejects the
    report. Returns ``True`` if there was a pending gate to resolve, ``False``
    if nothing was pending (e.g. a double-click, or approval for an id that
    already timed out). Never raises — a missing/already-resolved gate is a
    benign no-op from the caller's perspective.
    """
    fut = _pending.pop(investigation_id, None)
    if fut is None or fut.done():
        logger.info("hitl resolve for %s: no pending gate (approved=%s)",
                    investigation_id, approved)
        return False
    if not fut.get_loop().is_closed():
        fut.set_result(approved)
    _outcomes[investigation_id] = approved
    logger.info("hitl resolve for %s: approved=%s", investigation_id, approved)
    return True


async def request_approval(
    investigation_id: str,
    bus: Any,
    reason: str,
    payload: dict[str, Any],
    *,
    timeout: float | None = None,
) -> bool:
    """Block until the human approves/rejects the report gate.

    Publishes ``hitl.request`` (the UI flips to "paused" and shows the
    Approve/Reject buttons), then awaits the matching ``resolve_approval``
    call. Returns ``True`` if approved, ``False`` if rejected or the gate
    timed out. Always publishes a ``hitl.response`` event recording the
    outcome so the UI/audit trail reflects the decision.
    """
    to = DEFAULT_TIMEOUT if timeout is None else timeout

    # CI / headless auto-approve: when there is no human to click the button
    # (automated tests, the report-export pipeline that drives goals headless),
    # ``SVETOVID_HITL_AUTO_APPROVE`` short-circuits the gate so the goal
    # completes deterministically. This mirrors the old asyncio.sleep(1)
    # behavior but is explicit and auditable. In normal desktop use this env
    # var is unset and the gate truly blocks.
    if os.environ.get("SVETOVID_HITL_AUTO_APPROVE"):
        logger.info("hitl auto-approve (CI/headless) for %s", investigation_id)
        bus.publish(E.hitl_request(investigation_id, reason, payload))
        _outcomes[investigation_id] = True
        _publish_response(bus, investigation_id, True, "auto-approved (CI/headless)")
        return True

    # Cancel any prior pending gate for this id (defensive: a goal should not
    # have two gates in flight, but if it does the oldest one is rejected).
    stale = _pending.pop(investigation_id, None)
    if stale is not None and not stale.done() and not stale.get_loop().is_closed():
        stale.set_result(False)

    fut: "asyncio.Future[bool]" = _new_future()
    _pending[investigation_id] = fut

    bus.publish(E.hitl_request(investigation_id, reason, payload))

    try:
        approved = await asyncio.wait_for(fut, timeout=to)
        _outcomes[investigation_id] = approved
        outcome = "approved" if approved else "rejected"
        _publish_response(bus, investigation_id, approved, outcome)
        return approved
    except asyncio.TimeoutError:
        logger.warning("hitl gate timed out for %s after %ss", investigation_id, to)
        _pending.pop(investigation_id, None)
        _outcomes[investigation_id] = False
        _publish_response(bus, investigation_id, False, f"timeout after {to}s")
        return False


def _publish_response(bus: Any, investigation_id: str, approved: bool, detail: str) -> None:
    """Emit the ``hitl.response`` event so the UI clears the paused state."""
    try:
        bus.publish(E.hitl_response(investigation_id, approved, detail))
    except Exception:  # never let event emission break the gate
        logger.debug("hitl_response publish failed", exc_info=True)
