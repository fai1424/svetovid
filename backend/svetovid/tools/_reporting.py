"""Shared reporting helpers for tool wrappers.

Tool wrappers (chainsaw, hayabusa, volatility, yara, ...) parse vendor-specific
output into a list of "hits" and then need to do two things that are identical
across tools:

  1. **Persist the tool call** into the case DB's ``tool_calls`` table so the
     Cases screen and exports can replay what ran.
  2. **Emit ``report.timeline_entry`` and ``report.ioc`` events** so the IoC
     tab, Timeline tab, and ATT&CK heatmap populate from real tool output
     (previously they were permanently empty — Q1 in the wiring audit).

This module factors both out so each tool's ``invoke`` stays readable.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..agent import events as E
from ..agent.events import EventBus


async def record_tool_call_db(
    *,
    call_id: str,
    investigation_id: str,
    tool: str,
    args: dict[str, Any],
    exit_code: int,
    duration_s: float,
    output_hash: str | None,
) -> None:
    """Persist one tool call row. Best-effort: never raises into the caller.

    The case DB is a singleton; tools fetch it via ``get_db()``. A persistence
    failure is logged but does NOT fail the tool — the live result still
    returns to the agent over the bus.
    """
    try:
        from ..store import get_db
        db = await get_db()
        await db.record_tool_call(
            call_id=call_id,
            inv_id=investigation_id,
            tool=tool,
            args=args,
            exit_code=exit_code,
            duration_s=duration_s,
            output_hash=output_hash,
        )
    except Exception:  # noqa: BLE001 — tool must not fail because the DB hiccupped
        import logging
        logging.getLogger("svetovid").exception(
            "failed to persist tool_call %s for %s", call_id, tool,
        )


def _mitre_technique_from_tags(tags: Iterable[str] | None) -> str | None:
    """Pick the first ATT&CK technique id (T####) out of a tag list.

    Handles both bare forms (``T1059.001``) and the Sigma convention
    (``attack.t1059.001``) — Sigma/Hayabusa tags carry an ``attack.`` prefix.
    """
    if not tags:
        return None
    import re
    # Match T#### optionally followed by .###, after an optional 'attack.' prefix.
    tech = re.compile(r"^(?:attack\.)?(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
    for t in tags:
        if isinstance(t, str):
            m = tech.match(t.strip())
            if m:
                return m.group(1).upper()
    return None


def emit_hit_events(
    bus: EventBus,
    *,
    investigation_id: str,
    source: str,
    hits: list[dict[str, Any]],
    timeline_fields: dict[str, str],
    ioc_text_getter,
    node: str | None = None,
    max_events: int = 1000,
) -> tuple[int, int]:
    """Emit ``report.timeline_entry`` + ``report.ioc`` events for parsed hits.

    Parameters
    ----------
    bus
        The EventBus to publish onto (also reaches the DB via the persister).
    investigation_id, source
        The owning investigation and the producing tool name.
    hits
        Parsed vendor-specific hit dicts.
    timeline_fields
        Maps the tool's hit keys to the canonical timeline keys:
        ``{"timestamp": <hit key>, "event": <hit key>, "actor": <hit key?>}``.
        Missing keys are skipped gracefully.
    ioc_text_getter
        Callable(hit) -> str: returns the free-form text to scan for IOCs
        (typically the ``details`` blob). Return ``""`` to skip IOC extraction
        for that hit.
    node
        Optional LangGraph node name stamped onto emitted events.
    max_events
        Safety cap so a runaway tool can't flood the bus (and thus the DB).

    Returns ``(timeline_count, ioc_count)``.
    """
    from ..governance.ioc_store import extract_iocs_from_text

    timeline_count = 0
    ioc_count = 0
    emitted = 0
    for hit in hits:
        if emitted >= max_events:
            break
        ts = hit.get(timeline_fields.get("timestamp", "timestamp"))
        event_desc = hit.get(timeline_fields.get("event", "rule_name")) or hit.get("rule_name")
        tags = hit.get("mitre_tags") or hit.get("tags") or []
        if not isinstance(tags, list):
            tags = str(tags).split()
        technique = _mitre_technique_from_tags(tags) or hit.get("mitre_technique")

        actor_key = timeline_fields.get("actor")
        actor = str(hit.get(actor_key, "")).strip() if actor_key else ""
        if ts and event_desc:
            bus.publish(E.report_timeline_entry(
                investigation_id=investigation_id,
                ts=str(ts),
                source=source,
                event=str(event_desc),
                actor=actor or None,
                description=str(hit.get("details", ""))[:500] or None,
                mitre_technique=technique,
                mitre_tags=tags or None,
            ))
            timeline_count += 1
            emitted += 1

        # IOC extraction from the hit's free-form text.
        text = ioc_text_getter(hit) if ioc_text_getter else ""
        if text:
            for ind in extract_iocs_from_text(str(text)):
                if emitted >= max_events:
                    break
                bus.publish(E.report_ioc(
                    investigation_id=investigation_id,
                    ioc_type=ind["ioc_type"],
                    value=ind["value"],
                    context=f"{source}: {event_desc}" if event_desc else source,
                    confidence=0.6,
                    mitre_technique=technique,
                    mitre_tags=tags or None,
                ))
                ioc_count += 1
                emitted += 1
    return timeline_count, ioc_count
