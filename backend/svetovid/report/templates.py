"""Jinja2 report templates (kept as strings — no external template files).

Each template is a small Markdown fragment rendered against an
``investigation_data``-shaped context. ``render_template`` selects by name.
These are used by the report assembly path and by the frontend's
"executive summary" / "technical report" presets — they are intentionally
deterministic so the same inputs always produce the same prose, which
makes report diffs reviewable.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from jinja2 import Environment, StrictUndefined

from .exporters import _ioc_type, _ioc_value

# Templates as module-level strings so there are no external files to ship.
EXECUTIVE_SUMMARY = """
{% set inv = investigation %}
The Svetovid investigation **{{ inv.get("goal_id", "—") }}**
(case `{{ inv.get("case_id", "—") }}`) ran to a status of
**{{ inv.get("status", "—") }}** between {{ inv.get("started_at", "—") }}
and {{ inv.get("ended_at", "—") or "—" }}.
{% set n_iocs = iocs | length %}
{% set n_timeline = timeline | length %}
{% set n_tech = attack_techniques | length %}
{% set n_calls = tool_calls | length %}
During the engagement the analyst agent executed {{ n_calls }} forensic
tool call(s), surfaced {{ n_iocs }} indicator(s) of compromise, assembled
{{ n_timeline }} timeline entry/entries, and mapped the activity to
{{ n_tech }} MITRE ATT&CK technique(s).
{% if inv.get("user_prompt") %}

The stated objective was:

> {{ inv.get("user_prompt") }}
{% endif %}

{% if findings %}
Key findings:

{% for f in findings %}
- {{ f.get("title") or f.get("summary") or f.get("description") or ("finding " ~ loop.index) }}
{% endfor %}
{% else %}
No discrete findings were recorded; the structured timeline and indicator
tables remain the authoritative artifact.
{% endif %}
""".strip()


TECHNICAL_REPORT = """
# Technical Report — {{ investigation.get("goal_id", "—") }}

**Investigation**: `{{ investigation.get("id", "—") }}`
**Case**: {{ investigation.get("case_id", "—") }}
**Status**: {{ investigation.get("status", "—") }}
**Evidence**: `{{ investigation.get("evidence_path", "—") }}`
**Started**: {{ investigation.get("started_at", "—") }}  **Ended**: {{ investigation.get("ended_at", "—") or "—" }}

{% if investigation.get("user_prompt") %}
## Objective
{{ investigation.get("user_prompt") }}
{% endif %}

## Narrative
{% for s in report_sections %}
### {{ s.get("title", s.get("section_id")) }}
{{ s.get("markdown", "") }}
{% else %}
_No report sections were written._
{% endfor %}

## MITRE ATT&CK Techniques
{% for t in attack_techniques %}- `{{ t }}`
{% else %}_none mapped_
{% endfor %}
""".strip()


IOC_TABLE = """
| Type | Value | Description | ATT&CK |
|---|---|---|---|
{% for ioc in iocs %}
| {{ ioc_type(ioc) }} | `{{ ioc_value(ioc) }}` | {{ ioc.get("description") or "" }} | {{ (ioc.get("mitre_tags") or []) | join(", ") }} |
{% else %}
| _none_ | _none_ | _no indicators recorded_ | |
{% endfor %}
""".strip()


TIMELINE_TABLE = """
| Time | Source | Actor | Event | ATT&CK |
|---|---|---|---|---|
{% for e in timeline %}
| {{ e.get("timestamp") or e.get("ts") or "" }} | {{ e.get("source") or "" }} | {{ e.get("actor") or "" }} | {{ e.get("event") or e.get("description") or "" }} | {{ (e.get("mitre_tags") or []) | join(", ") }} |
{% else %}
| _none_ | | | _no timeline entries_ | |
{% endfor %}
""".strip()


_TEMPLATES: dict[str, str] = {
    "executive_summary": EXECUTIVE_SUMMARY,
    "technical_report": TECHNICAL_REPORT,
    "ioc_table": IOC_TABLE,
    "timeline_table": TIMELINE_TABLE,
}


def _make_env() -> Environment:
    env = Environment(
        # Templates emit Markdown (not HTML), so autoescaping is off — we
        # never want Jinja to HTML-entity-encode the pipe characters in our
        # table rows.
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
    )
    env.globals.update({
        "ioc_type": _ioc_type,
        "ioc_value": _ioc_value,
        "now": lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    return env


_ENV = _make_env()


def render_template(template_name: str, context: dict[str, Any]) -> str:
    """Render a named template against ``context``.

    ``template_name`` must be one of: ``executive_summary``,
    ``technical_report``, ``ioc_table``, ``timeline_table``.
    Missing keys raise (StrictUndefined) so a typo in the context is loud.
    """
    src = _TEMPLATES.get(template_name)
    if src is None:
        raise KeyError(
            f"unknown template {template_name!r}; "
            f"choose from {sorted(_TEMPLATES)}"
        )
    # Provide sensible defaults so callers don't have to pre-fill every key.
    full_context: dict[str, Any] = {
        "investigation": {},
        "report_sections": [],
        "iocs": [],
        "timeline": [],
        "findings": [],
        "tool_calls": [],
        "attack_techniques": [],
    }
    full_context.update(context or {})
    tmpl = _ENV.from_string(src)
    return tmpl.render(**full_context)
