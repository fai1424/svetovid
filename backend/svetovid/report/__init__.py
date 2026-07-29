"""Report assembly + export pipeline.

The agent streams ``report.section_added`` / ``report.ioc`` /
``report.timeline_entry`` / ``report.finding`` events during an
investigation. This package turns that event stream (persisted in the
``events`` table) plus the investigation row + tool calls into:

  * Markdown      — concatenated narrative sections
  * JSON          — the full structured data blob
  * STIX 2.1      — a bundle of Indicator / ObservedData / Report SDOs
  * CASE (UCO)    — a JSON-LD case bundle
  * PDF           — a printable report (Markdown → HTML → PDF)

Nothing here calls an external STIX/CASE library — the dicts are
constructed by hand against the published specifications. This keeps the
dependency surface small and the output easy to audit.
"""

from __future__ import annotations

from typing import Any

from .exporters import (
    export_case_uco,
    export_json,
    export_markdown,
    export_stix,
    gather_investigation_data,
)

__all__ = [
    "gather_investigation_data",
    "export_markdown",
    "export_stix",
    "export_case_uco",
    "export_json",
]


def supported_formats() -> list[str]:
    """The export formats the API accepts (matches ``?format=`` values)."""
    return ["markdown", "json", "stix", "case", "pdf"]


def render(investigation_data: dict[str, Any], fmt: str) -> tuple[Any, str]:
    """Render ``investigation_data`` in ``fmt``.

    Returns ``(payload, media_type)``. For ``pdf`` the payload is ``bytes``;
    for everything else it's a ``str`` / ``dict`` ready to serialize.
    """
    if fmt == "markdown":
        return export_markdown(investigation_data), "text/markdown; charset=utf-8"
    if fmt == "json":
        return export_json(investigation_data), "application/json"
    if fmt == "stix":
        return export_stix(investigation_data), "application/stix+json"
    if fmt == "case":
        return export_case_uco(investigation_data), "application/ld+json"
    raise ValueError(f"unsupported format {fmt!r} (render does not handle pdf)")
