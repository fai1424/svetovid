"""Markdown → HTML → PDF renderer.

Uses the ``markdown`` library (already a transitive dep) to turn the
report Markdown into HTML, then ``weasyprint`` to produce a PDF. WeasyPrint
is NOT a declared dependency — it pulls in native libs (cairo/pango) that
the Tauri sidecar shouldn't require. So we try to import it lazily and
fall back to a self-contained printable HTML wrapper when it's missing.

The frontend can always render the printable HTML in a webview and use the
browser's native print-to-PDF; this keeps the export working on every
install. The ``render_pdf`` contract is: return ``bytes`` that are either
a real PDF (``%PDF-`` magic) or UTF-8 HTML (the fallback). ``is_pdf`` lets
the caller set the right content-type.
"""

from __future__ import annotations

import html as _html
from datetime import datetime, timezone
from typing import Any

import markdown as _md

from .exporters import _ioc_type, _ioc_value  # noqa: F401  (re-export-friendly helpers)


def _now_pretty() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _md_to_html(md: str) -> str:
    """Convert Markdown to styled HTML."""
    body = _md.markdown(
        md,
        extensions=["tables", "fenced_code", "sane_lists", "nl2br"],
    )
    return body


def _build_title_page_html(metadata: dict[str, Any], toc: list[str]) -> str:
    inv = metadata.get("investigation") or {}
    case_id = inv.get("case_id") or "—"
    goal = inv.get("goal_id") or "—"
    inv_id = inv.get("id") or "—"
    status = inv.get("status") or "—"
    started = inv.get("started_at") or "—"
    ended = inv.get("ended_at") or "—"
    analyst = metadata.get("analyst") or "Svetovid (autonomous)"
    generated = metadata.get("generated_at") or _now_pretty()
    evidence = inv.get("evidence_path") or "—"

    toc_html = "\n".join(f'<li><span>{_html.escape(t)}</span></li>' for t in toc)

    return f"""
    <section class="title-page">
      <h1>Svetovid Investigation Report</h1>
      <table class="meta">
        <tr><th>Case ID</th><td>{_html.escape(str(case_id))}</td></tr>
        <tr><th>Investigation</th><td><code>{_html.escape(str(inv_id))}</code></td></tr>
        <tr><th>Goal</th><td>{_html.escape(str(goal))}</td></tr>
        <tr><th>Status</th><td>{_html.escape(str(status))}</td></tr>
        <tr><th>Started</th><td>{_html.escape(str(started))}</td></tr>
        <tr><th>Ended</th><td>{_html.escape(str(ended))}</td></tr>
        <tr><th>Evidence</th><td><code>{_html.escape(str(evidence))}</code></td></tr>
        <tr><th>Analyst</th><td>{_html.escape(str(analyst))}</td></tr>
        <tr><th>Generated</th><td>{_html.escape(str(generated))}</td></tr>
      </table>
      <h2 class="toc-heading">Table of Contents</h2>
      <ol class="toc">{toc_html}</ol>
    </section>
    """


def _build_attack_table_html(techniques: list[str]) -> str:
    if not techniques:
        return ""
    rows = "\n".join(
        f"<tr><td><code>{_html.escape(t)}</code></td>"
        f"<td>{_html.escape(t)}</td>"
        f'<td><a href="https://attack.mitre.org/techniques/{_html.escape(t.replace(".", "/"))}">'
        f"reference</a></td></tr>"
        for t in techniques
    )
    return f"""
    <section class="new-page">
      <h1>ATT&amp;CK Technique Summary</h1>
      <table class="data">
        <thead><tr><th>ID</th><th>Name</th><th>Reference</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
    """


def _build_ioc_table_html(iocs: list[dict[str, Any]]) -> str:
    if not iocs:
        return ""
    rows = []
    for ioc in iocs:
        t = _ioc_type(ioc)
        v = _ioc_value(ioc)
        desc = _html.escape(str(ioc.get("description") or ioc.get("desc") or ""))
        rows.append(
            f"<tr><td>{_html.escape(t)}</td><td><code>{_html.escape(v)}</code></td>"
            f"<td>{desc}</td></tr>"
        )
    return f"""
    <section class="new-page">
      <h1>Indicators of Compromise</h1>
      <table class="data">
        <thead><tr><th>Type</th><th>Value</th><th>Description</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </section>
    """


def _build_custody_appendix_html(tool_calls: list[dict[str, Any]]) -> str:
    if not tool_calls:
        return ""
    rows = []
    for tc in tool_calls:
        tool = _html.escape(str(tc.get("tool") or ""))
        exit_code = _html.escape(str(tc.get("exit_code", "—")))
        dur = _html.escape(str(tc.get("duration_s", "—")))
        h = _html.escape(str(tc.get("output_hash") or "—"))
        ts = _html.escape(str(tc.get("ts") or "—"))
        rows.append(
            f"<tr><td>{ts}</td><td>{tool}</td><td>{exit_code}</td>"
            f"<td>{dur}s</td><td><code>{h}</code></td></tr>"
        )
    return f"""
    <section class="new-page">
      <h1>Appendix — Chain of Custody</h1>
      <p>Every tool invocation is recorded below. Output hashes anchor the
      provenance chain: a reviewer can re-run a tool and confirm the same
      artifact by comparing the hash.</p>
      <table class="data">
        <thead><tr><th>Timestamp</th><th>Tool</th><th>Exit</th><th>Duration</th><th>Output hash</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </section>
    """


_CSS = """
@page { size: A4; margin: 2cm; }
body { font-family: -apple-system, "Helvetica Neue", Arial, sans-serif; color: #111;
       font-size: 11pt; line-height: 1.45; }
code, pre { font-family: "JetBrains Mono", "SF Mono", Menlo, monospace; font-size: 9.5pt; }
h1 { font-size: 20pt; border-bottom: 2px solid #0b3d2e; padding-bottom: 4px; margin-top: 0; }
h2 { font-size: 14pt; margin-top: 1.4em; }
.title-page { text-align: left; }
.title-page h1 { border: none; margin-top: 3cm; }
.title-page .meta { border-collapse: collapse; margin-top: 1.5cm; width: 100%; }
.title-page .meta th { text-align: left; width: 30%; padding: 4px 8px;
                       background: #f3f4f6; border: 1px solid #ddd; font-weight: 600; }
.title-page .meta td { padding: 4px 8px; border: 1px solid #ddd; }
.toc-heading { margin-top: 2cm; }
.toc { font-size: 10pt; }
table.data { border-collapse: collapse; width: 100%; margin: 0.6em 0; }
table.data th, table.data td { border: 1px solid #ccc; padding: 4px 8px; text-align: left;
                               font-size: 9.5pt; vertical-align: top; }
table.data th { background: #f3f4f6; }
.new-page { page-break-before: always; }
a { color: #0b3d2e; text-decoration: none; }
"""


def render_pdf(markdown_body: str, metadata: dict[str, Any]) -> bytes:
    """Render a printable report to bytes.

    ``markdown_body`` is the narrative Markdown (from ``export_markdown``);
    ``metadata`` is the gathered ``investigation_data`` dict plus an
    optional ``analyst`` name.

    Returns a real ``%PDF-`` document when weasyprint is importable; falls
    back to a printable HTML wrapper otherwise (so the frontend can still
    hand the user a downloadable artifact).
    """
    sections = sorted(
        (metadata.get("report_sections") or []),
        key=lambda s: s.get("order", 0),
    )
    toc = [s.get("title") or s.get("section_id") or "Section" for s in sections]
    toc += [x for x in (
        "Indicators of Compromise" if metadata.get("iocs") else None,
        "ATT&CK Technique Summary" if metadata.get("attack_techniques") else None,
        "Chain of Custody" if metadata.get("tool_calls") else None,
    ) if x]

    narrative_html = (
        f'<section class="new-page"><h1>Narrative</h1>'
        f'{_md_to_html(markdown_body)}</section>'
    )
    full_html = (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>Svetovid Report</title><style>{_CSS}</style></head><body>"
        f"{_build_title_page_html(metadata, toc)}"
        f"{_build_attack_table_html(metadata.get('attack_techniques') or [])}"
        f"{_build_ioc_table_html(metadata.get('iocs') or [])}"
        f"{narrative_html}"
        f"{_build_custody_appendix_html(metadata.get('tool_calls') or [])}"
        f"</body></html>"
    )

    try:
        import weasyprint  # type: ignore
        pdf_bytes = weasyprint.HTML(string=full_html).write_pdf()
        return pdf_bytes
    except Exception:
        # weasyprint not installed (or its native deps missing). Return the
        # printable HTML so the export still produces a downloadable artifact.
        return full_html.encode("utf-8")


def is_pdf(blob: bytes) -> bool:
    """True if ``blob`` starts with the PDF magic — distinguishes real PDFs
    from the printable-HTML fallback so the caller picks the right MIME."""
    return blob[:5] == b"%PDF-"
