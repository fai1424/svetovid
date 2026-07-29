"""Exporters: turn a gathered ``investigation_data`` blob into Markdown /
JSON / STIX 2.1 / CASE (UCO).

All exporters are pure functions on plain dicts — no I/O, no DB, no
external STIX library. The dict shapes follow the published specs:

  * STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
  * CASE / UCO: https://caseontology.org/  (JSON-LD, ``uco-core`` etc.)

Hand-rolled dicts keep the dependency surface tiny and the output
greppable. IDs are deterministic so two runs over the same data produce
the same bundle (stable diffs, no UUID churn).
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STIX_NS = uuid.UUID("8b8e6a7c-4f2d-4e1b-9c3a-2d1f0e9d8c7b")


def _stix_id(object_type: str, seed: str) -> str:
    """Deterministic STIX id ``{type}--{uuid}`` derived from a seed string.

    STIX 2.1 requires a v4 UUID after the ``--``. We hash the seed so the
    same IOC always maps to the same id (no random churn between exports).
    """
    digest = hashlib.sha256(f"{object_type}:{seed}".encode("utf-8")).digest()
    derived = uuid.UUID(bytes=digest[:16], version=4)
    # Force the variant bits so it parses as a strict RFC-4122 UUID.
    fixed = derived.variant  # noqa: B018  (touch to document intent)
    return f"{object_type}--{derived}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(text: str) -> str:
    """Lowercase alnum+dash slug — used for CASE node ids."""
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-") or "item"


# ---------------------------------------------------------------------------
# IOC helpers — an IOC is a loosely-shaped dict; normalize the common keys.
# ---------------------------------------------------------------------------

# Map our free-form IOC ``type`` to the STIX pattern indicator grammar.
_IOC_TYPE_TO_STIX_PATTERN: dict[str, str] = {
    "ipv4": "ipv4-addr:value",
    "ipv6": "ipv6-addr:value",
    "domain": "domain-name:value",
    "hostname": "domain-name:value",
    "url": "url:value",
    "md5": "file:hashes.MD5",
    "sha1": "file:hashes.SHA-1",
    "sha256": "file:hashes.SHA-256",
    "email": "email-addr:value",
    "mutex": "mutex:name",
    "registry": "windows-registry-key:key",
    "registry_key": "windows-registry-key:key",
    "user_agent": "network-traffic:user_agent",
    "filename": "file:name",
    "filepath": "file:name",
    "cidr": "ipv4-addr:value",
}


def _ioc_type(ioc: dict[str, Any]) -> str:
    return str(ioc.get("type") or ioc.get("ioc_type") or "unknown").lower()


def _ioc_value(ioc: dict[str, Any]) -> str:
    for key in ("value", "ioc", "indicator", "data"):
        if ioc.get(key):
            return str(ioc[key])
    return ""


# ---------------------------------------------------------------------------
# Data gathering
# ---------------------------------------------------------------------------


async def gather_investigation_data(inv_id: str) -> dict[str, Any]:
    """Pull every persisted record for ``inv_id`` into one dict.

    This is the single source the exporters read from. It returns:
      investigation   — the investigations row
      tool_calls      — ordered tool call rows
      events          — the raw event stream (ordered)
      report_sections — report.section_added events reduced to ordered sections
      iocs            — report.ioc events reduced to a list of IOC dicts
      timeline        — report.timeline_entry events reduced to a list
      findings        — report.finding events reduced to a list
      attack_techniques — distinct ATT&CK technique ids referenced anywhere
    """
    from ..store import get_db

    db = await get_db()
    inv = await db.get_investigation(inv_id)
    if inv is None:
        raise KeyError(f"investigation {inv_id!r} not found")
    tool_calls = await db.list_tool_calls(inv_id)
    events = await db.list_events(inv_id)

    sections, iocs, timeline, findings = _reduce_report_events(events)
    attack_techniques = _collect_attack_techniques(iocs, timeline, findings, sections)

    return {
        "investigation": inv,
        "tool_calls": tool_calls,
        "events": events,
        "report_sections": sections,
        "iocs": iocs,
        "timeline": timeline,
        "findings": findings,
        "attack_techniques": attack_techniques,
    }


def _reduce_report_events(events: list[dict[str, Any]]) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]
]:
    """Reduce the persisted event stream into report sections / IOCs / timeline.

    Mirrors the frontend reducer in ``frontend/src/lib/events.ts``:
      report.section_added → ordered sections (dedup by section_id)
      report.ioc           → IOC list
      report.timeline_entry→ timeline list
      report.finding       → finding list
    """
    sections: list[dict[str, Any]] = []
    iocs: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    seen_section_ids: set[str] = set()

    for ev in events:
        etype = ev.get("type")
        data = ev.get("data") or {}
        ts = ev.get("ts")
        node = ev.get("node")
        if etype == "report.section_added":
            sid = str(data.get("section_id") or "")
            section = {
                "section_id": sid,
                "title": str(data.get("title") or ""),
                "markdown": str(data.get("markdown") or ""),
                "order": len(sections),
                "ts": ts,
                "node": node,
            }
            if sid and sid in seen_section_ids:
                sections = [section if s["section_id"] == sid else s for s in sections]
            else:
                if sid:
                    seen_section_ids.add(sid)
                sections.append(section)
        elif etype == "report.ioc":
            iocs.append({**data, "ts": ts, "node": node})
        elif etype == "report.timeline_entry":
            timeline.append({**data, "ts": ts, "node": node})
        elif etype == "report.finding":
            findings.append({**data, "ts": ts, "node": node})

    return sections, iocs, timeline, findings


_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _collect_attack_techniques(
    iocs: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    sections: list[dict[str, Any]],
) -> list[str]:
    """Collect distinct ATT&CK technique ids referenced in the data.

    Looks at explicit ``mitre_tags`` / ``technique_id`` / ``attack_techniques``
    fields, plus free-text technique ids (T1059, T1059.001) in markdown and
    descriptions. Returns them sorted and upper-cased.
    """
    found: set[str] = set()

    def scan(obj: Any) -> None:
        if isinstance(obj, dict):
            for key in ("mitre_tags", "attack_techniques", "techniques", "tactic"):
                val = obj.get(key)
                if isinstance(val, list):
                    for v in val:
                        if isinstance(v, str):
                            for m in _TECHNIQUE_RE.findall(v):
                                found.add(m.upper())
                elif isinstance(val, str):
                    for m in _TECHNIQUE_RE.findall(val):
                        found.add(m.upper())
            tid = obj.get("technique_id")
            if isinstance(tid, str):
                for m in _TECHNIQUE_RE.findall(tid):
                    found.add(m.upper())
            for v in obj.values():
                if isinstance(v, str):
                    for m in _TECHNIQUE_RE.findall(v):
                        found.add(m.upper())
                elif isinstance(v, (dict, list)):
                    scan(v)
        elif isinstance(obj, list):
            for item in obj:
                scan(item)

    for bucket in (iocs, timeline, findings):
        scan(bucket)
    for sec in sections:
        for m in _TECHNIQUE_RE.findall(sec.get("markdown") or ""):
            found.add(m.upper())
        for m in _TECHNIQUE_RE.findall(sec.get("title") or ""):
            found.add(m.upper())

    return sorted(found)


# ---------------------------------------------------------------------------
# Markdown export
# ---------------------------------------------------------------------------


def export_markdown(investigation_data: dict[str, Any]) -> str:
    """Concatenate the report sections in order into a single Markdown doc.

    Prepends a header block (case id, goal, status, timestamps) so the
    exported document is self-describing even when opened outside the app.
    """
    inv = investigation_data.get("investigation") or {}
    sections = investigation_data.get("report_sections") or []
    sections = sorted(sections, key=lambda s: s.get("order", 0))

    title = inv.get("goal_id") or inv.get("id") or "Investigation"
    lines: list[str] = [
        f"# Svetovid Investigation Report — {title}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Case ID | {inv.get('case_id', '—')} |",
        f"| Investigation ID | `{inv.get('id', '—')}` |",
        f"| Goal | {inv.get('goal_id', '—')} |",
        f"| Status | {inv.get('status', '—')} |",
        f"| Started | {inv.get('started_at', '—')} |",
        f"| Ended | {inv.get('ended_at') or '—'} |",
        f"| Evidence | `{inv.get('evidence_path', '—')}` |",
        "",
        "---",
        "",
    ]

    if inv.get("user_prompt"):
        lines += ["## Objective", "", inv["user_prompt"], ""]

    if not sections:
        lines.append("_No report sections were written for this investigation._")
    else:
        for sec in sections:
            heading = sec.get("title") or sec.get("section_id") or "Section"
            lines.append(f"## {heading}")
            lines.append("")
            body = (sec.get("markdown") or "").strip()
            if body:
                lines.append(body)
            else:
                lines.append("_No content._")
            lines.append("")

    iocs = investigation_data.get("iocs") or []
    if iocs:
        lines.append("## Indicators of Compromise")
        lines.append("")
        lines.append("| Type | Value | Description |")
        lines.append("|---|---|---|")
        for ioc in iocs:
            t = _ioc_type(ioc)
            v = _ioc_value(ioc)
            desc = str(ioc.get("description") or ioc.get("desc") or "").replace("|", "/")
            lines.append(f"| {t} | `{v}` | {desc} |")
        lines.append("")

    timeline = investigation_data.get("timeline") or []
    if timeline:
        lines.append("## Timeline")
        lines.append("")
        lines.append("| Time | Source | Actor | Event | ATT&CK |")
        lines.append("|---|---|---|---|---|")
        for entry in timeline:
            when = entry.get("timestamp") or entry.get("ts") or ""
            src = str(entry.get("source") or "").replace("|", "/")
            actor = str(entry.get("actor") or "").replace("|", "/")
            desc = str(entry.get("event") or entry.get("description") or "").replace("|", "/")
            tags = ", ".join(entry.get("mitre_tags") or [])
            lines.append(f"| {when} | {src} | {actor} | {desc} | {tags} |")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


def export_json(investigation_data: dict[str, Any]) -> dict[str, Any]:
    """Return the full structured data blob (no transformation)."""
    return {
        "schema": "svetovid.investigation.v1",
        "exported_at": _now_iso(),
        "investigation": investigation_data.get("investigation") or {},
        "tool_calls": investigation_data.get("tool_calls") or [],
        "events": investigation_data.get("events") or [],
        "report_sections": sorted(
            investigation_data.get("report_sections") or [],
            key=lambda s: s.get("order", 0),
        ),
        "iocs": investigation_data.get("iocs") or [],
        "timeline": investigation_data.get("timeline") or [],
        "findings": investigation_data.get("findings") or [],
        "attack_techniques": investigation_data.get("attack_techniques") or [],
    }


# ---------------------------------------------------------------------------
# STIX 2.1 export
# ---------------------------------------------------------------------------

def export_stix(investigation_data: dict[str, Any]) -> dict[str, Any]:
    """Produce a STIX 2.1 bundle from the investigation data.

    Objects emitted:
      identity             — the tool (Svetovid) as the creator
      report               — the investigation itself (report_types=["investigation"])
      indicator            — one per IOC that maps to a STIX pattern
      observed-data        — one per IOC that doesn't map to a clean pattern
      attack-pattern       — referenced by external id for each technique
      relationship         — attack-pattern → report (uses)
    """
    inv = investigation_data.get("investigation") or {}
    iocs = investigation_data.get("iocs") or []
    techniques = investigation_data.get("attack_techniques") or []
    inv_id = inv.get("id") or "unknown"

    objects: list[dict[str, Any]] = []

    # --- identity (the tool) ---
    identity_id = _stix_id("identity", "svetovid")
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": inv.get("started_at") or _now_iso(),
        "modified": inv.get("ended_at") or _now_iso(),
        "name": "Svetovid",
        "identity_class": "system",
        "description": "Svetovid agentic DFIR platform",
    }
    objects.append(identity)

    # --- attack-pattern objects (referenced by external id) ---
    ap_ids: dict[str, str] = {}
    for tid in techniques:
        ap_id = _stix_id("attack-pattern", f"{inv_id}:{tid}")
        ap_ids[tid] = ap_id
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created_by_ref": identity_id,
            "created": inv.get("started_at") or _now_iso(),
            "modified": inv.get("ended_at") or _now_iso(),
            "name": tid,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
            }],
        })

    # --- IOC indicators / observed-data ---
    object_refs: list[str] = []
    for ioc in iocs:
        t = _ioc_type(ioc)
        v = _ioc_value(ioc)
        if not v:
            continue
        prop = _IOC_TYPE_TO_STIX_PATTERN.get(t)
        if prop:
            sid = _stix_id("indicator", f"{inv_id}:{t}:{v}")
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": sid,
                "created_by_ref": identity_id,
                "created": ioc.get("ts") or _now_iso(),
                "modified": ioc.get("ts") or _now_iso(),
                "name": f"{t}: {v}",
                "description": str(ioc.get("description") or ""),
                "indicator_types": ["malicious-activity"],
                "pattern": f"[{prop} = '{v}']",
                "pattern_type": "stix",
                "valid_from": ioc.get("ts") or _now_iso(),
            })
            object_refs.append(sid)
        else:
            oid = _stix_id("observed-data", f"{inv_id}:{t}:{v}")
            objects.append({
                "type": "observed-data",
                "spec_version": "2.1",
                "id": oid,
                "created_by_ref": identity_id,
                "created": ioc.get("ts") or _now_iso(),
                "modified": ioc.get("ts") or _now_iso(),
                "first_observed": ioc.get("ts") or _now_iso(),
                "last_observed": ioc.get("ts") or _now_iso(),
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": _stix_type_for_observed(t),
                        "value": v,
                    }
                },
            })
            object_refs.append(oid)

    # --- relationships: report uses each attack-pattern ---
    report_id = _stix_id("report", inv_id)
    for tid, ap_id in ap_ids.items():
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": _stix_id("relationship", f"{inv_id}:uses:{tid}"),
            "created_by_ref": identity_id,
            "created": inv.get("started_at") or _now_iso(),
            "modified": inv.get("ended_at") or _now_iso(),
            "relationship_type": "uses",
            "source_ref": report_id,
            "target_ref": ap_id,
            "description": f"Investigation references ATT&CK technique {tid}",
        })

    # --- the report SDO (the investigation itself) ---
    object_refs_for_report = list(object_refs) + [ap_ids[t] for t in techniques]
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created_by_ref": identity_id,
        "created": inv.get("started_at") or _now_iso(),
        "modified": inv.get("ended_at") or _now_iso(),
        "name": f"Svetovid Investigation {inv.get('goal_id') or inv_id}",
        "description": inv.get("user_prompt") or "",
        "report_types": ["investigation"],
        "published": inv.get("ended_at") or _now_iso(),
        "object_refs": object_refs_for_report,
    }
    objects.insert(1, report)  # after identity, before the rest

    return {
        "type": "bundle",
        "id": _stix_id("bundle", inv_id),
        "objects": objects,
    }


def _stix_type_for_observed(ioc_type: str) -> str:
    """Map an IOC type to a STIX SCO type for ObservedData.objects."""
    if ioc_type in ("md5", "sha1", "sha256", "filename", "filepath"):
        return "file"
    if ioc_type in ("ipv4", "ipv6", "cidr"):
        return "ipv4-addr" if ioc_type != "ipv6" else "ipv6-addr"
    if ioc_type in ("domain", "hostname"):
        return "domain-name"
    if ioc_type == "url":
        return "url"
    if ioc_type == "email":
        return "email-addr"
    if ioc_type == "mutex":
        return "mutex"
    if ioc_type in ("registry", "registry_key"):
        return "windows-registry-key"
    return "x-svetovid-observable"


# ---------------------------------------------------------------------------
# CASE (UCO) export — JSON-LD
# ---------------------------------------------------------------------------

_CASE_CONTEXT = {
    "uco": "https://ontology.unifiedcyberontology.org/uco/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-action": "https://ontology.unifiedcyberontology.org/uco/action/",
    "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
}


def export_case_uco(investigation_data: dict[str, Any]) -> dict[str, Any]:
    """Produce a CASE (Cyber-investigation Analysis Standard Expression) bundle.

    JSON-LD over the UCO ontology. Maps:
      investigation → uco:Case
      evidence items (tool_call inputs) → uco:ObservableObject with hash props
      tool calls → uco:Action
      IOC relationships → uco:Relationship
    """
    inv = investigation_data.get("investigation") or {}
    tool_calls = investigation_data.get("tool_calls") or []
    iocs = investigation_data.get("iocs") or []
    inv_id = inv.get("id") or "unknown"

    nodes: list[dict[str, Any]] = []
    node_ids: list[str] = []

    def node(kind: str, local: str) -> str:
        nid = f"kb:{_slug(inv_id)}-{kind}-{local}"
        return nid

    # --- the Case ---
    case_uri = f"kb:case-{_slug(inv_id)}"
    case_node = {
        "@id": case_uri,
        "@type": "uco-core:Bundle",
        "uco-core:name": inv.get("goal_id") or inv_id,
        "uco-core:description": inv.get("user_prompt") or "",
        "uco-core:object": [],   # populated with @id refs below
        "uco-core:objectCreatedTime": {
            "@type": "xsd:dateTime",
            "@value": inv.get("started_at") or _now_iso(),
        },
    }
    case_object_refs: list[dict[str, Any]] = []

    # --- evidence items (derived from tool_call args / evidence_path) ---
    seen_evidence: set[str] = set()
    evidence_sources = [str(inv.get("evidence_path") or "")]
    for tc in tool_calls:
        args = tc.get("args") or {}
        for key in ("path", "evidence_path", "evtx_path", "image", "file", "pcap"):
            val = args.get(key)
            if isinstance(val, str) and val:
                evidence_sources.append(val)

    for ev_path in evidence_sources:
        if not ev_path or ev_path in seen_evidence:
            continue
        seen_evidence.add(ev_path)
        obj_uri = node("evidence", _slug(ev_path))
        node_ids.append(obj_uri)
        case_object_refs.append({"@id": obj_uri})
        obj_node: dict[str, Any] = {
            "@id": obj_uri,
            "@type": "uco-observable:ObservableObject",
            "uco-core:hasFacet": [{
                "@type": "uco-observable:File",
                "uco-observable:filePath": ev_path,
            }],
        }
        # Attach the output_hash of any tool call that touched this path.
        for tc in tool_calls:
            tc_args = tc.get("args") or {}
            touched = any(tc_args.get(k) == ev_path for k in
                          ("path", "evidence_path", "evtx_path", "image", "file", "pcap"))
            if touched and tc.get("output_hash"):
                obj_node["uco-core:hasFacet"].append({
                    "@type": "uco-observable:ContentData",
                    "uco-observable:hash": [{
                        "@type": "uco-types:Hash",
                        "uco-types:hashMethod": {"@type": "uco-vocabulary:HashAlgoVocab",
                                                 "@value": "SHA-256"},
                        "uco-types:hashValue": tc["output_hash"],
                    }],
                })
        nodes.append(obj_node)

    # --- tool calls → uco:Action ---
    for i, tc in enumerate(tool_calls):
        act_uri = node("action", f"{i}-{_slug(tc.get('tool') or 'tool')}")
        node_ids.append(act_uri)
        case_object_refs.append({"@id": act_uri})
        act_node: dict[str, Any] = {
            "@id": act_uri,
            "@type": "uco-action:Action",
            "uco-action:name": tc.get("tool") or "tool",
            "uco-action:result": {
                "@type": "uco-action:Array",
                "@value": str(tc.get("exit_code", "")),
            },
            "uco-action:startTime": {
                "@type": "xsd:dateTime",
                "@value": tc.get("ts") or _now_iso(),
            },
            "uco-action:instrument": {"@id": "kb:svetovid-instrument"},
        }
        if tc.get("duration_s") is not None:
            act_node["uco-action:performanceDuration"] = {
                "@type": "xsd:decimal",
                "@value": str(tc.get("duration_s")),
            }
        nodes.append(act_node)

    # --- IOC observables ---
    for ioc in iocs:
        t = _ioc_type(ioc)
        v = _ioc_value(ioc)
        if not v:
            continue
        obj_uri = node("ioc", f"{_slug(t)}-{_slug(v)}")
        node_ids.append(obj_uri)
        case_object_refs.append({"@id": obj_uri})
        nodes.append({
            "@id": obj_uri,
            "@type": "uco-observable:ObservableObject",
            "uco-core:hasFacet": [{
                "@type": "uco-observable:ObservableObject",
                "uco-observable:objectState": t,
                "uco-observable:value": v,
                "uco-core:description": str(ioc.get("description") or ""),
            }],
        })

    # --- IOC relationships back to the case ---
    rel_index = 0
    for ioc in iocs:
        v = _ioc_value(ioc)
        if not v:
            continue
        rel_uri = node("relationship", f"ioc-{rel_index}")
        rel_index += 1
        node_ids.append(rel_uri)
        case_object_refs.append({"@id": rel_uri})
        nodes.append({
            "@id": rel_uri,
            "@type": "uco-core:Relationship",
            "uco-core:name": "related-to",
            "uco-core:source": {"@id": case_uri},
            "uco-core:target": {"@id": node("ioc", f"{_slug(_ioc_type(ioc))}-{_slug(v)}")},
            "uco-core:isDirectional": {"@type": "xsd:boolean", "@value": True},
        })

    case_node["uco-core:object"] = case_object_refs

    # The instrument node (Svetovid as a forensic tool).
    instrument_node = {
        "@id": "kb:svetovid-instrument",
        "@type": "uco-action:Instrument",
        "uco-core:name": "Svetovid",
    }
    nodes.insert(0, instrument_node)
    nodes.insert(0, case_node)

    return {
        "@context": _CASE_CONTEXT,
        "@graph": nodes,
        "@id": case_uri,
        "@type": "uco-core:Bundle",
    }
