"""Threat-intelligence enrichment tool (research item — IOC enrichment).

An API-based (not Dockerized) tool that enriches an indicator of compromise
(IOC) against public threat-intel sources. Commercial tools (CrowdStrike,
Chronicle) do this automatically; here we expose a single ``threat_intel_lookup``
the agent can call for any hash / IP / domain / URL it surfaces.

Sources (all optional, all best-effort — a missing API key or a network error
never fails the whole lookup):
  - **VirusTotal** (``virustotal``): v3 file/ip/domain/url report via
    ``X-Apikey`` from the ``VT_API_KEY`` env var. Skipped gracefully if unset.
  - **abuse.ch ThreatFox** (``abuse_ch``): ``search_ioc`` for any indicator
    type. No key required.
  - **abuse.ch MalwareBazaar** (``mip``): ``get_info`` by hash — used for hash
    lookups (sample reputation + tags). No key required.

This is an API tool, not a sandboxed one: ``image=None`` and
``sandboxed=False`` (runs on the host, never touches Docker). It follows the
same event pattern as the other tools (tool.start / tool.end /
agent.action / agent.observation / provenance.recorded) and records any IOC it
enriches into the per-investigation IOC store.
"""

from __future__ import annotations

import os
import time
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

# httpx is a declared dependency; imported lazily at module load so the rest of
# the module is still importable in environments without it (and so tests can
# patch ``httpx.AsyncClient`` before the first call).
try:
    import httpx
except ImportError:  # pragma: no cover - httpx is a core dep
    httpx = None  # type: ignore[assignment]

# Base endpoints. VT requires an API key; abuse.ch endpoints are keyless.
VT_BASE = "https://www.virustotal.com/api/v3"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

# VT uses different path segments per indicator type. Map our canonical enum
# onto the VT v3 collection name.
VT_TYPE_PATH = {
    "hash": "files",
    "ip": "ip_addresses",
    "domain": "domains",
    "url": "urls",
}

DEFAULT_SOURCES = ["virustotal", "abuse_ch", "mip"]


class ThreatIntelTool(Tool):
    name = "threat_intel_lookup"
    image = None                # API tool — runs on host, no Docker image
    description = (
        "Enrich an indicator of compromise (IOC) against public threat-intel "
        "sources. Returns structured reputation (VirusTotal detection counts, "
        "abuse.ch ThreatFox hits + tags, MalwareBazaar sample info). Sources "
        "are best-effort: VirusTotal is skipped if VT_API_KEY is unset; "
        "abuse.ch endpoints need no key. Use this to score hashes, IPs, "
        "domains, and URLs the investigation surfaces."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "indicator_type": {
                    "type": "string",
                    "enum": ["hash", "ip", "domain", "url"],
                    "description": (
                        "Kind of indicator being enriched. Use 'hash' for "
                        "SHA-256/SHA-1/MD5 file fingerprints."
                    ),
                },
                "indicator_value": {
                    "type": "string",
                    "description": "The IOC value (hash digest, IP, domain, or URL).",
                },
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Sources to query (subset of "
                        "['virustotal', 'abuse_ch', 'mip']). Defaults to all."
                    ),
                },
            },
            "required": ["indicator_type", "indicator_value"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        call_id = ctx.make_call_id()
        itype = (args.get("indicator_type") or "").strip().lower()
        value = (args.get("indicator_value") or "").strip()
        sources = args.get("sources") or list(DEFAULT_SOURCES)

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=False, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(
            ctx.investigation_id, tool=self.name, args=args,
        ))

        start = time.monotonic()
        exit_code = 0
        summary = ""
        data: dict[str, Any] = {
            "indicator": value,
            "type": itype,
            "sources": {},
        }

        if not itype or not value:
            msg = "threat_intel_lookup: indicator_type and indicator_value are required."
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            exit_code = 1
            summary = msg
        elif itype not in VT_TYPE_PATH:
            msg = f"threat_intel_lookup: unsupported indicator_type {itype!r}."
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            exit_code = 1
            summary = msg
        else:
            async with httpx.AsyncClient(timeout=20) as client:
                if "virustotal" in sources:
                    vt = await self._lookup_virustotal(client, itype, value)
                    data["sources"]["virustotal"] = vt
                if "abuse_ch" in sources:
                    tf = await self._lookup_threatfox(client, itype, value)
                    data["sources"]["abuse_ch"] = tf
                # MalwareBazaar is hash-only; only call it for hashes.
                if "mip" in sources and itype == "hash":
                    mb = await self._lookup_malwarebazaar(client, value)
                    data["sources"]["mip"] = mb
            summary = self._summarize(itype, value, data["sources"])

        duration = time.monotonic() - start
        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, exit_code, duration, None,
        ))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name,
            "image": self.image,
            "args": args,
            "exit_code": exit_code,
            "duration_s": duration,
            "output_hash": None,
            "ts": E._now_iso(),
        }))

        # Record the enriched IOC into the per-investigation store so the UI's
        # IoC tab and downstream analysis can pick it up. Best-effort: a store
        # failure never fails the lookup.
        if exit_code == 0:
            try:
                from ..governance.ioc_store import record_ioc
                await record_ioc(
                    investigation_id=ctx.investigation_id,
                    ioc_type=itype,
                    value=value,
                    context="threat_intel_lookup enrichment",
                    confidence=self._confidence(data["sources"]),
                )
            except Exception:
                pass

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=exit_code,
            duration_s=duration, output_hash=None, output_path=None,
            summary=summary, data=data,
        )

    # -- per-source lookups ------------------------------------------------

    async def _lookup_virustotal(self, client, itype: str, value: str) -> dict[str, Any]:
        key = os.environ.get("VT_API_KEY", "").strip()
        if not key:
            return {"status": "skipped", "reason": "VT_API_KEY not set"}
        path = VT_TYPE_PATH[itype]
        url = f"{VT_BASE}/{path}/{value}"
        headers = {"X-Apikey": key, "Accept": "application/json"}
        try:
            r = await client.get(url, headers=headers)
        except httpx.HTTPError as e:
            return {"status": "error", "reason": f"http_error: {e}"}
        if r.status_code == 404:
            return {"status": "not_found", "reason": "VT has no report for this indicator"}
        if r.status_code >= 400:
            return {"status": "error", "reason": f"http_{r.status_code}",
                    "detail": r.text[:200]}
        try:
            payload = r.json()
        except Exception:
            return {"status": "error", "reason": "non-json_response"}
        attrs = ((payload.get("data") or {}).get("attributes") or {})
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total": sum(stats.values()) if isinstance(stats, dict) and stats else 0,
            "reputation": attrs.get("reputation"),
            "permalink": f"https://www.virustotal.com/gui/{path}/{value}",
        }

    async def _lookup_threatfox(self, client, itype: str, value: str) -> dict[str, Any]:
        try:
            r = await client.post(THREATFOX_API, json={
                "query": "search_ioc", "search_term": value,
            })
        except httpx.HTTPError as e:
            return {"status": "error", "reason": f"http_error: {e}"}
        try:
            payload = r.json()
        except Exception:
            return {"status": "error", "reason": "non-json_response"}
        query_status = (payload.get("query_status") or "").lower()
        data = payload.get("data") or []
        if query_status != "ok" or not data:
            return {"status": "not_found", "reason": query_status or "no_hits"}
        tags: list[str] = []
        malware = set()
        for hit in data if isinstance(data, list) else []:
            tags += hit.get("tags") or []
            if hit.get("malware_printable"):
                malware.add(hit["malware_printable"])
        return {
            "status": "ok",
            "result": "malicious",
            "hits": len(data) if isinstance(data, list) else 1,
            "tags": sorted(set(tags))[:20],
            "malware_families": sorted(malware)[:10],
            "confidence_level": (
                (data[0] if isinstance(data, list) and data else {}) or {}
            ).get("confidence_level"),
        }

    async def _lookup_malwarebazaar(self, client, value: str) -> dict[str, Any]:
        try:
            r = await client.post(MALWAREBAZAAR_API, json={
                "query": "get_info", "hash": value,
            })
        except httpx.HTTPError as e:
            return {"status": "error", "reason": f"http_error: {e}"}
        try:
            payload = r.json()
        except Exception:
            return {"status": "error", "reason": "non-json_response"}
        query_status = (payload.get("query_status") or "").lower()
        data = payload.get("data") or []
        if query_status != "ok" or not data:
            return {"status": "not_found", "reason": query_status or "no_hits"}
        first = (data[0] if isinstance(data, list) and data else {}) or {}
        return {
            "status": "ok",
            "result": "known_sample",
            "sha256": first.get("sha256_hash"),
            "signature": first.get("signature"),
            "tags": sorted(set(first.get("tags") or []))[:20],
            "file_type": first.get("file_type"),
            "file_size": first.get("file_size"),
            "first_seen": first.get("first_seen"),
            "reporter": first.get("reporter"),
        }

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _summarize(itype: str, value: str, sources: dict[str, Any]) -> str:
        parts: list[str] = []
        vt = sources.get("virustotal")
        if isinstance(vt, dict) and vt.get("status") == "ok":
            parts.append(f"VT: {vt.get('malicious', 0)}/{vt.get('total', 0)} malicious")
        elif isinstance(vt, dict):
            parts.append(f"VT: {vt.get('status', '?')}")
        tf = sources.get("abuse_ch")
        if isinstance(tf, dict) and tf.get("status") == "ok":
            parts.append(f"ThreatFox: {tf.get('hits', 0)} hit(s)")
        elif isinstance(tf, dict):
            parts.append(f"ThreatFox: {tf.get('status', '?')}")
        if "mip" in sources:
            mb = sources["mip"]
            if isinstance(mb, dict) and mb.get("status") == "ok":
                parts.append(f"MalwareBazaar: {mb.get('signature') or 'known sample'}")
            elif isinstance(mb, dict):
                parts.append(f"MalwareBazaar: {mb.get('status', '?')}")
        body = "; ".join(parts) if parts else "no source returned data"
        return f"{itype} {value[:24]} — {body}"

    @staticmethod
    def _confidence(sources: dict[str, Any]) -> float:
        """Rough 0..1 confidence from the source verdicts."""
        score = 0.0
        vt = sources.get("virustotal")
        if isinstance(vt, dict) and vt.get("status") == "ok":
            mal = vt.get("malicious", 0) or 0
            total = vt.get("total", 0) or 1
            score = max(score, min(1.0, mal / max(1, total)))
        tf = sources.get("abuse_ch")
        if isinstance(tf, dict) and tf.get("status") == "ok":
            score = max(score, 0.8)
        return round(score, 3)


# Module-level instance so goals / the registry can pick it up uniformly.
tool = ThreatIntelTool()
