"""Ransomware decryptor lookup (EnScript gap — Tool 5).

EnCase scripts check an identified ransomware family against known decryptor
databases (NoMoreRansom.org, ID-Ransomware) to report whether free recovery
is possible. No OSS forensic tool automates this lookup. This tool does.

It is an API / host tool (``image=None``, ``sandboxed=False``) like
``threat_intel`` — it never touches Docker. Sources (all best-effort, all
optional; a network failure or unreachable API never fails the lookup):

  - **Internal static database**: a curated map of families NoMoreRansom /
    major AV vendors have free decryptors for (WannaCry, Petya/NotPetya,
    GandCrab, Aurora, etc.). This always answers, offline.
  - **NoMoreRansom.org**: scrapes the public decryptor list page.
  - **ID-Ransomware API** (``https://id-ransomware.makostech.dev/api.php``):
    POST the ransom-note text / encrypted extension for an online match.

The match logic (``match_family``) is host-testable so the unit test can drive
the WannaCry → available path without any network.
"""

from __future__ import annotations

import time
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

try:
    import httpx
except ImportError:  # pragma: no cover - httpx is a core dep
    httpx = None  # type: ignore[assignment]

NOMORERANSOM_URL = "https://www.nomoreransom.org/decryptors.html"
ID_RANSOMWARE_API = "https://id-ransomware.makostech.dev/api.php"

# Curated static map of families with publicly-available free decryptors.
# Each entry: family -> {decryptor_name, url, probability}. Probability is a
# rough recovery likelihood per public reporting. Sourced from NoMoreRansom
# and AV-vendor advisories (best-effort; verify against the live DB).
STATIC_DECRYPTORS: dict[str, dict[str, Any]] = {
    "wannacry": {
        "decryptor_name": "WannaCryDecryptor (Kaspersky / NoMoreRansom)",
        "url": "https://www.nomoreransom.org/decryption-tools.html",
        "probability": 0.9,
    },
    "wannacrypt": {
        "decryptor_name": "WannaCryDecryptor (Kaspersky / NoMoreRansom)",
        "url": "https://www.nomoreransom.org/decryption-tools.html",
        "probability": 0.9,
    },
    "petya": {
        "decryptor_name": "PetyaDecryptor (Kaspersky / NoMoreRansom)",
        "url": "https://www.nomoreransom.org/decryption-tools.html",
        "probability": 0.7,
    },
    "notpetya": {
        "decryptor_name": "PetyaDecryptor (NoMoreRansom)",
        "url": "https://www.nomoreransom.org/decryption-tools.html",
        "probability": 0.3,
    },
    "gandcrab": {
        "decryptor_name": "GandCrabDecryptor (Bitdefender / NoMoreRansom)",
        "url": "https://www.nomoreransom.org/decryption-tools.html",
        "probability": 0.85,
    },
    "aurora": {
        "decryptor_name": "AuroraDecryptor (Bitdefender / NoMoreRansom)",
        "url": "https://www.nomoreransom.org/decryption-tools.html",
        "probability": 0.8,
    },
    "matsnu": {
        "decryptor_name": "RakhniDecryptor (Kaspersky / NoMoreRansom)",
        "url": "https://www.nomoreransom.org/decryption-tools.html",
        "probability": 0.6,
    },
    "rakhni": {
        "decryptor_name": "RakhniDecryptor (Kaspersky / NoMoreRansom)",
        "url": "https://www.nomoreransom.org/decryption-tools.html",
        "probability": 0.6,
    },
    "troldesh": {
        "decryptor_name": "Troldesh / Shade Decryptor (NoMoreRansom)",
        "url": "https://www.nomoreransom.org/decryption-tools.html",
        "probability": 0.7,
    },
    "shade": {
        "decryptor_name": "ShadeDecryptor (Kaspersky / NoMoreRansom)",
        "url": "https://www.nomoreransom.org/decryption-tools.html",
        "probability": 0.7,
    },
}

# Extensions strongly indicative of specific families (used when only an
# encrypted extension is available). Lower-case, without the dot.
EXTENSION_HINTS: dict[str, str] = {
    "wcry": "wannacry",
    "wnry": "wannacry",
    "encrypted": "aurora",
    "gandcrab": "gandcrab",
    "petya": "petya",
    "locked": "troldesh",
}


def match_family(
    family: str | None = None,
    note_text: str | None = None,
    extension: str | None = None,
) -> str | None:
    """Resolve a canonical family name from any combination of hints.

    Order of precedence: explicit family > extension hint > note-text keyword
    scan. Returns the lowercased canonical family or None. Host-testable.
    """
    if family:
        key = family.strip().lower()
        if key in STATIC_DECRYPTORS:
            return key
        # Allow a few common aliases.
        for alias in (key.replace(" ", ""), key.replace("-", "")):
            if alias in STATIC_DECRYPTORS:
                return alias
        return key  # unknown family — caller will report no decryptor
    if extension:
        ext = extension.lower().lstrip(".")
        if ext in EXTENSION_HINTS:
            return EXTENSION_HINTS[ext]
    if note_text:
        low = note_text.lower()
        for fam in STATIC_DECRYPTORS:
            if fam in low:
                return fam
    return None


def static_lookup(family: str | None) -> dict[str, Any]:
    """Return the static-database verdict for a family. Always answers."""
    if not family:
        return {
            "family": None,
            "decryptor_available": False,
            "decryptor_name": "",
            "decryptor_url": "",
            "recovery_probability": 0.0,
            "source": "static_db",
        }
    info = STATIC_DECRYPTORS.get(family.lower())
    if not info:
        return {
            "family": family,
            "decryptor_available": False,
            "decryptor_name": "",
            "decryptor_url": "",
            "recovery_probability": 0.0,
            "source": "static_db",
        }
    return {
        "family": family,
        "decryptor_available": True,
        "decryptor_name": info["decryptor_name"],
        "decryptor_url": info["url"],
        "recovery_probability": float(info["probability"]),
        "source": "static_db",
    }


class RansomwareDecryptorTool(Tool):
    name = "ransomware_decryptor_check"
    image = None  # API / host tool — never Docker
    description = (
        "Check whether a free decryptor exists for an identified ransomware "
        "family. Resolves the family from a family name, ransom-note text, "
        "and/or encrypted extension, then consults an internal decryptor "
        "database (always answers, offline) plus best-effort NoMoreRansom.org "
        "and ID-Ransomware lookups. Reports recovery probability + tool URL. "
        "Fills the EnCase ransomware-decryptor-lookup EnScript gap."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "ransomware_family": {
                    "type": "string",
                    "description": (
                        "Identified ransomware family name (e.g. 'WannaCry', "
                        "'GandCrab'). Optional if a note/extension is given."
                    ),
                },
                "ransom_note_text": {
                    "type": "string",
                    "description": (
                        "Contents of the ransom note — scanned for family "
                        "keywords and sent to ID-Ransomware for matching."
                    ),
                },
                "encrypted_extension": {
                    "type": "string",
                    "description": (
                        "Extension appended to encrypted files (e.g. '.wcry'). "
                        "Used as a family hint."
                    ),
                },
            },
            "required": [],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        call_id = ctx.make_call_id()
        family_in = args.get("ransomware_family") or None
        note_text = args.get("ransom_note_text") or None
        extension = args.get("encrypted_extension") or None

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=False, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(
            ctx.investigation_id, tool=self.name, args=args,
        ))

        start = time.monotonic()
        family = match_family(family_in, note_text, extension)
        result = static_lookup(family)
        sources_tried: list[str] = ["static_db"]

        # Best-effort online enrichment. A network error never fails the call.
        if family and httpx is not None:
            async with httpx.AsyncClient(timeout=15) as client:
                nmr = await self._lookup_nomoreransom(client, family)
                if nmr:
                    result.update({
                        "decryptor_available": True,
                        "decryptor_url": nmr.get("url", result.get("decryptor_url", "")),
                        "decryptor_name": nmr.get("name") or result.get("decryptor_name", ""),
                        "recovery_probability": max(
                            float(result.get("recovery_probability", 0.0) or 0.0),
                            float(nmr.get("probability", 0.0) or 0.0)),
                        "source": "nomoreransom+static_db",
                    })
                    sources_tried.append("nomoreransom")
                if note_text:
                    idr = await self._lookup_id_ransomware(
                        client, note_text, extension)
                    if idr and idr.get("family"):
                        sources_tried.append("id_ransomware")
                        result["id_ransomware"] = idr

        result["sources_tried"] = sources_tried
        if not family and not (family_in or note_text or extension):
            result["error"] = "no family, note text, or extension provided"
            exit_code = 1
        else:
            exit_code = 0

        summary = self._summarize(result)
        duration = time.monotonic() - start

        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, exit_code, duration, None,
        ))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": {
                k: (v if k != "ransom_note_text" else "[redacted]")
                for k, v in args.items()},
            "exit_code": exit_code, "duration_s": duration,
            "output_hash": None, "ts": E._now_iso(),
        }))

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=exit_code,
            duration_s=duration, output_hash=None, output_path=None,
            summary=summary, data=result,
        )

    # -- online sources ----------------------------------------------------

    async def _lookup_nomoreransom(self, client, family: str) -> dict[str, Any]:
        """Scrape NoMoreRansom's decryptor list for a family match."""
        try:
            r = await client.get(NOMORERANSOM_URL)
        except httpx.HTTPError:
            return {}
        if r.status_code >= 400:
            return {}
        low = r.text.lower()
        # The page links to per-tool pages; a family name hit is a good signal.
        if family.lower() in low:
            return {
                "name": f"{family.title()} decryptor (NoMoreRansom)",
                "url": "https://www.nomoreransom.org/decryption-tools.html",
                "probability": 0.8,
            }
        return {}

    async def _lookup_id_ransomware(
        self, client, note_text: str, extension: str | None,
    ) -> dict[str, Any]:
        """POST to the ID-Ransomware API for a match."""
        data = {"textcontent": note_text[:8000]}
        if extension:
            data["ext"] = extension.lstrip(".")
        try:
            r = await client.post(ID_RANSOMWARE_API, data=data, timeout=20)
        except httpx.HTTPError:
            return {}
        if r.status_code >= 400:
            return {}
        # The API returns free-form text; capture whatever family / verdict it
        # reports without assuming a strict schema.
        text = r.text.strip()
        return {"raw": text[:500], "family": family_from_idr_text(text)}

    @staticmethod
    def _summarize(result: dict[str, Any]) -> str:
        fam = result.get("family") or "unknown family"
        if result.get("decryptor_available"):
            prob = int(round(float(result.get("recovery_probability", 0.0)) * 100))
            name = result.get("decryptor_name") or "a decryptor"
            return f"{fam}: decryptor available — {name} (~{prob}% recovery)"
        return f"{fam}: no free decryptor known"


def family_from_idr_text(text: str) -> str | None:
    """Pull a likely family name out of ID-Ransomware's free-form response."""
    if not text:
        return None
    low = text.lower()
    for fam in STATIC_DECRYPTORS:
        if fam in low:
            return fam
    return None


tool = RansomwareDecryptorTool()
