"""GoalPlanner — turns a natural-language investigation request into a goal + customized prompt.

Instead of the user picking from 23 goal cards, they describe what happened:
  "Our postgres container got compromised, we think it's mining crypto.
   Find the C2 server and what process the attacker used."

The planner sends this to the LLM along with the menu of available goals +
the scanned evidence types. The LLM returns:
  1. Which goal to run (G01-G23)
  2. A refined user_prompt that incorporates the user's specific questions
  3. A confidence score (0-1)
  4. A brief explanation of why this goal was chosen

If no LLM is configured, it falls back to keyword-based matching.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from ..config import Provider, load_settings
from ..llm.client import build_chat

logger = logging.getLogger(__name__)


@dataclass
class PlannedInvestigation:
    """The output of the planner — what to run and how."""

    goal_id: str
    user_prompt: str          # refined prompt incorporating user's specific questions
    confidence: float         # 0.0 to 1.0
    reasoning: str            # why this goal was chosen
    suggested_tools: list[str]  # which tools the agent will likely call


# ---------------------------------------------------------------------------
# Keyword fallback (when no LLM)
# ---------------------------------------------------------------------------

# Map keywords → goal IDs. Used when no LLM provider is configured.
KEYWORD_MAP: list[tuple[list[str], str]] = [
    # Windows
    (["evtx", "event log", "timeline", "attack timeline", "lateral movement",
      "4624", "4688", "login", "logon"], "G01"),
    (["malware", "persistence", "backdoor", "scheduled task", "service",
      "registry", "run key", "trojan", "rat", "implant"], "G02"),
    (["disk image", "e01", "deadbox", "dead box", "carving", "deleted files",
      "file system", "mft", "ntfs"], "G03"),
    # Endpoint
    (["linux", "syslog", "auth.log", "ssh", "sudo", "cron", "server compromise",
      "rootkit", "bash history"], "G04"),
    (["macos", "mac", "unified log", "knowledgec", "tcc", "quarantine",
      "launchagent", "apfs"], "G05"),
    # Memory
    (["memory", "ram", "volatility", "process injection", "malfind",
      "rootkit", "in-memory", "dmp", "hiberfil"], "G06"),
    # Network
    (["pcap", "network", "wireshark", "c2", "c2 server", "traffic capture",
      "beacon", "ja3", "tls", "http request"], "G07"),
    # Ransomware
    (["ransomware", "ransom", "encrypted files", "decrypt", "locker",
      "wannacry", "lockbit", "shadow copy", "vss"], "G08"),
    # Email
    (["email", "phishing", "bec", "pst", "outlook", "spoofing",
      "dkim", "spf", "dmarc", "wire transfer"], "G09"),
    # Mobile
    (["iphone", "ios", "ipad", "imessage", "knowledgec", "keychain",
      "itunes backup"], "G10"),
    (["android", "apk", "samsung", "whatsapp", "sms", "contacts2"], "G11"),
    # Cloud
    (["m365", "office 365", "azure ad", "entra", "teams", "sharepoint",
      "onedrive", "exchange online", "purview"], "G12"),
    (["google workspace", "gmail", "gws", "drive", "admin sdk", "oauth"], "G13"),
    (["aws", "cloudtrail", "guardduty", "s3", "ec2", "iam role", "lambda"], "G14"),
    (["azure", "microsoft azure", "activity log", "defender for cloud",
      "key vault", "resource group"], "G15"),
    (["gcp", "google cloud", "cloud audit", "scc", "compute engine",
      "bigquery", "gcs"], "G16"),
    # SaaS
    (["slack", "workspace", "channel", "slack audit"], "G17"),
    (["github", "azure devops", "jira", "gitlab", "pipeline", "ci/cd",
      "source code", "commit", "secret leak"], "G18"),
    # Container
    (["kubernetes", "k8s", "container", "pod", "docker", "etcd",
      "criu", "checkpoint", "namespace", "container escape",
      "postgres container", "mining crypto", "honeypot"], "G19"),
    (["acquisition", "imaging", "dd", "ewf", "chain of custody",
      "forensic image", "disk capture"], "G20"),
    (["orchestration", "fleet", "multiple hosts", "parallel", "turbinia",
      "large scale"], "G21"),
    (["super timeline", "correlate", "full timeline", "cross-evidence",
      "attack chain", "narrative", "everything"], "G22"),
    (["criu", "checkpoint", "memory pages", "container memory",
      "honeypot", "pages-.img"], "G23"),
]


def _keyword_match(request: str, evidence: list[dict] | None = None) -> PlannedInvestigation:
    """Fallback planner: match keywords in the request to a goal."""
    request_lower = request.lower()
    scores: dict[str, int] = {}

    for keywords, goal_id in KEYWORD_MAP:
        for kw in keywords:
            if kw in request_lower:
                scores[goal_id] = scores.get(goal_id, 0) + 1

    # Also boost goals whose input_artifacts match the evidence
    if evidence:
        from ..goals.registry import registry
        present = {e.get("artifact_id") for e in evidence if e.get("artifact_id")}
        for g in registry.all():
            overlap = len(present & set(g.input_artifacts))
            if overlap > 0:
                scores[g.id] = scores.get(g.id, 0) + overlap

    if not scores:
        # Default: G22 (super timeline — the catch-all)
        return PlannedInvestigation(
            goal_id="G22",
            user_prompt=request,
            confidence=0.3,
            reasoning="No specific keywords matched; defaulting to cross-evidence super-timeline which covers all evidence types.",
            suggested_tools=[],
        )

    best = max(scores, key=scores.get)
    return PlannedInvestigation(
        goal_id=best,
        user_prompt=request,
        confidence=min(0.7, 0.3 + scores[best] * 0.1),
        reasoning=f"Matched based on keywords in your description (score: {scores[best]}).",
        suggested_tools=[],
    )


# ---------------------------------------------------------------------------
# LLM-based planner
# ---------------------------------------------------------------------------

PLANNER_SYSTEM_PROMPT = """\
You are a DFIR triage assistant. The user has described a security incident \
and you must choose the BEST investigation goal from the available options.

Available goals:
{goals_menu}

Detected evidence types:
{evidence_summary}

User's request:
"{user_request}"

Respond with a JSON object (and NOTHING else):
{{
  "goal_id": "G01",
  "user_prompt": "Refined prompt incorporating the user's specific questions and context",
  "confidence": 0.85,
  "reasoning": "Brief explanation of why this goal was chosen",
  "suggested_tools": ["chainsaw_hunt", "mitre_attack"]
}}

Rules:
- Pick the SINGLE best goal for the user's described scenario.
- The user_prompt should be the user's original text PLUS any additional \
questions or focus areas that would help the investigation agent.
- If the user mentions multiple things (e.g. "find malware AND trace network \
connections"), pick the broader goal (G02 malware/persistence or G22 \
super-timeline) and list all questions in user_prompt.
- confidence 0.9+ = exact match; 0.5-0.8 = good match; <0.5 = uncertain.
"""


async def plan_investigation(
    user_request: str,
    evidence: list[dict] | None = None,
) -> PlannedInvestigation:
    """Turn a natural-language request into a PlannedInvestigation.

    Uses the LLM if configured; falls back to keyword matching otherwise.
    """
    settings = load_settings()
    provider = settings.active()

    if not provider or not provider.is_configured() or not provider.api_key:
        logger.info("No LLM provider; using keyword-based planner")
        return _keyword_match(user_request, evidence)

    # Build the goals menu for the prompt
    from ..goals.registry import registry
    goals_menu = "\n".join(
        f"  {g.id}: {g.label} — {g.description[:120]}"
        for g in registry.all()
    )

    evidence_summary = "No evidence scanned yet." if not evidence else "\n".join(
        f"  {e.get('family', '?')}: {e.get('kind', '?')} ({e.get('path', '?')})"
        for e in evidence[:20]
    )

    prompt = PLANNER_SYSTEM_PROMPT.format(
        goals_menu=goals_menu,
        evidence_summary=evidence_summary,
        user_request=user_request,
    )

    try:
        chat = build_chat(provider, streaming=False)
        response = await chat.ainvoke([
            {"role": "system", "content": "You are a JSON-only responder. Output valid JSON."},
            {"role": "user", "content": prompt},
        ])

        text = response.content if isinstance(response.content, str) else str(response.content)
        # Extract JSON from the response (LLMs sometimes wrap in ```json)
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        plan = json.loads(text)

        # Validate goal_id exists
        goal_id = plan.get("goal_id", "")
        if not any(g.id == goal_id for g in registry.all()):
            logger.warning("Planner returned unknown goal_id %s; falling back", goal_id)
            return _keyword_match(user_request, evidence)

        return PlannedInvestigation(
            goal_id=goal_id,
            user_prompt=plan.get("user_prompt", user_request),
            confidence=float(plan.get("confidence", 0.5)),
            reasoning=plan.get("reasoning", ""),
            suggested_tools=plan.get("suggested_tools", []),
        )

    except Exception as e:
        logger.warning("LLM planner failed (%s); falling back to keywords", e)
        return _keyword_match(user_request, evidence)
