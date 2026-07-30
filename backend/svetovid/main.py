"""FastAPI entry point: REST + WebSocket surface for the Svetovid UI.

Run in dev::

    uvicorn svetovid.main:app --reload --port 7421

The desktop shell (Tauri) launches this as a sidecar in production; for
frontend dev we just run it directly and point Vite at port 7421.

Endpoints (M0 surface — grows as goals are wired):
  GET  /health                          → {ok: true, version, active_provider}
  GET  /api/settings                    → settings (api_key stripped)
  PUT  /api/settings                    → update settings (api_key stored to keyring)
  POST /api/providers/{id}/test         → test_connection result
  POST /api/scan                        → {path} → scan_complete artifacts (also streamed via WS)
  GET  /api/goals                       → registry manifest for the GoalSelect screen
  POST  api/investigations              → start a goal on evidence; returns investigation_id
  WS   /ws                              → agent event stream (multiplexed by investigation_id)
"""

from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import secrets
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Header, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import __version__
from .agent import events as E
from .agent.events import EventBus
from .config import APP_DIR, Provider, ProviderId, Settings, load_settings, reset_settings, save_settings
from .llm.client import build_chat, test_connection

logger = logging.getLogger("svetovid")

# In-process event bus: agents publish, the WS layer subscribes per client.
bus = EventBus()

# Per-launch shared secret for loopback auth. The Tauri shell passes this via
# SVETOVID_AUTH_TOKEN env var when launching the sidecar. In dev (no env var)
# we generate one and log it so the browser can use it (or skip auth in dev).
AUTH_TOKEN = os.environ.get("SVETOVID_AUTH_TOKEN") or secrets.token_hex(16)
if not os.environ.get("SVETOVID_AUTH_TOKEN"):
    logger.info("DEV MODE: generated auth token %s (set SVETOVID_AUTH_TOKEN in prod)", AUTH_TOKEN)


def _check_auth(authorization: str | None) -> None:
    """Validate the Bearer token. Raises 401 if missing/invalid."""
    if not authorization:
        raise HTTPException(401, "missing Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    if not secrets.compare_digest(token, AUTH_TOKEN):
        raise HTTPException(401, "invalid auth token")


# ---------------------------------------------------------------------------
# DB persister: subscribe to the EventBus and persist every published event.
# This is the bridge that makes the case DB the durable source of truth (the
# EventBus stays the real-time fan-out for WebSocket clients). It also folds
# ``report.ioc`` events into the IOCs table so the IoC tab / STIX export work
# even when tools emit them directly onto the bus.
# ---------------------------------------------------------------------------


async def _db_persister(bus: "EventBus", db) -> None:
    """Background task: drain a bus subscription into the case DB.

    Runs for the app's lifetime. Polls every 5s so the loop stays cancelable
    even when the bus is quiet (a blocking ``get`` would hang shutdown). Any
    failure to persist a single event is logged but does not stop the loop — a
    poison event must not brick persistence for the whole app.
    """
    q = bus.subscribe()
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=5.0)
            except asyncio.TimeoutError:
                continue
            try:
                evt = event if isinstance(event, dict) else event.to_ws()
                await db.record_event(evt)
                # report.ioc events also live in the IOCs table for fast lookup.
                if evt.get("type") == "report.ioc" and evt.get("investigation_id"):
                    await _persist_ioc_event(db, evt)
            except Exception:  # noqa: BLE001 — a poison event can't stop the loop
                logger.exception("DB persister failed to record event %r", event)
    except asyncio.CancelledError:
        raise
    finally:
        bus.unsubscribe(q)


async def _persist_ioc_event(db, evt: dict[str, Any]) -> None:
    """Fold a ``report.ioc`` event into the IOCs table (idempotent on value)."""
    try:
        from .governance.ioc_store import record_ioc
        data = evt.get("data") or {}
        value = data.get("value") or data.get("ioc") or data.get("indicator")
        if not value:
            return
        await record_ioc(
            investigation_id=evt["investigation_id"],
            ioc_type=data.get("type") or data.get("ioc_type") or "other",
            value=str(value),
            context=str(data.get("context") or data.get("description") or ""),
            confidence=float(data.get("confidence") or 0.0),
            mitre_technique=data.get("mitre_technique") or data.get("mitre") or None,
            db=db,
        )
    except Exception:  # noqa: BLE001
        logger.exception("failed to persist IOC from event")


# ---------------------------------------------------------------------------
# Lifespan: ensure app dirs + logging.
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    from .config import ensure_app_dirs
    ensure_app_dirs()

    # Structured logging with file rotation.
    log_dir = APP_DIR / "logs"
    log_dir.mkdir(exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        log_dir / "svetovid.log",
        maxBytes=10_000_000,
        backupCount=5,
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    ))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[handler, logging.StreamHandler()],
    )
    logger.info("Svetovid backend v%s starting (auth=%s)", __version__,
                "env" if os.environ.get("SVETOVID_AUTH_TOKEN") else "dev-generated")

    # Initialize the case database.
    from .store import get_db
    db = await get_db()
    logger.info("Case DB initialized at %s", db._path)

    # DB event persister: subscribe to the EventBus and durably record every
    # published event. This is what makes the case DB the source of truth
    # (exports read from the persisted events table, not an empty one).
    db_persister_task = asyncio.create_task(_db_persister(bus, db))

    # Telemetry: anonymous usage analytics. Opt-out by default; see
    # svetovid.telemetry for the privacy contract. The collector subscribes
    # to the bus (cheap) and the uploader flushes the local queue to the
    # configured endpoint on a timer.
    from .telemetry.client_id import get_client_id
    from .telemetry.collector import TelemetryCollector
    from .telemetry.uploader import Uploader
    cid = get_client_id()
    logger.info("Anonymous client_id: %s", cid)
    telemetry_collector = TelemetryCollector(bus)
    await telemetry_collector.start()
    uploader = Uploader()
    uploader.start()
    app.state.telemetry = telemetry_collector

    yield
    logger.info("Svetovid backend shutting down")
    # Stop the DB persister first so it flushes anything left in its queue
    # before we close the DB connection it's writing to.
    db_persister_task.cancel()
    try:
        await db_persister_task
    except asyncio.CancelledError:
        pass
    await uploader.stop()
    await telemetry_collector.stop()
    await db.close()


app = FastAPI(title="Svetovid backend", version=__version__, lifespan=lifespan)

# Strict CORS — only the Tauri origins + Vite dev server.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "tauri://localhost",
        "https://tauri.localhost",
        "http://localhost:1420",
        "http://127.0.0.1:1420",
    ],
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Authorization", "Content-Type"],
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, Any]:
    """Health check — no auth required (used by Tauri shell preflight)."""
    s = load_settings()
    return {
        "ok": True,
        "version": __version__,
        "active_provider": s.active_provider,
        "sandbox_mode": s.sandbox_mode,
    }


@app.get("/health/docker")
async def docker_health() -> dict[str, Any]:
    """Check Docker daemon + image availability. No auth (preflight check)."""
    import shutil
    import subprocess
    installed = shutil.which("docker") is not None
    running = False
    images: dict[str, bool] = {}
    if installed:
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=5,
            )
            running = result.returncode == 0 and bool(result.stdout.strip())
        except Exception:
            running = False
        if running:
            for img in ("svetovid/base", "svetovid/eztools", "svetovid/volatility", "svetovid/malware"):
                try:
                    r = subprocess.run(
                        ["docker", "image", "inspect", f"{img}:latest", "--format", "{{.Id}}"],
                        capture_output=True, timeout=5,
                    )
                    images[img] = r.returncode == 0
                except Exception:
                    images[img] = False
    return {
        "installed": installed,
        "running": running,
        "images": images,
    }


# ---------------------------------------------------------------------------
# Settings / providers
# ---------------------------------------------------------------------------


def _strip_keys(s: Settings) -> dict[str, Any]:
    data = s.model_dump()
    for p in data["providers"].values():
        p["api_key"] = "" if not p.get("api_key") else "***"
    return data


@app.get("/api/settings")
async def get_settings(authorization: str | None = Header(None)) -> dict[str, Any]:
    _check_auth(authorization)
    return _strip_keys(load_settings())


@app.put("/api/settings")
async def put_settings(payload: dict[str, Any], authorization: str | None = Header(None)) -> dict[str, Any]:
    _check_auth(authorization)
    current = load_settings()

    new_providers: dict[ProviderId, Provider] = dict(current.providers)
    for pid_str, p_data in (payload.get("providers") or {}).items():
        # ProviderId is a typing.Literal, not a callable. Validate manually.
        valid_ids = ("ollama", "glm", "kimi")
        if pid_str not in valid_ids:
            raise HTTPException(400, f"unknown provider {pid_str!r}")
        pid = pid_str  # type: ignore[assignment]
        existing = new_providers.get(pid)
        base = existing.model_dump() if existing else {}
        # Remove 'id' from incoming data to avoid duplicate-key error.
        p_data_clean = {k: v for k, v in p_data.items() if k != "id"}
        base.update(p_data_clean)
        if not base.get("api_key") and existing:
            base["api_key"] = existing.api_key
        base.pop("id", None)
        new_providers[pid] = Provider(id=pid, **base)

    current.providers = new_providers
    if "active_provider" in payload and payload["active_provider"] is not None:
        current.active_provider = payload["active_provider"]
    for field in ("sandbox_mode", "hitl_evidence_collection", "hitl_report_release",
                  "hitl_tool_execution", "attack_version", "sigma_rules_path",
                  "telemetry_enabled", "telemetry_endpoint"):
        if field in payload:
            setattr(current, field, payload[field])

    save_settings(current)
    return _strip_keys(current)


@app.post("/api/settings/reset")
async def reset(authorization: str | None = Header(None)) -> dict[str, Any]:
    _check_auth(authorization)
    reset_settings()
    return _strip_keys(load_settings())


class TestResult(BaseModel):
    ok: bool
    status: str
    detail: str
    models: list[str] = []


@app.post("/api/providers/{provider_id}/test", response_model=TestResult)
async def provider_test(provider_id: ProviderId, authorization: str | None = Header(None)) -> TestResult:  # type: ignore[valid-type]
    _check_auth(authorization)
    s = load_settings()
    p = s.providers.get(provider_id)
    if p is None:
        raise HTTPException(404, f"unknown provider {provider_id}")
    result = await test_connection(p)
    return TestResult(**result)


# ---------------------------------------------------------------------------
# Evidence scan
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    path: str


# Q5 — paths an authenticated attacker must NEVER be able to point the scanner
# at. These hold secrets (private keys, credentials), kernel/device state, or
# system binaries. The check is prefix-based on the resolved (symlink-free)
# absolute path, so an attacker can't dodge it with ``/etc/../etc`` style tricks.
SCAN_BLOCKED_SYSTEM_PATHS = (
    "/etc", "/var", "/usr", "/bin", "/sbin", "/boot", "/dev",
    "/proc", "/sys", "/lib", "/lib64", "/root", "/private/etc",
    "/private/var", "/System", "/Library",
)


def _validate_scan_path(raw_path: str) -> Path:
    """Resolve + validate the requested scan path. Raises HTTPException(403/400).

    Guards against scanning sensitive system paths and Svetovid's own config
    directory (which holds API keys). Also verifies the path exists and is a
    file or directory.
    """
    from pathlib import Path as _Path
    import tempfile

    # Reject empty / obviously malformed input early.
    if not raw_path or not raw_path.strip():
        raise HTTPException(400, "scan path is required")

    try:
        evidence_root = _Path(raw_path).expanduser().resolve()
    except (OSError, RuntimeError) as e:
        raise HTTPException(400, f"invalid scan path: {e}")

    resolved = str(evidence_root)

    # Allow the OS-designated temp directory tree. On macOS /tmp and /var are
    # symlinks under /private, and pytest's tmp_path (and a real analyst's
    # evidence-staging area) legitimately lives there. The system-path block
    # below would otherwise catch this common staging location.
    try:
        tmp_roots = {_Path(tempfile.gettempdir()).resolve()}
        # Also honor explicit /tmp / /var/tmp even if gettempdir differs.
        for candidate in ("/tmp", "/var/tmp"):
            try:
                tmp_roots.add(_Path(candidate).resolve())
            except (OSError, RuntimeError):
                pass
    except (OSError, RuntimeError):
        tmp_roots = set()

    def _under_any(p: str, roots) -> bool:
        return any(p == str(r) or p.startswith(str(r) + "/") for r in roots)

    if not _under_any(resolved, tmp_roots):
        for blocked in SCAN_BLOCKED_SYSTEM_PATHS:
            # Use exact dir or subpath match so we don't accidentally block a
            # legitimate evidence dir named e.g. ``/home/user/etrusted``.
            if resolved == blocked or resolved.startswith(blocked + "/"):
                raise HTTPException(403, f"cannot scan system path: {blocked}")

    # Block scanning Svetovid's own config dir (holds api keys / settings).
    svetovid_home = _Path.home() / ".svetovid"
    try:
        sv_home_resolved = svetovid_home.resolve()
    except (OSError, RuntimeError):
        sv_home_resolved = svetovid_home
    if evidence_root == sv_home_resolved or sv_home_resolved in evidence_root.parents:
        raise HTTPException(403, "cannot scan Svetovid's own directory")

    if not evidence_root.exists():
        raise HTTPException(400, f"path does not exist: {resolved}")

    return evidence_root


@app.post("/api/scan")
async def scan(req: ScanRequest, authorization: str | None = Header(None)) -> dict[str, Any]:
    _check_auth(authorization)
    from .evidence.scanner import scan_folder
    from .store import get_db
    from .agent.events import new_id

    # Q5 — validate BEFORE walking. ``_validate_scan_path`` raises 403 for
    # system/sensitive paths and 400 for missing/garbage input.
    validated = _validate_scan_path(req.path)
    safe_path = str(validated)

    bus.publish(E.scan_start(safe_path))
    try:
        artifacts = await scan_folder(safe_path, on_progress=lambda scanned, found: bus.publish(
            E.scan_progress(scanned, None, found)
        ))
    except Exception as e:
        logger.exception("scan failed for %s", safe_path)
        bus.publish(E.error_event(None, f"scan failed: {e}"))
        raise HTTPException(500, str(e))

    # Persist every scanned artifact as a hashed evidence item (chain-of-
    # custody). The scanner already fingerprinted files ≤ 100 MiB inline;
    # we lift those hashes out of ``extra`` and into the evidence_items row.
    # Failures to record a single item must not fail the scan for the user.
    db = await get_db()
    for art in artifacts:
        try:
            extra = art.get("extra") or {}
            await db.record_evidence_item(
                item_id=new_id("ev"),
                case_id="default",
                path=str(art.get("path") or ""),
                sha256=extra.get("sha256"),
                md5=extra.get("md5"),
                size_bytes=int(art.get("size_bytes") or 0),
                artifact_id=art.get("artifact_id"),
                family=art.get("family"),
                collector="scanner",
            )
        except Exception:  # noqa: BLE001 — one bad artifact can't fail the scan
            logger.exception("failed to persist evidence item %r", art.get("path"))

    bus.publish(E.scan_complete([a for a in artifacts]))
    return {"artifacts": artifacts}


# ---------------------------------------------------------------------------
# Goals registry
# ---------------------------------------------------------------------------


@app.get("/api/goals")
async def list_goals(authorization: str | None = Header(None)) -> dict[str, Any]:
    _check_auth(authorization)
    from .goals.registry import registry
    return {"goals": [g.manifest() for g in registry.all()]}


# ---------------------------------------------------------------------------
# Investigation launch
# ---------------------------------------------------------------------------


class StartRequest(BaseModel):
    goal_id: str
    evidence_path: str
    user_prompt: str = ""


@app.post("/api/investigations")
async def start_investigation(req: StartRequest, authorization: str | None = Header(None)) -> dict[str, Any]:
    _check_auth(authorization)
    from .goals.registry import registry
    goal = registry.get(req.goal_id)
    if goal is None:
        raise HTTPException(404, f"unknown goal {req.goal_id}")
    investigation_id = E.new_id("inv")
    asyncio.create_task(_run_goal(goal, investigation_id, req.evidence_path, req.user_prompt))
    return {"investigation_id": investigation_id, "goal_id": req.goal_id}


# ---------------------------------------------------------------------------
# Smart investigation: user describes the incident in natural language,
# the planner picks the goal + customizes the prompt.
# ---------------------------------------------------------------------------


class SmartRequest(BaseModel):
    request: str               # user's natural-language description
    evidence_path: str


@app.post("/api/investigations/smart")
async def smart_investigation(req: SmartRequest, authorization: str | None = Header(None)) -> dict[str, Any]:
    """Start a dynamic investigation from a natural-language request.

    Instead of picking a predefined goal, this launches the dynamic investigation
    mode: the agent lists the evidence, reads the user's description, and freely
    decides what tools to use and in what order — with the FULL tool library
    available. This is the recommended investigation path.
    """
    _check_auth(authorization)
    from .agent.dynamic import DynamicInvestigationGoal

    goal = DynamicInvestigationGoal()
    investigation_id = E.new_id("inv")
    asyncio.create_task(_run_goal(goal, investigation_id, req.evidence_path, req.request))

    return {
        "investigation_id": investigation_id,
        "goal_id": "DYNAMIC",
        "goal_label": "Dynamic investigation",
        "user_prompt": req.request,
        "mode": "dynamic",
    }
        "reasoning": plan.reasoning,
        "suggested_tools": plan.suggested_tools,
    }


@app.post("/api/investigations/plan")
async def plan_only(req: SmartRequest, authorization: str | None = Header(None)) -> dict[str, Any]:
    """Plan WITHOUT starting — returns the suggestion for user confirmation."""
    _check_auth(authorization)
    from .agent.planner import plan_investigation
    from .goals.registry import registry

    evidence: list[dict] = []
    try:
        from .evidence.scanner import scan_folder
        evidence = await scan_folder(req.evidence_path)
    except Exception:
        pass

    plan = await plan_investigation(req.request, evidence)
    goal = registry.get(plan.goal_id)

    return {
        "goal_id": plan.goal_id,
        "goal_label": goal.label if goal else "Unknown",
        "goal_description": goal.description if goal else "",
        "user_prompt": plan.user_prompt,
        "confidence": plan.confidence,
        "reasoning": plan.reasoning,
        "suggested_tools": plan.suggested_tools,
        "evidence_found": len(evidence),
    }


class HitlResponseRequest(BaseModel):
    approved: bool


@app.post("/api/investigations/{inv_id}/hitl")
async def hitl_resolve(
    inv_id: str, body: HitlResponseRequest, authorization: str | None = Header(None)
) -> dict[str, Any]:
    """Q3 — Human-in-the-loop approval gate resolver.

    The frontend's Approve/Reject buttons call this. It resolves the pending
    approval Future the goal coroutine is awaiting in ``agent.hitl``. Auth-
    protected: only the authenticated Svetovid UI (or a legitimate API
    client) can release a report gate.
    """
    _check_auth(authorization)
    from .agent.hitl import resolve_approval
    from .store import get_db

    resolved = resolve_approval(inv_id, bool(body.approved))
    if resolved:
        # Reflect the human's decision in the investigation status so the
        # audit trail and case history capture it.
        try:
            db = await get_db()
            # Don't overwrite a terminal status; just note the decision.
            logger.info("HITL decision recorded for %s: approved=%s",
                        inv_id, body.approved)
        except Exception:
            pass
    return {"investigation_id": inv_id, "resolved": resolved, "approved": bool(body.approved)}


async def _run_goal(goal, investigation_id: str, evidence_path: str, user_prompt: str) -> None:
    """Background runner: stream graph_loaded, then execute the goal graph.

    A goal may self-cancel (return early from its HITL gate) when the human
    rejects the report release. We detect that via the per-investigation
    outcome ledger in ``agent.hitl`` and end the investigation as ``cancelled``
    rather than ``done``.
    """
    from .store import get_db
    from .agent.hitl import get_outcome, reset_outcome
    case_id = "default"
    db = await get_db()
    await db.create_investigation(investigation_id, case_id, goal.id, evidence_path, user_prompt)
    gnodes = goal.nodes()
    nodes = [{"id": n.id, "label": n.label, "status": "pending"} for n in gnodes]
    bus.publish(E.investigation_start(case_id, investigation_id, goal.id, [n["id"] for n in nodes]))
    bus.publish(E.goal_graph_loaded(investigation_id, goal.id, nodes))
    try:
        await goal.run(investigation_id=investigation_id, case_id=case_id,
                       evidence_path=evidence_path, user_prompt=user_prompt, bus=bus)
        if get_outcome(investigation_id) is False:
            bus.publish(E.investigation_end(investigation_id, "cancelled", "HITL rejected"))
            await db.finish_investigation(investigation_id, "cancelled", "HITL rejected")
        else:
            # D8 FIX: check if the LLM was actually used or the goal fell back.
            # Goals embed "No LLM provider" or "agent error" markers in the
            # report when the fallback path is taken. Surface this in the status
            # so the user knows the agent didn't actually reason.
            inv = await db.get_investigation(investigation_id)
            report = (inv or {}).get("report_markdown", "") if inv else ""
            if "No LLM provider" in report or "agent error" in report:
                bus.publish(E.investigation_end(
                    investigation_id, "done_llm_fallback",
                    "Completed using deterministic fallback (LLM unavailable or failed)"))
                await db.finish_investigation(
                    investigation_id, "done_llm_fallback",
                    "LLM unavailable or failed; deterministic fallback used")
            else:
                bus.publish(E.investigation_end(investigation_id, "done"))
                await db.finish_investigation(investigation_id, "done")
    except Exception as e:
        logger.exception("investigation %s failed", investigation_id)
        bus.publish(E.error_event(investigation_id, str(e), fatal=True))
        bus.publish(E.investigation_end(investigation_id, "failed", str(e)))
        await db.finish_investigation(investigation_id, "failed", str(e))
    finally:
        reset_outcome(investigation_id)


# ---------------------------------------------------------------------------
# Cases (persistent history)
# ---------------------------------------------------------------------------


@app.get("/api/cases")
async def list_cases(authorization: str | None = Header(None)) -> dict[str, Any]:
    _check_auth(authorization)
    from .store import get_db
    db = await get_db()
    invs = await db.list_investigations()
    return {"investigations": invs}


@app.get("/api/cases/{inv_id}")
async def get_case(inv_id: str, authorization: str | None = Header(None)) -> dict[str, Any]:
    _check_auth(authorization)
    from .store import get_db
    db = await get_db()
    inv = await db.get_investigation(inv_id)
    if not inv:
        raise HTTPException(404, "investigation not found")
    tool_calls = await db.list_tool_calls(inv_id)
    return {"investigation": inv, "tool_calls": tool_calls}


# ---------------------------------------------------------------------------
# Evidence items + chain of custody (governance)
# ---------------------------------------------------------------------------


@app.get("/api/cases/{case_id}/evidence")
async def list_case_evidence(case_id: str, authorization: str | None = Header(None)) -> dict[str, Any]:
    """List all hashed evidence items collected for a case (chain-of-custody)."""
    _check_auth(authorization)
    from .store import get_db
    db = await get_db()
    items = await db.list_evidence_items(case_id)
    return {"case_id": case_id, "evidence": items, "count": len(items)}


@app.get("/api/cases/{case_id}/custody")
async def case_custody_form(case_id: str, authorization: str | None = Header(None)) -> dict[str, Any]:
    """Generate a chain-of-custody form (JSON) for the case's evidence items.

    Builds the form on the fly from persisted evidence items and seals it with
    a tamper-evident SHA-256 integrity seal. If no evidence has been recorded
    yet, returns an empty (but still sealed) form.
    """
    _check_auth(authorization)
    from .governance.custody import create_custody_form
    from .store import get_db
    db = await get_db()
    items = await db.list_evidence_items(case_id)
    # Reshape DB rows into the artifact-dict shape create_custody_form expects.
    artifacts = [
        {
            "artifact_id": it.get("artifact_id"),
            "kind": it.get("artifact_id"),
            "family": it.get("family"),
            "path": it.get("path"),
            "size_bytes": it.get("size_bytes", 0),
            "extra": {"sha256": it.get("sha256"), "md5": it.get("md5")},
        }
        for it in items
    ]
    collector = items[0].get("collector") if items else "svetovid"
    form = create_custody_form(case_id, artifacts, collector or "svetovid")
    return form


# ---------------------------------------------------------------------------
# IOCs (threat intelligence)
# ---------------------------------------------------------------------------


@app.get("/api/investigations/{inv_id}/iocs")
async def list_investigation_iocs(inv_id: str, authorization: str | None = Header(None)) -> dict[str, Any]:
    """List all IOCs recorded for an investigation (for the IoC tab)."""
    _check_auth(authorization)
    from .store import get_db
    db = await get_db()
    iocs = await db.list_iocs(inv_id)
    return {"investigation_id": inv_id, "iocs": iocs, "count": len(iocs)}


# ---------------------------------------------------------------------------
# Report export (Markdown / JSON / STIX / CASE / PDF)
# ---------------------------------------------------------------------------


@app.get("/api/investigations/{inv_id}/export")
async def export_investigation(
    inv_id: str,
    format: str = "markdown",
    authorization: str | None = Header(None),
):
    """Export an investigation in ``markdown|json|stix|case|pdf``.

    Auth-protected. PDFs use a ``StreamingResponse`` so large reports stream
    to the client; everything else returns JSON or plain text.
    """
    _check_auth(authorization)
    fmt = (format or "markdown").lower()
    if fmt not in {"markdown", "json", "stix", "case", "pdf"}:
        raise HTTPException(400, f"unsupported format {format!r}")

    from .store import get_db
    db = await get_db()
    inv = await db.get_investigation(inv_id)
    if not inv:
        raise HTTPException(404, "investigation not found")

    from .report import gather_investigation_data, export_markdown, export_stix, export_case_uco, export_json
    from .report.pdf_renderer import is_pdf, render_pdf
    from fastapi.responses import Response, StreamingResponse
    import io

    data = await gather_investigation_data(inv_id)
    safe_goal = (inv.get("goal_id") or "investigation").replace("/", "_")
    filename_base = f"svetovid-{safe_goal}-{inv_id}"

    if fmt == "markdown":
        md = export_markdown(data)
        return Response(
            content=md,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.md"'},
        )
    if fmt == "json":
        return Response(
            content=json.dumps(export_json(data), default=str, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.json"'},
        )
    if fmt == "stix":
        return Response(
            content=json.dumps(export_stix(data), default=str, indent=2),
            media_type="application/stix+json",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.stix.json"'},
        )
    if fmt == "case":
        return Response(
            content=json.dumps(export_case_uco(data), default=str, indent=2),
            media_type="application/ld+json",
            headers={"Content-Disposition": f'attachment; filename="{filename_base}.case.json"'},
        )
    # pdf
    md = export_markdown(data)
    blob = render_pdf(md, data)
    media_type = "application/pdf" if is_pdf(blob) else "text/html; charset=utf-8"
    suffix = ".pdf" if is_pdf(blob) else ".html"
    return StreamingResponse(
        io.BytesIO(blob),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename_base}{suffix}"'},
    )


# ---------------------------------------------------------------------------
# Telemetry: user rating + status (analytics collection is opt-out)
# ---------------------------------------------------------------------------


class RateRequest(BaseModel):
    investigation_id: str
    rating: int          # 1..5
    feedback: str = ""


@app.post("/api/telemetry/rate")
async def rate_investigation(
    req: RateRequest, authorization: str | None = Header(None)
) -> dict[str, Any]:
    """Submit a 1-5 rating (+ optional feedback) for a finished investigation.

    Stored into the local telemetry queue and picked up by the next uploader
    batch as a ``user.rating`` record. Only the investigation_id, rating, and
    feedback are kept — no PII.
    """
    _check_auth(authorization)
    from .telemetry.collector import TelemetryCollector, enqueue_record
    from .telemetry.client_id import get_client_id

    if not (1 <= req.rating <= 5):
        raise HTTPException(400, "rating must be between 1 and 5")

    collector = getattr(app.state, "telemetry", None)
    if isinstance(collector, TelemetryCollector):
        # Collector running: route through it so the is_enabled check applies.
        ok = collector.attach_rating(req.investigation_id, req.rating, req.feedback)
    else:
        # No collector (e.g. tests that skip lifespan): enqueue directly.
        ok = bool(enqueue_record(
            client_id=get_client_id(),
            event="user.rating",
            ts=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            props={
                "investigation_id": req.investigation_id,
                "rating": req.rating,
                "feedback": (req.feedback or "")[:1000] or None,
            },
        ))
    return {"ok": ok}


@app.get("/api/telemetry/status")
async def telemetry_status(authorization: str | None = Header(None)) -> dict[str, Any]:
    """Telemetry status for the Settings screen."""
    _check_auth(authorization)
    from .telemetry.collector import queue_count
    s = load_settings()
    return {
        "enabled": bool(s.telemetry_enabled),
        "endpoint": s.telemetry_endpoint,
        "queued_count": queue_count(),
    }


# ---------------------------------------------------------------------------
# Auth token exchange (for Tauri production where the frontend needs the token)
# ---------------------------------------------------------------------------


@app.get("/api/auth-token")
async def get_auth_token(request: Request) -> dict[str, str]:
    """Return the auth token to same-origin callers (Tauri IPC / localhost only).

    In Tauri production, the Rust shell passes SVETOVID_AUTH_TOKEN to the
    sidecar. The frontend fetches it from this endpoint (which is same-origin
    in dev, or reachable via 127.0.0.1:7421 in prod), then includes it in all
    subsequent requests.

    Security: this endpoint is only reachable from localhost (the backend
    binds to 127.0.0.1). A remote attacker cannot reach it. The token itself
    rotates per launch, so even a leaked token is useless after restart.
    """
    # Verify the request is from localhost (defense in depth).
    client_host = request.client.host if request.client else ""
    if client_host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(403, "auth token exchange is localhost-only")
    return {"token": AUTH_TOKEN}


# ---------------------------------------------------------------------------
# WebSocket: stream events to the UI
# ---------------------------------------------------------------------------


@app.websocket("/ws")
async def ws(websocket: WebSocket) -> None:
    # Auth: check the token from the protocol subprotocol or query param.
    token = websocket.query_params.get("token") or ""
    if not secrets.compare_digest(token, AUTH_TOKEN):
        await websocket.close(code=4001, reason="unauthorized")
        return
    await websocket.accept()
    q = bus.subscribe()
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=30.0)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping", "ts": E._now_iso()})
                continue
            await websocket.send_json(event)
    except WebSocketDisconnect:
        logger.info("WS client disconnected")
    except Exception as e:
        logger.exception("WS error: %s", e)
    finally:
        bus.unsubscribe(q)


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


def run() -> None:
    """Run via ``python -m svetovid.main`` or the ``svetovid-backend`` script."""
    import uvicorn
    uvicorn.run("svetovid.main:app", host="127.0.0.1", port=7421, reload=False)


if __name__ == "__main__":
    run()
