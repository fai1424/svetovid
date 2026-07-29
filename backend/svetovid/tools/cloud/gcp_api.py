"""GCP cloud compromise audit tool (research item C16 / SaaS cloud).

A read-only, API-based tool that audits a Google Cloud Platform project for
signs of cloud compromise. Unlike the disk-image forensics tools (chainsaw,
eztools, volatility), this one talks directly to GCP REST APIs using a token
pulled from the ``GCP_ACCESS_TOKEN`` environment variable — there is no Docker
sandbox because the evidence lives in the GCP control plane, not on a mounted
disk image.

One tool, ``gcp_audit``, takes an ``operation`` selector plus optional
``project_id`` and ``time_range`` args:

  operation             API surface used                              what it finds
  --------------------- --------------------------------------------- -------------------------------
  admin_activity_logs   Cloud Logging ``entries.list`` over           API call timeline: every
                        ``projects/<p>/logs/cloudaudit.googleapis.com%2Factivity``   admin / config API call
  data_access_logs      Cloud Logging ``entries.list`` over           data-access events: who read
                        ``...%2Fdata_access``                         what (storage, secrets, etc.)
  scc_findings          Security Command Center ``projects.findings.list``  active security findings
  iam_policy_changes    Cloud Logging filtered to                     privilege escalation: IAM
                        ``SetIamPolicy`` / role binding changes       role / binding mutations
  compute_changes       Cloud Logging filtered to Compute Engine      resource hijacking: instance
                        methods (instances.insert / setMetadata /     creation, startup-script /
                        setMachineType / attachDisk)                  disk tampering, mining
  storage_access        Cloud Logging filtered to GCS + Data Access   storage exfiltration:
                        (objects.get / objects.list / compose)        bulk reads / copies

The tool follows the same event-publishing pattern as the other wrappers
(``tool.start`` / ``tool.stdout`` / ``tool.stderr`` / ``tool.end`` /
``agent.action`` / ``agent.observation`` / ``provenance.recorded``) but with
``sandboxed=False`` and ``image=None`` since it runs on the host.

If ``GCP_ACCESS_TOKEN`` is not set in the environment, the tool returns a
clear error result (exit_code=2, ``missing_token=True``) so the ReAct agent
can adapt and surface the gap instead of crashing.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from ...agent import events as E
from ..base import Tool, ToolContext, ToolResult

# ---------------------------------------------------------------------------
# Operation vocabulary
# ---------------------------------------------------------------------------

OPERATIONS = (
    "admin_activity_logs",
    "data_access_logs",
    "scc_findings",
    "iam_policy_changes",
    "compute_changes",
    "storage_access",
)

# env var that holds the OAuth2 / service-account access token.
TOKEN_ENV = "GCP_ACCESS_TOKEN"

# How many log entries / findings to pull per call by default.
DEFAULT_LIMIT = 50

# GCP API hosts. Overridable via env so an analyst can point at a restricted
# API endpoint / private.googleapis.com without code changes.
LOGGING_HOST = os.environ.get("GCP_LOGGING_HOST", "https://logging.googleapis.com")
SCC_HOST = os.environ.get("GCP_SCC_HOST", "https://securitycommandcenter.googleapis.com")

# Service/method substrings that map a log entry's ``protoPayload.methodName``
# to a compromise indicator. Used by compute_changes / storage_access /
# iam_policy_changes to flag rows.
COMPUTE_METHOD_HINTS = (
    "compute.instances.insert",
    "compute.instances.setMetadata",
    "compute.instances.setMachineType",
    "compute.instances.attachDisk",
    "compute.instances.setServiceAccount",
    "compute.firewalls.insert",
    "compute.networks.insert",
    "compute.images.create",
)

STORAGE_METHOD_HINTS = (
    "storage.objects.get",
    "storage.objects.list",
    "storage.objects.compose",
    "storage.objects.insert",
    "storage.buckets.list",
)

IAM_METHOD_HINTS = (
    "SetIamPolicy",
    "CreateServiceAccount",
    "UpdateServiceAccount",
    "BindServiceAccount",
    "CreateRole",
)

# Methods / log lines whose appearance is high-signal for an incident.
RISKY_HINTS = (
    "setMetadata", "setServiceAccount", "setMachineType", "attachDisk",
    "SetIamPolicy", "CreateServiceAccount", "BindServiceAccount",
    "insert", "exfil", "download", "compute.instances",
)


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


class GcpApiTool(Tool):
    """Read-only GCP compromise audit tool.

    Talks directly to GCP Cloud Logging and Security Command Center REST APIs
    using an access token from ``GCP_ACCESS_TOKEN``. Runs on the host (no
    Docker) and returns structured rows the ReAct agent can reason over.
    """

    name = "gcp_audit"
    image = None                # API-based, runs on host
    description = (
        "Audit a Google Cloud Platform (GCP) project for compromise. Calls the "
        "Cloud Logging + Security Command Center APIs read-only using an access "
        "token from env var GCP_ACCESS_TOKEN. Operations: admin_activity_logs "
        "(admin/config API call timeline), data_access_logs (who-read-what "
        "data access), scc_findings (active SCC security findings), "
        "iam_policy_changes (privilege escalation / role binding mutations), "
        "compute_changes (instance creation, startup-script / disk tampering), "
        "storage_access (GCS bulk reads / exfiltration). If no token is set the "
        "tool returns a clear error so you can configure one and retry."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": list(OPERATIONS),
                    "description": (
                        "admin_activity_logs = admin/config API call timeline; "
                        "data_access_logs = data-access (who-read-what) events; "
                        "scc_findings = active Security Command Center findings; "
                        "iam_policy_changes = SetIamPolicy / role binding "
                        "mutations (privilege escalation); compute_changes = "
                        "Compute Engine mutations (instance creation, "
                        "startup-script / disk tampering); storage_access = "
                        "GCS reads (bulk reads / exfiltration)."
                    ),
                },
                "project_id": {
                    "type": "string",
                    "description": (
                        "GCP project id (e.g. 'my-project-123'). Defaults to "
                        "the GCP_PROJECT_ID env var if omitted."
                    ),
                },
                "time_range": {
                    "type": "string",
                    "description": (
                        "Time window to query, e.g. '24h', '7d', or an RFC3339 "
                        "interval 'start/end'. Defaults to '24h'."
                    ),
                },
                "limit": {
                    "type": "number",
                    "description": f"Max rows to return (default {DEFAULT_LIMIT}).",
                },
            },
            "required": ["operation"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        call_id = ctx.make_call_id()
        operation = str(args.get("operation", "")).strip()
        project_id = str(args.get("project_id", "")).strip() or os.environ.get("GCP_PROJECT_ID", "").strip()
        time_range = str(args.get("time_range", "")).strip() or "24h"
        limit = _as_int(args.get("limit"), default=DEFAULT_LIMIT)
        t0 = time.monotonic()

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=False, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

        # ---- validate operation ----
        if operation not in OPERATIONS:
            msg = f"unknown operation {operation!r}; pick from {list(OPERATIONS)}"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 2, 0.0, None))
            return _result(call_id, self.name, 2, 0.0, msg, {"error": msg})

        # ---- resolve token ----
        token = os.environ.get(TOKEN_ENV, "").strip()
        if not token:
            msg = (
                f"no {TOKEN_ENV} environment variable set; set it to a GCP "
                f"OAuth2 access token (or service-account key-derived token) "
                f"with read scopes on logging + securitycenter, then retry."
            )
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.agent_observation(
                ctx.investigation_id, tool=self.name, summary=msg,
            ))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 2, 0.0, None))
            return _result(call_id, self.name, 2, 0.0, msg,
                           {"error": msg, "missing_token": True})

        # ---- dispatch ----
        try:
            ctx.bus.publish(E.tool_stdout(
                ctx.investigation_id, call_id,
                f"[gcp_audit] {operation} project={project_id or '-'} time_range={time_range} limit={limit}",
            ))
            rows = await _HANDLERS[operation](
                token=token, project_id=project_id, time_range=time_range,
                limit=limit, ctx=ctx, call_id=call_id,
            )
        except httpx.ConnectError as e:
            msg = f"GCP API unreachable: {e}"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg, {"error": msg})
        except httpx.TimeoutException:
            msg = "GCP API timed out"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg, {"error": msg})
        except httpx.HTTPError as e:
            msg = f"GCP API error: {e}"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg, {"error": msg})
        except _ApiError as e:
            # A structured error from the handler (e.g. HTTP 403, project
            # required). Surface it as a clear message so the agent adapts.
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, str(e)))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), str(e),
                           {"error": str(e), "operation": operation})
        except Exception as e:
            msg = f"{operation} failed: {e}"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg, {"error": msg})

        # ---- success ----
        flagged = [r for r in rows if r.get("flagged")]
        summary = (
            f"{operation}: {len(rows)} row(s)"
            + (f", {len(flagged)} flagged suspicious" if flagged else "")
            + (f" (project={project_id})" if project_id else "")
        )
        data: dict[str, Any] = {
            "operation": operation,
            "project_id": project_id,
            "time_range": time_range,
            "rows": rows,
            "flagged_count": len(flagged),
        }
        ctx.bus.publish(E.tool_stdout(ctx.investigation_id, call_id, summary))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 0, _dur(t0), None))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name,
            "image": self.image,
            "args": args,
            "exit_code": 0,
            "duration_s": _dur(t0),
            "output_hash": None,
            "operation": operation,
            "project_id": project_id,
            "rows": len(rows),
            "ts": E._now_iso(),
        }))
        return _result(call_id, self.name, 0, _dur(t0), summary, data)


# ---------------------------------------------------------------------------
# Shared HTTP / helpers
# ---------------------------------------------------------------------------


class _ApiError(RuntimeError):
    """A structured API error (non-2xx, or a precondition failure)."""


def _dur(t0: float) -> float:
    return round(time.monotonic() - t0, 3)


def _result(call_id: str, tool: str, exit_code: int, duration_s: float,
            summary: str, data: Any) -> ToolResult:
    return ToolResult(
        call_id=call_id, tool=tool, exit_code=exit_code,
        duration_s=duration_s, output_hash=None, output_path=None,
        summary=summary, data=data,
    )


def _as_int(val: Any, *, default: int) -> int:
    try:
        if val is None:
            return default
        n = int(val)
        return n if n > 0 else default
    except (TypeError, ValueError):
        return default


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "svetovid-dfir",
    }


def _parse_time_range(time_range: str) -> tuple[str, str]:
    """Resolve a time_range into (start_rfc3339, end_rfc3339) for GCP filters.

    Accepts:
      - '24h' / '7d' / '30m' style relative windows (end = now)
      - 'start/end' RFC3339 explicit interval
      - bare RFC3339 timestamps are treated as start..now
    Returns empty strings where a bound isn't usable.
    """
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    if not time_range:
        end = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        start = (now - timedelta(hours=24)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return start, end

    # explicit interval
    if "/" in time_range:
        start_s, end_s = time_range.split("/", 1)
        return start_s.strip(), end_s.strip()

    s = time_range.strip()
    units = {"m": 60, "h": 3600, "d": 86400}
    if len(s) > 1 and s[-1] in units and s[:-1].isdigit():
        secs = int(s[:-1]) * units[s[-1]]
        end = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        start = (now - timedelta(seconds=secs)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return start, end

    # bare RFC3339 timestamp → start..now
    end = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return s, end


async def _post_json(client: httpx.AsyncClient, url: str, *, headers: dict[str, str],
                     json_body: dict[str, Any], ctx: ToolContext, call_id: str) -> Any:
    """POST url, raise _ApiError on non-2xx, return parsed JSON (or text)."""
    ctx.bus.publish(E.tool_stdout(ctx.investigation_id, call_id, f"→ POST {url}"))
    resp = await client.post(url, headers=headers, json=json_body)
    if resp.status_code >= 400:
        body = (resp.text or "")[:300]
        raise _ApiError(f"HTTP {resp.status_code} from {url}: {body}")
    try:
        return resp.json()
    except Exception:
        return resp.text


async def _list_logs(
    *, token: str, project_id: str | None, time_range: str, limit: int,
    ctx: ToolContext, call_id: str, log_filter: str | None = None,
    extra_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Pull Cloud Logging entries via entries.list and normalize them.

    ``log_filter`` selects the log name (e.g. cloudaudit activity/data_access);
    ``extra_filter`` adds a method/permission predicate for the focused views.
    """
    headers = _headers(token)
    start, end = _parse_time_range(time_range)

    flt = [f'timestamp >= "{start}"', f'timestamp <= "{end}"']
    if log_filter:
        flt.append(f'logName =~ "{log_filter}"')
    if extra_filter:
        flt.append(extra_filter)

    body: dict[str, Any] = {
        "filter": " AND ".join(flt),
        "pageSize": min(limit, 100),
        "orderBy": "timestamp desc",
        "resourceNames": [f"projects/{project_id}"] if project_id else [],
    }

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        data = await _post_json(
            client, f"{LOGGING_HOST}/v2/entries:list",
            headers=headers, json_body=body, ctx=ctx, call_id=call_id,
        )

    entries = (data or {}).get("entries", []) if isinstance(data, dict) else []
    out: list[dict[str, Any]] = []
    for e in entries:
        proto = e.get("protoPayload") or {}
        method = proto.get("methodName", "")
        severity = e.get("severity", "")
        actor = (proto.get("authenticationInfo") or {}).get("principalEmail", "") \
            if isinstance(proto.get("authenticationInfo"), dict) else ""
        log_name = e.get("logName", "")
        flagged = _flag_entry(method, log_name, extra_filter)
        out.append({
            "source": "cloud_logging",
            "ts": e.get("timestamp"),
            "severity": severity,
            "log_name": log_name,
            "method": method,
            "actor": actor,
            "resource": (e.get("resource") or {}).get("type") if isinstance(e.get("resource"), dict) else None,
            "flagged": flagged,
            "detail": proto,
        })
        if len(out) >= limit:
            break
    return out


def _flag_entry(method: str, log_name: str, extra_filter: str | None) -> bool:
    """True if a log entry looks high-signal for compromise."""
    blob = f"{method} {log_name}".lower()
    if any(h.lower() in blob for h in RISKY_HINTS):
        return True
    # Focused views (iam/compute/storage) flag every matched entry by default.
    if extra_filter:
        return True
    return False


# ---------------------------------------------------------------------------
# Operation handlers
# ---------------------------------------------------------------------------


async def h_admin_activity_logs(*, token: str, project_id: str | None,
                                time_range: str, limit: int,
                                ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    """Admin Activity audit log — every admin/config API call (always-on)."""
    return await _list_logs(
        token=token, project_id=project_id, time_range=time_range,
        limit=limit, ctx=ctx, call_id=call_id,
        log_filter="cloudaudit.googleapis.com/activity",
    )


async def h_data_access_logs(*, token: str, project_id: str | None,
                             time_range: str, limit: int,
                             ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    """Data Access audit log — who-read-what (must be enabled separately)."""
    return await _list_logs(
        token=token, project_id=project_id, time_range=time_range,
        limit=limit, ctx=ctx, call_id=call_id,
        log_filter="cloudaudit.googleapis.com/data_access",
    )


async def h_iam_policy_changes(*, token: str, project_id: str | None,
                               time_range: str, limit: int,
                               ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    """Admin Activity filtered to IAM policy / role-binding mutations."""
    # protoPayload.methodName matches SetIamPolicy / CreateServiceAccount etc.
    method_pred = "(" + " OR ".join(
        f'protoPayload.methodName:"{m}"' for m in IAM_METHOD_HINTS
    ) + ")"
    return await _list_logs(
        token=token, project_id=project_id, time_range=time_range,
        limit=limit, ctx=ctx, call_id=call_id,
        log_filter="cloudaudit.googleapis.com/activity",
        extra_filter=method_pred,
    )


async def h_compute_changes(*, token: str, project_id: str | None,
                            time_range: str, limit: int,
                            ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    """Admin Activity filtered to Compute Engine mutations (hijack vectors)."""
    method_pred = "(" + " OR ".join(
        f'protoPayload.methodName:"{m}"' for m in COMPUTE_METHOD_HINTS
    ) + ")"
    return await _list_logs(
        token=token, project_id=project_id, time_range=time_range,
        limit=limit, ctx=ctx, call_id=call_id,
        log_filter="cloudaudit.googleapis.com/activity",
        extra_filter=method_pred,
    )


async def h_storage_access(*, token: str, project_id: str | None,
                           time_range: str, limit: int,
                           ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    """Data Access filtered to GCS object operations (exfiltration reads)."""
    method_pred = "(" + " OR ".join(
        f'protoPayload.methodName:"{m}"' for m in STORAGE_METHOD_HINTS
    ) + ")"
    return await _list_logs(
        token=token, project_id=project_id, time_range=time_range,
        limit=limit, ctx=ctx, call_id=call_id,
        log_filter="cloudaudit.googleapis.com/data_access",
        extra_filter=method_pred,
    )


async def h_scc_findings(*, token: str, project_id: str | None,
                         time_range: str, limit: int,
                         ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    """Active Security Command Center findings for the project."""
    if not project_id:
        raise _ApiError(
            "scc_findings: a project_id is required (pass project_id or set "
            "the GCP_PROJECT_ID env var)."
        )
    headers = _headers(token)
    # SCC v1: list findings under a source, filtered to ACTIVE state and a
    # recent event_time window. We list at the project level; for org-level,
    # an analyst can set GCP_SCC_HOST / a parent override later.
    parent = f"projects/{project_id}"
    start, end = _parse_time_range(time_range)
    flt = f'state="ACTIVE" AND event_time >= "{start}" AND event_time <= "{end}"'
    body: dict[str, Any] = {"filter": flt, "pageSize": min(limit, 100)}
    url = f"{SCC_HOST}/v1/{parent}/findings:list"

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        data = await _post_json(client, url, headers=headers, json_body=body,
                                ctx=ctx, call_id=call_id)

    items = (data or {}).get("findings", []) if isinstance(data, dict) else []
    out: list[dict[str, Any]] = []
    for f in items:
        severity = f.get("severity", "")
        out.append({
            "source": "scc",
            "ts": f.get("eventTime") or f.get("createTime"),
            "name": f.get("name", ""),
            "category": f.get("category", ""),
            "severity": severity,
            "resource": (f.get("resourceName") or "").split("/")[-1] or f.get("resourceName"),
            "state": f.get("state", ""),
            "flagged": severity in ("HIGH", "CRITICAL"),
            "detail": f.get("sourceProperties", {}),
        })
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_HANDLERS: dict[str, Any] = {
    "admin_activity_logs": h_admin_activity_logs,
    "data_access_logs": h_data_access_logs,
    "iam_policy_changes": h_iam_policy_changes,
    "compute_changes": h_compute_changes,
    "storage_access": h_storage_access,
    "scc_findings": h_scc_findings,
}


# Module-level instance the registry can pick up for tool enumeration.
tool = GcpApiTool()
