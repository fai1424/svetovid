"""Microsoft 365 / Graph API audit tool wrapper (research item C16).

An API-based (not Dockerized) tool that exposes ``m365_audit``. The agent
picks an ``operation``; we hit the appropriate Microsoft Graph endpoint with
an access token from the ``M365_ACCESS_TOKEN`` environment variable and
return flat JSON rows.

Operations → Graph endpoints:
  - unified_audit_log → ``/security/auditLog/queries`` / management APIs
                        (Unified Audit Log — mailbox, SharePoint, Teams, Entra)
  - entra_signins     → ``/auditLogs/signIns``                 (Entra ID sign-ins)
  - entra_audit       → ``/auditLogs/directoryAudits``         (Entra ID directory)
  - exchange_mailbox  → ``/security/auditLog/queries`` filtered to mailbox ops
                        (MailItemsAccessed, Send, InboxRule, New-InboxRule)
  - sharepoint_files  → ``/security/auditLog/queries`` filtered to SharePoint /
                        OneDrive file access + download ops
  - teams_activity    → ``/security/auditLog/queries`` filtered to Teams events
  - risky_users       → ``/identityProtection/riskyUsers``     (Entra ID Protection)

This is an API tool, not a sandboxed one: ``image=None`` and ``sandboxed=False``
(it runs on the host and never touches Docker). If ``M365_ACCESS_TOKEN`` is
unset the tool returns a clear error message so the agent can adapt — it never
raises.

Notes on the Unified Audit Log:
  The Graph ``/security/auditLog/queries`` API is the modern GA path into the
  UAL. Where that API is unavailable we fall back to listing records and
  classify by workload (Exchange / SharePoint / OneDrive / MicrosoftTeams /
  AzureActiveDirectory) recorded in each record. Each row keeps the raw
  ``Operation``, ``Workload``, ``CreationTime``, ``UserKey`` / ``UserId`` so the
  agent can reconstruct a timeline regardless of the operation selector.
"""

from __future__ import annotations

import os
from typing import Any

from ...agent import events as E
from ..base import Tool, ToolContext, ToolResult

# Microsoft Graph base URL. All endpoints below are appended to this.
GRAPH_API = "https://graph.microsoft.com/v1.0"

# Unified Audit Log workloads, mapped to the Graph auditLog Operation values.
# Used to filter the UAL stream down to the operations each selector cares
# about when the /security/auditLog/queries endpoint returns a flat record set.
UAL_WORKLOADS = {
    "exchange_mailbox": {"Exchange"},
    "sharepoint_files": {"SharePoint", "OneDrive"},
    "teams_activity": {"MicrosoftTeams"},
}

# High-signal mailbox operations that indicate takeover / exfil / persistence.
# These are the Operation strings the M365 UAL emits for Exchange records.
MAILBOX_OPS = {
    "MailItemsAccessed",
    "Send",
    "SendAs",
    "SendOnBehalf",
    "MoveToDeletedItems",
    "New-InboxRule",
    "Set-InboxRule",
    "UpdateInboxRules",
    "CreateInboxRule",
    "New-TransportRule",
    "Set-Mailbox",
    "Add-MailboxPermission",
    "Add-RecipientPermission",
}

# SharePoint / OneDrive file operations that indicate access or exfiltration.
FILE_OPS = {
    "FileAccessed",
    "FileDownloaded",
    "FileUploaded",
    "FileModified",
    "FileDeleted",
    "FileCopied",
    "FileMoved",
    "FilePreviewed",
    "FolderCreated",
    "SharingInvitationCreated",
    "SharingSet",
    "AnonymousLinkCreated",
    "AnonymousLinkUsed",
}


class M365ApiTool(Tool):
    name = "m365_audit"
    image = None                # API tool — runs on host, no Docker image
    description = (
        "Query a Microsoft 365 tenant via the Graph API for a cloud-compromise "
        "investigation. Returns flat JSON rows. Operations: unified_audit_log "
        "(full UAL timeline), entra_signins (Entra ID sign-in anomalies), "
        "entra_audit (Entra ID directory changes), exchange_mailbox (mailbox "
        "access / inbox rules / sends), sharepoint_files (SharePoint & OneDrive "
        "file access / exfil), teams_activity (Teams events), risky_users "
        "(Entra ID Protection). Optionally filter by user_filter (UPN) and "
        "time_range (e.g. '7d', '2026-07-01/2026-07-27'). Requires the "
        "M365_ACCESS_TOKEN environment variable."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": [
                        "unified_audit_log",
                        "entra_signins",
                        "entra_audit",
                        "exchange_mailbox",
                        "sharepoint_files",
                        "teams_activity",
                        "risky_users",
                    ],
                    "description": "Which Microsoft 365 / Graph query to run.",
                },
                "user_filter": {
                    "type": "string",
                    "description": (
                        "Optional userPrincipalName filter, e.g. "
                        "'alice@contoso.com'. Narrows mailbox, sign-in, and "
                        "audit queries to one identity."
                    ),
                },
                "time_range": {
                    "type": "string",
                    "description": (
                        "Optional time window for the query. Either a relative "
                        "duration ('24h', '7d', '30d') or an ISO range "
                        "'2026-07-01/2026-07-27'. Defaults to the last 7 days."
                    ),
                },
                "limit": {
                    "type": "number",
                    "description": "Maximum number of rows to return (default 200).",
                },
            },
            "required": ["operation"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        import time

        call_id = ctx.make_call_id()
        token = os.environ.get("M365_ACCESS_TOKEN", "").strip()
        operation = args.get("operation")
        user_filter = (args.get("user_filter") or "").strip()
        time_range = (args.get("time_range") or "").strip()
        try:
            limit = int(args.get("limit") or 200)
        except (TypeError, ValueError):
            limit = 200

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=False, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(
            ctx.investigation_id, tool=self.name, args=args,
        ))

        start = time.monotonic()

        # No token → clear, non-fatal error so the agent can adapt.
        if not token:
            msg = (
                "m365_audit: M365_ACCESS_TOKEN environment variable is not set. "
                "Set a Microsoft Graph access token (delegated or application "
                "permissions) carrying AuditLog.Read.All, Directory.Read.All, "
                "and IdentityRiskyUser.Read.All to enable M365 / cloud-compromise "
                "investigation."
            )
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, 0.0, None))
            ctx.bus.publish(E.agent_observation(
                ctx.investigation_id, tool=self.name, summary=msg,
            ))
            ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
                "tool": self.name,
                "image": self.image,
                "args": args,
                "exit_code": 1,
                "duration_s": 0.0,
                "output_hash": None,
                "ts": E._now_iso(),
            }))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=1, duration_s=0.0,
                output_hash=None, output_path=None, summary=msg,
                data={"error": "missing_token"},
            )

        try:
            import httpx
        except ImportError as e:  # pragma: no cover - httpx is a core dep
            msg = f"m365_audit: httpx unavailable ({e})"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, 0.0, None))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=1, duration_s=0.0,
                output_hash=None, output_path=None, summary=msg, data={"error": "no_httpx"},
            )

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        rows: list[dict[str, Any]] = []
        summary = ""
        exit_code = 0
        data: dict[str, Any] | None = None

        try:
            async with httpx.AsyncClient(timeout=30, headers=headers) as client:
                if operation == "unified_audit_log":
                    rows, summary = await self._unified_audit_log(
                        client, user_filter, time_range, limit,
                        workloads=None,
                    )
                elif operation == "exchange_mailbox":
                    rows, summary = await self._unified_audit_log(
                        client, user_filter, time_range, limit,
                        workloads=UAL_WORKLOADS["exchange_mailbox"], ops=MAILBOX_OPS,
                    )
                elif operation == "sharepoint_files":
                    rows, summary = await self._unified_audit_log(
                        client, user_filter, time_range, limit,
                        workloads=UAL_WORKLOADS["sharepoint_files"], ops=FILE_OPS,
                    )
                elif operation == "teams_activity":
                    rows, summary = await self._unified_audit_log(
                        client, user_filter, time_range, limit,
                        workloads=UAL_WORKLOADS["teams_activity"],
                    )
                elif operation == "entra_signins":
                    rows, summary = await self._entra_signins(
                        client, user_filter, time_range, limit,
                    )
                elif operation == "entra_audit":
                    rows, summary = await self._entra_audit(
                        client, user_filter, time_range, limit,
                    )
                elif operation == "risky_users":
                    rows, summary = await self._risky_users(client, limit)
                else:
                    raise ValueError(f"unknown operation {operation!r}")
            data = {"operation": operation, "rows": rows}
        except httpx.HTTPError as e:
            msg = f"m365_audit: network/HTTP error calling Graph API ({e})"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            exit_code, summary, data = 1, msg, {"error": "http_error", "detail": str(e)}
        except _M365ApiError as e:
            # Graph responded but indicated failure (non-2xx / 401 / 403).
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, str(e)))
            exit_code, summary, data = 1, str(e), {"error": e.kind, "detail": str(e)}
        except Exception as e:
            ctx.bus.publish(E.tool_stderr(
                ctx.investigation_id, call_id, f"m365_audit failed: {e}"))
            exit_code, summary, data = 1, f"m365_audit failed: {e}", {"error": str(e)}

        duration = time.monotonic() - start
        ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, exit_code, duration, None))
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

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=exit_code,
            duration_s=duration, output_hash=None, output_path=None,
            summary=summary, data=data,
        )

    # -- per-operation handlers -------------------------------------------

    async def _unified_audit_log(
        self, client, user_filter: str, time_range: str, limit: int,
        *, workloads: set[str] | None = None, ops: set[str] | None = None,
    ):
        """Pull the Unified Audit Log via /security/auditLog/queries.

        Optionally filter by workload (Exchange/SharePoint/OneDrive/MicrosoftTeams)
        and by a set of Operation names. ``user_filter`` and ``time_range``
        narrow the query. Records are normalized into flat rows.
        """
        start, end = _parse_time_range(time_range)
        # The GA auditLog query API: create a query, then list its records.
        body: dict[str, Any] = {
            "displayName": "svetovid-ual-query",
            "filterStartDateTime": start,
            "filterEndDateTime": end,
        }
        payload = await self._graph_post(client, "/security/auditLog/queries", body=body)
        # The created query includes a records navigation link.
        records_url = _extract_link(payload, "records")
        records: list[dict[str, Any]] = []
        if records_url:
            rparams = {"$top": min(limit, 1000)}
            records = await self._graph_get_list(client, records_url, params=rparams)
        else:
            # Some tenants expose the flat /records list directly off the query.
            records = payload.get("records") or payload.get("value") or []

        rows: list[dict[str, Any]] = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            workload = rec.get("Workload") or rec.get("workload")
            op_name = rec.get("Operation") or rec.get("operation")
            if workloads is not None and workload not in workloads:
                continue
            if ops is not None and op_name not in ops:
                continue
            if user_filter:
                actor = (rec.get("UserKey") or rec.get("UserId")
                         or rec.get("userPrincipalName") or "")
                if user_filter.lower() not in str(actor).lower():
                    continue
            rows.append(self._shape_audit_record(rec))
        label = (
            f"({workloads or 'all'} workloads"
            + (f", {len(ops)} op filter" if ops else "")
            + ")"
        )
        summary = f"{len(rows)} Unified Audit Log record(s) {label}"
        return rows, summary

    async def _entra_signins(
        self, client, user_filter: str, time_range: str, limit: int,
    ):
        """Entra ID sign-in logs — anomalous / failed / risky sign-ins."""
        start, end = _parse_time_range(time_range)
        filters = [f"createdDateTime ge {start}", f"createdDateTime le {end}"]
        if user_filter:
            filters.append(f"userPrincipalName eq '{user_filter}'")
        params = {
            "$filter": " and ".join(filters),
            "$top": min(limit, 999),
            "$orderby": "createdDateTime desc",
        }
        entries = await self._graph_get_list(
            client, "/auditLogs/signIns", params=params,
        )
        rows = [self._shape_signin(e) for e in entries]
        summary = f"{len(rows)} Entra ID sign-in event(s)"
        return rows, summary

    async def _entra_audit(
        self, client, user_filter: str, time_range: str, limit: int,
    ):
        """Entra ID directory audit — privilege / app / account changes."""
        start, end = _parse_time_range(time_range)
        filters = [f"activityDateTime ge {start}", f"activityDateTime le {end}"]
        if user_filter:
            filters.append(f"initiatedBy/user/userPrincipalName eq '{user_filter}'")
        params = {
            "$filter": " and ".join(filters),
            "$top": min(limit, 999),
            "$orderby": "activityDateTime desc",
        }
        entries = await self._graph_get_list(
            client, "/auditLogs/directoryAudits", params=params,
        )
        rows = [self._shape_directory_audit(e) for e in entries]
        summary = f"{len(rows)} Entra ID directory audit event(s)"
        return rows, summary

    async def _risky_users(self, client, limit: int):
        """Entra ID Identity Protection risky users."""
        params = {"$top": min(limit, 999)}
        entries = await self._graph_get_list(
            client, "/identityProtection/riskyUsers", params=params,
        )
        rows = [self._shape_risky_user(e) for e in entries]
        summary = f"{len(rows)} risky user(s) from Identity Protection"
        return rows, summary

    # -- low-level HTTP helpers ------------------------------------------

    async def _graph_get_list(
        self, client, path: str, params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """GET a Graph list endpoint and return its ``value`` array."""
        url = path if path.startswith("http") else f"{GRAPH_API}{path}"
        r = await client.get(url, params=params)
        _check_graph_response(r, path)
        payload = r.json()
        if isinstance(payload, dict):
            value = payload.get("value")
            return value if isinstance(value, list) else []
        return payload if isinstance(payload, list) else []

    async def _graph_get(
        self, client, path: str, params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = path if path.startswith("http") else f"{GRAPH_API}{path}"
        r = await client.get(url, params=params)
        _check_graph_response(r, path)
        return r.json()

    async def _graph_post(
        self, client, path: str, body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = path if path.startswith("http") else f"{GRAPH_API}{path}"
        r = await client.post(url, json=body or {})
        _check_graph_response(r, path)
        try:
            return r.json()
        except Exception:
            return {}

    # -- record shapers ---------------------------------------------------

    @staticmethod
    def _shape_audit_record(rec: dict[str, Any]) -> dict[str, Any]:
        """Normalize one Unified Audit Log record into a flat row."""
        return {
            "creation_time": rec.get("CreationTime") or rec.get("creationTime"),
            "id": rec.get("Id") or rec.get("id"),
            "operation": rec.get("Operation") or rec.get("operation"),
            "workload": rec.get("Workload") or rec.get("workload"),
            "result_status": rec.get("ResultStatus") or rec.get("resultStatus"),
            "user_key": rec.get("UserKey") or rec.get("userKey"),
            "user_id": rec.get("UserId") or rec.get("userId"),
            "client_ip": rec.get("ClientIp") or rec.get("clientIp"),
            "user_agent": rec.get("UserAgent") or rec.get("userAgent"),
            "object_id": rec.get("ObjectId") or rec.get("objectId"),
            "item": rec.get("Item") or rec.get("item"),
            "audit_data": rec.get("AuditData") or rec.get("auditData"),
        }

    @staticmethod
    def _shape_signin(e: dict[str, Any]) -> dict[str, Any]:
        loc = e.get("location") or {}
        dev = e.get("deviceDetail") or {}
        return {
            "id": e.get("id"),
            "created_date_time": e.get("createdDateTime"),
            "user_principal_name": e.get("userPrincipalName"),
            "user_display_name": e.get("userDisplayName"),
            "app_display_name": e.get("appDisplayName"),
            "client_app_used": e.get("clientAppUsed"),
            "ip_address": e.get("ipAddress"),
            "client_ip": e.get("ipAddress"),
            "location": loc.get("city") or loc.get("state") if isinstance(loc, dict) else loc,
            "country": loc.get("countryOrRegion") if isinstance(loc, dict) else None,
            "status": (e.get("status") or {}).get("errorCode") if isinstance(e.get("status"), dict) else e.get("status"),
            "error_code": (e.get("status") or {}).get("errorCode") if isinstance(e.get("status"), dict) else None,
            "failure_reason": (e.get("status") or {}).get("failureReason") if isinstance(e.get("status"), dict) else None,
            "device_detail": dev.get("displayName") or dev.get("operatingSystem") if isinstance(dev, dict) else dev,
            "conditional_access_status": e.get("conditionalAccessStatus"),
            "risk_level_during_sign_in": e.get("riskLevelDuringSignIn"),
            "risk_state": e.get("riskState"),
        }

    @staticmethod
    def _shape_directory_audit(e: dict[str, Any]) -> dict[str, Any]:
        initiated = e.get("initiatedBy") or {}
        user = initiated.get("user") if isinstance(initiated, dict) else {}
        target_res = e.get("targetResources") or []
        return {
            "id": e.get("id"),
            "activity_date_time": e.get("activityDateTime"),
            "activity_display_name": e.get("activityDisplayName"),
            "category": e.get("category"),
            "operation_type": e.get("operationType"),
            "result": e.get("result"),
            "result_reason": e.get("resultReason"),
            "correlation_id": e.get("correlationId"),
            "initiated_by_upn": (user or {}).get("userPrincipalName") if isinstance(user, dict) else None,
            "initiated_by_app": initiated.get("app") if isinstance(initiated, dict) else None,
            "target_resources": [
                {"id": t.get("id"), "display_name": t.get("displayName"),
                 "type": t.get("type")}
                for t in target_res if isinstance(t, dict)
            ],
        }

    @staticmethod
    def _shape_risky_user(e: dict[str, Any]) -> dict[str, Any]:
        hist = e.get("riskDetail") or {}
        return {
            "id": e.get("id"),
            "user_principal_name": e.get("userPrincipalName"),
            "display_name": e.get("userDisplayName"),
            "risk_level": e.get("riskLevel"),
            "risk_state": e.get("riskState"),
            "risk_detail": hist.get("eventTime") if isinstance(hist, dict) else hist,
            "risk_last_updated": e.get("riskLastUpdatedDateTime"),
            "is_deleted": e.get("isDeleted"),
        }


def _parse_time_range(time_range: str) -> tuple[str, str]:
    """Resolve a time_range spec into Graph-compatible ISO start/end strings.

    Accepts:
      - '' (empty)  → last 7 days
      - '24h', '7d', '30d' → relative look-back from now
      - '2026-07-01/2026-07-27' → explicit ISO date range
      - full ISO timestamps pass through

    Returns ``(start, end)`` as ``YYYY-MM-DDTHH:MM:SSZ`` strings.
    """
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    tr = (time_range or "").strip().lower()
    if not tr or tr.endswith(("h", "d")):
        if not tr:
            delta = timedelta(days=7)
        elif tr.endswith("h"):
            delta = timedelta(hours=int(tr[:-1]))
        else:  # ends with 'd'
            delta = timedelta(days=int(tr[:-1]))
        return ((now - delta).strftime("%Y-%m-%dT%H:%M:%SZ"),
                now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    if "/" in tr:
        start_s, end_s = tr.split("/", 1)
        return _to_iso(start_s.strip()), _to_iso(end_s.strip())
    # Single timestamp → treat as start, end = now.
    return _to_iso(tr), now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_iso(s: str) -> str:
    """Coerce a date or datetime string into a Graph ISO timestamp."""
    s = s.strip()
    if not s:
        return "1970-01-01T00:00:00Z"
    if "T" in s:
        return s if s.endswith("Z") else s + "Z"
    # Pure date — append midnight UTC.
    return f"{s}T00:00:00Z"


def _check_graph_response(r, context: str) -> None:
    """Raise _M365ApiError on a non-2xx Graph response with a clear kind."""
    if r.status_code >= 400:
        snippet = r.text[:280] if r.text else "(no body)"
        if r.status_code in (401, 403):
            raise _M365ApiError(
                "graph_forbidden",
                f"Microsoft Graph {context} returned HTTP {r.status_code}: "
                f"{snippet}. The M365_ACCESS_TOKEN is missing, expired, or "
                f"lacks the required Graph permissions "
                f"(AuditLog.Read.All / Directory.Read.All / "
                f"IdentityRiskyUser.Read.All).",
            )
        raise _M365ApiError(
            "graph_http",
            f"Microsoft Graph {context} returned HTTP {r.status_code}: {snippet}",
        )


def _extract_link(payload: dict[str, Any], key: str) -> str | None:
    """Pull a navigation/odata next-link URL from a Graph payload."""
    if not isinstance(payload, dict):
        return None
    # Graph often surfaces navigation links under "@odata.<key>" or a top-level key.
    candidates = [
        payload.get(f"@odata.{key}"),
        payload.get(key),
    ]
    for c in candidates:
        if isinstance(c, str) and c.startswith("http"):
            return c
    return None


class _M365ApiError(Exception):
    """Microsoft Graph API returned an error envelope or HTTP failure."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind


# Module-level instance so the goal and any registry can pick it up.
tool = M365ApiTool()
