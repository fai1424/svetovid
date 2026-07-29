"""Azure cloud API tool wrapper (research item C16).

An API-based (not Dockerized) tool that exposes ``azure_audit``. The agent
picks an ``operation``; we hit the appropriate Azure REST / Microsoft Graph
endpoint with a bearer token from the ``AZURE_ACCESS_TOKEN`` environment
variable and return flat JSON rows.

Operations → endpoints:
  - activity_log      → Azure Activity Log
                        (``/subscriptions/{sub}/providers/Microsoft.Insights/
                        eventtypes/management/values`` via the Azure REST API)
  - entra_signins     → Microsoft Graph risky / interactive sign-ins
                        (``/auditLogs/signIns``)
  - entra_audit       → Microsoft Graph directory audit (Entra ID)
                        (``/auditLogs/directoryAudits``)
  - defender_alerts   → Microsoft Graph security alerts (Defender for Cloud /
                        Defender XDR) (``/security/alerts_v2``)
  - resource_changes  → Azure Activity Log filtered to resource write/change
                        operations (Accepted, Created, Updated)
  - key_vault_events  → Azure Activity Log filtered to Key Vault activity
                        (Microsoft.KeyVault / Microsoft.KeyVault/vaults)

This is an API tool, not a sandboxed one: ``image=None`` and ``sandboxed=False``
(it runs on the host and never touches Docker). If ``AZURE_ACCESS_TOKEN`` is
unset the tool returns a clear error message so the agent can adapt — it never
raises.
"""

from __future__ import annotations

import os
from typing import Any

from ...agent import events as E
from ..base import Tool, ToolContext, ToolResult

# Azure Resource Manager REST API surface (subscription-scoped Activity Log).
ARM_API = "https://management.azure.com"
# Microsoft Graph API surface (Entra ID sign-in / directory audit + Defender).
GRAPH_API = "https://graph.microsoft.com/v1.0"

# Default lookback window (ISO 8601 duration) when the agent omits time_range.
DEFAULT_TIME_RANGE = "PT24H"

# Azure Activity Log operations that represent a resource create/update/delete
# (i.e. unauthorized modification). HTTP verb → short status for filtering.
WRITE_STATUSES = {"Accepted", "Created", "Updated", "Succeeded", "Created", "Failed"}

# Resource providers/namespaces that surface in the Key Vault activity stream.
KEYVAULT_NAMESPACES = {"microsoft.keyvault", "microsoft.keyvault/vaults"}


class AzureApiTool(Tool):
    name = "azure_audit"
    image = None                # API tool — runs on host, no Docker image
    description = (
        "Query an Azure tenant via the REST API / Microsoft Graph for a cloud "
        "compromise investigation. Returns flat JSON rows. Operations: "
        "activity_log (subscription management-plane events), entra_signins "
        "(interactive/non-interactive/risky sign-ins), entra_audit (directory "
        "audit — service principal / role / app changes), defender_alerts "
        "(Defender for Cloud alerts), resource_changes (resource write/create/"
        "delete operations), key_vault_events (Key Vault secret/key/cert "
        "access). Requires the AZURE_ACCESS_TOKEN environment variable and, "
        "for Activity-Log operations, a subscription_id."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": [
                        "activity_log",
                        "entra_signins",
                        "entra_audit",
                        "defender_alerts",
                        "resource_changes",
                        "key_vault_events",
                    ],
                    "description": "Which Azure / Graph query to run.",
                },
                "subscription_id": {
                    "type": "string",
                    "description": (
                        "Azure subscription GUID. Required for activity_log, "
                        "resource_changes, and key_vault_events; ignored by the "
                        "Graph (Entra ID / Defender) operations."
                    ),
                },
                "time_range": {
                    "type": "string",
                    "description": (
                        "Lookback window as an ISO 8601 duration (e.g. PT24H, "
                        "PT12H, P1D). Defaults to PT24H."
                    ),
                },
            },
            "required": ["operation"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        import time

        call_id = ctx.make_call_id()
        token = os.environ.get("AZURE_ACCESS_TOKEN", "").strip()
        operation = args.get("operation")
        subscription_id = args.get("subscription_id") or ""
        time_range = args.get("time_range") or DEFAULT_TIME_RANGE

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
                "azure_audit: AZURE_ACCESS_TOKEN environment variable is not "
                "set. Provision an Entra ID service principal / managed "
                "identity and export a bearer token (with Reader on the "
                "subscription for Activity Log, AuditLog.Read.All + "
                "DirectoryRead.All for Graph sign-in/directory audit, and "
                "SecurityEvents.Read.All for Defender alerts) to enable Azure "
                "compromise investigation."
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

        # Subscription requirement for the Activity-Log family.
        if operation in ("activity_log", "resource_changes", "key_vault_events") and not subscription_id:
            msg = (
                f"azure_audit: {operation} requires a subscription_id. Pass the "
                "target Azure subscription GUID via the subscription_id argument."
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
                data={"error": "missing_subscription"},
            )

        try:
            import httpx
        except ImportError as e:  # pragma: no cover - httpx is a core dep
            msg = f"azure_audit: httpx unavailable ({e})"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, 0.0, None))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=1, duration_s=0.0,
                output_hash=None, output_path=None, summary=msg, data={"error": "no_httpx"},
            )

        headers = {"Authorization": f"Bearer {token}"}
        rows: list[dict[str, Any]] = []
        summary = ""
        exit_code = 0
        data: dict[str, Any] | None = None

        try:
            async with httpx.AsyncClient(timeout=30, headers=headers) as client:
                if operation == "activity_log":
                    rows, summary = await self._activity_log(
                        client, subscription_id, time_range)
                elif operation == "resource_changes":
                    raw, _ = await self._activity_log(
                        client, subscription_id, time_range)
                    rows = [r for r in raw if r.get("status") in WRITE_STATUSES]
                    summary = f"{len(rows)} resource write/change event(s)"
                elif operation == "key_vault_events":
                    raw, _ = await self._activity_log(
                        client, subscription_id, time_range)
                    rows = [
                        r for r in raw
                        if (r.get("resource_provider") or "").lower() in KEYVAULT_NAMESPACES
                    ]
                    summary = f"{len(rows)} Key Vault event(s)"
                elif operation == "entra_signins":
                    rows, summary = await self._graph_get(
                        client, "/auditLogs/signIns", time_range, shape="signin")
                elif operation == "entra_audit":
                    rows, summary = await self._graph_get(
                        client, "/auditLogs/directoryAudits", time_range, shape="directory")
                elif operation == "defender_alerts":
                    rows, summary = await self._graph_get(
                        client, "/security/alerts_v2", time_range, shape="alert")
                else:
                    raise ValueError(f"unknown operation {operation!r}")
            data = {"operation": operation, "rows": rows}
        except httpx.HTTPError as e:
            msg = f"azure_audit: network/HTTP error calling Azure API ({e})"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            exit_code, summary, data = 1, msg, {"error": "http_error", "detail": str(e)}
        except _AzureApiError as e:
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, str(e)))
            exit_code, summary, data = 1, str(e), {"error": e.kind, "detail": str(e)}
        except Exception as e:
            ctx.bus.publish(E.tool_stderr(
                ctx.investigation_id, call_id, f"azure_audit failed: {e}"))
            exit_code, summary, data = 1, f"azure_audit failed: {e}", {"error": str(e)}

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

    async def _activity_log(self, client, subscription_id: str, time_range: str):
        """Pull the Activity Log for a subscription (management-plane events)."""
        from datetime import datetime, timedelta, timezone

        try:
            window = _parse_iso8601_duration(time_range)
        except ValueError:
            window = timedelta(hours=24)
        now = datetime.now(timezone.utc)
        since = now - window
        path = (
            f"/subscriptions/{subscription_id}/providers/"
            f"Microsoft.Insights/eventtypes/management/values"
        )
        params = {
            "api-version": "2015-04-01",
            "$filter": (
                f"eventTimestamp ge '{since.strftime('%Y-%m-%dT%H:%M:%SZ')}' "
                f"and eventTimestamp le '{now.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
            ),
        }
        payload = await self._arm_get(client, path, params)
        values = payload.get("value", []) if isinstance(payload, dict) else []
        rows = [self._shape_activity_event(v) for v in values]
        return rows, f"{len(rows)} Activity Log event(s) over {time_range}"

    async def _graph_get(self, client, path: str, time_range: str, *, shape: str):
        """Hit a Microsoft Graph endpoint and normalize rows by ``shape``."""
        params = {"$top": 100}
        payload = await self._graph_request(client, path, params)
        values = payload.get("value", []) if isinstance(payload, dict) else []
        if shape == "signin":
            rows = [self._shape_signin(v) for v in values]
            label = "sign-in"
        elif shape == "directory":
            rows = [self._shape_directory(v) for v in values]
            label = "directory-audit"
        else:  # alert
            rows = [self._shape_alert(v) for v in values]
            label = "Defender alert"
        return rows, f"{len(rows)} {label} record(s) over {time_range}"

    # -- low-level HTTP helpers ------------------------------------------

    async def _arm_get(self, client, path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Hit the Azure Resource Manager REST API and validate the envelope."""
        r = await client.get(f"{ARM_API}{path}", params=params)
        if r.status_code == 401 or r.status_code == 403:
            raise _AzureApiError(
                "auth_forbidden",
                f"Azure ARM API returned {r.status_code} — the AZURE_ACCESS_TOKEN "
                "is expired, invalid, or lacks Reader on the target subscription.",
            )
        if r.status_code >= 400:
            raise _AzureApiError(
                "arm_http",
                f"Azure ARM API returned HTTP {r.status_code}: {r.text[:200]}",
            )
        try:
            return r.json()
        except Exception:
            raise _AzureApiError(
                "arm_http",
                f"Azure ARM API returned non-JSON response: {r.text[:200]}",
            )

    async def _graph_request(self, client, path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Hit Microsoft Graph and validate the envelope."""
        r = await client.get(f"{GRAPH_API}{path}", params=params)
        if r.status_code == 401 or r.status_code == 403:
            raise _AzureApiError(
                "auth_forbidden",
                f"Microsoft Graph returned {r.status_code} — the "
                "AZURE_ACCESS_TOKEN lacks the required Graph scopes "
                "(AuditLog.Read.All / Directory.Read.All / SecurityEvents.Read.All).",
            )
        if r.status_code == 404:
            raise _AzureApiError(
                "graph_unavailable",
                f"Microsoft Graph endpoint {path} not found (404) — the tenant "
                "may not have the corresponding workload licensed.",
            )
        if r.status_code >= 400:
            raise _AzureApiError(
                "graph_http",
                f"Microsoft Graph returned HTTP {r.status_code}: {r.text[:200]}",
            )
        try:
            return r.json()
        except Exception:
            raise _AzureApiError(
                "graph_http",
                f"Microsoft Graph returned non-JSON response: {r.text[:200]}",
            )

    # -- row shapers ------------------------------------------------------

    @staticmethod
    def _shape_activity_event(v: dict[str, Any]) -> dict[str, Any]:
        """Normalize one Azure Activity Log event into a flat row."""
        return {
            "event_timestamp": v.get("eventTimestamp") or v.get("time"),
            "event_name": (v.get("eventName") or {}).get("value")
                          if isinstance(v.get("eventName"), dict) else v.get("operationName"),
            "operation_name": (v.get("operationName") or {}).get("value")
                              if isinstance(v.get("operationName"), dict)
                              else v.get("operationName"),
            "resource_provider": (v.get("resourceProvider") or {}).get("value")
                                 if isinstance(v.get("resourceProvider"), dict)
                                 else v.get("resourceProviderValue"),
            "resource_id": v.get("resourceId"),
            "status": (v.get("status") or {}).get("value")
                      if isinstance(v.get("status"), dict)
                      else v.get("statusValue") or v.get("status"),
            "caller": v.get("caller"),
            "level": v.get("level"),
            "submission_timestamp": v.get("submissionTimestamp"),
            "properties": v.get("properties") or {},
        }

    @staticmethod
    def _shape_signin(v: dict[str, Any]) -> dict[str, Any]:
        """Normalize one Graph signIn record."""
        return {
            "id": v.get("id"),
            "timestamp": v.get("createdDateTime"),
            "user": (v.get("userPrincipalName") or
                     (v.get("user") or {}).get("userPrincipalName")),
            "user_id": (v.get("userId") or (v.get("user") or {}).get("id")),
            "app": v.get("appDisplayName"),
            "app_id": v.get("appId"),
            "client_app": v.get("clientAppUsed"),
            "status": ((v.get("status") or {}).get("errorCode")
                       if isinstance(v.get("status"), dict) else v.get("status")),
            "ip": v.get("ipAddress"),
            "location": (v.get("location") or {}).get("city")
                        if isinstance(v.get("location"), dict) else v.get("location"),
            "risk_level": v.get("riskLevelAggregated") or v.get("riskLevelDuringSignIn"),
            "conditional_access": (v.get("conditionalAccessStatus")
                                   or v.get("appliedConditionalAccessPolicies")),
            "service_principal": (v.get("servicePrincipalId")
                                  or v.get("servicePrincipalName")),
        }

    @staticmethod
    def _shape_directory(v: dict[str, Any]) -> dict[str, Any]:
        """Normalize one Graph directoryAudit record."""
        target = (v.get("targetResources") or [{}])
        return {
            "id": v.get("id"),
            "timestamp": v.get("activityDateTime"),
            "activity": v.get("activityDisplayName"),
            "category": v.get("category"),
            "operation_type": v.get("operationType"),
            "actor": (v.get("initiatedBy") or {}).get("user", {}).get("userPrincipalName")
                     if isinstance((v.get("initiatedBy") or {}).get("user"), dict)
                     else (v.get("initiatedBy") or {}).get("app", {}).get("displayName"),
            "actor_type": (v.get("initiatedBy") or {}).get("app", {}).get("servicePrincipalId")
                          and "servicePrincipal",
            "target": target[0].get("displayName") if target else None,
            "target_type": target[0].get("type") if target else None,
            "result": v.get("result"),
            "result_reason": v.get("resultReason"),
            "additional_details": v.get("additionalDetails") or [],
        }

    @staticmethod
    def _shape_alert(v: dict[str, Any]) -> dict[str, Any]:
        """Normalize one Graph security alert (Defender) record."""
        return {
            "id": v.get("id"),
            "title": v.get("title"),
            "severity": v.get("severity"),
            "status": v.get("status"),
            "category": v.get("category"),
            "created": v.get("createdDateTime"),
            "description": (v.get("description") or "")[:400],
            "service_source": v.get("serviceSource"),
            "detection_source": v.get("detectionSource"),
            "assigned_to": v.get("assignedTo"),
            "user": (v.get("userDisplayName") or
                     (v.get("comments") and v.get("comments")[0])),
            "techniques": v.get("techniques") or [],
            "evidence": [
                {"type": e.get("@odata.type") or e.get("type"),
                 "name": e.get("name"), "role": e.get("remediationStatus")}
                for e in (v.get("evidence") or [])
            ],
        }


class _AzureApiError(Exception):
    """Azure / Graph API returned an error envelope or HTTP failure."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind


def _parse_iso8601_duration(value: str) -> timedelta:
    """Parse the date portion of an ISO 8601 duration (e.g. PT24H, P1D)."""
    from datetime import timedelta
    import re

    m = re.match(
        r"^P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?)?$",
        value.strip(),
    )
    if not m or not value.strip():
        raise ValueError(f"invalid ISO 8601 duration: {value!r}")
    parts = {k: int(v) for k, v in m.groupdict(default="0").items() if v is not None}
    return timedelta(
        days=parts.get("days", 0),
        hours=parts.get("hours", 0),
        minutes=parts.get("minutes", 0),
    )


# Module-level instance so the goal and any registry can pick it up.
tool = AzureApiTool()
