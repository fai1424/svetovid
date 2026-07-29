"""Google Workspace audit API tool wrapper (research item C16).

An API-based (not Dockerized) tool that exposes ``gworkspace_audit``. The agent
picks an ``operation``; we hit the appropriate Google Admin SDK Reports API
endpoint with an OAuth2 access token from the ``GWS_ACCESS_TOKEN`` environment
variable and return flat JSON rows.

Operations → Admin SDK Reports API applications:
  - admin_reports_login  → ``admin/directory/v1/customer/<id>/.../login`` via
                            the Reports API ``activities/applicationName=login``
  - admin_reports_token  → ``activities/applicationName=token`` (OAuth token
                            grants/revokes — the OAuth consent abuse channel)
  - admin_reports_admin  → ``activities/applicationName=admin`` (admin console
                            changes: user/role/group/OAuth-app mutations)
  - admin_reports_drive  → ``activities/applicationName=drive`` (Drive view/
                            download/upload/share — the data-exfil channel)
  - admin_reports_gmail  → ``activities/applicationName=gmail`` (Gmail filter /
                            forwarding-rule injection — BEC-style persistence)
  - oauth_grants         → token report filtered to OAuth grants (lists the
                            third-party apps holding delegated access per user)
  - user_list            → ``directory/v1/users`` (membership / account roster)

This is an API tool, not a sandboxed one: ``image=None`` and ``sandboxed=False``
(it runs on the host and never touches Docker). If ``GWS_ACCESS_TOKEN`` is unset
the tool returns a clear error message so the agent can adapt — it never raises.

The token must be a Google OAuth2 access token (service-account or delegated
user) with the scopes:
  - https://www.googleapis.com/auth/admin.reports.audit.readonly
  - https://www.googleapis.com/auth/admin.directory.user.readonly
  - https://www.googleapis.com/auth/admin.directory.user.security
"""

from __future__ import annotations

import os
from typing import Any

from ...agent import events as E
from ..base import Tool, ToolContext, ToolResult

# Google Admin SDK endpoints.
REPORTS_API = "https://admin.googleapis.com/admin/reports/v1"
DIRECTORY_API = "https://admin.googleapis.com/admin/directory/v1"

# Map operation → Reports API applicationName. token/users-list are handled
# specially (token is a sub-filter of the token application; oauth_grants hits
# the per-user token report; user_list hits the Directory API).
APP_NAME: dict[str, str] = {
    "admin_reports_login": "login",
    "admin_reports_token": "token",
    "admin_reports_admin": "admin",
    "admin_reports_drive": "drive",
    "admin_reports_gmail": "gmail",
}

# Login-event names that are strong account-takeover / anomaly signals. Used to
# decorate login rows so the agent can triage quickly without re-reading raw
# payloads.
SUSPICIOUS_LOGIN_EVENTS = {
    "login_failure",
    "suspicious_login",
    "suspicious_login_less_secure_app",
    "gov_attack_warning",          # government-backed attack warning
    "logout_all",
}

# Token/OAuth application events that indicate consent grants or revokes — the
# OAuth-abuse channel (malicious third-party app, consent-phishing).
TOKEN_GRANT_EVENTS = {
    "authorize",
    "revoke",
    "add_access",
    "remove_access",
}


class GworkspaceApiTool(Tool):
    name = "gworkspace_audit"
    image = None                # API tool — runs on host, no Docker image
    description = (
        "Query Google Workspace via the Admin SDK Reports API for a "
        "compromise investigation. Returns flat JSON rows. Operations: "
        "admin_reports_login (auth anomalies / impossible travel), "
        "admin_reports_token (OAuth token grants/revokes), admin_reports_admin "
        "(admin console changes), admin_reports_drive (Drive view/download/"
        "upload/share — data exfil), admin_reports_gmail (Gmail filter / "
        "forwarding-rule injection), oauth_grants (third-party apps holding "
        "delegated access per user), user_list (directory roster). Supports an "
        "optional user_filter (primary email). Requires the GWS_ACCESS_TOKEN "
        "environment variable."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": [
                        "admin_reports_login",
                        "admin_reports_token",
                        "admin_reports_admin",
                        "admin_reports_drive",
                        "admin_reports_gmail",
                        "oauth_grants",
                        "user_list",
                    ],
                    "description": "Which Google Workspace Admin SDK query to run.",
                },
                "user_filter": {
                    "type": "string",
                    "description": (
                        "Optional primary email to scope the query "
                        "(e.g. attacker@example.com). Applies a Reports API "
                        "actor filter or a Directory userKey as appropriate."
                    ),
                },
            },
            "required": ["operation"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        import time

        call_id = ctx.make_call_id()
        token = os.environ.get("GWS_ACCESS_TOKEN", "").strip()
        operation = args.get("operation")
        user_filter = (args.get("user_filter") or "").strip()

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
                "gworkspace_audit: GWS_ACCESS_TOKEN environment variable is "
                "not set. Set a Google OAuth2 access token (service-account or "
                "delegated user) carrying the admin.reports.audit.readonly, "
                "admin.directory.user.readonly, and admin.directory.user.security "
                "scopes to enable Google Workspace compromise investigation."
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
            msg = f"gworkspace_audit: httpx unavailable ({e})"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, 0.0, None))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=1, duration_s=0.0,
                output_hash=None, output_path=None, summary=msg,
                data={"error": "no_httpx"},
            )

        headers = {"Authorization": f"Bearer {token}"}
        rows: list[dict[str, Any]] = []
        summary = ""
        exit_code = 0
        data: dict[str, Any] | None = None

        try:
            async with httpx.AsyncClient(timeout=30, headers=headers) as client:
                if operation in APP_NAME:
                    rows, summary = await self._activities(
                        client, APP_NAME[operation], user_filter,
                    )
                elif operation == "oauth_grants":
                    rows, summary = await self._oauth_grants(client, user_filter)
                elif operation == "user_list":
                    rows, summary = await self._user_list(client, user_filter)
                else:
                    raise ValueError(f"unknown operation {operation!r}")
            data = {"operation": operation, "rows": rows}
        except httpx.HTTPError as e:
            msg = f"gworkspace_audit: network/HTTP error calling Google API ({e})"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            exit_code, summary, data = 1, msg, {"error": "http_error", "detail": str(e)}
        except _GwsApiError as e:
            # Google responded but indicated failure (non-2xx / quota / scope).
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, str(e)))
            exit_code, summary, data = 1, str(e), {"error": e.kind, "detail": str(e)}
        except Exception as e:
            ctx.bus.publish(E.tool_stderr(
                ctx.investigation_id, call_id, f"gworkspace_audit failed: {e}"))
            exit_code, summary, data = 1, f"gworkspace_audit failed: {e}", {"error": str(e)}

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

    async def _activities(self, client, application_name: str, user_filter: str):
        """Pull Reports API activities for an applicationName and flatten them."""
        params: dict[str, Any] = {"maxResults": 1000}
        if user_filter:
            # Reports API actor filter takes the form user:user@domain.
            params["actorEmail"] = user_filter
        payload = await self._reports_get(
            client, f"activities", {"applicationName": application_name, **params},
        )
        items = payload.get("items", []) if isinstance(payload, dict) else []
        rows = []
        for it in items:
            shaped = self._shape_activity(it)
            # Flag suspicious event names so the agent can triage fast.
            name = (shaped.get("event_name") or "").lower()
            if application_name == "login" and name in SUSPICIOUS_LOGIN_EVENTS:
                shaped["suspicious"] = True
            elif application_name == "token" and name in TOKEN_GRANT_EVENTS:
                shaped["suspicious"] = True
            rows.append(shaped)
        label = application_name
        scope = f" for {user_filter}" if user_filter else ""
        return rows, f"{len(rows)} {label} activity event(s){scope}"

    async def _oauth_grants(self, client, user_filter: str):
        """List the third-party apps that hold delegated OAuth access.

        Uses the token application report (events authorize/add_access) and
        collapses to one row per (user, app) so the agent gets a clean
        permissions inventory rather than a raw event stream.
        """
        params: dict[str, Any] = {"maxResults": 1000}
        if user_filter:
            params["actorEmail"] = user_filter
        payload = await self._reports_get(
            client, "activities",
            {"applicationName": "token", **params},
        )
        items = payload.get("items", []) if isinstance(payload, dict) else []
        grants: dict[tuple[str, str], dict[str, Any]] = {}
        for it in items:
            actor = it.get("actor", {})
            user = actor.get("email", "?")
            for ev in it.get("events", []) or []:
                name = (ev.get("name") or "").lower()
                params_ev = ev.get("parameter", []) or []
                app = _param(params_ev, "app_name") or _param(params_ev, "client_id") or "?"
                scopes = _param(params_ev, "scope")
                key = (user, app)
                row = grants.setdefault(key, {
                    "user": user,
                    "app": app,
                    "scopes": set(),
                    "events": [],
                    "last_ts": it.get("id", {}).get("time"),
                })
                if isinstance(scopes, str) and scopes:
                    row["scopes"].update(s.replace("[", "").replace("]", "").split(","))
                elif isinstance(scopes, list):
                    row["scopes"].update(scopes)
                row["events"].append(name)
                t = it.get("id", {}).get("time")
                if t and (not row["last_ts"] or t > row["last_ts"]):
                    row["last_ts"] = t
        rows = []
        for row in grants.values():
            row["scopes"] = sorted(s for s in row["scopes"] if s)
            row["events"] = sorted(set(row["events"]))
            rows.append(row)
        scope = f" for {user_filter}" if user_filter else ""
        return rows, f"{len(rows)} OAuth app grant(s){scope}"

    async def _user_list(self, client, user_filter: str):
        """Directory API users.list (optionally a single userKey)."""
        params: dict[str, Any] = {"maxResults": 500, "viewType": "admin_view"}
        path = "users"
        if user_filter:
            # A single user lookup: users/<userKey> gives full detail incl. security.
            payload = await self._directory_get(client, f"users/{user_filter}")
            users = [payload] if isinstance(payload, dict) else []
        else:
            payload = await self._directory_get(client, "users", params)
            users = payload.get("users", []) if isinstance(payload, dict) else []
        rows = []
        for u in users:
            name = u.get("name", {}) or {}
            rows.append({
                "primary_email": u.get("primaryEmail"),
                "full_name": name.get("fullName"),
                "suspended": u.get("suspended"),
                "suspended_at": u.get("suspensionReason"),
                "is_admin": u.get("isAdmin"),
                "is_delegated_admin": u.get("isDelegatedAdmin"),
                "creation_time": u.get("creationTime"),
                "last_login_time": u.get("lastLoginTime"),
                "org_unit_path": u.get("orgUnitPath"),
                "agreed_to_terms": u.get("agreedToTerms"),
                "2sv_enrolled": bool((u.get("isEnrolledIn2Sv") or u.get("isEnforcedIn2Sv"))),
            })
        scope = f" for {user_filter}" if user_filter else ""
        return rows, f"{len(rows)} user(s){scope}"

    # -- low-level HTTP helpers ------------------------------------------

    async def _reports_get(self, client, path: str, params: dict[str, Any]) -> dict[str, Any]:
        """Hit the Admin SDK Reports API and return the parsed JSON body."""
        r = await client.get(f"{REPORTS_API}/{path}", params=params)
        if r.status_code == 401 or r.status_code == 403:
            raise _GwsApiError(
                "auth_forbidden",
                "Google Admin SDK Reports API returned 401/403 — the token is "
                "missing or lacks the admin.reports.audit.readonly scope (or "
                "the user is not a delegated admin for the target customer).",
            )
        if r.status_code == 404:
            raise _GwsApiError(
                "not_found",
                f"Google Admin SDK endpoint not found (404): {r.text[:200]}",
            )
        if r.status_code == 429:
            raise _GwsApiError("rate_limited", "Google API rate limited (429); retry later.")
        if r.status_code >= 400:
            raise _GwsApiError(
                "http",
                f"Google Reports API returned HTTP {r.status_code}: {r.text[:200]}",
            )
        try:
            return r.json()
        except Exception:
            raise _GwsApiError(
                "http",
                f"Google Reports API returned non-JSON: {r.text[:200]}",
            )

    async def _directory_get(self, client, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Hit the Admin SDK Directory API and return the parsed JSON body."""
        r = await client.get(f"{DIRECTORY_API}/{path}", params=params or {})
        if r.status_code in (401, 403):
            raise _GwsApiError(
                "auth_forbidden",
                "Google Admin SDK Directory API returned 401/403 — the token "
                "lacks the admin.directory.user.readonly scope or the caller is "
                "not a delegated admin.",
            )
        if r.status_code == 404:
            raise _GwsApiError(
                "not_found",
                f"Google Directory resource not found (404): {r.text[:200]}",
            )
        if r.status_code >= 400:
            raise _GwsApiError(
                "http",
                f"Google Directory API returned HTTP {r.status_code}: {r.text[:200]}",
            )
        try:
            return r.json()
        except Exception:
            raise _GwsApiError(
                "http",
                f"Google Directory API returned non-JSON: {r.text[:200]}",
            )

    @staticmethod
    def _shape_activity(it: dict[str, Any]) -> dict[str, Any]:
        """Normalize one Reports API activity item into a flat row."""
        eid = it.get("id", {}) or {}
        actor = it.get("actor", {}) or {}
        events = it.get("events", []) or []
        # Surface the first event's name/params as the headline; keep the rest.
        first = events[0] if events else {}
        return {
            "time": eid.get("time"),
            "application": eid.get("applicationName"),
            "actor_email": actor.get("email"),
            "actor_caller_type": actor.get("callerType"),
            "actor_key": actor.get("key"),
            "event_name": first.get("name"),
            "event_type": first.get("type"),
            "parameters": _flatten_params(first.get("parameter", []) or []),
            "ip_address": it.get("ipAddress"),
            "all_events": [
                {"name": e.get("name"), "type": e.get("type"),
                 "parameters": _flatten_params(e.get("parameter", []) or [])}
                for e in events
            ],
        }


def _flatten_params(params: list[dict[str, Any]]) -> dict[str, Any]:
    """Collapse the Reports API ``parameter`` list into a flat {name: value}."""
    out: dict[str, Any] = {}
    for p in params:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        if not name:
            continue
        # Reports API params carry one of: boolValue / intValue / multiValue /
        # messageValue / value (legacy string). Prefer the most specific.
        for k in ("value", "boolValue", "intValue", "multiValue", "messageValue"):
            if k in p:
                out[name] = p[k]
                break
    return out


def _param(params: list[dict[str, Any]], name: str) -> Any:
    """Read a single parameter value from a Reports API event param list."""
    for p in params:
        if isinstance(p, dict) and p.get("name") == name:
            for k in ("value", "boolValue", "intValue", "multiValue", "messageValue"):
                if k in p:
                    return p[k]
    return None


class _GwsApiError(Exception):
    """Google Admin SDK API returned an error envelope or HTTP failure."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind


# Module-level instance so the goal and any registry can pick it up.
tool = GworkspaceApiTool()
