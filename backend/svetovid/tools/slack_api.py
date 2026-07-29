"""Slack audit API tool wrapper (research item C16).

An API-based (not Dockerized) tool that exposes ``slack_audit``. The agent
picks an ``operation``; we hit the appropriate Slack REST endpoint with a
token from the ``SLACK_TOKEN`` environment variable and return flat JSON rows.

Operations → endpoints:
  - list_conversations → ``conversations.list``
  - message_history    → ``conversations.history``  (needs ``channel_id``)
  - audit_log          → ``audit/v1/actions``       (security/audit events)
  - user_list          → ``users.list``
  - file_shares        → ``files.list``             (optionally per channel)
  - app_perms          → ``audit/v1/actions`` filtered to OAuth/app grants

This is an API tool, not a sandboxed one: ``image=None`` and ``sandboxed=False``
(it runs on the host and never touches Docker). If ``SLACK_TOKEN`` is unset the
tool returns a clear error message so the agent can adapt — it never raises.
"""

from __future__ import annotations

import os
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

# Slack Web API (conversations / users / files) lives under https://slack.com/api.
# The enterprise Audit Logs API is published at https://api.slack.com/audit/v1/actions.
WEB_API = "https://slack.com/api"
AUDIT_API = "https://api.slack.com/audit/v1/actions"

# Audit-log action types that indicate an OAuth grant / app permission change.
# Used to filter audit_log down to just the app/oauth events for app_perms.
APP_ACTION_TYPES = {
    "oauth_authorize",
    "oauth_scopes",
    "app_installed",
    "app_uninstalled",
    "app_scoped_token_added",
    "app_scoped_token_revoked",
    "workflow_app_installed",
    "workflow_app_uninstalled",
}


class SlackApiTool(Tool):
    name = "slack_audit"
    image = None                # API tool — runs on host, no Docker image
    description = (
        "Query the Slack workspace via the REST API for a compromise "
        "investigation. Returns flat JSON rows. Operations: "
        "list_conversations (channels), message_history (needs channel_id), "
        "audit_log (security/audit events), user_list (members), file_shares "
        "(shared files), app_perms (OAuth/app permission grants). Requires the "
        "SLACK_TOKEN environment variable."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": [
                        "list_conversations",
                        "message_history",
                        "audit_log",
                        "user_list",
                        "file_shares",
                        "app_perms",
                    ],
                    "description": "Which Slack API query to run.",
                },
                "channel_id": {
                    "type": "string",
                    "description": (
                        "Slack channel ID (e.g. C012ABC4567). Required for "
                        "message_history; optional scope for file_shares."
                    ),
                },
                "limit": {
                    "type": "number",
                    "description": "Maximum number of rows to return (default 100).",
                },
            },
            "required": ["operation"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        import time

        call_id = ctx.make_call_id()
        token = os.environ.get("SLACK_TOKEN", "").strip()
        operation = args.get("operation")
        channel_id = args.get("channel_id") or ""
        try:
            limit = int(args.get("limit") or 100)
        except (TypeError, ValueError):
            limit = 100

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
                "slack_audit: SLACK_TOKEN environment variable is not set. "
                "Set a Slack user/bot token (xoxb-/xoxp-/xoxa-) with the "
                "audit:read, channels:read, users:read, and files:read scopes "
                "to enable Slack compromise investigation."
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
            msg = f"slack_audit: httpx unavailable ({e})"
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
                if operation == "list_conversations":
                    rows, summary = await self._list_conversations(client, limit)
                elif operation == "message_history":
                    if not channel_id:
                        raise ValueError("channel_id is required for message_history")
                    rows, summary = await self._message_history(client, channel_id, limit)
                elif operation == "audit_log":
                    rows, summary = await self._audit_log(client, limit)
                elif operation == "user_list":
                    rows, summary = await self._user_list(client, limit)
                elif operation == "file_shares":
                    rows, summary = await self._file_shares(client, channel_id, limit)
                elif operation == "app_perms":
                    rows, summary = await self._app_perms(client, limit)
                else:
                    raise ValueError(f"unknown operation {operation!r}")
            data = {"operation": operation, "rows": rows}
        except httpx.HTTPError as e:
            msg = f"slack_audit: network/HTTP error calling Slack API ({e})"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            exit_code, summary, data = 1, msg, {"error": "http_error", "detail": str(e)}
        except _SlackApiError as e:
            # Slack responded but indicated failure (ok=false / non-2xx / audit 403).
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, str(e)))
            exit_code, summary, data = 1, str(e), {"error": e.kind, "detail": str(e)}
        except Exception as e:
            ctx.bus.publish(E.tool_stderr(
                ctx.investigation_id, call_id, f"slack_audit failed: {e}"))
            exit_code, summary, data = 1, f"slack_audit failed: {e}", {"error": str(e)}

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

    async def _list_conversations(self, client, limit: int):
        params = {
            "types": "public_channel,private_channel,mpim,im",
            "limit": min(limit, 999),
            "exclude_archived": "false",
        }
        payload = await self._web_get(client, "conversations.list", params)
        channels = payload.get("channels", []) if isinstance(payload, dict) else []
        rows = []
        for c in channels:
            rows.append({
                "id": c.get("id"),
                "name": c.get("name"),
                "is_channel": c.get("is_channel"),
                "is_private": c.get("is_private"),
                "is_im": c.get("is_im"),
                "num_members": c.get("num_members"),
                "created": c.get("created"),
                "creator": c.get("creator"),
            })
        return rows, f"{len(rows)} conversation(s) listed"

    async def _message_history(self, client, channel_id: str, limit: int):
        params = {"channel": channel_id, "limit": min(limit, 200)}
        payload = await self._web_get(client, "conversations.history", params)
        messages = payload.get("messages", []) if isinstance(payload, dict) else []
        rows = []
        for m in messages:
            rows.append({
                "ts": m.get("ts"),
                "user": m.get("user"),
                "username": m.get("username"),
                "bot_id": m.get("bot_id"),
                "text": (m.get("text") or "")[:500],
                "subtype": m.get("subtype"),
                "files": [f.get("name") for f in (m.get("files") or [])],
                "reactions": [
                    {"name": r.get("name"), "count": r.get("count")}
                    for r in (m.get("reactions") or [])
                ],
                "is_edited": bool(m.get("edited")),
                "reply_count": m.get("reply_count"),
            })
        return rows, f"{len(rows)} message(s) from {channel_id}"

    async def _audit_log(self, client, limit: int):
        params = {"limit": min(limit, 9999)}
        entries = await self._audit_get(client, params)
        rows = [self._shape_audit_entry(e) for e in entries]
        return rows, f"{len(rows)} audit/security event(s)"

    async def _user_list(self, client, limit: int):
        params = {"limit": min(limit, 999)}
        payload = await self._web_get(client, "users.list", params)
        members = payload.get("members", []) if isinstance(payload, dict) else []
        rows = []
        for m in members:
            profile = m.get("profile", {}) or {}
            rows.append({
                "id": m.get("id"),
                "name": m.get("name"),
                "real_name": m.get("real_name"),
                "email": profile.get("email"),
                "display_name": profile.get("display_name"),
                "deleted": m.get("deleted"),
                "is_admin": m.get("is_admin"),
                "is_owner": m.get("is_owner"),
                "is_bot": m.get("is_bot"),
                "is_app_user": m.get("is_app_user"),
                "updated": m.get("updated"),
            })
        return rows, f"{len(rows)} workspace member(s)"

    async def _file_shares(self, client, channel_id: str, limit: int):
        params: dict[str, Any] = {"limit": min(limit, 200)}
        if channel_id:
            params["channel"] = channel_id
        payload = await self._web_get(client, "files.list", params)
        files = payload.get("files", []) if isinstance(payload, dict) else []
        rows = []
        for f in files:
            rows.append({
                "id": f.get("id"),
                "name": f.get("name"),
                "title": f.get("title"),
                "mimetype": f.get("mimetype"),
                "filetype": f.get("filetype"),
                "size": f.get("size"),
                "user": f.get("user"),
                "created": f.get("created"),
                "url_private": f.get("url_private"),
                "channels": f.get("channels"),
                "shares": f.get("shares"),
            })
        scope = f" in {channel_id}" if channel_id else ""
        return rows, f"{len(rows)} shared file(s){scope}"

    async def _app_perms(self, client, limit: int):
        params = {"limit": min(limit, 9999)}
        entries = await self._audit_get(client, params)
        # Filter the audit stream down to OAuth / app-install events.
        filtered = []
        for e in entries:
            kind = (e.get("type") or e.get("action") or "").lower()
            if kind in APP_ACTION_TYPES or "app" in kind or "oauth" in kind:
                filtered.append(e)
        rows = [self._shape_audit_entry(e) for e in filtered]
        return rows, f"{len(rows)} app/OAuth permission event(s)"

    # -- low-level HTTP helpers ------------------------------------------

    async def _web_get(self, client, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Hit a Slack Web API method and validate the ``ok`` envelope."""
        r = await client.get(f"{WEB_API}/{method}", params=params)
        if r.status_code >= 400:
            raise _SlackApiError(
                "slack_api",
                f"Slack {method} returned HTTP {r.status_code}: {r.text[:200]}",
            )
        try:
            payload = r.json()
        except Exception:
            raise _SlackApiError(
                "slack_api",
                f"Slack {method} returned non-JSON response: {r.text[:200]}",
            )
        if not payload.get("ok"):
            err = payload.get("error", "unknown_error")
            raise _SlackApiError(
                "slack_api",
                f"Slack {method} call failed: {err}",
            )
        return payload

    async def _audit_get(self, client, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Hit the enterprise Audit Logs API and return the entries list."""
        r = await client.get(AUDIT_API, params=params)
        if r.status_code == 403 or r.status_code == 401:
            raise _SlackApiError(
                "audit_forbidden",
                "Slack audit API returned 403/401 — the token lacks the "
                "audit:read scope or this is not an Enterprise Grid workspace. "
                "audit_log/app_perms require Enterprise Grid/Enterprise+.",
            )
        if r.status_code == 404:
            raise _SlackApiError(
                "audit_unavailable",
                "Slack audit API endpoint not found (404) — audit logs may be "
                "unavailable for this workspace tier.",
            )
        if r.status_code >= 400:
            raise _SlackApiError(
                "audit_http",
                f"Slack audit API returned HTTP {r.status_code}: {r.text[:200]}",
            )
        try:
            payload = r.json()
        except Exception:
            raise _SlackApiError(
                "audit_http",
                f"Slack audit API returned non-JSON: {r.text[:200]}",
            )
        # The audit endpoint returns {"entries": [...]}.
        if isinstance(payload, dict):
            entries = payload.get("entries") or payload.get("actions") or []
        else:
            entries = payload if isinstance(payload, list) else []
        return entries if isinstance(entries, list) else []

    @staticmethod
    def _shape_audit_entry(e: dict[str, Any]) -> dict[str, Any]:
        """Normalize one audit-log entry into a flat row."""
        return {
            "id": e.get("id"),
            "ts": e.get("ts"),
            "type": e.get("type") or e.get("action"),
            "actor": e.get("actor"),
            "entity": e.get("entity"),
            "context": e.get("context"),
            "details": e.get("details"),
        }


class _SlackApiError(Exception):
    """Slack API returned an error envelope or HTTP failure."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind


# Module-level instance so the goal and any registry can pick it up.
tool = SlackApiTool()
