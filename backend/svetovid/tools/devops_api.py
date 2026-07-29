"""DevOps / source-control compromise audit tool (research item C15/C16/SaaS).

A read-only, API-based tool that audits GitHub, Azure DevOps, Jira, and GitLab
for signs of source-control / supply-chain compromise. Unlike the forensics
tools (chainsaw, eztools, volatility), this one talks directly to the
platform's REST API using tokens pulled from environment variables — there is
no Docker sandbox because the evidence lives in the SaaS control plane, not on
a mounted disk image.

One tool, ``devops_audit``, takes a ``platform`` selector and an ``operation``
selector plus optional ``repo`` and ``limit`` args:

  platform   env var          token header used
  ---------  ---------------  ---------------------------------------------
  github     GITHUB_TOKEN     Authorization: Bearer <token>
  azure_devops  AZDO_PAT      Authorization: Basic <base64(:PAT)>
  jira       JIRA_TOKEN       Authorization: Bearer <token>  (+ user email
                              from JIRA_USER, sent as Basic auth for Cloud)
  gitlab     GITLAB_TOKEN     PRIVATE-TOKEN: <token>

operations:
  - audit_log     : pull the org/repo audit / security log (admin actions,
                    repo/pipeline changes, member/role changes)
  - repo_changes  : recent commits on a repo (flag mass file changes and
                    .git / CI file modifications)
  - user_perms    : members of an org/repo/project and their roles
  - pipeline_runs : CI/CD workflow / pipeline run history (unauthorized runs)
  - secrets_scan  : detect leaked secrets in code (GitHub secret scanning
                    alerts; GitLab/Jira best-effort) and PAT/credential
                    exposure indicators

The tool follows the same event-publishing pattern as the other wrappers
(``tool.start`` / ``tool.stdout`` / ``tool.stderr`` / ``tool.end`` /
``agent.action`` / ``agent.observation`` / ``provenance.recorded``) but with
``sandboxed=False`` and ``image=None`` since it runs on the host.

If the requested platform has no token in the environment, the tool returns a
clear error result (exit_code=2) so the ReAct agent can adapt and try a
different platform instead of crashing.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

# ---------------------------------------------------------------------------
# Platform / operation vocabulary
# ---------------------------------------------------------------------------

PLATFORMS = ("github", "azure_devops", "jira", "gitlab")

OPERATIONS = ("audit_log", "repo_changes", "user_perms", "pipeline_runs", "secrets_scan")

# env var that holds the credential per platform
PLATFORM_TOKEN_ENV: dict[str, str] = {
    "github": "GITHUB_TOKEN",
    "azure_devops": "AZDO_PAT",
    "jira": "JIRA_TOKEN",
    "gitlab": "GITLAB_TOKEN",
}

# Optional base URLs / orgs configurable via env (with sensible defaults).
# These let an analyst point the tool at GitHub Enterprise, a self-hosted
# GitLab, Jira Server/DC, or an Azure DevOps org without code changes.
DEFAULT_API_BASE: dict[str, str] = {
    "github": "https://api.github.com",
    "azure_devops": "https://dev.azure.com",
    "jira": "https://your-domain.atlassian.net",
    "gitlab": "https://gitlab.com",
}

# File types / path fragments that signal CI/CD or git-internal tampering when
# they appear in a commit's changed files. Used by repo_changes to flag
# suspicious commits.
CI_PATH_HINTS = (
    ".github/workflows/",
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    ".azure-pipelines/",
    "Jenkinsfile",
    ".circleci/",
    ".travis.yml",
    ".git/",
    ".gitattributes",
    ".gitignore",
    "Dockerfile",
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "go.mod",
    "Cargo.toml",
)

# High-risk actions pulled from audit logs across platforms. We match these
# substrings (case-insensitive) against audit action strings to flag rows.
RISKY_ACTION_HINTS = (
    "remove", "delete", "role", "permission", "member", "admin", "grant",
    "token", "secret", "key", "deploy", "pipeline", "workflow", "fork",
    "transfer", "impersonat", "oauth", "service", "hook", "webhook",
)


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


class DevOpsApiTool(Tool):
    """Read-only DevOps / source-control compromise audit tool.

    Talks directly to GitHub / Azure DevOps / Jira / GitLab REST APIs using
    credentials from environment variables. Runs on the host (no Docker) and
    returns structured rows the ReAct agent can reason over.
    """

    name = "devops_audit"
    image = None                # API-based, runs on host
    description = (
        "Audit a DevOps / source-control platform (GitHub, Azure DevOps, "
        "Jira, GitLab) for compromise. Calls the platform REST API read-only "
        "using tokens from env vars (GITHUB_TOKEN, AZDO_PAT, JIRA_TOKEN, "
        "GITLAB_TOKEN). Operations: audit_log (admin/security events), "
        "repo_changes (recent commits, flags mass/CI changes), user_perms "
        "(members + roles), pipeline_runs (CI/CD history), secrets_scan "
        "(leaked-credential alerts). If no token is set for a platform the "
        "tool returns a clear error so you can switch platforms."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "platform": {
                    "type": "string",
                    "enum": list(PLATFORMS),
                    "description": "Which DevOps platform to audit.",
                },
                "operation": {
                    "type": "string",
                    "enum": list(OPERATIONS),
                    "description": (
                        "audit_log = admin/security events; repo_changes = "
                        "recent commits on a repo; user_perms = members + "
                        "roles; pipeline_runs = CI/CD run history; "
                        "secrets_scan = leaked-credential alerts."
                    ),
                },
                "repo": {
                    "type": "string",
                    "description": (
                        "Repository / project identifier. GitHub/GitLab: "
                        "'owner/name' (e.g. 'octocat/Hello-World'). Azure "
                        "DevOps: project name. Jira: project key. "
                        "Required for repo_changes / pipeline_runs / "
                        "secrets_scan on most platforms."
                    ),
                },
                "limit": {
                    "type": "number",
                    "description": "Max rows to return (default 50).",
                },
            },
            "required": ["platform", "operation"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        import time

        call_id = ctx.make_call_id()
        platform = str(args.get("platform", "")).strip()
        operation = str(args.get("operation", "")).strip()
        repo = str(args.get("repo", "")).strip() or None
        limit = _as_int(args.get("limit"), default=50)
        t0 = time.monotonic()

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=False, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

        # ---- validate selectors ----
        if platform not in PLATFORMS:
            msg = (f"unknown platform {platform!r}; pick from {list(PLATFORMS)}")
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 2, 0.0, None))
            return _result(call_id, self.name, 2, 0.0, msg, {"error": msg})
        if operation not in OPERATIONS:
            msg = (f"unknown operation {operation!r}; pick from {list(OPERATIONS)}")
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 2, 0.0, None))
            return _result(call_id, self.name, 2, 0.0, msg, {"error": msg})

        # ---- resolve token ----
        token = os.environ.get(PLATFORM_TOKEN_ENV[platform], "").strip()
        if not token:
            msg = (
                f"no {PLATFORM_TOKEN_ENV[platform]} environment variable set for "
                f"platform {platform!r}; set it to a read-only token/PAT and "
                f"retry, or audit a different platform."
            )
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.agent_observation(
                ctx.investigation_id, tool=self.name, summary=msg,
            ))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 2, 0.0, None))
            return _result(call_id, self.name, 2, 0.0, msg, {"error": msg, "missing_token": True})

        # ---- dispatch to the platform-specific handler ----
        try:
            ctx.bus.publish(E.tool_stdout(
                ctx.investigation_id, call_id,
                f"[devops_audit] {platform} / {operation} repo={repo or '-'} limit={limit}",
            ))
            handler = _HANDLERS[(platform, operation)]
            rows = await handler(token=token, repo=repo, limit=limit, ctx=ctx, call_id=call_id)
        except httpx.ConnectError as e:
            msg = f"{platform} API unreachable: {e}"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg,
                           {"error": msg, "platform": platform})
        except httpx.TimeoutException:
            msg = f"{platform} API timed out"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg,
                           {"error": msg, "platform": platform})
        except httpx.HTTPError as e:
            msg = f"{platform} API error: {e}"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg,
                           {"error": msg, "platform": platform})
        except _ApiError as e:
            # A structured error from the handler (e.g. HTTP 404 / 403 / repo
            # required). Surface it as a clear message so the agent adapts.
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, str(e)))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), str(e),
                           {"error": str(e), "platform": platform})
        except Exception as e:
            msg = f"{platform} {operation} failed: {e}"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg,
                           {"error": msg, "platform": platform})

        # ---- success ----
        flagged = [r for r in rows if r.get("flagged")]
        summary = (
            f"{platform} / {operation}: {len(rows)} row(s)"
            + (f", {len(flagged)} flagged suspicious" if flagged else "")
        )
        data: dict[str, Any] = {
            "platform": platform,
            "operation": operation,
            "repo": repo,
            "rows": rows,
            "flagged_count": len(flagged),
        }
        ctx.bus.publish(E.tool_stdout(
            ctx.investigation_id, call_id, summary,
        ))
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
            "platform": platform,
            "operation": operation,
            "rows": len(rows),
            "ts": E._now_iso(),
        }))
        return _result(call_id, self.name, 0, _dur(t0), summary, data)


# ---------------------------------------------------------------------------
# Shared HTTP helpers
# ---------------------------------------------------------------------------


class _ApiError(RuntimeError):
    """A structured API error (non-2xx, or a precondition failure)."""


def _dur(t0: float) -> float:
    import time
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


def _require_repo(repo: str | None, platform: str) -> str:
    if not repo:
        raise _ApiError(
            f"{platform}: a repo/project identifier is required for this "
            f"operation (GitHub/GitLab 'owner/name', Azure DevOps project, "
            f"Jira project key)."
        )
    return repo


def _flag_action(action: str) -> bool:
    """True if an audit-log action string looks risky."""
    if not action:
        return False
    low = action.lower()
    return any(h in low for h in RISKY_ACTION_HINTS)


async def _get_json(client: httpx.AsyncClient, url: str, **kw: Any) -> Any:
    """GET url, raise _ApiError on non-2xx, return parsed JSON (or text)."""
    resp = await client.get(url, **kw)
    if resp.status_code >= 400:
        body = (resp.text or "")[:300]
        raise _ApiError(f"HTTP {resp.status_code} from {url}: {body}")
    try:
        return resp.json()
    except Exception:
        return resp.text


async def _request(
    method: str, url: str, *, headers: dict[str, str], ctx: ToolContext,
    call_id: str, params: dict[str, Any] | None = None, timeout: float = 30.0,
) -> Any:
    """Issue an HTTP request, streaming a one-line status note to the bus."""
    ctx.bus.publish(E.tool_stdout(
        ctx.investigation_id, call_id, f"→ {method} {url}",
    ))
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.request(method, url, headers=headers, params=params)
    if resp.status_code >= 400:
        body = (resp.text or "")[:300]
        raise _ApiError(f"HTTP {resp.status_code} from {url}: {body}")
    try:
        return resp.json()
    except Exception:
        return resp.text


# ---------------------------------------------------------------------------
# GitHub handlers
# ---------------------------------------------------------------------------


def _gh_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "svetovid-dfir",
    }


def _gh_base() -> str:
    return os.environ.get("GITHUB_API_BASE", DEFAULT_API_BASE["github"]).rstrip("/")


async def _gh_org() -> str:
    """Org to audit for org-level audit_log / members. From GITHUB_ORG."""
    org = os.environ.get("GITHUB_ORG", "").strip()
    if not org:
        raise _ApiError(
            "github: set GITHUB_ORG (the organization login) to use "
            "audit_log / user_perms at the org level, or pass repo=owner/name "
            "for a single repository."
        )
    return org


async def gh_audit_log(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    # Org audit log requires admin:org scope. Fall back to repo activity if
    # the caller passed repo=owner/name instead.
    headers = _gh_headers(token)
    rows: list[dict[str, Any]] = []
    if repo:
        owner, _, name = repo.partition("/")
        if not name:
            raise _ApiError(f"github: repo must be 'owner/name', got {repo!r}")
        # Recent repo events (push / create / permission changes).
        data = await _request("GET", f"{_gh_base()}/repos/{owner}/{name}/events",
                              headers=headers, ctx=ctx, call_id=call_id,
                              params={"per_page": min(limit, 100)})
        for ev in data if isinstance(data, list) else []:
            action = ev.get("type", "")
            actor = (ev.get("actor") or {}).get("login", "")
            rows.append({
                "source": f"{owner}/{name}",
                "ts": ev.get("created_at"),
                "action": action,
                "actor": actor,
                "flagged": _flag_action(action),
                "detail": ev.get("payload", {}),
            })
        return rows[:limit]
    org = await _gh_org()
    data = await _request("GET", f"{_gh_base()}/orgs/{org}/audit-log",
                          headers=headers, ctx=ctx, call_id=call_id,
                          params={"per_page": min(limit, 100)})
    for ev in data if isinstance(data, list) else []:
        action = ev.get("action", "") or ev.get("@type", "")
        actor = ev.get("actor", "") or ev.get("actor_login", "")
        rows.append({
            "source": f"org:{org}",
            "ts": ev.get("created_at") or ev.get("@timestamp"),
            "action": action,
            "actor": actor,
            "flagged": _flag_action(action),
            "detail": {k: v for k, v in ev.items()
                       if k not in ("action", "actor", "created_at", "@timestamp", "@type")},
        })
    return rows[:limit]


async def gh_repo_changes(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    repo = _require_repo(repo, "github")
    owner, _, name = repo.partition("/")
    if not name:
        raise _ApiError(f"github: repo must be 'owner/name', got {repo!r}")
    headers = _gh_headers(token)
    data = await _request("GET", f"{_gh_base()}/repos/{owner}/{name}/commits",
                          headers=headers, ctx=ctx, call_id=call_id,
                          params={"per_page": min(limit, 100)})
    out: list[dict[str, Any]] = []
    for c in data if isinstance(data, list) else []:
        sha = (c.get("sha") or "")[:12]
        commit = c.get("commit") or {}
        msg = (commit.get("message") or "").splitlines()[0][:160]
        author = (commit.get("author") or {}).get("name") or \
                 (c.get("author") or {}).get("login", "")
        ts = commit.get("author", {}).get("date")
        # stats field requires a follow-up per commit; pull files for risk
        files = []
        try:
            detail = await _request("GET", f"{_gh_base()}/repos/{owner}/{name}/commits/{c.get('sha')}",
                                    headers=headers, ctx=ctx, call_id=call_id)
            files = [f.get("filename", "") for f in (detail.get("files") or [])] if isinstance(detail, dict) else []
        except _ApiError:
            pass
        flagged = bool(files) and (
            len(files) >= 50
            or any(any(h in f for h in CI_PATH_HINTS) for f in files)
        )
        out.append({
            "source": repo,
            "sha": sha,
            "ts": ts,
            "author": author,
            "message": msg,
            "files_changed": len(files),
            "ci_files": sorted({f for f in files if any(h in f for h in CI_PATH_HINTS)}),
            "flagged": flagged,
        })
        if len(out) >= limit:
            break
    return out


async def gh_user_perms(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    headers = _gh_headers(token)
    rows: list[dict[str, Any]] = []
    if repo:
        owner, _, name = repo.partition("/")
        if not name:
            raise _ApiError(f"github: repo must be 'owner/name', got {repo!r}")
        data = await _request("GET", f"{_gh_base()}/repos/{owner}/{name}/collaborators",
                              headers=headers, ctx=ctx, call_id=call_id,
                              params={"per_page": min(limit, 100)})
        for u in data if isinstance(data, list) else []:
            role = ", ".join(p.get("permission") or "" for p in ([u] if isinstance(u, dict) else []))
            perms = []
            if isinstance(u, dict):
                for key in ("permissions", "role_name"):
                    v = u.get(key)
                    if isinstance(v, dict):
                        perms = [k for k, on in v.items() if on]
                        role = ",".join(perms) or role
                    elif isinstance(v, str):
                        role = v
            rows.append({
                "source": repo,
                "user": u.get("login", "") if isinstance(u, dict) else str(u),
                "role": role,
                "admin": "admin" in str(role).lower(),
                "flagged": "admin" in str(role).lower(),
            })
        return rows[:limit]
    org = await _gh_org()
    data = await _request("GET", f"{_gh_base()}/orgs/{org}/members",
                          headers=headers, ctx=ctx, call_id=call_id,
                          params={"per_page": min(limit, 100)})
    for u in data if isinstance(data, list) else []:
        rows.append({
            "source": f"org:{org}",
            "user": u.get("login", ""),
            "role": "member",
            "admin": False,
            "flagged": False,
        })
    return rows[:limit]


async def gh_pipeline_runs(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    repo = _require_repo(repo, "github")
    owner, _, name = repo.partition("/")
    if not name:
        raise _ApiError(f"github: repo must be 'owner/name', got {repo!r}")
    headers = _gh_headers(token)
    data = await _request("GET", f"{_gh_base()}/repos/{owner}/{name}/actions/runs",
                          headers=headers, ctx=ctx, call_id=call_id,
                          params={"per_page": min(limit, 100)})
    runs = (data or {}).get("workflow_runs", []) if isinstance(data, dict) else []
    out: list[dict[str, Any]] = []
    for r in runs:
        actor = (r.get("actor") or {}).get("login", "")
        event = r.get("event", "")
        status = r.get("conclusion") or r.get("status", "")
        out.append({
            "source": repo,
            "ts": r.get("created_at"),
            "run_id": r.get("id"),
            "workflow": (r.get("name") or "") + " / " + (r.get("head_branch") or ""),
            "actor": actor,
            "event": event,           # push / pull_request / workflow_dispatch / schedule
            "status": status,
            # Manual dispatches and pull_request runs are the most common
            # pipeline-tampering vectors.
            "flagged": event in ("workflow_dispatch", "pull_request")
                       or event in ("repository_dispatch",),
        })
        if len(out) >= limit:
            break
    return out


async def gh_secrets_scan(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    headers = _gh_headers(token)
    out: list[dict[str, Any]] = []
    if repo:
        owner, _, name = repo.partition("/")
        if not name:
            raise _ApiError(f"github: repo must be 'owner/name', got {repo!r}")
        url = f"{_gh_base()}/repos/{owner}/{name}/secret-scanning/alerts"
        params = {"per_page": min(limit, 100), "state": "open"}
        data = await _request("GET", url, headers=headers, ctx=ctx, call_id=call_id, params=params)
        for a in data if isinstance(data, list) else []:
            out.append({
                "source": repo,
                "ts": a.get("created_at"),
                "secret_type": a.get("secret_type"),
                "secret_provider": a.get("secret_type_display_name") or a.get("secret_type"),
                "state": a.get("state"),
                "resolution": a.get("resolution"),
                "url": a.get("html_url"),
                "flagged": True,
            })
        return out[:limit]
    # Org-wide alerts need the secret-scanning alerts org endpoint (enterprise).
    org = await _gh_org()
    data = await _request("GET", f"{_gh_base()}/orgs/{org}/secret-scanning/alerts",
                          headers=headers, ctx=ctx, call_id=call_id,
                          params={"per_page": min(limit, 100), "state": "open"})
    for a in data if isinstance(data, list) else []:
        out.append({
            "source": f"org:{org}",
            "ts": a.get("created_at"),
            "secret_type": a.get("secret_type"),
            "repo": a.get("repository", {}).get("full_name") if isinstance(a.get("repository"), dict) else None,
            "state": a.get("state"),
            "flagged": True,
        })
    return out[:limit]


# ---------------------------------------------------------------------------
# Azure DevOps handlers
# ---------------------------------------------------------------------------


def _azdo_auth(pat: str) -> dict[str, str]:
    import base64
    cred = base64.b64encode(f":{pat}".encode()).decode()
    return {
        "Authorization": f"Basic {cred}",
        "Accept": "application/json",
        "User-Agent": "svetovid-dfir",
    }


def _azdo_base() -> str:
    return os.environ.get("AZDO_BASE_URL", DEFAULT_API_BASE["azure_devops"]).rstrip("/")


def _azdo_org() -> str:
    org = os.environ.get("AZDO_ORG", "").strip()
    if not org:
        raise _ApiError(
            "azure_devops: set AZDO_ORG (the Azure DevOps organization name) "
            "to query audit logs / projects."
        )
    return org


async def azdo_audit_log(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    # Azure DevOps audit log is org-level (auditing.auditlog).
    org = _azdo_org()
    url = f"https://auditservice.dev.azure.com/{org}/_apis/audit/auditlog"
    data = await _request("GET", url, headers=_azdo_auth(token), ctx=ctx, call_id=call_id,
                          params={"$top": limit, "api-version": "7.1"})
    entries = (data or {}).get("decoratedAuditLogEntries") or (data or {}).get("auditLogEntries") or []
    out: list[dict[str, Any]] = []
    for e in entries:
        action = e.get("actionId", "") or e.get("actionName", "")
        actor = e.get("actorUserId", "") or e.get("actorCnn", "")
        out.append({
            "source": f"org:{org}",
            "ts": e.get("timestamp"),
            "action": action,
            "actor": actor,
            "ip": e.get("actorIpAddress"),
            "detail": e.get("data") or {},
            "flagged": _flag_action(str(action)),
        })
    return out[:limit]


async def azdo_repo_changes(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    repo = _require_repo(repo, "azure_devops")
    org = _azdo_org()
    headers = _azdo_auth(token)
    # Resolve the repo's default branch + recent commits via the Git API.
    repo_data = await _request(
        "GET", f"{_azdo_base()}/{org}/_apis/git/repositories/{repo}",
        headers=headers, ctx=ctx, call_id=call_id, params={"api-version": "7.1"},
    )
    rid = (repo_data or {}).get("id") if isinstance(repo_data, dict) else None
    default_branch = ((repo_data or {}).get("defaultBranch") or "refs/heads/main").split("/")[-1]
    if not rid:
        raise _ApiError(f"azure_devops: repository {repo!r} not found in org {org!r}")
    data = await _request(
        "GET", f"{_azdo_base()}/{org}/_apis/git/repositories/{rid}/commits",
        headers=headers, ctx=ctx, call_id=call_id,
        params={"$top": min(limit, 100), "api-version": "7.1",
                "searchCriteria.itemVersion.version": default_branch},
    )
    out: list[dict[str, Any]] = []
    for c in (data or {}).get("value", []) if isinstance(data, dict) else []:
        sha = (c.get("commitId") or "")[:12]
        msg = (c.get("comment") or "").splitlines()[0][:160]
        author = c.get("author", {}).get("name", "") if isinstance(c.get("author"), dict) else str(c.get("author", ""))
        # Pull changed file count / paths from the commit details.
        ci_files: list[str] = []
        changed = 0
        try:
            detail = await _request(
                "GET", f"{_azdo_base()}/{org}/_apis/git/repositories/{rid}/commits/{c.get('commitId')}/changes",
                headers=headers, ctx=ctx, call_id=call_id, params={"api-version": "7.1"},
            )
            changes = (detail or {}).get("changes", []) if isinstance(detail, dict) else []
            changed = len(changes)
            ci_files = sorted({ch.get("item", {}).get("path", "") for ch in changes
                               if isinstance(ch.get("item"), dict)
                               and any(h in ch.get("item", {}).get("path", "") for h in CI_PATH_HINTS)})
        except _ApiError:
            pass
        flagged = changed >= 50 or bool(ci_files)
        out.append({
            "source": f"{org}/{repo}",
            "sha": sha,
            "ts": c.get("author", {}).get("date") if isinstance(c.get("author"), dict) else None,
            "author": author,
            "message": msg,
            "files_changed": changed,
            "ci_files": ci_files,
            "flagged": flagged,
        })
        if len(out) >= limit:
            break
    return out


async def azdo_user_perms(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    org = _azdo_org()
    headers = _azdo_auth(token)
    url = f"https://vsaex.dev.azure.com/{org}/_apis/groupentitlements"
    data = await _request("GET", url, headers=headers, ctx=ctx, call_id=call_id,
                          params={"$top": limit, "api-version": "7.1-preview.3"})
    out: list[dict[str, Any]] = []
    members = (data or {}).get("members", []) if isinstance(data, dict) else []
    for m in members:
        login = m.get("id") or m.get("displayName", "")
        out.append({
            "source": f"org:{org}",
            "user": login,
            "role": m.get("origin", "") or "member",
            "admin": False,
            "flagged": False,
        })
        if len(out) >= limit:
            break
    return out


async def azdo_pipeline_runs(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    repo = _require_repo(repo, "azure_devops")
    org = _azdo_org()
    headers = _azdo_auth(token)
    data = await _request(
        "GET", f"{_azdo_base()}/{org}/{repo}/_apis/build/builds",
        headers=headers, ctx=ctx, call_id=call_id,
        params={"$top": min(limit, 100), "api-version": "7.1"},
    )
    out: list[dict[str, Any]] = []
    for b in (data or {}).get("value", []) if isinstance(data, dict) else []:
        reason = b.get("reason") or ""     # manual, individualCI, schedule, pullRequest...
        out.append({
            "source": f"{org}/{repo}",
            "ts": b.get("startTime") or b.get("queueTime"),
            "build_id": b.get("id"),
            "pipeline": (b.get("definition") or {}).get("name", "") if isinstance(b.get("definition"), dict) else "",
            "actor": b.get("requestedFor", {}).get("displayName", "") if isinstance(b.get("requestedFor"), dict) else "",
            "reason": reason,
            "status": b.get("result") or b.get("status", ""),
            "flagged": str(reason).lower() in ("manual", "pullrequest"),
        })
        if len(out) >= limit:
            break
    return out


async def azdo_secrets_scan(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    # Azure DevOps has no first-party secret-scanning API; surface the repo's
    # pipeline variables / library secrets metadata as best-effort. Flagging
    # actual leaks requires scanning commit content, which we report as a
    # limitation so the agent can pivot to repo_changes.
    repo = _require_repo(repo, "azure_devops")
    org = _azdo_org()
    headers = _azdo_auth(token)
    data = await _request(
        "GET", f"{_azdo_base()}/{org}/{repo}/_apis/distributedtask/variablegroups",
        headers=headers, ctx=ctx, call_id=call_id, params={"api-version": "7.1"},
    )
    out: list[dict[str, Any]] = []
    for vg in (data or {}).get("value", []) if isinstance(data, dict) else []:
        variables = vg.get("variables") or {}
        for vname, vmeta in variables.items():
            is_secret = bool((vmeta or {}).get("isSecret")) if isinstance(vmeta, dict) else False
            out.append({
                "source": f"{org}/{repo}",
                "variable_group": vg.get("name", ""),
                "name": vname,
                "secret": is_secret,
                "flagged": is_secret,
                "note": "Azure DevOps exposes no native secret-scanning API; "
                        "this lists stored pipeline secrets, not leaked ones. "
                        "Use repo_changes + content review to find leaks.",
            })
            if len(out) >= limit:
                break
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Jira handlers
# ---------------------------------------------------------------------------


def _jira_base() -> str:
    base = os.environ.get("JIRA_BASE_URL", DEFAULT_API_BASE["jira"]).rstrip("/")
    return base


def _jira_headers(token: str) -> dict[str, str]:
    # Jira Cloud uses email + API token as Basic auth; Server/DC + many
    # modern setups also accept a PAT as Bearer. Support both: if JIRA_USER
    # is set, send Basic(email:token); otherwise Bearer.
    import base64
    user = os.environ.get("JIRA_USER", "").strip()
    if user:
        cred = base64.b64encode(f"{user}:{token}".encode()).decode()
        return {
            "Authorization": f"Basic {cred}",
            "Accept": "application/json",
            "User-Agent": "svetovid-dfir",
        }
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "svetovid-dfir",
    }


async def jira_audit_log(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    # The audit log API differs between Cloud (rest/api/3/auditing) and
    # Data Center (/rest/api/2/auditing). Try 3 then 2.
    headers = _jira_headers(token)
    base = _jira_base()
    for ver in ("3", "2"):
        try:
            data = await _request(
                "GET", f"{base}/rest/api/{ver}/auditing",
                headers=headers, ctx=ctx, call_id=call_id, params={"limit": limit},
            )
        except _ApiError:
            continue
        records = (data or {}).get("records") or data or []
        out: list[dict[str, Any]] = []
        for r in records if isinstance(records, list) else []:
            action = r.get("action") or r.get("actionCategory", "")
            actor = (r.get("actor") or {}).get("name") or (r.get("actor") or {}).get("displayName", "") \
                if isinstance(r.get("actor"), dict) else r.get("authorKey", "")
            out.append({
                "source": base,
                "ts": r.get("created"),
                "action": action,
                "actor": actor,
                "object": r.get("objectItem", {}).get("name") if isinstance(r.get("objectItem"), dict) else None,
                "flagged": _flag_action(str(action)),
            })
            if len(out) >= limit:
                break
        return out
    raise _ApiError(
        "jira: audit log endpoint returned an error on both API v3 and v2 "
        "(may require admin scope or be disabled on this instance)."
    )


async def jira_repo_changes(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    # Jira has no git history; "repo_changes" maps to recent issue
    # change-history events (edits to DevOps-linked issues), which are the
    # Jira analog of source-control tampering. Requires a project key.
    project = _require_repo(repo, "jira")
    headers = _jira_headers(token)
    base = _jira_base()
    issues = await _request(
        "GET", f"{base}/rest/api/3/search",
        headers=headers, ctx=ctx, call_id=call_id,
        params={"jql": f"project = {project} ORDER BY updated DESC",
                "maxResults": min(limit, 100), "fields": "summary,updated,status"},
    )
    out: list[dict[str, Any]] = []
    for issue in (issues or {}).get("issues", []) if isinstance(issues, dict) else []:
        key = issue.get("key", "")
        out.append({
            "source": f"project:{project}",
            "ts": (issue.get("fields") or {}).get("updated"),
            "issue": key,
            "summary": (issue.get("fields") or {}).get("summary", ""),
            "note": "Jira issue change history (no git history in Jira); "
                    "review linked DevOps commits via repo_changes on the "
                    "connected Git platform.",
            "flagged": False,
        })
        if len(out) >= limit:
            break
    return out


async def jira_user_perms(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    project = repo  # optional; list org members if omitted
    headers = _jira_headers(token)
    base = _jira_base()
    if project:
        data = await _request(
            "GET", f"{base}/rest/api/3/project/{project}/role",
            headers=headers, ctx=ctx, call_id=call_id,
        )
        out: list[dict[str, Any]] = []
        # data maps role-name -> role-url; fetch each to enumerate actors.
        if isinstance(data, dict):
            for role_name, role_url in data.items():
                try:
                    role = await _request("GET", role_url, headers=headers, ctx=ctx, call_id=call_id)
                except _ApiError:
                    continue
                for actor in (role or {}).get("actors", []) if isinstance(role, dict) else []:
                    name = actor.get("displayName") or actor.get("name", "")
                    out.append({
                        "source": f"project:{project}",
                        "user": name,
                        "role": role_name,
                        "type": actor.get("type", ""),
                        "admin": "admin" in str(role_name).lower(),
                        "flagged": "admin" in str(role_name).lower(),
                    })
                    if len(out) >= limit:
                        return out
        return out
    # org-level: list groups
    data = await _request(
        "GET", f"{base}/rest/api/3/group",
        headers=headers, ctx=ctx, call_id=call_id,
        params={"limit": min(limit, 100)},
    )
    out: list[dict[str, Any]] = []
    for g in ((data or {}).get("groups") or []) if isinstance(data, dict) else []:
        out.append({
            "source": base,
            "user": g.get("name", ""),
            "role": "group",
            "admin": False,
            "flagged": False,
        })
    return out


async def jira_pipeline_runs(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    # Jira has no CI pipelines; surface DevOps-linked deployments from the
    # deployments API (Jira Software) if available.
    headers = _jira_headers(token)
    base = _jira_base()
    project = _require_repo(repo, "jira")
    try:
        data = await _request(
            "GET", f"{base}/rest/api/3/deployments/project/{project}",
            headers=headers, ctx=ctx, call_id=call_id, params={"maxResults": min(limit, 100)},
        )
    except _ApiError as e:
        raise _ApiError(
            "jira: deployments/pipeline API unavailable (Jira has no native "
            "CI/CD; review the connected DevOps platform's pipeline_runs "
            f"instead). Detail: {e}"
        )
    items = data if isinstance(data, list) else ((data or {}).get("deployments") or [])
    out: list[dict[str, Any]] = []
    for d in items:
        out.append({
            "source": f"project:{project}",
            "ts": d.get("deploymentSequenceNumber"),
            "environment": d.get("environment", {}).get("displayName") if isinstance(d.get("environment"), dict) else None,
            "state": d.get("state", ""),
            "pipeline": d.get("pipeline", {}).get("displayName") if isinstance(d.get("pipeline"), dict) else None,
            "flagged": False,
        })
        if len(out) >= limit:
            break
    return out


async def jira_secrets_scan(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    # Best-effort: search recent issues/comments for high-signal credential
    # keywords. Jira stores no source, so this is content-based detection.
    project = _require_repo(repo, "jira")
    headers = _jira_headers(token)
    base = _jira_base()
    jql = (f'project = {project} AND text ~ "\\"password\\"" OR '
           f'project = {project} AND text ~ "\\"api key\\""')
    try:
        data = await _request(
            "GET", f"{base}/rest/api/3/search",
            headers=headers, ctx=ctx, call_id=call_id,
            params={"jql": jql, "maxResults": min(limit, 50),
                    "fields": "summary,updated"},
        )
    except _ApiError as e:
        raise _ApiError(
            "jira: secrets search failed (Jira stores no source code; use the "
            f"connected Git platform's secrets_scan). Detail: {e}"
        )
    out: list[dict[str, Any]] = []
    for issue in (data or {}).get("issues", []) if isinstance(data, dict) else []:
        out.append({
            "source": f"project:{project}",
            "ts": (issue.get("fields") or {}).get("updated"),
            "issue": issue.get("key", ""),
            "summary": (issue.get("fields") or {}).get("summary", ""),
            "match": "password / api key keyword",
            "flagged": True,
            "note": "Jira keyword-based secret hit (no native secret scanning).",
        })
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# GitLab handlers
# ---------------------------------------------------------------------------


def _gl_headers(token: str) -> dict[str, str]:
    return {
        "PRIVATE-TOKEN": token,
        "Accept": "application/json",
        "User-Agent": "svetovid-dfir",
    }


def _gl_base() -> str:
    return os.environ.get("GITLAB_BASE_URL", DEFAULT_API_BASE["gitlab"]).rstrip("/")


def _gl_project_id(repo: str) -> str:
    # GitLab uses URL-encoded "group/project" as the project id path segment.
    import urllib.parse
    return urllib.parse.quote(repo.strip(), safe="")


def _gl_group() -> str:
    g = os.environ.get("GITLAB_GROUP", "").strip()
    if not g:
        raise _ApiError(
            "gitlab: set GITLAB_GROUP (top-level group path) to use org-level "
            "audit_log / user_perms, or pass repo=group/project for a single "
            "repository."
        )
    return g


async def gl_audit_log(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    headers = _gl_headers(token)
    base = _gl_base()
    if repo:
        pid = _gl_project_id(repo)
        data = await _request("GET", f"{base}/api/v4/projects/{pid}/events",
                              headers=headers, ctx=ctx, call_id=call_id,
                              params={"per_page": min(limit, 100)})
        out: list[dict[str, Any]] = []
        for e in data if isinstance(data, list) else []:
            action = e.get("action_name", "")
            out.append({
                "source": repo,
                "ts": e.get("created_at"),
                "action": action,
                "actor": (e.get("author") or {}).get("username", "") if isinstance(e.get("author"), dict) else "",
                "target": e.get("target_title"),
                "flagged": _flag_action(str(action)),
            })
            if len(out) >= limit:
                break
        return out
    group = _gl_group()
    data = await _request("GET", f"{base}/api/v4/groups/{group}/audit_events",
                          headers=headers, ctx=ctx, call_id=call_id,
                          params={"per_page": min(limit, 100)})
    out: list[dict[str, Any]] = []
    for e in data if isinstance(data, list) else []:
        details = e.get("details", {}) if isinstance(e.get("details"), dict) else {}
        action = e.get("action") or details.get("action") or details.get("custom_message", "")
        out.append({
            "source": f"group:{group}",
            "ts": e.get("created_at"),
            "action": action,
            "actor": e.get("author_name") or details.get("author_name", ""),
            "entity": e.get("entity_path"),
            "flagged": _flag_action(str(action)),
        })
        if len(out) >= limit:
            break
    return out


async def gl_repo_changes(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    repo = _require_repo(repo, "gitlab")
    pid = _gl_project_id(repo)
    headers = _gl_headers(token)
    base = _gl_base()
    data = await _request("GET", f"{base}/api/v4/projects/{pid}/repository/commits",
                          headers=headers, ctx=ctx, call_id=call_id,
                          params={"per_page": min(limit, 100)})
    out: list[dict[str, Any]] = []
    for c in data if isinstance(data, list) else []:
        stats = c.get("stats") or {}
        changed = (stats.get("total") or 0)
        msg = (c.get("message") or "").splitlines()[0][:160]
        # Detect CI/.git path changes from the commit's diff (one extra call).
        ci_files: list[str] = []
        try:
            diff = await _request("GET",
                                  f"{base}/api/v4/projects/{pid}/repository/commits/{c.get('id')}/diff",
                                  headers=headers, ctx=ctx, call_id=call_id)
            ci_files = sorted({d.get("new_path", "") for d in (diff or [])
                               if any(h in d.get("new_path", "") for h in CI_PATH_HINTS)})
        except _ApiError:
            pass
        flagged = changed >= 50 or bool(ci_files)
        out.append({
            "source": repo,
            "sha": (c.get("short_id") or c.get("id", ""))[:12],
            "ts": c.get("created_at"),
            "author": c.get("author_name", ""),
            "message": msg,
            "files_changed": changed,
            "ci_files": ci_files,
            "flagged": flagged,
        })
        if len(out) >= limit:
            break
    return out


async def gl_user_perms(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    headers = _gl_headers(token)
    base = _gl_base()
    out: list[dict[str, Any]] = []
    if repo:
        pid = _gl_project_id(repo)
        data = await _request("GET", f"{base}/api/v4/projects/{pid}/members",
                              headers=headers, ctx=ctx, call_id=call_id,
                              params={"per_page": min(limit, 100)})
        for u in data if isinstance(data, list) else []:
            access = u.get("access_level")
            out.append({
                "source": repo,
                "user": u.get("username", ""),
                "role": _gl_access_label(access),
                "access_level": access,
                "admin": access in (40, 50),
                "flagged": access in (40, 50),   # maintainer/owner
            })
        return out[:limit]
    group = _gl_group()
    data = await _request("GET", f"{base}/api/v4/groups/{group}/members",
                          headers=headers, ctx=ctx, call_id=call_id,
                          params={"per_page": min(limit, 100)})
    for u in data if isinstance(data, list) else []:
        access = u.get("access_level")
        out.append({
            "source": f"group:{group}",
            "user": u.get("username", ""),
            "role": _gl_access_label(access),
            "access_level": access,
            "admin": access in (40, 50),
            "flagged": access in (40, 50),
        })
    return out[:limit]


def _gl_access_label(level: Any) -> str:
    return {
        10: "guest", 20: "reporter", 30: "developer",
        40: "maintainer", 50: "owner",
    }.get(int(level) if isinstance(level, (int, str)) and str(level).lstrip("-").isdigit() else -1, str(level))


async def gl_pipeline_runs(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    repo = _require_repo(repo, "gitlab")
    pid = _gl_project_id(repo)
    headers = _gl_headers(token)
    base = _gl_base()
    data = await _request("GET", f"{base}/api/v4/projects/{pid}/pipelines",
                          headers=headers, ctx=ctx, call_id=call_id,
                          params={"per_page": min(limit, 100)})
    out: list[dict[str, Any]] = []
    for p in data if isinstance(data, list) else []:
        source = p.get("source", "")      # push, web, schedule, trigger, api...
        out.append({
            "source": repo,
            "ts": p.get("created_at"),
            "pipeline_id": p.get("id"),
            "ref": p.get("ref"),
            "actor": p.get("user", {}).get("username", "") if isinstance(p.get("user"), dict) else "",
            "source_type": source,
            "status": p.get("status", ""),
            "flagged": source in ("web", "api", "trigger"),
        })
        if len(out) >= limit:
            break
    return out


async def gl_secrets_scan(token: str, repo: str | None, limit: int, ctx: ToolContext, call_id: str) -> list[dict[str, Any]]:
    headers = _gl_headers(token)
    base = _gl_base()
    out: list[dict[str, Any]] = []
    if repo:
        pid = _gl_project_id(repo)
        data = await _request("GET", f"{base}/api/v4/projects/{pid}/secret_detection_findings",
                              headers=headers, ctx=ctx, call_id=call_id,
                              params={"per_page": min(limit, 100)})
        for f in data if isinstance(data, list) else []:
            out.append({
                "source": repo,
                "ts": f.get("created_at"),
                "status": f.get("status"),
                "severity": f.get("severity"),
                "url": f.get("blob_url") or f.get("location", {}).get("blob_url") if isinstance(f.get("location"), dict) else None,
                "flagged": True,
            })
        if out:
            return out[:limit]
    # Fallback: project/group CI/CD variables list (best-effort for secrets
    # stored as pipeline vars, mirrors the Azure DevOps strategy).
    if not repo:
        raise _ApiError("gitlab: secrets_scan needs repo=group/project.")
    pid = _gl_project_id(repo)
    try:
        data = await _request("GET", f"{base}/api/v4/projects/{pid}/variables",
                              headers=headers, ctx=ctx, call_id=call_id,
                              params={"per_page": min(limit, 100)})
    except _ApiError as e:
        raise _ApiError(
            "gitlab: no secret-detection findings and variables API "
            f"unavailable. Detail: {e}"
        )
    for v in data if isinstance(data, list) else []:
        out.append({
            "source": repo,
            "name": v.get("key"),
            "protected": v.get("protected"),
            "masked": v.get("masked"),
            "environment": v.get("environment_scope"),
            "flagged": True,
            "note": "GitLab CI/CD variable (not a scanned leak).",
        })
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_HANDLERS: dict[tuple[str, str], Any] = {
    ("github", "audit_log"): gh_audit_log,
    ("github", "repo_changes"): gh_repo_changes,
    ("github", "user_perms"): gh_user_perms,
    ("github", "pipeline_runs"): gh_pipeline_runs,
    ("github", "secrets_scan"): gh_secrets_scan,
    ("azure_devops", "audit_log"): azdo_audit_log,
    ("azure_devops", "repo_changes"): azdo_repo_changes,
    ("azure_devops", "user_perms"): azdo_user_perms,
    ("azure_devops", "pipeline_runs"): azdo_pipeline_runs,
    ("azure_devops", "secrets_scan"): azdo_secrets_scan,
    ("jira", "audit_log"): jira_audit_log,
    ("jira", "repo_changes"): jira_repo_changes,
    ("jira", "user_perms"): jira_user_perms,
    ("jira", "pipeline_runs"): jira_pipeline_runs,
    ("jira", "secrets_scan"): jira_secrets_scan,
    ("gitlab", "audit_log"): gl_audit_log,
    ("gitlab", "repo_changes"): gl_repo_changes,
    ("gitlab", "user_perms"): gl_user_perms,
    ("gitlab", "pipeline_runs"): gl_pipeline_runs,
    ("gitlab", "secrets_scan"): gl_secrets_scan,
}


# Module-level instance the registry can pick up for tool enumeration.
tool = DevOpsApiTool()
