"""AWS cloud-incident audit tool (research item C16 / cloud cluster).

An API-based (non-sandboxed) tool that audits an AWS account directly for signs
of a cloud compromise. Unlike the disk-image tools (chainsaw, eztools,
volatility), this one talks to the AWS control plane over HTTPS using
credentials read from the standard AWS environment variables — there is no
Docker sandbox because the evidence lives in CloudTrail / GuardDuty / VPC Flow
Logs, not on a mounted image.

One tool, ``aws_audit``, takes an ``operation`` selector plus optional
``region`` and ``time_range`` args:

  operation           AWS API(s) consulted                                  surfaces
  ------------------  ----------------------------------------------------  --------
  cloudtrail_events   CloudTrail ``LookupEvents``                           API-call timeline
  guardduty_findings  GuardDuty ``ListDetectors``→``ListFindings``→``GetFindings``  detection alerts
  iam_changes         CloudTrail ``LookupEvents`` filtered to iam.amazonaws.com  privilege escalation
  s3_access           CloudTrail ``LookupEvents`` filtered to s3.amazonaws.com    data exfil (GetObject / DeleteBucket / PutAcl)
  vpc_flows           CloudWatch Logs ``FilterLogEvents`` on a VPC flow-log   network anomalies (REJECT, unusual peers)
                      log group (auto-discovered or supplied via ``log_group``)
  cloudwatch_alarms   CloudWatch ``DescribeAlarms`` (StateValue=ALARM)        active alarms

Credentials are read from the standard AWS environment variables:

  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
  (AWS_SESSION_TOKEN optional, for STS/temporary credentials)

Signing: AWS SigV4. To keep the dependency footprint light we implement a
minimal SigV4 signer on top of ``httpx`` (no ``boto3`` dependency). If ``boto3``
happens to be importable we'll still use the httpx path — it's the same wire
protocol and one less runtime concern.

If the credentials are missing the tool returns a clear, non-fatal error result
(exit_code=2) so the ReAct agent can adapt (e.g. pivot to a different data
source, or report that the AWS integration is unconfigured) instead of raising.
The tool follows the same event-publishing pattern as the other API wrappers
(``tool.start`` / ``tool.stderr`` / ``tool.end`` / ``agent.action`` /
``agent.observation`` / ``provenance.recorded``) with ``sandboxed=False`` and
``image=None``.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import re
import time
from typing import Any
from urllib.parse import urlencode, urlparse

from ...agent import events as E
from ..base import Tool, ToolContext, ToolResult

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

OPERATIONS = (
    "cloudtrail_events",
    "guardduty_findings",
    "iam_changes",
    "s3_access",
    "vpc_flows",
    "cloudwatch_alarms",
)

# X-Amz-Target headers for the JSON-protocol AWS services we call.
_CLOUDTRAIL_TARGET = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"
_GUARDDUTY_TARGETS = {
    "list_detectors": "GuardDutyV2.ListDetectors",
    "list_findings": "GuardDutyV2.ListFindings",
    "get_findings": "GuardDutyV2.GetFindings",
}
_LOGS_TARGET = "Logs_20140328.FilterLogEvents"
_LOGS_LIST_TARGET = "Logs_20140328.DescribeLogGroups"

# Event-name substrings that, when seen in CloudTrail, are strong compromise /
# privilege-escalation / data-exfil / anti-forensics signals. We flag any event
# whose EventName contains one of these (case-insensitive) so the agent gets a
# "X flagged suspicious" summary line, mirroring devops_audit's behavior.
RISKY_EVENT_HINTS = (
    "delete", "create", "attach", "detach", "put", "policy", "role", "user",
    "permission", "admin", "grant", "accesskey", "loginprofile", "password",
    "mfa", "bucket", "acl", "cors", "assume", "token", "secret", "impersonat",
    "disable", "deletemfa", "createmfa", "changepassword", "putrolepolicy",
    "attachrolepolicy", "assumeRole", "getobject",
)

# A VPC flow-log line is whitespace-separated. The classic format column order
# (version 2) is:
#   version account-id interface-id srcaddr dstaddr srcport dstport protocol
#   packets start end action log-status
# We extract the fields most useful for compromise triage. Field names indexed
# by position; flow-log formats can vary, so we guard every access.
_FLOW_FIELDS = (
    "version", "account_id", "interface_id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "start", "end",
    "action", "log_status",
)


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


class AwsApiTool(Tool):
    """Read-only AWS cloud-incident audit tool.

    Talks directly to CloudTrail / GuardDuty / CloudWatch Logs / CloudWatch
    using SigV4-signed HTTPS calls with credentials from the standard AWS
    environment variables. Runs on the host (no Docker) and returns structured
    rows the ReAct agent can reason over.
    """

    name = "aws_audit"
    image = None                # API-based, runs on host
    description = (
        "Audit an AWS account for a cloud compromise via read-only API calls. "
        "Authenticates with credentials from the AWS_ACCESS_KEY_ID / "
        "AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION environment variables. "
        "Operations: cloudtrail_events (API-call timeline), guardduty_findings "
        "(detection alerts), iam_changes (privilege escalation), s3_access "
        "(data exfil via S3), vpc_flows (network anomalies), cloudwatch_alarms "
        "(active alarms). Optional region and time_range (e.g. '24h', '7d') "
        "scope each query. If credentials are unset the tool returns a clear "
        "error so you can adapt."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": list(OPERATIONS),
                    "description": (
                        "cloudtrail_events = CloudTrail API-call timeline; "
                        "guardduty_findings = GuardDuty detection alerts; "
                        "iam_changes = CloudTrail filtered to iam.amazonaws.com "
                        "(privilege escalation); s3_access = CloudTrail filtered "
                        "to s3.amazonaws.com (data exfil); vpc_flows = VPC flow "
                        "log events (network anomalies); cloudwatch_alarms = "
                        "active CloudWatch alarms."
                    ),
                },
                "region": {
                    "type": "string",
                    "description": (
                        "AWS region to query (default: AWS_DEFAULT_REGION env "
                        "var, or us-east-1). For multi-region services like "
                        "CloudTrail/IAM, us-east-1 returns global activity."
                    ),
                },
                "time_range": {
                    "type": "string",
                    "description": (
                        "Lookback window: 'Nh' (hours), 'Nd' (days), or an "
                        "ISO8601 'start/end' pair. Default '24h'. Applied to "
                        "CloudTrail and VPC flow queries where supported."
                    ),
                },
                "log_group": {
                    "type": "string",
                    "description": (
                        "CloudWatch Logs log group for vpc_flows (e.g. "
                        "'vpc-flow-logs'). If omitted, the tool auto-discovers "
                        "the first log group whose name contains 'flow'."
                    ),
                },
                "limit": {
                    "type": "number",
                    "description": "Max rows to return (default 50).",
                },
            },
            "required": ["operation"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        call_id = ctx.make_call_id()
        operation = str(args.get("operation", "")).strip()
        region = (str(args.get("region", "")).strip()
                  or os.environ.get("AWS_DEFAULT_REGION", "").strip()
                  or os.environ.get("AWS_REGION", "").strip()
                  or "us-east-1")
        time_range = str(args.get("time_range", "")).strip() or None
        log_group = str(args.get("log_group", "")).strip() or None
        try:
            limit = int(args.get("limit") or 50)
        except (TypeError, ValueError):
            limit = 50

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

        # ---- resolve credentials ----
        creds = _resolve_creds()
        if creds is None:
            msg = (
                "aws_audit: AWS credentials are not set. Export "
                "AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and "
                "AWS_DEFAULT_REGION (AWS_SESSION_TOKEN optional, for STS/"
                "temporary credentials) to enable AWS compromise investigation. "
                "The IAM/CloudTrail/S3 identity needs read-only permissions "
                "(cloudtrail:LookupEvents, guardduty:List*/Get*, "
                "logs:FilterLogEvents, cloudwatch:DescribeAlarms)."
            )
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.agent_observation(
                ctx.investigation_id, tool=self.name, summary=msg,
            ))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 2, 0.0, None))
            ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
                "tool": self.name, "image": self.image, "args": args,
                "exit_code": 2, "duration_s": 0.0, "output_hash": None,
                "ts": E._now_iso(),
            }))
            return _result(call_id, self.name, 2, 0.0, msg,
                           {"error": msg, "missing_credentials": True})

        # ---- httpx availability ----
        try:
            import httpx
        except ImportError as e:  # pragma: no cover - httpx is a core dep
            msg = f"aws_audit: httpx unavailable ({e})"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg, {"error": msg})

        tr = _parse_time_range(time_range)

        ctx.bus.publish(E.tool_stdout(
            ctx.investigation_id, call_id,
            f"[aws_audit] {operation} region={region} "
            f"window={_fmt_range(tr)} limit={limit}",
        ))

        # ---- dispatch ----
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                if operation == "cloudtrail_events":
                    rows, summary = await self._cloudtrail_events(
                        client, creds, region, tr, limit,
                        attribute=None,
                    )
                elif operation == "iam_changes":
                    rows, summary = await self._cloudtrail_events(
                        client, creds, region, tr, limit,
                        attribute=("EventSource", "iam.amazonaws.com"),
                    )
                elif operation == "s3_access":
                    rows, summary = await self._cloudtrail_events(
                        client, creds, region, tr, limit,
                        attribute=("EventSource", "s3.amazonaws.com"),
                    )
                elif operation == "guardduty_findings":
                    rows, summary = await self._guardduty_findings(
                        client, creds, region, tr, limit,
                    )
                elif operation == "vpc_flows":
                    rows, summary = await self._vpc_flows(
                        client, creds, region, tr, log_group, limit,
                    )
                elif operation == "cloudwatch_alarms":
                    rows, summary = await self._cloudwatch_alarms(
                        client, creds, region, limit,
                    )
                else:  # pragma: no cover - guarded above
                    raise ValueError(f"unknown operation {operation!r}")
        except httpx.ConnectError as e:
            msg = f"AWS API unreachable: {e}"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg,
                           {"error": msg, "operation": operation})
        except httpx.TimeoutException:
            msg = f"AWS API timed out ({operation})"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg,
                           {"error": msg, "operation": operation})
        except httpx.HTTPError as e:
            msg = f"AWS API error: {e}"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg,
                           {"error": msg, "operation": operation})
        except _AwsApiError as e:
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, str(e)))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), str(e),
                           {"error": str(e), "operation": operation})
        except Exception as e:
            msg = f"aws_audit {operation} failed: {e}"
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 1, _dur(t0), None))
            return _result(call_id, self.name, 1, _dur(t0), msg,
                           {"error": msg, "operation": operation})

        # ---- success ----
        flagged = [r for r in rows if r.get("flagged")]
        summary_full = (
            f"{operation}: {len(rows)} row(s)"
            + (f", {len(flagged)} flagged suspicious" if flagged else "")
            + f" in {region}"
        )
        data: dict[str, Any] = {
            "operation": operation,
            "region": region,
            "time_range": _fmt_range(tr),
            "rows": rows,
            "flagged_count": len(flagged),
        }
        ctx.bus.publish(E.tool_stdout(ctx.investigation_id, call_id, summary_full))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary_full,
        ))
        ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 0, _dur(t0), None))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": args,
            "exit_code": 0, "duration_s": _dur(t0), "output_hash": None,
            "ts": E._now_iso(),
        }))
        return _result(call_id, self.name, 0, _dur(t0), summary_full, data)

    # -- per-operation handlers -------------------------------------------

    async def _cloudtrail_events(
        self, client, creds, region: str, tr, limit: int,
        attribute: tuple[str, str] | None,
    ) -> tuple[list[dict[str, Any]], str]:
        """CloudTrail LookupEvents — the API-call timeline backbone.

        ``attribute`` optionally filters by a LookupAttribute (e.g.
        ``("EventSource", "iam.amazonaws.com")``).
        """
        body: dict[str, Any] = {"MaxResults": min(limit, 50)}
        if attribute:
            body["LookupAttributes"] = [
                {"AttributeKey": attribute[0], "AttributeValue": attribute[1]}
            ]
        if tr:
            body["StartTime"], body["EndTime"] = tr
        payload = await self._json_call(
            client, creds, "cloudtrail", region,
            url=f"https://cloudtrail.{region}.amazonaws.com/",
            target=_CLOUDTRAIL_TARGET,
            body=body,
        )
        events = payload.get("Events", []) if isinstance(payload, dict) else []
        rows = [self._shape_cloudtrail_event(e) for e in events]
        label = f" (filtered to {attribute[1]})" if attribute else ""
        return rows, f"{len(rows)} CloudTrail event(s){label} in {region}"

    async def _guardduty_findings(
        self, client, creds, region: str, tr, limit: int,
    ) -> tuple[list[dict[str, Any]], str]:
        """GuardDuty: discover a detector, list finding IDs, then fetch them."""
        # 1) ListDetectors (GET, no body).
        detectors = await self._json_call(
            client, creds, "guardduty", region,
            url=f"https://guardduty.{region}.amazonaws.com/detector",
            target=_GUARDDUTY_TARGETS["list_detectors"],
            body=None, method="GET",
        )
        detector_ids = detectors.get("DetectorIds", []) if isinstance(detectors, dict) else []
        if not detector_ids:
            return [], (f"GuardDuty is not enabled in {region} (no detector); "
                        "enable it or query a different region")
        detector_id = detector_ids[0]

        # 2) ListFindings — get finding IDs (optionally filtered by severity).
        list_body: dict[str, Any] = {"MaxResults": min(limit, 50)}
        listf = await self._json_call(
            client, creds, "guardduty", region,
            url=f"https://guardduty.{region}.amazonaws.com/detector/{detector_id}/findings",
            target=_GUARDDUTY_TARGETS["list_findings"],
            body=list_body,
        )
        finding_ids = listf.get("FindingIds", []) if isinstance(listf, dict) else []
        if not finding_ids:
            return [], f"0 GuardDuty finding(s) in {region} (detector {detector_id[:8]}…)"

        # 3) GetFindings — fetch the full finding objects.
        getf = await self._json_call(
            client, creds, "guardduty", region,
            url=f"https://guardduty.{region}.amazonaws.com/detector/{detector_id}/findings",
            target=_GUARDDUTY_TARGETS["get_findings"],
            body={"FindingIds": finding_ids[:limit]},
        )
        findings = getf.get("Findings", []) if isinstance(getf, dict) else []
        rows = [self._shape_guardduty_finding(f) for f in findings]
        return rows, f"{len(rows)} GuardDuty finding(s) in {region}"

    async def _vpc_flows(
        self, client, creds, region: str, tr, log_group: str | None, limit: int,
    ) -> tuple[list[dict[str, Any]], str]:
        """CloudWatch Logs FilterLogEvents over a VPC flow-log log group."""
        group = log_group
        if not group:
            group = await self._discover_flow_log_group(client, creds, region)
            if not group:
                return [], (
                    "no VPC flow-log log group found in "
                    f"{region}; pass log_group explicitly or enable VPC flow logs"
                )

        body: dict[str, Any] = {
            "logGroupName": group,
            "limit": min(limit, 1000),
            # FilterLogEvents requires a non-empty filterPattern to be set; " "
            # matches all events. We flag REJECTs / unusual peers client-side.
            "filterPattern": " ",
        }
        if tr:
            body["startTime"] = int(tr[0] * 1000)
            body["endTime"] = int(tr[1] * 1000)
        payload = await self._json_call(
            client, creds, "logs", region,
            url=f"https://logs.{region}.amazonaws.com/",
            target=_LOGS_TARGET,
            body=body,
        )
        events = payload.get("events", []) if isinstance(payload, dict) else []
        rows = [self._shape_flow_event(e) for e in events]
        # Keep only the most interesting rows (REJECTs first) up to the limit.
        rows.sort(key=lambda r: (0 if r.get("action") == "REJECT" else 1))
        rows = rows[:limit]
        return rows, f"{len(rows)} VPC flow-log event(s) from {group} in {region}"

    async def _cloudwatch_alarms(
        self, client, creds, region: str, limit: int,
    ) -> tuple[list[dict[str, Any]], str]:
        """CloudWatch DescribeAlarms (Query/XML protocol) — StateValue=ALARM."""
        form = urlencode({
            "Action": "DescribeAlarms",
            "Version": "2010-08-01",
            "StateValue": "ALARM",
            "MaxRecords": min(limit, 100),
        })
        resp = await self._signed_request(
            client, creds, "monitoring", region,
            method="POST",
            url=f"https://monitoring.{region}.amazonaws.com/",
            body=form.encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        alarms = _parse_describe_alarms(resp.content)
        rows = [self._shape_alarm(a) for a in alarms[:limit]]
        return rows, f"{len(rows)} CloudWatch alarm(s) (ALARM) in {region}"

    async def _discover_flow_log_group(
        self, client, creds, region: str,
    ) -> str | None:
        """Return the first CloudWatch Logs log group whose name looks flow-y."""
        payload = await self._json_call(
            client, creds, "logs", region,
            url=f"https://logs.{region}.amazonaws.com/",
            target=_LOGS_LIST_TARGET,
            body={"limit": 50},
        )
        groups = payload.get("logGroups", []) if isinstance(payload, dict) else []
        for g in groups:
            name = (g.get("logGroupName") or "").lower()
            if "flow" in name or "vpc" in name:
                return g.get("logGroupName")
        return None

    # -- low-level SigV4 HTTP --------------------------------------------

    async def _json_call(
        self, client, creds, service: str, region: str, *,
        url: str, target: str, body: dict[str, Any] | None,
        method: str = "POST",
    ) -> dict[str, Any]:
        """POST a JSON body with the AWS JSON-protocol ``X-Amz-Target`` header
        and return the parsed JSON response."""
        payload = json.dumps(body or {}, separators=(",", ":")).encode("utf-8")
        resp = await self._signed_request(
            client, creds, service, region,
            method=method,
            url=url,
            body=b"" if body is None and method == "GET" else payload,
            headers={
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": target,
            },
        )
        return _check_aws_json(resp)

    async def _signed_request(
        self, client, creds, service: str, region: str, *,
        method: str, url: str, body: bytes, headers: dict[str, str],
    ):
        """Add an AWS SigV4 signature to ``headers`` and fire the request."""
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"
        query = parsed.query

        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        # Canonical headers — must include host + x-amz-date (+ token if any).
        # host is sent by httpx automatically from the URL; we keep it in the
        # canonical computation only (not the outgoing dict) so httpx owns it.
        canon: dict[str, str] = {"host": host, "x-amz-date": amz_date}
        if creds["session_token"]:
            canon["x-amz-security-token"] = creds["session_token"]
        for k, v in headers.items():
            canon[k.lower()] = str(v).strip()
        sorted_items = sorted(canon.items())
        canonical_headers = "".join(f"{k}:{v.strip()}\n" for k, v in sorted_items)
        signed_headers = ";".join(k for k, _ in sorted_items)

        payload_hash = _sha256_hex(body)
        canonical_request = "\n".join([
            method.upper(),
            _canonical_uri(path),
            _canonical_query(query),
            canonical_headers,
            signed_headers,
            payload_hash,
        ])

        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            _sha256_hex(canonical_request.encode("utf-8")),
        ])

        k_signing = _derive_signing_key(
            creds["secret_key"], date_stamp, region, service)
        signature = hmac.new(
            k_signing, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        authorization = (
            "AWS4-HMAC-SHA256 "
            f"Credential={creds['access_key']}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )

        out_headers = dict(headers)
        out_headers["X-Amz-Date"] = amz_date
        if creds["session_token"]:
            out_headers["X-Amz-Security-Token"] = creds["session_token"]
        out_headers["Authorization"] = authorization

        return await client.request(
            method, url, headers=out_headers, content=body,
        )

    # -- row shapers ------------------------------------------------------

    @staticmethod
    def _shape_cloudtrail_event(e: dict[str, Any]) -> dict[str, Any]:
        # The ``CloudTrailEvent`` field is a JSON string with the real detail.
        detail: dict[str, Any] = {}
        raw = e.get("CloudTrailEvent")
        if raw:
            try:
                detail = json.loads(raw)
            except Exception:
                detail = {}
        event_name = e.get("EventName") or detail.get("eventName") or ""
        flagged = _is_risky(event_name) or bool(detail.get("errorCode"))
        return {
            "event_time": e.get("EventTime"),
            "event_name": event_name,
            "event_source": e.get("EventSource") or detail.get("eventSource"),
            "username": e.get("Username") or detail.get("userIdentity", {}).get("arn"),
            "source_ip": detail.get("sourceIPAddress"),
            "user_agent": detail.get("userAgent"),
            "error_code": detail.get("errorCode"),
            "aws_account_id": detail.get("recipientAccountId") or e.get("CloudTrailEvent") and "",
            "resources": [
                {"type": r.get("ResourceType"), "name": r.get("ResourceName")}
                for r in (e.get("Resources") or [])
            ],
            "flagged": flagged,
        }

    @staticmethod
    def _shape_guardduty_finding(f: dict[str, Any]) -> dict[str, Any]:
        sev = (f.get("Severity") or 0)
        # GuardDuty may return severity as a float (0.0–8.0+) or a label.
        sev_label = f.get("SeverityLabel")
        flagged = _sev_high(sev) or (sev_label in {"HIGH", "CRITICAL"})
        svc = f.get("Service") or {}
        action = svc.get("Action") or {}
        return {
            "id": f.get("Id"),
            "type": f.get("Type"),
            "title": f.get("Title"),
            "severity": sev_label or sev,
            "description": (f.get("Description") or "")[:300],
            "created_at": f.get("CreatedAt"),
            "updated_at": f.get("UpdatedAt"),
            "account_id": f.get("AccountId"),
            "resource_type": (f.get("Resource") or {}).get("ResourceType"),
            "resource": _flatten_resource(f.get("Resource") or {}),
            "action_type": action.get("ActionType"),
            "action": _flatten_action(action),
            "flagged": flagged,
        }

    @staticmethod
    def _shape_flow_event(e: dict[str, Any]) -> dict[str, Any]:
        msg = e.get("message") or ""
        parts = msg.split()
        fields: dict[str, Any] = {}
        for i, name in enumerate(_FLOW_FIELDS):
            if i < len(parts):
                fields[name] = parts[i]
        action = fields.get("action", "").upper()
        flagged = action == "REJECT"
        return {
            "timestamp": e.get("timestamp"),
            "log_group": e.get("logGroup"),
            "log_stream": e.get("logStream"),
            "srcaddr": fields.get("srcaddr"),
            "dstaddr": fields.get("dstaddr"),
            "srcport": _as_int(fields.get("srcport")),
            "dstport": _as_int(fields.get("dstport")),
            "protocol": fields.get("protocol"),
            "packets": _as_int(fields.get("packets")),
            "action": action,
            "log_status": fields.get("log_status"),
            "flagged": flagged,
        }

    @staticmethod
    def _shape_alarm(a: dict[str, Any]) -> dict[str, Any]:
        return {
            "alarm_name": a.get("AlarmName"),
            "state": a.get("StateValue"),
            "state_reason": (a.get("StateReason") or "")[:200],
            "state_updated": a.get("StateUpdatedTimestamp"),
            "namespace": a.get("Namespace"),
            "metric_name": a.get("MetricName"),
            "actions": a.get("AlarmActions") or [],
            "flagged": (a.get("StateValue") == "ALARM"),
        }


# ---------------------------------------------------------------------------
# SigV4 helpers
# ---------------------------------------------------------------------------


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _derive_signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _canonical_uri(path: str) -> str:
    # URI-encode each path segment but keep the slashes. For the services we
    # call the paths are simple (/  /detector/<id>/findings) so this is light.
    if not path:
        return "/"
    return path


def _canonical_query(query: str) -> str:
    if not query:
        return ""
    # query is "k=v&k2=v2"; sort by key, re-encode with RFC3986 unreserved set.
    pairs: list[tuple[str, str]] = []
    for part in query.split("&"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        pairs.append((_aws_uri_encode(k), _aws_uri_encode(v)))
    pairs.sort()
    return "&".join(f"{k}={v}" for k, v in pairs)


def _aws_uri_encode(s: str) -> str:
    # AWS SigV4: encode everything except A-Z a-z 0-9 - _ . ~
    safe = "-_.~"
    out = []
    for ch in s:
        if ch.isalnum() or ch in safe:
            out.append(ch)
        else:
            out.append(f"%{ord(ch):02X}")
    return "".join(out)


# ---------------------------------------------------------------------------
# Response handling
# ---------------------------------------------------------------------------


def _check_aws_json(resp) -> dict[str, Any]:
    """Validate an AWS JSON-protocol response and surface errors clearly."""
    if resp.status_code >= 400:
        snippet = resp.text[:300] if hasattr(resp, "text") else ""
        raise _AwsApiError(
            "aws_http",
            f"AWS returned HTTP {resp.status_code}: {snippet}",
        )
    try:
        return resp.json()
    except Exception:
        raise _AwsApiError(
            "aws_http",
            f"AWS returned non-JSON: {getattr(resp, 'text', '')[:200]}",
        )


def _parse_describe_alarms(xml_bytes: bytes) -> list[dict[str, Any]]:
    """Parse a CloudWatch DescribeAlarms XML response into flat alarm dicts.

    CloudWatch uses the Query protocol (XML). We strip the AWS namespace and
    walk the ``MetricAlarms`` members defensively.
    """
    import xml.etree.ElementTree as ET
    alarms: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_bytes)
    except Exception:
        return alarms
    # Namespace-agnostic: match on local tag name.
    for member in _iter_tag(root, "member"):
        alarm: dict[str, Any] = {}
        for child in member:
            tag = _local(child.tag)
            if len(child) == 0:
                alarm[tag] = child.text
            elif tag in ("AlarmActions", "OKActions", "InsufficientDataActions"):
                alarm[tag] = [c.text for c in child if _local(c.tag) == "member"]
        alarms.append(alarm)
    return alarms


def _iter_tag(root, name: str):
    for el in root.iter():
        if _local(el.tag) == name:
            yield el


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


# ---------------------------------------------------------------------------
# Credential + time-range resolution
# ---------------------------------------------------------------------------


def _resolve_creds() -> dict[str, str] | None:
    access_key = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    session_token = (os.environ.get("AWS_SESSION_TOKEN")
                     or os.environ.get("AWS_SECURITY_TOKEN") or "").strip()
    if not access_key or not secret_key:
        return None
    return {
        "access_key": access_key,
        "secret_key": secret_key,
        "session_token": session_token,
    }


def _parse_time_range(spec: str | None) -> tuple[float, float] | None:
    """Parse a lookback spec into an (start_epoch, end_epoch) pair (epoch secs).

    Accepted forms:
      - "Nh" / "Nd"        → last N hours / days
      - "start_iso/end_iso" → explicit window
      - None               → None (let the service default apply)
    """
    if not spec:
        return None
    spec = spec.strip()
    m = re.fullmatch(r"(\d+)([hHdDmM])", spec)
    now = datetime.datetime.now(datetime.timezone.utc)
    if m:
        n = int(m.group(1))
        unit = m.group(2).lower()
        if unit == "h":
            start = now - datetime.timedelta(hours=n)
        elif unit == "d":
            start = now - datetime.timedelta(days=n)
        else:  # minutes
            start = now - datetime.timedelta(minutes=n)
        return (start.timestamp(), now.timestamp())
    if "/" in spec:
        a, b = spec.split("/", 1)
        try:
            s = _parse_iso(a)
            e = _parse_iso(b)
            return (s.timestamp(), e.timestamp())
        except Exception:
            return None
    # Bare ISO string → from then until now.
    try:
        s = _parse_iso(spec)
        return (s.timestamp(), now.timestamp())
    except Exception:
        return None


def _parse_iso(s: str) -> datetime.datetime:
    s = s.strip()
    # Accept a trailing Z and fractional seconds.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.datetime.fromisoformat(s)


def _fmt_range(tr) -> str:
    if not tr:
        return "default"
    return f"{int(tr[0])}..{int(tr[1])}"


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def _is_risky(name: str) -> bool:
    low = (name or "").lower()
    return any(h.lower() in low for h in RISKY_EVENT_HINTS)


def _sev_high(sev: Any) -> bool:
    try:
        return float(sev) >= 4.0
    except (TypeError, ValueError):
        return False


def _flatten_resource(resource: dict[str, Any]) -> dict[str, Any]:
    """Pull the most useful fields out of a GuardDuty Resource block."""
    details = resource.get("InstanceDetails") or resource.get("S3BucketDetails") \
        or resource.get("AccessKeyDetails") or {}
    if isinstance(details, list) and details:
        details = details[0]
    return {
        "type": resource.get("ResourceType"),
        "detail": details if isinstance(details, dict) else {},
    }


def _flatten_action(action: dict[str, Any]) -> dict[str, Any]:
    """Summarize a GuardDuty Action (network / API / port-probe)."""
    out: dict[str, Any] = {"type": action.get("ActionType")}
    for key in ("NetworkConnectionAction", "AwsApiCallAction",
                "PortProbeAction", "DnsRequestAction"):
        if action.get(key):
            out[key] = action[key]
            break
    return out


def _as_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _result(call_id: str, tool: str, exit_code: int, dur: float,
            summary: str, data: dict[str, Any]) -> ToolResult:
    return ToolResult(
        call_id=call_id, tool=tool, exit_code=exit_code, duration_s=dur,
        output_hash=None, output_path=None, summary=summary, data=data,
    )


def _dur(t0: float) -> float:
    return round(time.monotonic() - t0, 3)


class _AwsApiError(Exception):
    """An AWS API returned an error envelope or HTTP failure."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind


# Module-level instance so the goal and any registry can pick it up.
tool = AwsApiTool()
