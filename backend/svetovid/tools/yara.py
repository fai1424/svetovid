"""YARA tool wrapper (research item C15).

Pattern matcher for malware binaries / files. Runs in the ``svetovid/malware``
image. Used by G02 (binary triage), G08 (ransomware ID), G18 (CI artifact
scan). The agent can either use built-in rule sets (security-focused YARA
rules from Yara-Rules and Neo23x0/signature-base) or pass custom rules.

CLI shape::

    yara -r -m -s /opt/yara-rules/index.yar /evidence > /work/yara_hits.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


class YaraTool(Tool):
    name = "yara_scan"
    image = "svetovid/malware"
    description = (
        "Scan files for malware patterns using YARA rules. Returns rule name, "
        "matched file, and metadata (severity, ATT&CK tag, family). Uses "
        "bundled security rules; pass custom_rules to override."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {
                    "type": "string",
                    "description": "Subpath under /evidence to scan (file or dir).",
                },
                "rules_set": {
                    "type": "string",
                    "enum": ["security", "signature-base", "custom"],
                    "default": "security",
                    "description": "Which rule set: security (Yara-Rules), signature-base (Neo23x0), or custom (pass custom_rules).",
                },
                "custom_rules": {
                    "type": "string",
                    "description": "Inline YARA rules text (only used when rules_set='custom').",
                },
                "max_file_size_mb": {
                    "type": "number",
                    "default": 16,
                    "description": "Skip files larger than this (YARA is slow on huge files).",
                },
            },
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        sub = args.get("evidence_subpath") or ""
        rules_set = args.get("rules_set", "security")
        custom = args.get("custom_rules") or ""
        max_mb = int(args.get("max_file_size_mb", 16))

        # Build rules path
        if rules_set == "custom" and custom:
            rules_path = "/work/custom_rules.yar"
            local_rules = Path(ctx.output_dir) / "custom_rules.yar"
            local_rules.write_text(custom)
        elif rules_set == "signature-base":
            rules_path = "/opt/signature-base/yara"
        else:
            rules_path = "/opt/yara-rules/index.yar"

        out_file = "/work/yara_hits.txt"
        target = f"/evidence/{sub}".rstrip("/") if sub else "/evidence"
        cmd = [
            "yara",
            "-r",            # recursive
            "-m",            # print metadata
            "-s",            # print strings (truncated by our parser)
            f"-l{max_mb * 1024 * 1024}",  # skip-larger-than
            rules_path,
            target,
        ]

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

        stdout_lines: list[str] = []
        def on_stdout(line: str) -> None:
            stdout_lines.append(line)
            ctx.bus.publish(E.tool_stdout(ctx.investigation_id, call_id, line))

        def on_stderr(line: str) -> None:
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, line))

        try:
            res = await run_in_sandbox(
                image=self.image or "",
                command=cmd,
                evidence_path=ctx.evidence_path,
                output_dir=ctx.output_dir,
                investigation_id=ctx.investigation_id,
                on_stdout=on_stdout,
                on_stderr=on_stderr,
                timeout_s=1200,
                mem_limit="4g",
                host_fallback=False,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(ctx.investigation_id, f"yara failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None, summary=f"yara failed: {e}",
            )

        # Parse YARA's text output:
        # <rule_name> <file_path> [<metadata k=v> ...]
        hits: list[dict[str, Any]] = []
        for line in stdout_lines:
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            rule, path = parts[0], parts[1]
            meta = {}
            if len(parts) > 2:
                # metadata is in [k=v k=v ...] format when -m is used
                meta_str = parts[2].strip().strip("[]")
                for kv in meta_str.split():
                    if "=" in kv:
                        k, _, v = kv.partition("=")
                        meta[k] = v
            hits.append({"rule": rule, "file": path, "meta": meta})
        hits = hits[:500]
        summary = f"YARA: {len(hits)} hit(s) (rules_set={rules_set})"

        output_hash = None
        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s, output_hash,
        ))
        ctx.bus.publish(E.agent_observation(ctx.investigation_id, tool=self.name, summary=summary))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": {**args, "custom_rules": "[redacted]" if custom else ""},
            "exit_code": res.exit_code, "duration_s": res.duration_s,
            "output_hash": output_hash, "ts": E._now_iso(),
        }))

        # Persist this tool call to the case DB and emit an IOC per matched
        # file (hash when YARA's metadata carries one, else the filename as a
        # lower-confidence indicator). Feeds the IoC tab + STIX export.
        from ._reporting import record_tool_call_db
        await record_tool_call_db(
            call_id=call_id, investigation_id=ctx.investigation_id,
            tool=self.name, args=args, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
        )
        _emit_yara_iocs(ctx.bus, ctx.investigation_id, hits)

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash, output_path=None,
            summary=summary, data={"hits": hits},
        )


def _emit_yara_iocs(bus, investigation_id: str, hits: list[dict[str, Any]]) -> None:
    """Emit a ``report.ioc`` for each YARA-matched file.

    Rule metadata may carry a SHA/MD5 (some authors embed ``hash=``); when it
    does we use that as the indicator. Otherwise we fall back to the matched
    filename as a low-confidence indicator so the match still surfaces in the
    IoC tab. YARA's ATT&CK tags (when present) ride along as ``mitre_tags``.
    """
    from ..governance.ioc_store import extract_iocs_from_text
    max_events = 500
    emitted = 0
    for hit in hits[:max_events]:
        if emitted >= max_events:
            break
        meta = hit.get("meta") or {}
        file_path = str(hit.get("file") or "")
        rule = str(hit.get("rule") or "")
        # Prefer an explicit hash in metadata; else mine the rule name + meta.
        ioc_type: str | None = None
        ioc_value: str | None = None
        for mk, mv in (meta.items() if isinstance(meta, dict) else []):
            if str(mv) and any(k in str(mk).lower() for k in ("sha256", "sha1", "md5", "hash")):
                inds = extract_iocs_from_text(str(mv))
                if inds:
                    ioc_type, ioc_value = inds[0]["ioc_type"], inds[0]["value"]
                    break
        if not ioc_value:
            # Filename fallback: surface the matched artifact even without hash.
            ioc_type, ioc_value = "filename", file_path.split("/")[-1] or file_path
        if not ioc_value:
            continue
        # ATT&CK tags: YARA rules sometimes put them in metadata as attack.tXXXX.
        tags = [str(v) for k, v in (meta.items() if isinstance(meta, dict) else [])
                if "attack" in str(k).lower() or "mitre" in str(k).lower()]
        bus.publish(E.report_ioc(
            investigation_id=investigation_id,
            ioc_type=ioc_type,
            value=ioc_value,
            context=f"yara rule '{rule}' matched {file_path}",
            confidence=0.5,
            mitre_tags=tags or None,
        ))
        emitted += 1


tool = YaraTool()
