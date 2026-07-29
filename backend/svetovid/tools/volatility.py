"""Volatility 3 tool wrapper (research item C13).

The de-facto memory forensics framework. Wraps ``vol`` (Volatility 3) inside
the ``svetovid/volatility`` image. Used by G02 (memory malware hunt) and G06
(dedicated memory forensics goal).

CLI shape::

    vol -f /evidence/image.raw <plugin> --output-format jsonl -r json
    # examples: pslist, malfind, netscan, handles, dlllist, cmdline, svcscan

The agent picks plugins based on what it's looking for. We expose a single
``run_plugin`` tool with the plugin name as an arg — flat schema, LLM-friendly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


# Plugins the LLM is allowed to call. Whitelisted for safety — Vol3 has 60+
# plugins; exposing all of them bloats the tool schema and risks the LLM
# picking irrelevant ones. Add to this list as goals demand.
ALLOWED_PLUGINS: dict[str, str] = {
    "pslist": "List active processes (EPROCESS double-linked list).",
    "psscan": "Pool-scan for hidden/terminated processes (finds DKOM hides).",
    "cmdline": "Process command lines.",
    "dlllist": "Loaded DLLs per process.",
    "handles": "Process handles (files, keys, mutexes, events).",
    "malfind": "Detect code injection (RWX pages with MZ/PE headers).",
    "netscan": "Network connections (pool-scan _ADDRESS_OBJECT / _TCP_ENDPOINT).",
    "modules": "Loaded kernel modules.",
    "modscan": "Pool-scan for unloaded/hidden kernel modules.",
    "callbacks": "Kernel callback routines (rootkit hook detection).",
    "svcscan": "Windows services.",
    "filescan": "Pool-scan for FILE_OBJECTs.",
    "envars": "Process environment variables.",
    "hashdump": "Extract NTLM password hashes from LSASS (SAM/SECURITY hive).",
    "lsadump": "Extract LSA secrets.",
    "hivelist": "List registry hives in memory.",
    "printkey": "Read a registry key (use args: key='HKLM\\Software\\...').",
}


class VolatilityTool(Tool):
    name = "volatility"
    image = "svetovid/volatility"
    description = (
        "Run a Volatility 3 memory-forensics plugin on a memory image. "
        "Returns structured JSON output. Choose plugins based on the question: "
        "pslist/psscan for process hiding, malfind for code injection, "
        "netscan for network connections, hashdump for credentials."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "plugin": {
                    "type": "string",
                    "enum": list(ALLOWED_PLUGINS.keys()),
                    "description": "Volatility 3 plugin name.",
                },
                "image_subpath": {
                    "type": "string",
                    "description": "Subpath under /evidence to the memory image (default: auto-detect *.raw/*.lime/*.vmem).",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Optional plugin-specific args (e.g. 'key=HKLM\\\\Software\\\\Microsoft' for printkey).",
                },
            },
            "required": ["plugin"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        plugin = args.get("plugin", "")
        if plugin not in ALLOWED_PLUGINS:
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"plugin {plugin!r} not in allowed list: {list(ALLOWED_PLUGINS)}",
            )

        sub = args.get("image_subpath") or ""
        extra = args.get("extra_args") or ""

        # Build the vol command. Output goes to a per-call JSON file.
        out_file = f"/work/vol3_{plugin}.jsonl"
        cmd = [
            "vol", "-f", f"/evidence/{sub}".rstrip("/") if sub else "/evidence/image.raw",
            plugin,
            "--output-format", "jsonl",
            "-r", "json",
        ]
        if extra:
            cmd.extend(extra.split())

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

        def on_stdout(line: str) -> None:
            ctx.bus.publish(E.tool_stdout(ctx.investigation_id, call_id, line))

        def on_stderr(line: str) -> None:
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, line))

        try:
            # Vol3 can be slow on large memory images; generous timeout.
            res = await run_in_sandbox(
                image=self.image or "",
                command=cmd,
                evidence_path=ctx.evidence_path,
                output_dir=ctx.output_dir,
                investigation_id=ctx.investigation_id,
                on_stdout=on_stdout,
                on_stderr=on_stderr,
                timeout_s=1800,
                mem_limit="8g",   # Vol3 needs more RAM for big images
                host_fallback=False,   # Vol3 rarely installed on host
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(ctx.investigation_id, f"volatility failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None, summary=f"volatility failed: {e}",
            )

        # Parse JSONL → structured rows
        local_out = Path(ctx.output_dir) / f"vol3_{plugin}.jsonl"
        rows: list[dict[str, Any]] = []
        summary = ""
        if local_out.exists():
            try:
                for line in local_out.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
                rows = rows[:1000]   # cap
                summary = f"vol3 {plugin}: {len(rows)} row(s)"
            except Exception as e:
                summary = f"vol3 {plugin} ran but JSONL parse failed: {e}"
        else:
            # Vol3 may have printed JSON to stdout if -o wasn't used; synthesize.
            summary = f"vol3 {plugin} exited {res.exit_code} (no JSON file produced)"

        output_hash = _hash_file(local_out)
        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s, output_hash,
        ))
        ctx.bus.publish(E.agent_observation(ctx.investigation_id, tool=self.name, summary=summary))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": args,
            "exit_code": res.exit_code, "duration_s": res.duration_s,
            "output_hash": output_hash, "ts": E._now_iso(),
        }))

        # Persist this tool call to the case DB.
        from ._reporting import record_tool_call_db
        await record_tool_call_db(
            call_id=call_id, investigation_id=ctx.investigation_id,
            tool=self.name, args=args, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
        )
        # Emit plugin-specific report events so the IoC / Timeline tabs and the
        # ATT&CK heatmap populate from real memory-forensics findings.
        _emit_volatility_report_events(ctx.bus, ctx.investigation_id, plugin, rows)

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
            output_path=str(local_out) if local_out.exists() else None,
            summary=summary, data={"plugin": plugin, "rows": rows},
        )


def _emit_volatility_report_events(
    bus, investigation_id: str, plugin: str, rows: list[dict[str, Any]],
) -> None:
    """Turn Vol3 plugin output into ``report.ioc`` / ``report.timeline_entry``.

    The mapping is plugin-specific because Vol3 plugins return heterogeneous
    column sets. We only handle the high-signal plugins (netscan → IOCs,
    pslist/malfind → timeline entries); other plugins' rows are still returned
    to the agent in the ToolResult but don't auto-emit report events.
    """
    if not rows:
        return
    max_events = 1000

    if plugin == "netscan":
        emitted = 0
        for row in rows:
            if emitted >= max_events:
                break
            # Vol3 netscan columns vary by OS; fish for the remote endpoint.
            for key in ("ForeignAddress", "RemoteAddress", "remote_addr", "Remote"):
                val = row.get(key)
                if not val:
                    continue
                ip = _extract_ip(str(val))
                if ip:
                    ctx_proc = row.get("Process") or row.get("Owner") or row.get("PID") or ""
                    bus.publish(E.report_ioc(
                        investigation_id=investigation_id,
                        ioc_type="ip",
                        value=ip,
                        context=f"volatility netscan: {ctx_proc} -> {val}",
                        confidence=0.7,
                    ))
                    emitted += 1
                    break
        return

    if plugin in ("pslist", "psscan", "malfind"):
        emitted = 0
        for row in rows:
            if emitted >= max_events:
                break
            name = row.get("Name") or row.get("ImageFileName") or ""
            pid = row.get("PID") or row.get("pid") or ""
            if not name:
                continue
            # malfind hits (RWX injected pages) are inherently suspicious;
            # pslist rows are recorded as a baseline process timeline.
            desc = f"process {name} (PID {pid})"
            if plugin == "malfind":
                desc = f"INJECTED code in {name} (PID {pid})"
            bus.publish(E.report_timeline_entry(
                investigation_id=investigation_id,
                ts=str(row.get("CreateTime") or row.get("TimeCreated") or E._now_iso()),
                source=f"volatility:{plugin}",
                event=desc,
                actor=str(name),
                mitre_technique="T1055" if plugin == "malfind" else None,
            ))
            emitted += 1


def _extract_ip(text: str) -> str | None:
    """Pull the first IPv4 address out of an address:port string."""
    import re
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
    return m.group(1) if m else None


def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


tool = VolatilityTool()
