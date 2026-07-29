"""Network packet/log analysis tool wrapper (research item C14).

Wraps the network forensics stack that lives in the ``svetovid/network``
Docker image:

  - tshark (Wireshark CLI)  — protocol summary + per-protocol field extraction
                              from PCAP/PCAPNG
  - Suricata                — IDS / signature engine; emits eve.json alerts
  - Zeek                    — connection/DNS/file/logon metadata in tab-separated
                              log files

The agent picks what to extract via ``analysis_type``. All seven modes return
flat JSON rows that the LLM can reason over. Used by G07 (network C2 / web-attack
reconstruction).

CLI shapes (inside the container)::

    # protocol distribution
    tshark -r /evidence/capture.pcap -q -z io,phs

    # per-protocol field extraction (one row per packet/frame)
    tshark -r /evidence/capture.pcap -T fields -E header=y -E separator=\\t \\
        -e frame.number -e frame.time -e ip.src -e ip.dst -e <proto fields>

    # IDS
    suricata -r /evidence/capture.pcap -l /work/suri -k none

    # Zeek metadata
    zeek -r /evidence/capture.pcap LogAscii::use_json=T local

tshark is asked for ``-T json`` for the HTTP/DNS/TLS extraction modes so the
parsed output is already structured; for the summary we parse the PHS tree.
Suricata writes ``eve.json`` (one JSON event per line) and Zeek writes JSON
``*.log`` files, both of which we read back from the mounted output dir.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


# Per-mode tshark field lists. Kept intentionally focused — the goal is enough
# signal for the LLM to reconstruct web attacks / C2, not a full packet decode.
# -T json gives us nested objects; we flatten the interesting leaves below.
TSHARK_FIELDS: dict[str, list[str]] = {
    "tshark_http": [
        "frame.number", "frame.time_epoch", "ip.src", "tcp.srcport",
        "ip.dst", "tcp.dstport",
        "http.request.method", "http.host", "http.request.uri",
        "http.user_agent", "http.response.code", "http.content_length",
        "http.file_data",
    ],
    "tshark_dns": [
        "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
        "dns.qry.name", "dns.qry.type", "dns.flags.response",
        "dns.a", "dns.cname",
    ],
    "tshark_tls": [
        "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
        "tls.handshake.type", "tls.handshake.extensions_server_name",
        "tls.handshake.ja3", "tls.handshake.ja4",
        "tls.handshake.version",
    ],
}

# Default field set for the generic tshark_extract mode: a compact flow record.
DEFAULT_EXTRACT_FIELDS: list[str] = [
    "frame.number", "frame.time_epoch",
    "ip.src", "tcp.srcport", "udp.srcport",
    "ip.dst", "tcp.dstport", "udp.dstport",
    "_ws.col.Protocol", "_ws.col.Info",
]


class NetworkAnalysisTool(Tool):
    name = "network_analyze"
    image = "svetovid/network"
    description = (
        "Analyze network captures (PCAP/PCAPNG) and IDS logs. Returns JSON "
        "rows. Use tshark_summary for protocol distribution, tshark_http for "
        "web-attack reconstruction, tshark_dns for C2 domain identification, "
        "tshark_tls for JA3/JA4 fingerprint C2 matching, suricata_alerts for "
        "known-bad signatures, and zeek_logs for connection/DNS/file metadata."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "analysis_type": {
                    "type": "string",
                    "enum": [
                        "tshark_summary", "tshark_extract",
                        "tshark_http", "tshark_dns", "tshark_tls",
                        "suricata_alerts", "zeek_logs",
                    ],
                    "description": "What to extract from the capture or logs.",
                },
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence to the PCAP/PCAPNG capture "
                        "(for tshark/suricata/zeek), or to a Zeek *.log / "
                        "Suricata eve.json file (for the *_logs modes)."
                    ),
                },
                "fields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "tshark_extract only: which fields to extract "
                        "(e.g. ['frame.number','ip.src','ip.dst']). Defaults to a "
                        "common flow set when omitted."
                    ),
                },
            },
            "required": ["analysis_type", "evidence_subpath"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        atype = args.get("analysis_type", "")
        sub = (args.get("evidence_subpath") or "").strip()

        if not sub:
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None,
                summary="network_analyze requires evidence_subpath pointing at "
                        "a PCAP/PCAPNG or a Zeek/Suricata log file.",
            )

        target = f"/evidence/{sub}".strip()
        cmd, out_file = _build_command(atype, target, args)

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(
            ctx.investigation_id, tool=self.name, args=args,
        ))

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
                host_fallback=True,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(
                ctx.investigation_id, f"network_analyze failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"network_analyze failed: {e}",
            )

        # Parse output → JSON rows. Each mode knows where it wrote (file under
        # /work or captured stdout). /work/* is bind-mounted to output_dir, so
        # the in-container path maps to the same name under output_dir.
        rows: list[dict[str, Any]] = []
        summary = ""
        try:
            if atype == "tshark_summary":
                rows = _parse_phs(stdout_lines)
                summary = f"tshark summary: {len(rows)} protocol bucket(s)"
            elif atype == "tshark_extract":
                rows = _parse_tshark_fields(stdout_lines)
                summary = f"tshark extract: {len(rows)} row(s)"
            elif atype in TSHARK_FIELDS:
                rows = _parse_tshark_json(stdout_lines)
                summary = f"tshark {atype}: {len(rows)} row(s)"
            elif atype == "suricata_alerts":
                local_eve = Path(ctx.output_dir) / "suri" / "eve.json"
                rows = _parse_jsonl(local_eve, stdout_lines)
                rows = [r for r in rows if r.get("event_type") == "alert"]
                summary = f"suricata: {len(rows)} alert(s)"
            elif atype == "zeek_logs":
                local_zeek = Path(ctx.output_dir) / "zeek"
                rows = _parse_zeek_logs(local_zeek, stdout_lines)
                summary = f"zeek: {len(rows)} log row(s)"
            else:
                summary = f"network_analyze: unknown analysis_type {atype!r}"
        except Exception as e:
            summary = f"network_analyze ran (exit {res.exit_code}) but parsing failed: {e}"

        # Cap so a giant capture can't flood the context window.
        rows = rows[:2000]
        output_hash = _hash_file(Path(ctx.output_dir) / Path(out_file).name) \
            if out_file else None
        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s,
            output_hash,
        ))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        # Provenance record (governance)
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name,
            "image": self.image,
            "args": args,
            "exit_code": res.exit_code,
            "duration_s": res.duration_s,
            "output_hash": output_hash,
            "ts": E._now_iso(),
        }))

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
            output_path=None,
            summary=summary, data={"analysis_type": atype, "rows": rows},
        )


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------


def _build_command(atype: str, target: str, args: dict[str, Any]) -> tuple[list[str], str]:
    """Return (argv, in-container output file) for the requested analysis type.

    The sandbox runs ``command`` as an argv list (no shell), so we MUST NOT use
    shell redirection (``>``, ``;``, ``&&``). Tools that only stream to stdout
    (tshark summary / extraction) are parsed from the captured stdout lines;
    tools that write files (Suricata eve.json, Zeek *.log) write under /work
    and we read the file back.
    """
    if atype == "tshark_summary":
        # Protocol hierarchy statistics — terse tree printed to stdout.
        return ["tshark", "-r", target, "-q", "-z", "io,phs"], ""

    if atype == "tshark_extract":
        # Generic -T fields extraction. The caller picks the fields (defaults
        # below). Output is a header + tab-separated rows to stdout, which we
        # parse back into per-row dicts.
        fields = list(args.get("fields") or DEFAULT_EXTRACT_FIELDS)
        cmd = ["tshark", "-r", target, "-T", "fields",
               "-E", "header=y", "-E", "separator=\t"]
        for f in fields:
            cmd += ["-e", f]
        return cmd, ""

    if atype in TSHARK_FIELDS:
        # -T json emits one JSON object per frame to stdout; we flatten leaves.
        display_filter = {
            "tshark_http": "http",
            "tshark_dns": "dns",
            "tshark_tls": "tls.handshake",
        }[atype]
        return [
            "tshark", "-r", target, "-T", "json", "--no-duplicate-keys",
            "-Y", display_filter,
        ], ""

    if atype == "suricata_alerts":
        # -l is the logdir; eve.json is written there by default.
        return ["suricata", "-r", target, "-l", "/work/suri", "-k", "none"], \
            "/work/suri/eve.json"

    if atype == "zeek_logs":
        # One -e script (no shell): turn on JSON logs, set the logdir, and
        # disable rotation so each stream lands in a single *.log file.
        zeek_script = (
            "redef LogAscii::use_json=T; "
            "redef Log::default_rotation_interval = 0sec; "
            "redef Log::default_logdir = \"/work/zeek\";"
        )
        return ["zeek", "-r", target, "local", "-e", zeek_script], "/work/zeek"

    # Shouldn't reach here (schema enum constrains atype), but be defensive.
    raise ValueError(f"unknown analysis_type {atype!r}")


# ---------------------------------------------------------------------------
# Output parsers — turn each tool's native format into flat JSON rows
# ---------------------------------------------------------------------------


def _parse_phs(stdout_lines: list[str]) -> list[dict[str, Any]]:
    """Parse tshark 'io,phs' protocol hierarchy tree into per-protocol buckets.

    The summary streams to stdout, so we read it from the captured lines.
    """
    rows: list[dict[str, Any]] = []
    # Lines look like: "  ip              1234 0.000% 0.000% ..."
    for line in stdout_lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        proto, count = parts[0], parts[1]
        if count.isdigit():
            rows.append({"protocol": proto, "packets": int(count)})
    return rows


def _parse_tshark_fields(stdout_lines: list[str]) -> list[dict[str, Any]]:
    """Parse ``tshark -T fields -E header=y -E separator=\\t`` stdout.

    First non-empty line is the header (field names); each following line is a
    tab-separated row. Missing fields render as empty strings.
    """
    rows: list[dict[str, Any]] = []
    header: list[str] | None = None
    for line in stdout_lines:
        if not line.strip():
            continue
        cols = line.split("\t")
        if header is None:
            header = cols
            continue
        if len(cols) != len(header):
            # tolerate ragged rows
            cols = cols + [""] * (len(header) - len(cols))
        rows.append({h: v for h, v in zip(header, cols)})
    return rows


def _parse_tshark_json(stdout_lines: list[str]) -> list[dict[str, Any]]:
    """Parse tshark -T json output (one JSON object per frame) into flat rows.

    tshark streams the JSON to stdout; we reassemble it from the captured
    lines (it may span several).
    """
    raw = "\n".join(stdout_lines).strip()
    if not raw:
        return []
    # tshark -T json emits either a JSON array or concatenated objects.
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        doc = _loads_concatenated(raw)

    frames = doc if isinstance(doc, list) else [doc]
    rows: list[dict[str, Any]] = []
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        layers = frame.get("_source", {}).get("layers", frame)
        row: dict[str, Any] = {}
        for key, val in layers.items():
            # tshark wraps field values in single-element lists; unwrap scalars.
            if isinstance(val, list) and len(val) == 1:
                val = val[0]
            row[key] = val
        rows.append(row)
    return rows


def _loads_concatenated(raw: str) -> list[dict[str, Any]]:
    """Best-effort parse of concatenated JSON objects (no array wrapper)."""
    decoder = json.JSONDecoder()
    out: list[dict[str, Any]] = []
    s = raw
    while s:
        s = s.lstrip()
        if not s:
            break
        try:
            obj, idx = decoder.raw_decode(s)
        except json.JSONDecodeError:
            break
        out.append(obj)
        s = s[idx:]
    return out


def _parse_jsonl(local_out: Path, stdout_lines: list[str]) -> list[dict[str, Any]]:
    """Parse a JSONL file (Suricata eve.json / Zeek *.log) into rows.

    If the on-disk file isn't there (e.g. host fallback wrote to stdout), parse
    the streamed stdout lines instead.
    """
    rows: list[dict[str, Any]] = []
    lines: list[str]
    if local_out.exists():
        lines = local_out.read_text(encoding="utf-8", errors="replace").splitlines()
    else:
        lines = list(stdout_lines)
    for line in lines:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _parse_zeek_logs(zeek_dir: Path, stdout_lines: list[str]) -> list[dict[str, Any]]:
    """Parse all Zeek JSON *.log files written under ``zeek_dir``.

    Each row is tagged with its source log (conn.log, dns.log, …) so the LLM
    can tell connection metadata from DNS from file transfers. If the dir is
    absent (host fallback, no Zeek), fall back to stdout lines.
    """
    rows: list[dict[str, Any]] = []
    if zeek_dir.exists():
        for log_file in sorted(zeek_dir.glob("*.log")):
            log_name = log_file.stem   # conn, dns, files, http, ssl, weird, ...
            for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                row["_zeek_log"] = log_name
                rows.append(row)
        return rows
    # Fallback: stdout (Zeek prints a summary line, not the logs, so this is
    # sparse — but keeps the contract that we always return *something*).
    return _parse_jsonl(zeek_dir, stdout_lines)


def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


# Module-level instance the registry can pick up if we ever want to enumerate
# tools the same way we enumerate goals.
tool = NetworkAnalysisTool()
