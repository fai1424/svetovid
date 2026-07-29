"""macOS artifact parser tool wrapper (research item C16).

Parses the forensic artifacts that an macOS endpoint-compromise investigation
revolves around, using only the standard library available in the
``svetovid/base`` Docker image (python3 + sqlite3 + plistlib). Exposes a single
tool, ``macos_artifact_parse``, that dispatches on ``artifact_type``:

  - unified_log      — .tracev3 binary Unified Logs (metadata only; the actual
                       records need Apple's `log` tool which isn't in the image)
  - knowledgec       — knowledgeC.db (app usage / device-usage timeline)
  - tcc_db           — TCC.db (privacy permission grants)
  - fsevents         — .fseventsd files (file-system activity log)
  - quarantine       — QuarantineEventsV2 (download provenance)
  - launchagents     — LaunchAgents/LaunchDaemons .plist (persistence)
  - install_history  — InstallHistory.plist (software install timeline)
  - safari_history   — History.db (browsing history)

The wrapper ships an embedded Python parser script that runs inside the
container, reads the artifact under ``/evidence`` (read-only), and writes
parsed rows to ``/work/macos_artifacts.json``. We then read that file back,
feed it to the agent, and emit the full tool event stream
(``tool.start`` / ``tool.stdout`` / ``tool.end`` / ``agent.action`` /
``agent.observation`` / ``provenance.recorded``) — exactly like the other
wrappers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

# Artifact types this tool knows how to parse. Kept in sync with the parser
# script's dispatch table below.
ARTIFACT_TYPES = (
    "unified_log",
    "knowledgec",
    "tcc_db",
    "fsevents",
    "quarantine",
    "launchagents",
    "install_history",
    "safari_history",
)


# ---------------------------------------------------------------------------
# Parser script run inside the container.
#
# We embed it as a string and write it to the per-call output dir, then invoke
# ``python3 <script>`` in the sandbox. Using an embedded script (rather than
# baking one into the image) keeps the base image generic and makes the parser
# trivially editable / testable on the host.
# ---------------------------------------------------------------------------

_PARSER_SCRIPT = r'''#!/usr/bin/env python3
"""macOS artifact parser — runs inside the svetovid/base container.

Reads one artifact (file or directory) under /evidence, parses it with the
stdlib, and writes a JSON document to the output path given on the CLI.

Usage:
    parse_macos.py <artifact_type> <evidence_path> <output_json>

The evidence_path is resolved relative to /evidence inside the container; the
caller passes us an absolute /evidence/<sub> path.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import plistlib
import sqlite3
import sys
from pathlib import Path


def _ts(value):
    """Best-effort normalization of timestamps into ISO-ish strings."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        # macOS CoreData/mac epoch = 2001-01-01 00:00:00 UTC, 1e9 ns units.
        try:
            if isinstance(value, float):
                secs = value + 978307200.0
            else:
                # Large ints in knowledgeC are nanoseconds since 2001-epoch.
                if value > 1_000_000_000_000:  # ns
                    secs = value / 1e9 + 978307200.0
                else:
                    secs = value + 978307200.0
            return _dt.datetime.fromtimestamp(secs, _dt.timezone.utc).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _rows_from_sqlite(path, query, row_key=None):
    """Open a SQLite DB read-only and yield dict rows for ``query``."""
    if not Path(path).exists():
        return [], f"database not found: {path}"
    # uri=true + mode=ro keeps the evidence file truly read-only.
    uri = f"file:{path}?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as e:
        return [], f"cannot open sqlite db {path}: {e}"
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute(query)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = []
        for r in cur.fetchall():
            row = {}
            for c in cols:
                v = r[c]
                if isinstance(v, bytes):
                    v = v.decode("utf-8", "replace")
                row[c] = v
            rows.append(row)
        return rows, f"{len(rows)} row(s) from {Path(path).name}"
    except sqlite3.Error as e:
        return [], f"query failed on {path}: {e}"
    finally:
        con.close()


def parse_knowledgec(path):
    """App usage timeline from knowledgeC.db.

    The interesting rows live in the KC.TABLES-style schema used by Apple:
    ``ZOBJECT`` with ``ZBUNDLEID`` (app), ``ZCREATIONDT`` (time),
    ``ZVALUEINTEGER`` (usage seconds), ``ZSTREAMNAME`` (event type).
    """
    query = (
        "SELECT ZCREATIONDT AS start_time, "
        "ZBUNDLEID AS bundle_id, "
        "ZVALUESTRING AS string_value, "
        "ZVALUEINTEGER AS duration_s, "
        "ZSTREAMNAME AS stream_name "
        "FROM ZOBJECT "
        "WHERE ZBUNDLEID IS NOT NULL OR ZSTREAMNAME IS NOT NULL "
        "ORDER BY ZCREATIONDT DESC LIMIT 2000"
    )
    rows, summary = _rows_from_sqlite(path, query)
    for r in rows:
        if r.get("start_time") is not None:
            r["start_time"] = _ts(r["start_time"])
    return rows, summary


def parse_tcc(path):
    """Privacy permission grants from TCC.db (TCC.access table)."""
    query = (
        "SELECT service AS service, client AS client, "
        "client_type AS client_type, auth_value AS auth_value, "
        "auth_reason AS auth_reason, last_modified AS last_modified "
        "FROM access ORDER BY last_modified DESC LIMIT 2000"
    )
    rows, summary = _rows_from_sqlite(path, query)
    for r in rows:
        if r.get("last_modified") is not None:
            r["last_modified"] = _ts(r["last_modified"])
    return rows, summary


def parse_safari_history(path):
    """Browsing history from Safari History.db (history_items)."""
    query = (
        "SELECT h.url AS url, v.visit_time AS visit_time, "
        "v.title AS title "
        "FROM history_items h "
        "LEFT JOIN history_visits v ON v.history_item = h.id "
        "ORDER BY v.visit_time DESC LIMIT 2000"
    )
    rows, summary = _rows_from_sqlite(path, query)
    for r in rows:
        if r.get("visit_time") is not None:
            r["visit_time"] = _ts(r["visit_time"])
    return rows, summary


def parse_quarantine(path):
    """Download provenance from Gatekeeper's QuarantineEventsV2."""
    query = (
        "SELECT LSQuarantineAgentName AS agent, "
        "LSQuarantineOriginURLString AS origin_url, "
        "LSQuarantineDataURLString AS data_url, "
        "LSQuarantineTimeStamp AS ts "
        "FROM LSQuarantineEvent "
        "ORDER BY LSQuarantineTimeStamp DESC LIMIT 2000"
    )
    rows, summary = _rows_from_sqlite(path, query)
    for r in rows:
        if r.get("ts") is not None:
            r["ts"] = _ts(r["ts"])
    return rows, summary


def parse_plist_dir(path):
    """All .plist files in a dir (LaunchAgents/LaunchDaemons persistence)."""
    root = Path(path)
    if not root.exists():
        return [], f"path not found: {path}"
    plists = sorted(p for p in root.rglob("*.plist")) if root.is_dir() else [root]
    rows = []
    for p in plists:
        try:
            with open(p, "rb") as fh:
                data = plistlib.load(fh)
        except (plistlib.InvalidFileException, OSError, ValueError) as e:
            rows.append({"file": str(p), "error": f"unreadable plist: {e}"})
            continue
        rows.append({
            "file": str(p),
            "label": data.get("Label") or p.stem,
            "program": data.get("Program") or data.get("ProgramArguments", []),
            "run_at_load": data.get("RunAtLoad"),
            "keep_alive": data.get("KeepAlive"),
            "start_interval": data.get("StartInterval"),
            "watch_paths": data.get("WatchPaths"),
            "program_arguments": data.get("ProgramArguments"),
        })
    return rows, f"{len(rows)} LaunchAgent/Daemon plist(s)"


def parse_install_history(path):
    """InstallHistory.plist — software install timeline."""
    if not Path(path).exists():
        return [], f"plist not found: {path}"
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except (plistlib.InvalidFileException, OSError, ValueError) as e:
        return [], f"unreadable plist: {e}"
    rows = []
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            rows.append({
                "name": item.get("displayName") or item.get("packageIdentifier"),
                "version": item.get("displayVersion"),
                "date": _ts(item.get("date")),
                "process": item.get("processName"),
                "identifiers": item.get("packageIdentifiers"),
            })
    return rows, f"{len(rows)} install record(s)"


def parse_fsevents(path):
    """FSEvents log (.fseventsd) — file-system activity records.

    These are a compact Apple-proprietary format. We don't fully decode them
    (no public spec), but we extract per-file size/mtime plus a textual sniff
    so the analyst has something to pivot on. The companion unified_log parse
    usually carries the human-readable side.
    """
    root = Path(path)
    if not root.exists():
        return [], f"path not found: {path}"
    files = sorted(root.rglob("*")) if root.is_dir() else [root]
    rows = []
    for f in files:
        if not f.is_file():
            continue
        try:
            st = f.stat()
            with open(f, "rb") as fh:
                head = fh.read(64)
        except OSError as e:
            rows.append({"file": str(f), "error": str(e)})
            continue
        rows.append({
            "file": str(f),
            "size": st.st_size,
            "mtime": _dt.datetime.fromtimestamp(st.st_mtime, _dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "preview": head.decode("utf-8", "replace").replace("\x00", ""),
        })
    return rows, f"{len(rows)} FSEvents file(s) enumerated"


def parse_unified_log(path):
    """Unified Log (.tracev3) — binary metadata only.

    The full record decode needs Apple's ``log`` tool (not in the base image).
    We surface file metadata + a magic check so the agent knows it found a
    real .tracev3 and can note that deeper analysis requires the host's log
    tool on a live macOS system.
    """
    root = Path(path)
    if not root.exists():
        return [], f"path not found: {path}"
    files = sorted(root.rglob("*.tracev3")) if root.is_dir() else [root]
    rows = []
    for f in files:
        if not f.is_file():
            continue
        try:
            st = f.stat()
            with open(f, "rb") as fh:
                head = fh.read(4)
        except OSError as e:
            rows.append({"file": str(f), "error": str(e)})
            continue
        rows.append({
            "file": str(f),
            "size": st.st_size,
            "mtime": _dt.datetime.fromtimestamp(st.st_mtime, _dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "magic_ok": head[:2] == b"\x0b\x00",  # tracev3 chunk header
            "note": ("Binary Unified Log. Full decode requires Apple's `log` "
                     "tool on a live macOS host; metadata captured here."),
        })
    return rows, f"{len(rows)} tracev3 file(s) (metadata only)"


DISPATCH = {
    "knowledgec": parse_knowledgec,
    "tcc_db": parse_tcc,
    "safari_history": parse_safari_history,
    "quarantine": parse_quarantine,
    "launchagents": parse_plist_dir,
    "install_history": parse_install_history,
    "fsevents": parse_fsevents,
    "unified_log": parse_unified_log,
}


def main(argv):
    if len(argv) != 4:
        print("usage: parse_macos.py <artifact_type> <evidence_path> <output_json>",
              file=sys.stderr)
        return 2
    artifact_type, evidence_path, out_json = argv[1], argv[2], argv[3]
    fn = DISPATCH.get(artifact_type)
    if fn is None:
        print(f"unknown artifact_type: {artifact_type}", file=sys.stderr)
        return 2
    rows, summary = fn(evidence_path)
    payload = {
        "artifact_type": artifact_type,
        "source": evidence_path,
        "summary": summary,
        "rows": rows,
    }
    with open(out_json, "w") as fh:
        json.dump(payload, fh, ensure_ascii=False, default=str)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


class MacosArtifactTool(Tool):
    name = "macos_artifact_parse"
    image = "svetovid/base"
    description = (
        "Parse macOS forensic artifacts (Unified Logs, knowledgeC.db, TCC.db, "
        "LaunchAgents/InstallHistory plists, FSEvents, Quarantine, Safari "
        "History) into structured rows. One call parses one artifact_type."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "artifact_type": {
                    "type": "string",
                    "enum": list(ARTIFACT_TYPES),
                    "description": (
                        "Which macOS artifact to parse: unified_log (.tracev3, "
                        "metadata only), knowledgec (app usage), tcc_db "
                        "(privacy grants), fsevents (FS activity), quarantine "
                        "(download provenance), launchagents (persistence "
                        "plists), install_history (software installs), "
                        "safari_history (browsing)."
                    ),
                },
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence pointing at the artifact "
                        "file or directory (e.g. 'private/var/db/Knowledge/ "
                        "knowledgeC.db' or 'Library/LaunchAgents')."
                    ),
                },
            },
            "required": ["artifact_type", "evidence_subpath"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        artifact_type = args.get("artifact_type", "")
        sub = args.get("evidence_subpath", "") or ""

        # Validate artifact_type up front so we surface a clean error rather
        # than letting the parser script silently exit 2.
        if artifact_type not in ARTIFACT_TYPES:
            msg = (f"unknown artifact_type {artifact_type!r}; "
                   f"one of {list(ARTIFACT_TYPES)}")
            ctx.bus.publish(E.error_event(ctx.investigation_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 2, 0.0, None))
            return ToolResult(call_id=call_id, tool=self.name, exit_code=2,
                              duration_s=0.0, output_hash=None, output_path=None,
                              summary=msg)

        out_json = "/work/macos_artifacts.json"
        # Stash the parser script into the per-call output dir so it is mounted
        # into the container at /work and we can invoke it there directly.
        script_host = Path(ctx.output_dir) / "parse_macos.py"
        script_host.write_text(_PARSER_SCRIPT)

        cmd = [
            "python3", "/work/parse_macos.py",
            artifact_type,
            (f"/evidence/{sub}".rstrip("/") if sub else "/evidence"),
            out_json,
        ]

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(
            ctx.investigation_id, tool=self.name, args=args,
        ))

        def on_stdout(line: str) -> None:
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
                host_fallback=True,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(
                ctx.investigation_id, f"macos_artifact_parse failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"macos_artifact_parse failed: {e}",
            )

        # Parse the JSON the script wrote to /work (mounted at output_dir).
        rows: list[dict[str, Any]] = []
        summary = ""
        local_out = Path(ctx.output_dir) / "macos_artifacts.json"
        if local_out.exists():
            try:
                payload = json.loads(local_out.read_text())
                rows = payload.get("rows", []) if isinstance(payload, dict) else []
                summary = payload.get("summary", "") if isinstance(payload, dict) else ""
            except Exception as e:
                summary = f"output couldn't be parsed: {e}"
        if not summary:
            summary = (f"{artifact_type}: parser exited {res.exit_code} "
                       f"with no usable output")

        output_hash = _hash_file(local_out)
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
            output_path=str(local_out) if local_out.exists() else None,
            summary=summary, data={"artifact_type": artifact_type, "rows": rows},
        )


def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


# Module-level instance the registry can pick up the same way as the other tools.
tool = MacosArtifactTool()
