"""iLEAPP-style iOS artifact parser tool wrapper (research item C12a).

Parses the forensic artifacts that an iOS mobile-device examination revolves
around, using only the standard library available in the ``svetovid/base``
Docker image (python3 + sqlite3 + plistlib). Exposes a single tool,
``ileapp_parse``, that dispatches on ``artifact_type``:

  - knowledgec       — knowledgeC.db (app / device-usage timeline)
  - sms              — sms.db (iMessage + SMS text message history)
  - call_history     — CallHistory.storedata (incoming/outgoing/missed calls)
  - keychain         — Keychain (general credentials & internet passwords)
  - photos           — Photos.sqlite (camera roll / media library metadata)
  - health           — healthdb_secure.sqlite (step + workout summary)
  - wallet           — Passes (Wallet pass metadata)
  - location         — consolidatedated DB / cache_encryptedA (location history)
  - app_usage        — Runtime (app runtime / screen-on telemetry)
  - browser_history  — Safari History.db (browsing history)

The wrapper ships an embedded Python parser script that runs inside the
container, reads the artifact under ``/evidence`` (read-only), and writes
parsed rows to ``/work/ios_artifacts.json``. We then read that file back,
feed it to the agent, and emit the full tool event stream
(``tool.start`` / ``tool.stdout`` / ``tool.end`` / ``agent.action`` /
``agent.observation`` / ``provenance.recorded``) — exactly like the other
wrappers (chainsaw / macos_logs).
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
    "knowledgec",
    "sms",
    "call_history",
    "keychain",
    "photos",
    "health",
    "wallet",
    "location",
    "app_usage",
    "browser_history",
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
"""iOS artifact parser (iLEAPP-style) — runs inside the svetovid/base container.

Reads one artifact (file or directory) under /evidence, parses it with the
stdlib, and writes a JSON document to the output path given on the CLI.

Usage:
    parse_ios.py <artifact_type> <evidence_path> <output_json>

The evidence_path is resolved relative to /evidence inside the container; the
caller passes us an absolute /evidence/<sub> path.

The caller is responsible for pointing evidence_path at the right backing
database/plist (these live at well-known paths inside an iOS extraction or
iTunes backup). We don't assume a backup-conversion step: we read whatever
SQLite/plist the agent pointed us at.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import plistlib
import sqlite3
import sys
from pathlib import Path


# iOS / macOS Cocoa + Core Data epoch: 2001-01-01 00:00:00 UTC.
_COCOA_EPOCH = 978307200.0


def _ts(value):
    """Best-effort normalization of timestamps into ISO-ish strings.

    iOS stores time three common ways:
      - Cocoa seconds since 2001-01-01 (float)
      - Cocoa nanoseconds since 2001-01-01 (large int)
      - Unix seconds since 1970-01-01 (int, ~1e9..1e10)
      - Already a datetime / iso string
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            if isinstance(value, float):
                secs = value + _COCOA_EPOCH
            else:
                # Large ints are nanoseconds since the 2001-epoch.
                if value > 1_000_000_000_000:  # ns
                    secs = value / 1e9 + _COCOA_EPOCH
                elif value > 1_000_000_000_000_0:  # ns-since-1970 (rare)
                    secs = value / 1e9
                elif 1e8 < value < 1e11:
                    # Ambiguous band; treat as Unix seconds (1970-epoch).
                    secs = float(value)
                else:
                    secs = value + _COCOA_EPOCH
            return _dt.datetime.fromtimestamp(secs, _dt.timezone.utc).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _rows_from_sqlite(path, query, params=()):
    """Open a SQLite DB read-only and yield dict rows for ``query``.

    Uses the SQLite URI form ``file:...?mode=ro`` so the evidence file is never
    written to (some iOS DBs carry -wal/-journal sidecars; read-only mode keeps
    them from being created).
    """
    if not Path(path).exists():
        return [], f"database not found: {path}"
    uri = f"file:{path}?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as e:
        return [], f"cannot open sqlite db {path}: {e}"
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute(query, params)
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
        return [], f"query failed on {Path(path).name}: {e}"
    finally:
        con.close()


def _find_db(root, candidates):
    """Walk a directory looking for the first candidate filename (case-insensitive).

    iOS extraction trees vary (full file system vs. iTunes backup domain), so
    we let the agent point at a directory and resolve the DB by name.
    """
    root = Path(root)
    wanted = {c.lower() for c in candidates}
    if root.is_file():
        return root if root.name.lower() in wanted else None
    if root.is_dir():
        names = {c.lower() for c in candidates}
        for p in root.rglob("*"):
            if p.is_file() and p.name.lower() in names:
                return p
    return None


def parse_knowledgec(path):
    """App / device-usage timeline from knowledgeC.db.

    Schema mirrors Apple's Core Data ``ZOBJECT`` table: ``ZBUNDLEID`` (app),
    ``ZCREATIONDT`` (Cocoa time), ``ZVALUEINTEGER`` (usage seconds),
    ``ZVALUESTRING`` (text value), ``ZSTREAMNAME`` (event type).
    """
    db = _find_db(path, ["knowledgec.db"]) or path
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
    rows, summary = _rows_from_sqlite(db, query)
    for r in rows:
        if r.get("start_time") is not None:
            r["start_time"] = _ts(r["start_time"])
    return rows, summary


def parse_sms(path):
    """iMessage + SMS text-message history from sms.db (message table).

    Columns: ROWID, text, handle_id, date (Cocoa), is_from_me, service,
    read_state. handle_id is resolved to the conversation partner via the
    handle.id column when present.
    """
    db = _find_db(path, ["sms.db"]) or path
    query = (
        "SELECT m.ROWID AS msg_id, m.text AS text, "
        "h.id AS contact, m.handle_id AS handle_id, "
        "m.date AS date, m.is_from_me AS is_from_me, "
        "m.service AS service, m.read_state AS read_state "
        "FROM message m "
        "LEFT JOIN handle h ON h.ROWID = m.handle_id "
        "ORDER BY m.date DESC LIMIT 2000"
    )
    rows, summary = _rows_from_sqlite(db, query)
    for r in rows:
        if r.get("date") is not None:
            r["date"] = _ts(r["date"])
    return rows, summary


def parse_call_history(path):
    """Call history from CallHistory.storedata (ZCALLRECORD table).

    Columns: ZDATE (Cocoa), ZADDRESS, ZCALLER_NAME, ZDURATION, ZANSWERED,
    ZORIGINATED. Call type is derived from answered/originated flags.
    """
    db = _find_db(path, ["callhistory.storedata"]) or path
    query = (
        "SELECT ZDATE AS date, ZADDRESS AS address, "
        "ZCALLER_NAME AS caller_name, ZDURATION AS duration_s, "
        "ZANSWERED AS answered, ZORIGINATED AS originated, "
        "ZCALL_TYPE AS call_type "
        "FROM ZCALLRECORD "
        "ORDER BY ZDATE DESC LIMIT 2000"
    )
    rows, summary = _rows_from_sqlite(db, query)
    for r in rows:
        if r.get("date") is not None:
            r["date"] = _ts(r["date"])
        # Normalize direction for the analyst.
        if r.get("originated"):
            r["direction"] = "outgoing"
        elif r.get("answered"):
            r["direction"] = "incoming"
        else:
            r["direction"] = "missed"
    return rows, summary


def parse_keychain(path):
    """Keychain credentials (general + internet passwords).

    The Keychain on iOS is a set of Keychain DBs (default.keychain etc.); the
    rows we can read without the class-key wrap live in ``genp`` (general) and
    ``inet`` (internet). Account / data blobs are often encrypted, so we focus
    on the readable metadata (service, account, srvr, creation/modification).
    """
    db = _find_db(path, ["keychain-db", "keychain.db", "default.keychain"]) or path
    rows = []
    summaries = []
    # general passwords
    q_genp = (
        "SELECT aggp.svce AS service, aggp.acct AS account, "
        "cdata.cdatp AS created, cdata.mdatp AS modified "
        "FROM genp "
        "LEFT JOIN cdata ON cdata.rowid = genp.cdatid "
        "LEFT JOIN aggp ON aggp.rowid = genp.agrp "
        "LIMIT 2000"
    )
    genp_rows, genp_sum = _rows_from_sqlite(db, q_genp)
    for r in genp_rows:
        r["kind"] = "general"
        r["created"] = _ts(r.get("created"))
        r["modified"] = _ts(r.get("modified"))
    rows.extend(genp_rows)
    summaries.append(genp_sum)
    # internet passwords
    q_inet = (
        "SELECT aggp.svce AS service, aggp.acct AS account, "
        "inet.srvr AS server, inet.ptcl AS protocol, "
        "cdata.cdatp AS created, cdata.mdatp AS modified "
        "FROM inet "
        "LEFT JOIN cdata ON cdata.rowid = inet.cdatid "
        "LEFT JOIN aggp ON aggp.rowid = inet.agrp "
        "LIMIT 2000"
    )
    inet_rows, inet_sum = _rows_from_sqlite(db, q_inet)
    for r in inet_rows:
        r["kind"] = "internet"
        r["created"] = _ts(r.get("created"))
        r["modified"] = _ts(r.get("modified"))
    rows.extend(inet_rows)
    return rows, "; ".join(s for s in summaries if s) or "no keychain rows"


def parse_photos(path):
    """Camera roll / media library metadata from Photos.sqlite (ZASSETS).

    Columns: ZDATECREATED (Cocoa), ZFILENAME, ZTITLE, ZLATITUDE, ZLONGITUDE,
    ZDURATION (for video), ZKIND (image/video). Geo on media is a strong
    movement pivot.
    """
    db = _find_db(path, ["photos.sqlite"]) or path
    query = (
        "SELECT ZDATECREATED AS created, ZFILENAME AS filename, "
        "ZTITLE AS title, ZLATITUDE AS latitude, ZLONGITUDE AS longitude, "
        "ZDURATION AS duration_s, ZKIND AS kind "
        "FROM ZASSET "
        "WHERE ZFILENAME IS NOT NULL "
        "ORDER BY ZDATECREATED DESC LIMIT 2000"
    )
    rows, summary = _rows_from_sqlite(db, query)
    for r in rows:
        if r.get("created") is not None:
            r["created"] = _ts(r["created"])
    return rows, summary


def parse_health(path):
    """Health data summary from healthdb_secure.sqlite (workouts + steps).

    The full workout table is large; we surface a compact summary: start/end,
    type, duration, total distance/energy. Used to corroborate movement +
    activity timeline.
    """
    db = _find_db(path, ["healthdb_secure.sqlite"]) or path
    query = (
        "SELECT startDate AS start_time, endDate AS end_time, "
        "workoutActivityType AS activity_type, duration AS duration_s, "
        "totalDistance AS distance, totalEnergyBurned AS energy "
        "FROM workout "
        "ORDER BY startDate DESC LIMIT 2000"
    )
    rows, summary = _rows_from_sqlite(db, query)
    for r in rows:
        if r.get("start_time") is not None:
            r["start_time"] = _ts(r["start_time"])
        if r.get("end_time") is not None:
            r["end_time"] = _ts(r["end_time"])
    return rows, summary


def parse_wallet(path):
    """Wallet pass metadata.

    Passes are .pkpass bundles (a zip); inside is ``pass.json``. We enumerate
    every pass.json under the given path and surface the descriptive fields
    (organization, kind, serial, relevant dates) — never the secrets.
    """
    root = Path(path)
    if not root.exists():
        return [], f"path not found: {path}"
    files = [p for p in (root.rglob("pass.json") if root.is_dir() else [root])
             if p.is_file()]
    rows = []
    for p in files:
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError) as e:
            rows.append({"file": str(p), "error": f"unreadable pass.json: {e}"})
            continue
        desc = data.get("organizationName") or ""
        rows.append({
            "file": str(p),
            "organization": desc,
            "description": data.get("description"),
            "type": (data.get("storeCard") and "storeCard")
                 or (data.get("boardingPass") and "boardingPass")
                 or (data.get("generic") and "generic")
                 or (data.get("coupon") and "coupon")
                 or (data.get("eventTicket") and "eventTicket")
                 or None,
            "serial": data.get("serialNumber"),
            "relevant_date": _ts(data.get("relevantDate")),
            "expiration": _ts(data.get("expirationDate")),
            "locations": [
                {"lat": loc.get("latitude"), "lon": loc.get("longitude")}
                for loc in data.get("locations", []) if isinstance(loc, dict)
            ],
        })
    return rows, f"{len(rows)} wallet pass(es)"


def parse_location(path):
    """Location history from the iOS consolidated(ated) location DB.

    The location cache schema changed across iOS versions. We try the modern
    ``cache_encryptedA``/``CellLocation`` layout first, then fall back to the
    classic ``WifiLocation``/`CellLocationLocation` tables. Timestamps are Unix
    seconds since 1970 in this table.
    """
    db = _find_db(path, ["cache_encrypteda", "consolidated.db", "locationdb"])
    if db is None:
        # accept being pointed straight at a sqlite file
        if Path(path).is_file():
            db = Path(path)
        else:
            return [], f"no location db under {path}"
    # Modern: CellLocation table (mac, lat, lon, timestamp)
    candidates = [
        (
            "SELECT timestamp AS ts, latitude AS latitude, longitude AS longitude, "
            "horizontalAccuracy AS accuracy, speed AS speed "
            "FROM CellLocation "
            "ORDER BY timestamp DESC LIMIT 2000"
        ),
        (
            "SELECT Timestamp AS ts, Latitude AS latitude, Longitude AS longitude, "
            "Accuracy AS accuracy "
            "FROM CellLocation "
            "ORDER BY Timestamp DESC LIMIT 2000"
        ),
        (
            "SELECT Timestamp AS ts, Latitude AS latitude, Longitude AS longitude, "
            "LocationAccuracy AS accuracy "
            "FROM Location "
            "ORDER BY Timestamp DESC LIMIT 2000"
        ),
    ]
    last_err = ""
    for q in candidates:
        rows, summary = _rows_from_sqlite(db, q)
        if rows or "not found" not in summary and "failed" not in summary:
            for r in rows:
                if r.get("ts") is not None:
                    r["ts"] = _ts(r["ts"])
            return rows, summary
        last_err = summary
    return [], last_err or "no recognized location table"


def parse_app_usage(path):
    """App runtime / screen-on telemetry from Runtime (apprunnegptd) DB.

    Newer iOS keeps a per-app runtime table (``ZRTACTIVITYRECORD`` /
    ``usage``). We surface start, duration, and bundle id so the agent can
    cross-check knowledgeC.
    """
    db = _find_db(path, ["runtime", "apprunnegptd", "appusage.db"]) or path
    query = (
        "SELECT ZSTARTDATE AS start_time, ZENDDATE AS end_time, "
        "ZBUNDLEID AS bundle_id, ZTOTALTIME AS duration_s "
        "FROM ZRTACTIVITYRECORD "
        "WHERE ZBUNDLEID IS NOT NULL "
        "ORDER BY ZSTARTDATE DESC LIMIT 2000"
    )
    rows, summary = _rows_from_sqlite(db, query)
    if not rows or "failed" in summary:
        # Generic fallback: a table literally called `usage`.
        q2 = (
            "SELECT start_time AS start_time, end_time AS end_time, "
            "bundle_id AS bundle_id, duration AS duration_s "
            "FROM usage "
            "WHERE bundle_id IS NOT NULL "
            "ORDER BY start_time DESC LIMIT 2000"
        )
        rows, summary = _rows_from_sqlite(db, q2)
    for r in rows:
        if r.get("start_time") is not None:
            r["start_time"] = _ts(r["start_time"])
        if r.get("end_time") is not None:
            r["end_time"] = _ts(r["end_time"])
    return rows, summary


def parse_browser_history(path):
    """Safari browsing history from History.db (history_items / history_visits).

    Same schema as on macOS. visit_time is Cocoa (2001-epoch).
    """
    db = _find_db(path, ["history.db"]) or path
    query = (
        "SELECT h.url AS url, v.visit_time AS visit_time, v.title AS title "
        "FROM history_items h "
        "LEFT JOIN history_visits v ON v.history_item = h.id "
        "ORDER BY v.visit_time DESC LIMIT 2000"
    )
    rows, summary = _rows_from_sqlite(db, query)
    for r in rows:
        if r.get("visit_time") is not None:
            r["visit_time"] = _ts(r["visit_time"])
    return rows, summary


DISPATCH = {
    "knowledgec": parse_knowledgec,
    "sms": parse_sms,
    "call_history": parse_call_history,
    "keychain": parse_keychain,
    "photos": parse_photos,
    "health": parse_health,
    "wallet": parse_wallet,
    "location": parse_location,
    "app_usage": parse_app_usage,
    "browser_history": parse_browser_history,
}


def main(argv):
    if len(argv) != 4:
        print("usage: parse_ios.py <artifact_type> <evidence_path> <output_json>",
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


class IleappTool(Tool):
    name = "ileapp_parse"
    image = "svetovid/base"
    description = (
        "Parse iOS mobile forensic artifacts (knowledgeC usage timeline, "
        "SMS/iMessage, call history, keychain credentials, photos, health, "
        "wallet passes, location history, app usage, Safari browser history) "
        "into structured rows using sqlite3/plistlib. One call parses one "
        "artifact_type. Open each SQLite database read-only."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "artifact_type": {
                    "type": "string",
                    "enum": list(ARTIFACT_TYPES),
                    "description": (
                        "Which iOS artifact to parse: knowledgec (app usage), "
                        "sms (iMessage/SMS texts), call_history (calls), "
                        "keychain (credentials), photos (camera roll), "
                        "health (workouts), wallet (passes), location "
                        "(consolidated location cache), app_usage (runtime), "
                        "browser_history (Safari)."
                    ),
                },
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence pointing at the artifact "
                        "file or directory (e.g. "
                        "'HomeDomain/Library/SMS/sms.db' or the parent dir of "
                        "a backup domain). May be a directory; the parser "
                        "resolves the right DB by name."
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

        out_json = "/work/ios_artifacts.json"
        # Stash the parser script into the per-call output dir so it is mounted
        # into the container at /work and we can invoke it there directly.
        script_host = Path(ctx.output_dir) / "parse_ios.py"
        script_host.write_text(_PARSER_SCRIPT)

        cmd = [
            "python3", "/work/parse_ios.py",
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
                ctx.investigation_id, f"ileapp_parse failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"ileapp_parse failed: {e}",
            )

        # Parse the JSON the script wrote to /work (mounted at output_dir).
        rows: list[dict[str, Any]] = []
        summary = ""
        local_out = Path(ctx.output_dir) / "ios_artifacts.json"
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
tool = IleappTool()
