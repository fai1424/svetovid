"""Timeline gap / tampering detector (EnScript gap — Tool 2).

EnCase ships scripts that detect *absence* of events: gaps in event logs that
indicate clearing/tampering, and $SI-vs-$FN timestamp deltas in the MFT that
indicate timestomping. Chainsaw and Hayabusa find *hits*; they don't flag the
silence between them. This tool does.

Two analyses:
  - **Gap detection**: extract all event timestamps from EVTX (and from any
    plain timestamp / JSONL logs in the evidence path), sort them, and flag
    inter-event intervals that exceed ``sensitivity`` standard deviations of
    the mean interval. A 48-hour hole in a normally hourly Security log is a
    classic sign of ``wevtutil cl`` (log clearing).
  - **Timestomping**: if the evidence contains an MFT body file (TSK
    ``mactime`` output or a body file), compare $STANDARD_INFORMATION times
    against $FILE_NAME times for each record. A large positive delta
    ($SI newer than $FN) on an executable is a strong timestomp signal —
    $FN times are set at file creation and are harder to forge than $SI.

The gap-detection statistics are factored into host-testable helpers
(``detect_gaps``) so the unit test can drive them with synthetic timestamps.
Runs inside ``svetovid/base`` (python3 stdlib + optional python-evtx).
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

FREQUENCIES = ("hourly", "daily", "weekly")
# Expected inter-event interval (hours) per declared frequency. Used to
# sanity-check whether a detected gap is "missing N expected events" rather
# than just a quiet period.
EXPECTED_INTERVAL_HOURS = {"hourly": 1.0, "daily": 24.0, "weekly": 168.0}
DEFAULT_SENSITIVITY = 2.0
# $SI vs $FN delta (seconds) above which we flag a timestomp suspect.
TIMESTOMP_DELTA_THRESHOLD_S = 3600.0


def detect_gaps(
    timestamps: list[float],
    sensitivity: float = DEFAULT_SENSITIVITY,
    expected_interval_hours: float | None = None,
) -> list[dict[str, Any]]:
    """Given epoch-second timestamps (sorted or not), return gap records.

    A gap is an inter-event interval strictly greater than
    ``mean + sensitivity * stdev`` of all intervals. Each gap reports its
    start/end epoch, duration in hours, and (if an expected interval is given)
    how many events "should" have appeared in the hole. Host-testable.
    """
    ts = sorted(float(t) for t in timestamps if t is not None)
    if len(ts) < 3:
        return []
    intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    mean = statistics.fmean(intervals)
    try:
        stdev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
    except statistics.StatisticsError:
        stdev = 0.0
    threshold = mean + sensitivity * stdev if stdev > 0 else mean * (1 + sensitivity)
    gaps: list[dict[str, Any]] = []
    for i, gap in enumerate(intervals):
        if gap > threshold and gap > 0:
            duration_hours = gap / 3600.0
            record: dict[str, Any] = {
                "start": ts[i],
                "end": ts[i + 1],
                "duration_hours": round(duration_hours, 3),
                "expected_events": 0,
                "actual_events": 0,
            }
            if expected_interval_hours:
                expected = int(duration_hours // float(expected_interval_hours))
                record["expected_events"] = expected
                record["actual_events"] = 0
            gaps.append(record)
    return gaps


def detect_timestomps(body_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Given MFT body-file-style rows, flag $SI vs $FN timestamp deltas.

    Each row may carry ``si_time`` / ``fn_time`` (epoch seconds) plus ``file``.
    Records where $SI is materially newer than $FN (the creation-time
    timestomping signature) are returned. Host-testable.
    """
    suspects: list[dict[str, Any]] = []
    for row in body_rows:
        si = row.get("si_time")
        fn = row.get("fn_time")
        if si is None or fn is None:
            continue
        try:
            delta = float(si) - float(fn)
        except (TypeError, ValueError):
            continue
        if delta >= TIMESTOMP_DELTA_THRESHOLD_S:
            suspects.append({
                "file": row.get("file", ""),
                "si_time": si,
                "fn_time": fn,
                "delta_seconds": round(delta, 3),
            })
    return suspects


# ---------------------------------------------------------------------------
# Embedded analyzer script run inside svetovid/base.
# ---------------------------------------------------------------------------

_ANALYZER_SCRIPT = r'''#!/usr/bin/env python3
"""Timeline gap / timestomp analyzer — runs inside svetovid/base.

Walks the evidence path collecting event timestamps from EVTX files and from
plain-text / JSONL log lines carrying ISO-8601 timestamps, then computes gaps.
Optionally reads an MFT body file (``*.body`` / ``mactime`` output) for
$SI-vs-$FN timestomping. Writes JSON to the output path.

Timestamps are accepted in these per-line forms (first match wins):
  - bare ISO-8601 / common date prefixes  (2026-07-29T13:01:22Z ...)
  - JSON object with a ``time``/``timestamp``/@timestamp`` field
  - log lines with an ISO timestamp in the first 40 chars

Usage:
    timeline_gap.py <evidence_path> <output_json> <frequency> <sensitivity>
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import statistics
import sys
from pathlib import Path

EVTX_MAGIC = b"ElfFile\x00"
_TS_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)"
)
FREQUENCIES = {"hourly": 1.0, "daily": 24.0, "weekly": 168.0}
TIMESTOMP_DELTA_S = 3600.0


def _to_epoch(s):
    if s is None:
        return None
    if isinstance(s, (int, float)):
        return float(s)
    s = str(s).strip()
    # Strip a trailing Z and fractional seconds for fromisoformat compatibility.
    iso = s
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    for fmt in (None, "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            if fmt is None:
                dt = _dt.datetime.fromisoformat(iso)
            else:
                dt = _dt.datetime.strptime(s, fmt)
                dt = dt.replace(tzinfo=_dt.timezone.utc) if dt.tzinfo is None else dt
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_dt.timezone.utc)
            return dt.timestamp()
        except (ValueError, TypeError):
            continue
    return None


def _evtx_timestamps(path):
    """Best-effort EVTX timestamp extraction.

    Tries python-evtx if importable; on any failure (broken install, corrupt
    file) falls back to scanning the raw bytes for embedded FILETIME/ISO
    stamps. We never let a single unreadable .evtx abort the whole scan.
    """
    stamps = []
    raw = b""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return stamps, "unreadable"

    # Try python-evtx. Its import is fragile across installs, so guard heavily.
    try:
        import Evtx.Evtx as _evtx_mod  # type: ignore
        with _evtx_mod.Evtx(path) as log:
            for rec in log.records():
                try:
                    root = rec.root()
                    # python-evtx exposes .timestamp() on the record via xml too.
                    ts_str = rec.timestamp().isoformat()
                    e = _to_epoch(ts_str)
                    if e is not None:
                        stamps.append(e)
                        continue
                except Exception:
                    continue
                # Fallback: pull TimeCreated SystemTime from XML.
                try:
                    xml = rec.xml()
                    m = _TS_RE.search(xml)
                    if m:
                        e = _to_epoch(m.group(1))
                        if e is not None:
                            stamps.append(e)
                except Exception:
                    continue
        if stamps:
            return stamps, "python-evtx"
    except Exception:
        pass

    # Fallback: scan raw text for ISO timestamps inside the binary.
    text = raw.decode("utf-8", "replace")
    for m in _TS_RE.finditer(text):
        e = _to_epoch(m.group(1))
        if e is not None:
            stamps.append(e)
    return stamps, "raw-scan" if stamps else "none"


def collect_timestamps(root):
    """Walk the evidence tree, returning (timestamps, per_source_counts)."""
    stamps = []
    counts = {"evtx": 0, "text": 0, "jsonl": 0}
    files = sorted(root.rglob("*")) if root.is_dir() else [root]
    for f in files:
        if not f.is_file():
            continue
        head = b""
        try:
            with open(f, "rb") as fh:
                head = fh.read(8)
        except OSError:
            continue
        if head.startswith(EVTX_MAGIC):
            s, _ = _evtx_timestamps(f)
            stamps.extend(s)
            counts["evtx"] += len(s)
            continue
        # Text / JSONL mining.
        try:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("{"):
                        try:
                            obj = json.loads(line)
                        except ValueError:
                            obj = None
                        if isinstance(obj, dict):
                            for k in ("@timestamp", "timestamp", "time", "TimeCreated"):
                                if k in obj:
                                    e = _to_epoch(obj[k])
                                    if e is not None:
                                        stamps.append(e)
                                        counts["jsonl"] += 1
                                        break
                            continue
                    m = _TS_RE.search(line[:60])
                    if m:
                        e = _to_epoch(m.group(1))
                        if e is not None:
                            stamps.append(e)
                            counts["text"] += 1
        except OSError:
            continue
    return stamps, counts


def parse_body_file(path):
    """Parse a TSK body file into rows with si_time/fn_time/file.

    Body file columns: md5|name|inode|mode_as_string|uid|gid|size|atime|
    mtime|ctime|crtime. mactime uses the same layout. We treat mtime as $SI
    and crtime as $FN (creation) for the timestomp comparison.
    """
    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("|")
                if len(parts) < 11:
                    continue
                name = parts[1]
                try:
                    mtime = float(parts[8]) if parts[8] else None
                    crtime = float(parts[10]) if parts[10] else None
                except ValueError:
                    continue
                if mtime and crtime:
                    rows.append({"file": name, "si_time": mtime, "fn_time": crtime})
    except OSError:
        pass
    return rows


def detect_gaps(ts, sensitivity, expected_interval_hours):
    ts = sorted(float(t) for t in ts if t is not None)
    if len(ts) < 3:
        return []
    intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    mean = statistics.fmean(intervals)
    try:
        stdev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
    except statistics.StatisticsError:
        stdev = 0.0
    threshold = mean + sensitivity * stdev if stdev > 0 else mean * (1 + sensitivity)
    gaps = []
    for i, gap in enumerate(intervals):
        if gap > threshold and gap > 0:
            hours = gap / 3600.0
            rec = {"start": ts[i], "end": ts[i + 1],
                   "duration_hours": round(hours, 3),
                   "expected_events": 0, "actual_events": 0}
            if expected_interval_hours:
                rec["expected_events"] = int(hours // float(expected_interval_hours))
            gaps.append(rec)
    return gaps


def main(argv):
    if len(argv) != 5:
        print("usage: timeline_gap.py <evidence_path> <output_json> "
              "<frequency> <sensitivity>", file=sys.stderr)
        return 2
    evidence_path, out_json, frequency, sensitivity_s = argv[1:5]
    try:
        sensitivity = float(sensitivity_s)
    except ValueError:
        sensitivity = 2.0
    expected = FREQUENCIES.get(frequency, None)
    root = Path(evidence_path)
    if not root.exists():
        payload = {"gaps": [], "timestomp_suspects": [],
                   "error": "path not found: " + evidence_path}
        with open(out_json, "w") as fh:
            json.dump(payload, fh, ensure_ascii=False, default=str)
        return 0

    stamps, counts = collect_timestamps(root)
    gaps = detect_gaps(stamps, sensitivity, expected)

    # Timestomp: look for body / mactime files anywhere in the tree.
    suspects = []
    body_files = ([p for p in root.rglob("*.body")] +
                  [p for p in root.rglob("mactime*")] if root.is_dir() else [])
    for bf in body_files:
        for row in parse_body_file(bf):
            si, fn = row.get("si_time"), row.get("fn_time")
            if si is None or fn is None:
                continue
            delta = float(si) - float(fn)
            if delta >= TIMESTOMP_DELTA_S:
                suspects.append({"file": row.get("file", ""), "si_time": si,
                                 "fn_time": fn, "delta_seconds": round(delta, 3)})

    summary = (str(len(gaps)) + " gap(s) from " + str(len(stamps)) +
               " events; " + str(len(suspects)) + " timestomp suspect(s)")
    payload = {"gaps": gaps, "timestomp_suspects": suspects,
               "events_examined": len(stamps), "source_counts": counts,
               "sensitivity": sensitivity, "frequency": frequency,
               "summary": summary}
    with open(out_json, "w") as fh:
        json.dump(payload, fh, ensure_ascii=False, default=str)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


class TimelineGapTool(Tool):
    name = "timeline_gap_analysis"
    image = "svetovid/base"
    description = (
        "Detect gaps and tampering in event timelines. Extracts timestamps "
        "from EVTX and text/JSONL logs, flags inter-event intervals that "
        "exceed N standard deviations of the mean (evidence of log "
        "clearing/tampering), and checks MFT body files for $SI vs $FN "
        "timestamp deltas (timestomping). Fills the EnCase timeline-gap / "
        "tampering EnScript gap."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence to analyze (directory of "
                        ".evtx / logs, optionally with MFT body files)."
                    ),
                },
                "expected_frequency": {
                    "type": "string",
                    "enum": list(FREQUENCIES),
                    "default": "daily",
                    "description": (
                        "How often events should appear — used to estimate "
                        "how many events a detected gap 'swallowed'."
                    ),
                },
                "sensitivity": {
                    "type": "number",
                    "default": DEFAULT_SENSITIVITY,
                    "description": (
                        "Standard deviations above the mean interval that "
                        "counts as a gap (higher = fewer, larger gaps)."
                    ),
                },
            },
            "required": [],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        sub = args.get("evidence_subpath", "") or ""
        frequency = args.get("expected_frequency", "daily")
        if frequency not in FREQUENCIES:
            frequency = "daily"
        sensitivity = float(args.get("sensitivity", DEFAULT_SENSITIVITY))

        out_json = "/work/timeline_gap.json"
        script_host = Path(ctx.output_dir) / "timeline_gap.py"
        script_host.write_text(_ANALYZER_SCRIPT)

        cmd = [
            "python3", "/work/timeline_gap.py",
            (f"/evidence/{sub}".rstrip("/") if sub else "/evidence"),
            out_json,
            frequency,
            str(sensitivity),
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
                ctx.investigation_id, f"timeline_gap_analysis failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"timeline_gap_analysis failed: {e}",
            )

        gaps: list[dict[str, Any]] = []
        timestomp_suspects: list[dict[str, Any]] = []
        summary = ""
        local_out = Path(ctx.output_dir) / "timeline_gap.json"
        if local_out.exists():
            try:
                payload = json.loads(local_out.read_text())
                if isinstance(payload, dict):
                    gaps = payload.get("gaps", [])
                    timestomp_suspects = payload.get("timestomp_suspects", [])
                    summary = payload.get("summary", "")
            except Exception as e:
                summary = f"timeline_gap output couldn't be parsed: {e}"
        if not summary:
            summary = f"timeline_gap_analysis exited {res.exit_code} with no output"

        output_hash = _hash_file(local_out)
        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s,
            output_hash,
        ))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": args,
            "exit_code": res.exit_code, "duration_s": res.duration_s,
            "output_hash": output_hash, "ts": E._now_iso(),
        }))

        try:
            from ._reporting import record_tool_call_db
            await record_tool_call_db(
                call_id=call_id, investigation_id=ctx.investigation_id,
                tool=self.name, args=args, exit_code=res.exit_code,
                duration_s=res.duration_s, output_hash=output_hash,
            )
        except Exception:
            pass

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
            output_path=str(local_out) if local_out.exists() else None,
            summary=summary,
            data={"gaps": gaps, "timestomp_suspects": timestomp_suspects},
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


tool = TimelineGapTool()
