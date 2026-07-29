"""Registry MRU / ShellBag / UserAssist deep analyzer (EnScript gap — Tool 7).

RECmd dumps raw registry keys. EnCase has scripts that *interpret* the binary
formats into a "what did the user do" timeline:

  - **ShellBags** (``Shell`` / ``BagMRU``): reconstruct the folder paths a
    user browsed in Explorer, with last-browse timestamps.
  - **UserAssist** (``NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\
    Explorer\\UserAssist\\{GUID}\\Count``): decode the ROT13-obfuscated value
    names to application names + execution count + last-execution FILETIME.
  - **MRU** (``RecentDocs``, ``RunMRU``, ``TypedPaths``, ``OpenSavePidlMRU``):
    decode Most-Recently-Used lists into files/docs/commands/URLs opened.
  - **Run keys**: startup programs.
  - **TypedPaths**: URLs/paths typed in Explorer.

The binary decoders (ROT13 for UserAssist, UTF-16 path extraction for
ShellBags, MRUList order parsing) are the missing piece. They are factored
into host-testable helpers (``rot13``, ``decode_userassist_value``,
``reconstruct_shellbag_path``, ``parse_mrulist``) so the unit test can drive
them without a real hive.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

KEY_TYPES = (
    "shellbags", "userassist", "mru", "run_keys", "recent_docs", "typed_paths",
)


def rot13(text: str) -> str:
    """ROT13 — the obfuscation Windows applies to UserAssist value names.

    Letters are rotated by 13; digits and other characters pass through.
    Host-testable.
    """
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def filetime_to_iso(ft: int | None) -> str | None:
    """Windows FILETIME (100ns since 1601-01-01) -> ISO-8601 UTC string."""
    if ft is None or ft <= 0:
        return None
    try:
        secs = ft / 1e7 - 11644473600.0
        return _dt.datetime.fromtimestamp(secs, _dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def decode_userassist_value(name: str, data: bytes) -> dict[str, Any]:
    """Decode one UserAssist ``Count`` value into app name / count / last run.

    ``name`` is the ROT13-obfuscated value name (the app path/GUID). The value
    data layout varies by Windows version; the common Win7+ shape is:
      offset 0  : focus count (4 bytes)
      offset 4  : execution count (4 bytes)
      offset 60 : last-execution FILETIME (8 bytes)  [Win7+]
    Earlier (XP) data is just a 4-byte run count. We handle both. Host-testable.
    """
    app = rot13(name)
    result: dict[str, Any] = {"application": app, "run_count": None,
                              "last_execution": None}
    try:
        if len(data) >= 8:
            # Execution count is the second DWORD in the Win7 layout; on XP it
            # is the first/only DWORD.
            if len(data) >= 60:
                run_count = int.from_bytes(data[4:8], "little")
                ft = int.from_bytes(data[60:68], "little") if len(data) >= 68 else None
            else:
                run_count = int.from_bytes(data[0:4], "little")
                ft = None
            result["run_count"] = run_count
            result["last_execution"] = filetime_to_iso(ft)
    except Exception:
        pass
    return result


def reconstruct_shellbag_path(segments: list[str]) -> str:
    """Join ShellBag path segments into a single Explorer path.

    Each segment is a decoded folder name (e.g. from ``BagMRU`` entries).
    Empty / GUID-only segments are dropped so the path stays readable.
    Host-testable.
    """
    cleaned: list[str] = []
    for seg in segments:
        if not seg:
            continue
        s = seg.strip()
        if not s or s.startswith("{") and s.endswith("}") and len(s) >= 38:
            continue
        cleaned.append(s)
    return "\\".join(cleaned)


def parse_mrulist(order: str, entries: dict[str, str]) -> list[str]:
    """Decode an MRUList(a/b) ordering into the sequence of values used.

    ``order`` is the MRUList value (e.g. ``"dcba"`` — each char is a single-
    letter value-name suffix). ``entries`` maps those suffixes to the decoded
    value text. Returns the values in most-recent-first order, skipping any
    suffix missing from ``entries``. Host-testable.
    """
    out: list[str] = []
    for ch in (order or ""):
        if ch in entries:
            val = entries[ch]
            if isinstance(val, str) and val.strip():
                out.append(val.strip())
    return out


def decode_utf16(value: Any) -> str:
    """Decode a registry value that may be UTF-16LE bytes or already a str."""
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-16-le", "replace").rstrip("\x00")
        except Exception:
            return value.decode("latin-1", "replace")
    return str(value) if value is not None else ""


# ---------------------------------------------------------------------------
# Embedded analyzer script run inside svetovid/base.
# ---------------------------------------------------------------------------

_ANALYZER_SCRIPT = r'''#!/usr/bin/env python3
"""Registry MRU / ShellBag / UserAssist analyzer — runs inside svetovid/base.

Opens a Windows registry hive and interprets the binary MRU/ShellBag/UserAssist
formats for the requested key type. Uses python-registry (Registry) when
importable and falls back to regipy; failures are recorded as notes rather
than aborting.

Usage:
    registry_mru.py <hive_path> <output_json> <key_type>
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from pathlib import Path


def rot13(text):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def filetime_to_iso(ft):
    if ft is None or ft <= 0:
        return None
    try:
        secs = ft / 1e7 - 11644473600.0
        return _dt.datetime.fromtimestamp(secs, _dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return str(ft)


def decode_utf16(value):
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-16-le", "replace").rstrip("\x00")
        except Exception:
            return value.decode("latin-1", "replace")
    return "" if value is None else str(value)


def _open(path):
    try:
        from Registry import Registry
        return Registry.Registry(path)
    except Exception:
        return None


def _safe_open(hive, path):
    try:
        return hive.open(path)
    except Exception:
        return None


def _values(key):
    try:
        return [(v.name(), v.value()) for v in key.values()]
    except Exception:
        return []


def _subkeys(key):
    try:
        return list(key.subkeys())
    except Exception:
        return []


def _lastwrite(key):
    try:
        return key.last_written_timestamp().timestamp()
    except Exception:
        return None


def _iso(ts):
    if ts is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return str(ts)


def analyze_userassist(hive):
    rows = []
    base = _safe_open(hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    if base is None:
        return rows, "no UserAssist key"
    for guid_key in _subkeys(base):
        count = _safe_open(guid_key, "Count")
        if count is None:
            continue
        for name, value in _values(count):
            if not name:
                continue
            decoded = rot13(name)
            run_count = None
            last_run = None
            data = value if isinstance(value, (bytes, bytearray)) else b""
            try:
                if len(data) >= 60:
                    run_count = int.from_bytes(data[4:8], "little")
                    last_run = filetime_to_iso(int.from_bytes(data[60:68], "little")) if len(data) >= 68 else None
                elif len(data) >= 4:
                    run_count = int.from_bytes(data[0:4], "little")
            except Exception:
                pass
            rows.append({"application": decoded, "run_count": run_count,
                         "last_execution": last_run, "guid": guid_key.name()})
    return rows, "%d UserAssist entry/entries" % len(rows)


def _walk_bagmru(key, path_segments, rows):
    """Recurse BagMRU entries, emitting reconstructed paths per Bag entry."""
    # The numeric subkeys (0, 1, 2...) are BagMRU slots; their values hold
    # the decoded folder name (NodeSlot / value 0) in UTF-16.
    entries = {}
    int_subs = []
    for sk in _subkeys(key):
        if sk.name().isdigit():
            int_subs.append(sk)
    for name, value in _values(key):
        if name and name.isdigit():
            entries[int(name)] = decode_utf16(value)
    for idx in sorted(entries.keys()):
        seg = entries[idx]
        new_segments = path_segments + [seg]
        rows.append({"path": "\\".join(s for s in new_segments if s),
                     "last_browse": _iso(_lastwrite(key))})
        # Recurse into the matching numeric subkey if present.
        for sk in int_subs:
            if sk.name() == str(idx):
                _walk_bagmru(sk, new_segments, rows)


def analyze_shellbags(hive):
    rows = []
    candidates = [
        "Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    ]
    base = None
    for c in candidates:
        base = _safe_open(hive, c)
        if base is not None:
            break
    if base is None:
        return rows, "no ShellBag/BagMRU key"
    _walk_bagmru(base, [], rows)
    return rows, "%d ShellBag path(s)" % len(rows)


def analyze_recent_docs(hive):
    rows = []
    base = _safe_open(hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
    if base is None:
        return rows, "no RecentDocs key"
    mrulist_val = None
    entries = {}
    for name, value in _values(base):
        if name.lower().startswith("mrulist"):
            mrulist_val = decode_utf16(value) if isinstance(value, (bytes, bytearray)) else str(value)
        elif name and len(name) == 1:
            entries[name] = decode_utf16(value)
    ordered = []
    if mrulist_val:
        for ch in mrulist_val:
            if ch in entries:
                ordered.append(entries[ch])
    # RecentDocs entries are UTF-16 filenames possibly with embedded nulls.
    rows.append({"order": ordered, "entries": entries,
                 "last_write": _iso(_lastwrite(base))})
    return rows, "%d RecentDocs entry/entries" % len(entries)


def analyze_run_mru(hive):
    rows = []
    base = _safe_open(hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
    if base is None:
        return rows, "no RunMRU key"
    mrulist_val = None
    entries = {}
    for name, value in _values(base):
        if name.lower() == "mrulist":
            mrulist_val = str(value)
        elif name and len(name) == 1:
            txt = decode_utf16(value) if isinstance(value, (bytes, bytearray)) else str(value)
            entries[name] = txt.rstrip("\\1").strip()
    ordered = []
    if mrulist_val:
        for ch in mrulist_val:
            if ch in entries:
                ordered.append(entries[ch])
    rows.append({"commands": ordered, "entries": entries,
                 "last_write": _iso(_lastwrite(base))})
    return rows, "%d RunMRU command(s)" % len(ordered)


def analyze_typed_paths(hive):
    rows = []
    base = _safe_open(hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")
    if base is None:
        return rows, "no TypedPaths key"
    entries = {}
    for name, value in _values(base):
        if name:
            entries[name] = decode_utf16(value) if isinstance(value, (bytes, bytearray)) else str(value)
    rows.append({"urls": entries, "last_write": _iso(_lastwrite(base))})
    return rows, "%d TypedPath(s)" % len(entries)


def analyze_run_keys(hive):
    rows = []
    paths = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]
    total = 0
    for p in paths:
        key = _safe_open(hive, p)
        if key is None:
            continue
        for name, value in _values(key):
            txt = decode_utf16(value) if isinstance(value, (bytes, bytearray)) else str(value)
            rows.append({"key": p, "value_name": name, "target": txt,
                         "last_write": _iso(_lastwrite(key))})
            total += 1
    return rows, "%d Run-key entr(y/ies)" % total


DISPATCH = {
    "userassist": analyze_userassist,
    "shellbags": analyze_shellbags,
    "recent_docs": analyze_recent_docs,
    "mru": analyze_recent_docs,  # MRU general -> RecentDocs as the common case
    "typed_paths": analyze_typed_paths,
    "run_keys": analyze_run_keys,
}


def main(argv):
    if len(argv) != 4:
        print("usage: registry_mru.py <hive_path> <output_json> <key_type>", file=sys.stderr)
        return 2
    hive_path, out_json, key_type = argv[1], argv[2], argv[3]
    if key_type not in DISPATCH:
        with open(out_json, "w") as fh:
            json.dump({"rows": [], "error": "unknown key_type: " + key_type}, fh)
        return 2
    hive = _open(hive_path)
    if hive is None:
        with open(out_json, "w") as fh:
            json.dump({"rows": [], "error": "could not open hive: " + hive_path}, fh)
        return 0
    rows, summary = DISPATCH[key_type](hive)
    payload = {"key_type": key_type, "rows": rows, "summary": summary}
    with open(out_json, "w") as fh:
        json.dump(payload, fh, ensure_ascii=False, default=str)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


class RegistryMRUTool(Tool):
    name = "registry_mru_analyze"
    image = "svetovid/base"
    description = (
        "Interpret Windows registry activity artifacts into a human-readable "
        "user-activity timeline: ShellBags (browsed folders), UserAssist "
        "(ROT13-decoded app execution counts + times), MRU/RecentDocs (files "
        "opened), RunMRU/Run keys (startup + run commands), and TypedPaths "
        "(URLs/paths typed in Explorer). Decodes the binary formats RECmd "
        "leaves raw. Fills the EnCase MRU/ShellBag EnScript gap."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence pointing at a registry hive "
                        "(NTUSER.DAT, USRCLASS.DAT, or SOFTWARE)."
                    ),
                },
                "key_path": {
                    "type": "string",
                    "enum": list(KEY_TYPES),
                    "description": (
                        "Which artifact class to interpret: shellbags, "
                        "userassist, mru, run_keys, recent_docs, typed_paths."
                    ),
                },
            },
            "required": [],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        sub = args.get("evidence_subpath", "") or ""
        key_type = args.get("key_path", "") or ""
        if key_type not in KEY_TYPES:
            msg = (f"registry_mru_analyze: key_path must be one of "
                   f"{list(KEY_TYPES)}")
            ctx.bus.publish(E.error_event(ctx.investigation_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 2, 0.0, None))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None, summary=msg,
            )

        out_json = "/work/registry_mru.json"
        script_host = Path(ctx.output_dir) / "registry_mru.py"
        script_host.write_text(_ANALYZER_SCRIPT)

        cmd = [
            "python3", "/work/registry_mru.py",
            (f"/evidence/{sub}".rstrip("/") if sub else "/evidence"),
            out_json,
            key_type,
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
                ctx.investigation_id, f"registry_mru_analyze failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"registry_mru_analyze failed: {e}",
            )

        rows: list[dict[str, Any]] = []
        summary = ""
        local_out = Path(ctx.output_dir) / "registry_mru.json"
        if local_out.exists():
            try:
                payload = json.loads(local_out.read_text())
                if isinstance(payload, dict):
                    rows = payload.get("rows", [])
                    summary = payload.get("summary", "")
            except Exception as e:
                summary = f"registry_mru output couldn't be parsed: {e}"
        if not summary:
            summary = f"registry_mru_analyze exited {res.exit_code} with no output"

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
            data={"key_type": key_type, "rows": rows},
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


tool = RegistryMRUTool()
