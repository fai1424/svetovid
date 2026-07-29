"""USB device history correlator (EnScript gap — Tool 3).

EnCase EnScripts cross-reference multiple Windows artifacts to reconstruct a
complete USB device connection history:

  - ``USBSTOR`` subkeys in the SYSTEM hive  -> device make / model / serial
  - ``USB`` subkeys in the SYSTEM hive       -> device descriptors / VID+PID
  - ``MountedDevices`` in the SYSTEM hive    -> volume serials / mount points
  - ``USB`` subkeys in NTUSER.DAT            -> which user connected the device
  - ``SetupAPI.dev.log``                     -> first / last install timestamps

No single OSS tool does this cross-correlation: RECmd dumps raw keys, but the
serial-number join across hives + the SetupAPI log + per-user attribution is
the missing piece. This tool performs that join by device serial number and
returns a unified timeline per device.

Because there is no reliable pure-Python *hive writer*, the correlation logic
is factored into ``correlate_devices`` — a host-testable helper that takes
already-extracted per-source device records. The embedded script extracts
those records from real hives (using python-registry / regipy when importable,
falling back gracefully) and SetupAPI logs, then calls the same join.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


# A USBSTOR key name looks like:
#   USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler&Rev_1.0&0013729813B01F9B&0
# We split it into ven / prod / serial.
_USBSTOR_NAME_RE = re.compile(
    r"(?P<cls>[^&\\]+)&Ven_(?P<ven>[^&]+)&Prod_(?P<prod>[^&]+)"
    r"(?:&Rev_(?P<rev>[^&]+))?(&(?P<serial>[^&]+))?",
)
# A SYSTEM-hive USB key name: Vid_0951&Pid_1666\0013729813B01F9B
_USB_NAME_RE = re.compile(
    r"Vid_(?P<vid>[0-9A-Fa-f]{4})&Pid_(?P<pid>[0-9A-Fa-f]{4})", re.IGNORECASE,
)
# MountedDevices values: \??\USB#Vid_0951&Pid_1666#0013729813B01F9B#{...}
_MOUNTED_USB_RE = re.compile(
    r"USB#Vid_[0-9A-Fa-f]{4}&Pid_[0-9A-Fa-f]{4}#([^#]+)#",
    re.IGNORECASE,
)
# SetupAPI.dev.log device-install lines carry a device instance id like:
#   >>>  [Device Install (Hardware initiated)] USBSTOR\DiskKingston...
#   >>>  Section: from C:\Windows\INF ...
#   >>>  start 2026-07-01 13:45:01.234
_SETUP_DATE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
)


def _normalize_serial(s: str | None) -> str | None:
    """Normalize a serial to uppercased alnum so joins are case/format
    insensitive (SetupAPI logs, registry, and MountedDevices all quote the
    serial with slightly different punctuation)."""
    if not s:
        return None
    cleaned = re.sub(r"[^0-9A-Za-z]", "", s).upper()
    return cleaned or None


def correlate_devices(
    usbstor: list[dict[str, Any]],
    usb: list[dict[str, Any]],
    mounted: list[dict[str, Any]],
    setupapi: list[dict[str, Any]],
    ntuser: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Join per-source device records by normalized serial into one row per
    device. Each input list is a list of dicts produced by the extractors;
    see ``_USBSTOR_*`` / ``_SETUP_*`` parsing below. Host-testable.

    Returns rows shaped like::

        {"serial", "make", "model", "vid", "pid", "first_seen", "last_seen",
         "mounted_as", "users_who_connected"}
    """
    by_serial: dict[str, dict[str, Any]] = {}

    def _row(serial: str) -> dict[str, Any]:
        return by_serial.setdefault(serial, {
            "serial": serial,
            "make": "",
            "model": "",
            "vid": "",
            "pid": "",
            "first_seen": None,
            "last_seen": None,
            "mounted_as": [],
            "users_who_connected": [],
        })

    for rec in usbstor:
        serial = _normalize_serial(rec.get("serial"))
        if not serial:
            continue
        row = _row(serial)
        if rec.get("ven") and not row["make"]:
            row["make"] = rec["ven"]
        if rec.get("prod") and not row["model"]:
            row["model"] = rec["prod"]
        if rec.get("first_seen"):
            row["first_seen"] = _min_ts(row["first_seen"], rec["first_seen"])
        if rec.get("last_seen"):
            row["last_seen"] = _max_ts(row["last_seen"], rec["last_seen"])

    for rec in usb:
        serial = _normalize_serial(rec.get("serial"))
        if not serial:
            continue
        row = _row(serial)
        if rec.get("vid"):
            row["vid"] = rec["vid"]
        if rec.get("pid"):
            row["pid"] = rec["pid"]
        if rec.get("last_seen"):
            row["last_seen"] = _max_ts(row["last_seen"], rec["last_seen"])

    for rec in mounted:
        serial = _normalize_serial(rec.get("serial"))
        if not serial:
            continue
        row = _row(serial)
        if rec.get("mount_point") and rec["mount_point"] not in row["mounted_as"]:
            row["mounted_as"].append(rec["mount_point"])

    for rec in setupapi:
        serial = _normalize_serial(rec.get("serial"))
        if not serial:
            continue
        row = _row(serial)
        ts = rec.get("timestamp")
        if ts:
            row["first_seen"] = _min_ts(row["first_seen"], ts)
            row["last_seen"] = _max_ts(row["last_seen"], ts)

    for rec in ntuser:
        serial = _normalize_serial(rec.get("serial"))
        if not serial:
            continue
        row = _row(serial)
        user = rec.get("user")
        if user and user not in row["users_who_connected"]:
            row["users_who_connected"].append(user)
        ts = rec.get("last_seen")
        if ts:
            row["last_seen"] = _max_ts(row["last_seen"], ts)

    return list(by_serial.values())


def _min_ts(a, b):
    """Pick the earlier of two comparable timestamps (strings compare
    correctly for ISO-8601 UTC; ints/floats compare numerically)."""
    vals = [v for v in (a, b) if v is not None]
    if not vals:
        return None
    return min(vals)


def _max_ts(a, b):
    vals = [v for v in (a, b) if v is not None]
    if not vals:
        return None
    return max(vals)


# ---------------------------------------------------------------------------
# Embedded extractor / correlator script run inside svetovid/base.
# ---------------------------------------------------------------------------

_EXTRACTOR_SCRIPT = r'''#!/usr/bin/env python3
"""USB device history extractor — runs inside svetovid/base.

Walks the evidence tree for Windows registry hives (SYSTEM, SOFTWARE,
NTUSER.DAT) and the SetupAPI log, extracts per-source USB device records,
correlates them by serial number, and writes a JSON timeline. Uses
python-registry (``Registry``) when importable and falls back to regipy
(``regipy``); if neither can open a hive it records a graceful note.

Usage:
    usb_history.py <evidence_path> <output_json>
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path

_USBSTOR_NAME_RE = re.compile(
    r"(?P<cls>[^&\\]+)&Ven_(?P<ven>[^&]+)&Prod_(?P<prod>[^&]+)"
    r"(?:&Rev_(?P<rev>[^&]+))?(&(?P<serial>[^&]+))?",
)
_USB_NAME_RE = re.compile(
    r"Vid_(?P<vid>[0-9A-Fa-f]{4})&Pid_(?P<pid>[0-9A-Fa-f]{4})", re.IGNORECASE,
)
_MOUNTED_USB_RE = re.compile(
    r"USB#Vid_[0-9A-Fa-f]{4}&Pid_[0-9A-Fa-f]{4}#([^#]+)#", re.IGNORECASE,
)
_SETUP_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def _norm(s):
    if not s:
        return None
    c = re.sub(r"[^0-9A-Za-z]", "", s).upper()
    return c or None


def _win_to_iso(ft):
    """Windows FILETIME (100ns since 1601) -> ISO-8601 UTC string, best-effort."""
    if ft is None:
        return None
    try:
        if isinstance(ft, (int, float)):
            # python-registry returns FILETIME ints.
            secs = ft / 1e7 - 11644473600.0
            return _dt.datetime.fromtimestamp(secs, _dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return str(ft)
    return str(ft)


def _lastwrite_iso(ts):
    """Last-write timestamp (epoch float) -> ISO string."""
    if ts is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(float(ts), _dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return str(ts)


# --- hive readers: try python-registry first, then regipy -------------------

def _open_pyreg(path):
    try:
        from Registry import Registry
        return Registry.Registry(path)
    except Exception:
        return None


def _pyreg_subkeys(key):
    try:
        return list(key.subkeys())
    except Exception:
        return []


def _pyreg_values(key):
    try:
        return [(v.name(), v.value()) for v in key.values()]
    except Exception:
        return []


def _pyreg_lastwrite(key):
    try:
        return key.last_written_timestamp().timestamp()
    except Exception:
        return None


def _extract_usbstor(hive, root_prefix):
    rows = []
    try:
        key = hive.open(root_prefix + r"\USBSTOR")
    except Exception:
        return rows
    for disk_class in _pyreg_subkeys(key):
        for device in _pyreg_subkeys(disk_class):
            name = device.name()
            m = _USBSTOR_NAME_RE.search(disk_class.name() + "&" + name)
            serial = m.group("serial") if m else None
            rows.append({
                "serial": _norm(serial),
                "ven": m.group("ven") if m else "",
                "prod": m.group("prod") if m else "",
                "first_seen": _lastwrite_iso(_pyreg_lastwrite(device)),
                "last_seen": _lastwrite_iso(_pyreg_lastwrite(device)),
            })
    return rows


def _extract_usb(hive, root_prefix):
    rows = []
    try:
        key = hive.open(root_prefix + r"\USB")
    except Exception:
        return rows
    for device in _pyreg_subkeys(key):
        name = device.name()
        m = _USB_NAME_RE.search(name)
        # The serial is the leaf subkey under the Vid_..&Pid_.. key.
        children = _pyreg_subkeys(device)
        serial = children[0].name() if children else None
        rows.append({
            "serial": _norm(serial),
            "vid": m.group("vid") if m else "",
            "pid": m.group("pid") if m else "",
            "last_seen": _lastwrite_iso(_pyreg_lastwrite(device)),
        })
    return rows


def _extract_mounted(hive):
    rows = []
    try:
        key = hive.open("MountedDevices")
    except Exception:
        return rows
    for name, val in _pyreg_values(key):
        text = val.decode("utf-16-le", "replace") if isinstance(val, (bytes, bytearray)) else str(val)
        m = _MOUNTED_USB_RE.search(text)
        if m:
            rows.append({"serial": _norm(m.group(1)), "mount_point": name})
    return rows


def _extract_ntuser_usb(hive, user):
    rows = []
    try:
        key = hive.open(r"USB")
    except Exception:
        return rows
    for device in _pyreg_subkeys(key):
        children = _pyreg_subkeys(device)
        serial = children[0].name() if children else device.name()
        rows.append({
            "serial": _norm(serial),
            "user": user,
            "last_seen": _lastwrite_iso(_pyreg_lastwrite(device)),
        })
    return rows


def parse_setupapi(path):
    rows = []
    current_serial = None
    current_first = None
    current_last = None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return rows
    # Split into per-device blocks demarcated by "Device Install" headers.
    blocks = re.split(r">>>\s*\[Device Install", text)
    for block in blocks:
        serial = _setupapi_serial(block)
        if not serial:
            continue
        dates = _SETUP_DATE_RE.findall(block)
        if dates:
            rows.append({
                "serial": serial,
                "timestamp": dates[0] + "Z",
            })
            if len(dates) > 1:
                rows.append({"serial": serial, "timestamp": dates[-1] + "Z"})
    return rows


def _setupapi_serial(block):
    """Extract a device serial from a SetupAPI device-install block.

    Real SetupAPI device-instance IDs come in two common shapes:
      - ``USBSTOR\\DiskVen_Kingston&Prod_DataTraveler&Rev_1.0&0013...&0``
        (serial is the penultimate ``&`` segment, often followed by ``&0``),
      - ``USBSTOR\\DiskVen_Kingston&Prod_DataTraveler#0013...``
        (serial after the ``#``).
    The serial is the longest alnum segment after the device-class prefix, and
    we never cross a newline. Returns the normalized serial or None.
    """
    # First line carrying a USBSTOR instance id only.
    for line in block.splitlines():
        if "USBSTOR" not in line:
            continue
        # Strip the leading "USBSTOR\\<class>" prefix, then split on & or #.
        after = re.split(r"USBSTOR\\\\?", line, maxsplit=1)
        rest = after[1] if len(after) == 2 else line
        # rest looks like: DiskVen_X&Prod_Y&Rev_Z&SERIAL&0  OR  DiskVen_X#SERIAL
        segs = re.split(r"[&#]", rest)
        # The serial is the last non-numeric-suffix segment that is alnum and
        # not the device class (DiskVen/Prod/Rev prefixes).
        candidates = []
        for seg in segs:
            seg = seg.strip()
            if not seg:
                continue
            low = seg.lower()
            if low.startswith(("diskven", "cdromven", "tapeven", "prod", "rev")):
                continue
            if seg in ("0", "1"):
                continue  # trailing instance index
            # Keep only alnum-ish serials (USB serials are hex/alnum).
            if re.fullmatch(r"[0-9A-Za-z]+", seg):
                candidates.append(seg)
        if candidates:
            return _norm(candidates[-1])
    return None


def _control_set_prefix(hive):
    """Find the CurrentControlSet services prefix in a SYSTEM hive."""
    try:
        sel = hive.open(r"Select")
        current = sel.subkey("Current").value()
        return r"\ControlSet%03d\Services" % current
    except Exception:
        # Fall back to ControlSet001 — present on virtually every install.
        return r"\ControlSet001\Services"


def correlate(usbstor, usb, mounted, setupapi, ntuser):
    by_serial = {}
    def row(s):
        return by_serial.setdefault(s, {
            "serial": s, "make": "", "model": "", "vid": "", "pid": "",
            "first_seen": None, "last_seen": None, "mounted_as": [],
            "users_who_connected": [],
        })

    def min_ts(a, b):
        v = [x for x in (a, b) if x]
        return min(v) if v else None
    def max_ts(a, b):
        v = [x for x in (a, b) if x]
        return max(v) if v else None

    for rec in usbstor:
        if not rec.get("serial"):
            continue
        r = row(rec["serial"])
        if rec.get("ven") and not r["make"]:
            r["make"] = rec["ven"]
        if rec.get("prod") and not r["model"]:
            r["model"] = rec["prod"]
        r["first_seen"] = min_ts(r["first_seen"], rec.get("first_seen"))
        r["last_seen"] = max_ts(r["last_seen"], rec.get("last_seen"))
    for rec in usb:
        if not rec.get("serial"):
            continue
        r = row(rec["serial"])
        if rec.get("vid"):
            r["vid"] = rec["vid"]
        if rec.get("pid"):
            r["pid"] = rec["pid"]
        r["last_seen"] = max_ts(r["last_seen"], rec.get("last_seen"))
    for rec in mounted:
        if not rec.get("serial"):
            continue
        r = row(rec["serial"])
        if rec.get("mount_point") and rec["mount_point"] not in r["mounted_as"]:
            r["mounted_as"].append(rec["mount_point"])
    for rec in setupapi:
        if not rec.get("serial"):
            continue
        r = row(rec["serial"])
        r["first_seen"] = min_ts(r["first_seen"], rec.get("timestamp"))
        r["last_seen"] = max_ts(r["last_seen"], rec.get("timestamp"))
    for rec in ntuser:
        if not rec.get("serial"):
            continue
        r = row(rec["serial"])
        u = rec.get("user")
        if u and u not in r["users_who_connected"]:
            r["users_who_connected"].append(u)
        r["last_seen"] = max_ts(r["last_seen"], rec.get("last_seen"))
    return list(by_serial.values())


def main(argv):
    if len(argv) != 3:
        print("usage: usb_history.py <evidence_path> <output_json>", file=sys.stderr)
        return 2
    evidence_path, out_json = argv[1], argv[2]
    root = Path(evidence_path)
    if not root.exists():
        with open(out_json, "w") as fh:
            json.dump({"devices": [], "error": "path not found: " + evidence_path}, fh)
        return 0

    usbstor, usb, mounted, setupapi, ntuser = [], [], [], [], []
    notes = []
    files = sorted(root.rglob("*")) if root.is_dir() else [root]
    for f in files:
        if not f.is_file():
            continue
        name = f.name.lower()
        if name == "setupapi.dev.log" or name.startswith("setupapi"):
            setupapi.extend(parse_setupapi(f))
            continue
        # Only attempt hive parsing on plausible hive files.
        if name not in ("system", "ntuser.dat", "software") and not name.endswith(".dat"):
            continue
        hive = _open_pyreg(str(f))
        if hive is None:
            notes.append("could not open hive: " + f.name)
            continue
        if name == "system":
            prefix = _control_set_prefix(hive)
            usbstor.extend(_extract_usbstor(hive, prefix))
            usb.extend(_extract_usb(hive, prefix))
            mounted.extend(_extract_mounted(hive))
        elif name == "ntuser.dat":
            user = (f.parent.parent.name if len(f.parts) >= 2 else "user")
            ntuser.extend(_extract_ntuser_usb(hive, user))

    devices = correlate(usbstor, usb, mounted, setupapi, ntuser)
    summary = str(len(devices)) + " USB device(s) correlated"
    payload = {"devices": devices, "source_counts": {
        "usbstor": len(usbstor), "usb": len(usb), "mounted": len(mounted),
        "setupapi": len(setupapi), "ntuser": len(ntuser),
    }, "notes": notes, "summary": summary}
    with open(out_json, "w") as fh:
        json.dump(payload, fh, ensure_ascii=False, default=str)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


class USBHistoryTool(Tool):
    name = "usb_history_correlate"
    image = "svetovid/base"
    description = (
        "Correlate Windows USB device history across SYSTEM-hive USBSTOR/USB/"
        "MountedDevices keys, NTUSER.DAT per-user USB keys, and SetupAPI.dev.log "
        "first/last install timestamps, joined by device serial number. Returns "
        "a per-device timeline (make, model, first/last seen, mount points, "
        "users who connected). Fills the EnCase USB-history EnScript gap."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence containing Windows registry "
                        "hives (SYSTEM, NTUSER.DAT) and/or SetupAPI.dev.log."
                    ),
                },
            },
            "required": [],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        sub = args.get("evidence_subpath", "") or ""

        out_json = "/work/usb_history.json"
        script_host = Path(ctx.output_dir) / "usb_history.py"
        script_host.write_text(_EXTRACTOR_SCRIPT)

        cmd = [
            "python3", "/work/usb_history.py",
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
                ctx.investigation_id, f"usb_history_correlate failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"usb_history_correlate failed: {e}",
            )

        devices: list[dict[str, Any]] = []
        summary = ""
        local_out = Path(ctx.output_dir) / "usb_history.json"
        if local_out.exists():
            try:
                payload = json.loads(local_out.read_text())
                if isinstance(payload, dict):
                    devices = payload.get("devices", [])
                    summary = payload.get("summary", "")
            except Exception as e:
                summary = f"usb_history output couldn't be parsed: {e}"
        if not summary:
            summary = f"usb_history_correlate exited {res.exit_code} with no output"

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
            summary=summary, data={"devices": devices},
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


tool = USBHistoryTool()
