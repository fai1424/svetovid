"""ALEAPP Android artifact parser tool wrapper (research item C12b).

Parses the common Android mobile-forensics artifacts using only the standard
Python modules already present in the ``svetovid/base`` image (python3 +
``sqlite3``, ``json`` and the ``email``/xml stdlib helpers). One tool,
``aleapp_parse``, takes an ``artifact_type`` selector and an
``evidence_subpath`` and returns structured rows. Supported:

  - contacts        : contacts2.db contacts table → name, phone, email, org
  - sms_mms         : mmssms.db sms/mms/pdu tables → address, body, date, type
  - call_log        : contacts2.db / calllog.db calls table → number, date, duration, type
  - usage_stats     : usagestats XML/binary under /system/usagestats → app usage timeline
  - chrome_history  : Chrome com.android.chrome History SQLite → urls, visits, search terms
  - location_history: Google location-history / fused location SQLite + JSON payloads
  - accounts        : accounts.db / Google AccountManager SQLite → account type + name
  - app_metadata    : packages.xml (+ V1/V2 backup) → sideloaded / suspicious packages
  - wifi_config     : WifiConfigStore.xml → known SSIDs + creds / softap config
  - firebase        : Firebase / google-services.json + Firebase Installations → project / api keys

For every parsed artifact we return rows tailored to that type. SQLite types
are opened read-only (``file:...?mode=ro``). usage_stats parses the
``usagestats`` / ``uri-logs`` XML and the binary ``usage-history`` blobs.

CLI shape (inside the container)::

    python3 -c '<PARSER>' <artifact_type> <target>

The parser emits one JSON object per row to stdout; the wrapper collects them,
persists a provenance copy at ``/work/aleapp_<type>.jsonl`` and parses them
into structured data. ``host_fallback=True`` lets the parser run on the host
(no Docker) so the unit tests exercise it without a sandbox.

Follows the same event-publishing pattern as chainsaw / email_parse /
linux_logs: tool.start, tool.stdout/stderr, tool.end, agent.action,
agent.observation, provenance.recorded.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


# ---------------------------------------------------------------------------
# artifact_type → human description (used by the agent to pick the right type)
# ---------------------------------------------------------------------------

ARTIFACT_TYPES: dict[str, str] = {
    "contacts": "contacts2.db contacts table — names, phone numbers, emails, orgs.",
    "sms_mms": "mmssms.db sms/mms/pdu tables — message address, body, date, direction.",
    "call_log": "contacts2.db / calllog.db calls table — number, timestamp, duration, direction.",
    "usage_stats": "usagestats XML + binary usage-history blobs — per-app usage timeline.",
    "chrome_history": "Chrome com.android.chrome History SQLite — URLs, visit timestamps, search terms.",
    "location_history": "Google / fused-location SQLite + JSON — location fixes with lat/lon + ts.",
    "accounts": "accounts.db / Google AccountManager SQLite — account type + account name.",
    "app_metadata": "packages.xml + backup metadata — installed packages, installer source, perms.",
    "wifi_config": "WifiConfigStore.xml — known SSIDs, softap / tethering configuration.",
    "firebase": "google-services.json + Firebase Installations — project id, API keys, app id.",
}


# ---------------------------------------------------------------------------
# Inline parser — a self-contained python3 program run inside svetovid/base.
# Takes <artifact_type> <target> on argv and emits JSON rows to stdout. Keeping
# the parser in python3 means we don't fight shell quoting and get reliable
# structured rows across every artifact type. All SQLite opens are read-only.
# ---------------------------------------------------------------------------

_PARSER = r'''
import json, os, re, sqlite3, struct, sys
import xml.etree.ElementTree as ET

fmt = sys.argv[1]
target = sys.argv[2]            # /evidence/<subpath> or empty for discovery
out = sys.stdout

def emit(row):
    out.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    out.flush()


# ---- file discovery ------------------------------------------------------

def discover(target, names=(), exts=()):
    """Walk /evidence (or target) for files matching names or extensions.

    ``names`` matches case-insensitively on the basename (useful for fixed
    names like packages.xml or contacts2.db). ``exts`` matches on suffix.
    """
    found = []
    roots = [target] if target and os.path.isdir(target) else \
            ([target] if target and os.path.isfile(target) else ["/evidence"])
    lnames = tuple(n.lower() for n in names)
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dp, dns, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                if lnames and fl in lnames:
                    found.append(os.path.join(dp, fn))
                elif exts and fl.endswith(exts):
                    found.append(os.path.join(dp, fn))
    return found


def first(targets, names=(), exts=()):
    """Return first existing *file* target or the first discovered match.

    Uses ``isfile`` (not ``exists``) so a target that points at a *directory*
    falls through to discovery — the common case where evidence_subpath names
    a folder (e.g. an app data dir) rather than the db file itself. When a
    directory target is passed, discovery is scoped to that directory; with no
    usable target we walk all of /evidence.
    """
    root = ""
    for t in targets:
        if not t:
            continue
        if os.path.isfile(t):
            return t
        if os.path.isdir(t):
            root = t  # scope discovery to this directory
            break
    hits = discover(root, names=names, exts=exts) if (names or exts) else []
    return hits[0] if hits else None


def open_ro(path):
    """Open a SQLite database READ-ONLY so we can never mutate evidence."""
    if not path or not os.path.exists(path):
        return None
    uri = "file:" + path.replace("?", "%3f") + "?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True)
        con.row_factory = sqlite3.Row
        return con
    except Exception as e:
        emit({"error": f"sqlite open failed for {path}: {e}"})
        return None


def read_text(path, limit=4 * 1024 * 1024):
    try:
        with open(path, "rb") as f:
            data = f.read(limit)
        for enc in ("utf-8", "utf-16", "latin-1"):
            try:
                return data.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        emit({"error": f"read failed for {path}: {e}"})
        return ""


# ---- contacts ------------------------------------------------------------

def parse_contacts(target):
    path = target if (target and os.path.isfile(target)) else \
        first([target], names=("contacts2.db", "contacts.db"))
    con = open_ro(path)
    if con is None:
        emit({"artifact_type": "contacts", "source": path or "(none)",
              "error": "contacts2.db not found"})
        return
    # Map raw contact id → structured contact by aggregating data rows.
    contacts = {}
    try:
        # display name lives on the raw_contacts / name_raw
        try:
            rows = con.execute(
                "SELECT contact_id, display_name FROM raw_contacts"
            ).fetchall()
            for r in rows:
                cid = r["contact_id"]
                contacts.setdefault(cid, {})["display_name"] = r["display_name"]
        except Exception:
            pass
        # phones / emails / organizations live on the data table joined to mimetypes
        try:
            data = con.execute(
                "SELECT contact_id, mimetype, data1, data2 FROM data"
            ).fetchall()
            for r in data:
                cid = r["contact_id"]
                c = contacts.setdefault(cid, {})
                mt = r["mimetype"] or ""
                if mt.endswith("/phone"):
                    c.setdefault("phones", []).append(r["data1"])
                elif mt.endswith("/email"):
                    c.setdefault("emails", []).append(r["data1"])
                elif mt.endswith("/organization"):
                    c["organization"] = r["data1"]
                elif mt.endswith("/name"):
                    c.setdefault("names", []).append(r["data1"])
        except Exception:
            pass
    finally:
        con.close()
    for cid, c in sorted(contacts.items(), key=lambda kv: str(kv[0])):
        if any(c.get(k) for k in ("display_name", "names", "phones", "emails", "organization")):
            emit({"artifact_type": "contacts", "source": os.path.basename(path),
                  "contact_id": cid,
                  "display_name": c.get("display_name") or (c.get("names") or [""])[0],
                  "phones": c.get("phones", []),
                  "emails": c.get("emails", []),
                  "organization": c.get("organization", "")})
    emit({"artifact_type": "contacts", "source": os.path.basename(path),
          "summary": f"{len(contacts)} raw contacts"})


# ---- sms / mms -----------------------------------------------------------

def parse_sms_mms(target):
    path = target if (target and os.path.isfile(target)) else \
        first([target], names=("mmssms.db", "telephony.db"))
    con = open_ro(path)
    if con is None:
        emit({"artifact_type": "sms_mms", "source": path or "(none)",
              "error": "mmssms.db not found"})
        return
    count = 0
    try:
        # SMS
        try:
            for r in con.execute(
                "SELECT address, body, date, type, read FROM sms ORDER BY date"
            ):
                emit({"artifact_type": "sms_mms", "kind": "sms",
                      "source": os.path.basename(path),
                      "address": r["address"], "body": (r["body"] or "")[:1000],
                      "date_ms": r["date"],
                      "direction": "incoming" if (r["type"] == 1) else "outgoing",
                      "read": r["read"]})
                count += 1
        except Exception:
            pass
        # MMS — address lives in the addr table, body in part
        try:
            addrs = {}
            for a in con.execute("SELECT msg_box, address FROM addr"):
                addrs.setdefault(a["msg_box"], a["address"])
            for m in con.execute(
                "SELECT _id, date, msg_box, read FROM pdu ORDER BY date"
            ):
                mid = m["_id"]
                body = ""
                try:
                    pr = con.execute(
                        "SELECT text FROM part WHERE mid = ?", (mid,)
                    ).fetchall()
                    body = "\n".join((p["text"] or "") for p in pr)[:1000]
                except Exception:
                    pass
                emit({"artifact_type": "sms_mms", "kind": "mms",
                      "source": os.path.basename(path),
                      "message_id": mid, "address": addrs.get(m["msg_box"], ""),
                      "body": body, "date_ms": m["date"],
                      "direction": "incoming" if (m["msg_box"] == 1) else "outgoing",
                      "read": m["read"]})
                count += 1
        except Exception:
            pass
    finally:
        con.close()
    emit({"artifact_type": "sms_mms", "source": os.path.basename(path),
          "summary": f"{count} message(s)"})


# ---- call log ------------------------------------------------------------

def parse_call_log(target):
    path = target if (target and os.path.isfile(target)) else \
        first([target], names=("contacts2.db", "calllog.db", "contacts.db"))
    con = open_ro(path)
    if con is None:
        emit({"artifact_type": "call_log", "source": path or "(none)",
              "error": "call log db not found"})
        return
    call_types = {1: "incoming", 2: "outgoing", 3: "missed", 4: "voicemail",
                  5: "rejected", 6: "blocked"}
    count = 0
    try:
        # the calls table is normally inside the calllog db, but some backups
        # fold it into contacts2.db. Try both.
        for tbl in ("calls",):
            try:
                rows = con.execute(
                    f"SELECT number, date, duration, type, name FROM {tbl} ORDER BY date"
                ).fetchall()
            except Exception:
                continue
            for r in rows:
                emit({"artifact_type": "call_log", "source": os.path.basename(path),
                      "number": r["number"], "name": r["name"] or "",
                      "date_ms": r["date"], "duration_s": r["duration"],
                      "type": call_types.get(r["type"], str(r["type"]))})
                count += 1
            break
    finally:
        con.close()
    emit({"artifact_type": "call_log", "source": os.path.basename(path),
          "summary": f"{count} call(s)"})


# ---- usage stats ---------------------------------------------------------

def parse_usage_stats(target):
    """usagestats XML (system/usagestats) + binary usage-history blobs.

    Modern Android writes per-package usage records under
    ``system/usagestats/<interval>/`` as XML and a rolling ``usage-history``
    binary log. We parse the XML (preferred) and best-effort decode the
    binary blobs for app launch / last-used timestamps.
    """
    root = target if target else "/evidence"
    rows_emitted = 0
    # 1. XML packages lists under usagestats/<bucket>/packages-*.xml
    xml_files = []
    if target and os.path.isfile(target):
        xml_files = [target]
    elif os.path.isdir(root):
        for dp, dns, fns in os.walk(root):
            for fn in fns:
                if fn.startswith("packages-") and fn.endswith(".xml"):
                    xml_files.append(os.path.join(dp, fn))
    for xf in xml_files:
        try:
            tree = ET.parse(xf)
        except Exception as e:
            emit({"artifact_type": "usage_stats", "source": os.path.basename(xf),
                  "error": f"xml parse: {e}"})
            continue
        for pkg in tree.getroot().findall("package"):
            name = pkg.get("name", "")
            stats = {}
            for attr in ("lastTimeActive", "totalTimeActive",
                         "lastEventTime", "appLaunchCount"):
                if pkg.get(attr):
                    try:
                        stats[attr] = int(pkg.get(attr))
                    except (TypeError, ValueError):
                        pass
            if name:
                emit({"artifact_type": "usage_stats", "source": os.path.basename(xf),
                      "package": name, **stats})
                rows_emitted += 1
    # 2. binary usage-history blobs (best-effort)
    bin_files = []
    if os.path.isdir(root):
        for dp, dns, fns in os.walk(root):
            for fn in fns:
                if fn == "usage-history":
                    bin_files.append(os.path.join(dp, fn))
    for bf in bin_files:
        try:
            data = open(bf, "rb").read()
        except Exception:
            continue
        # The format is a sequence of package-name-length + package-name +
        # per-record (count, times). We only extract package names + the
        # readable ASCII chunks so the timeline is non-empty.
        ascii_re = re.compile(rb"[\x20-\x7e]{4,}")
        pkgs = sorted({m.decode("ascii", "replace")
                       for m in ascii_re.findall(data)
                       if b"." in m and len(m) <= 120})
        for p in pkgs[:500]:
            emit({"artifact_type": "usage_stats", "source": os.path.basename(bf),
                  "package": p, "note": "binary usage-history candidate"})
            rows_emitted += 1
    emit({"artifact_type": "usage_stats",
          "summary": f"{rows_emitted} usage record(s) across {len(xml_files)} xml + {len(bin_files)} binary file(s)"})


# ---- chrome history ------------------------------------------------------

def parse_chrome_history(target):
    path = target if (target and os.path.isfile(target)) else \
        first([target], names=("History", "history"), exts=(".db",))
    con = open_ro(path)
    if con is None:
        emit({"artifact_type": "chrome_history", "source": path or "(none)",
              "error": "Chrome History db not found"})
        return
    count = 0
    try:
        try:
            for r in con.execute(
                "SELECT u.url, u.title, u.visit_count, v.visit_time, v.transition "
                "FROM urls u LEFT JOIN visits v ON u.id = v.url "
                "ORDER BY v.visit_time"
            ):
                emit({"artifact_type": "chrome_history", "source": os.path.basename(path),
                      "url": r["url"], "title": r["title"] or "",
                      "visit_count": r["visit_count"],
                      "visit_time_chrome": r["visit_time"],
                      # Chrome epoch = 1601-01-01 in microseconds
                      "visit_time_unix_ms": (
                          (int(r["visit_time"]) // 1000) - 11644473600000
                      ) if r["visit_time"] else None})
                count += 1
        except Exception:
            pass
        # keyword search terms
        try:
            for r in con.execute(
                "SELECT term, url_id FROM keyword_search_terms"
            ):
                emit({"artifact_type": "chrome_history", "source": os.path.basename(path),
                      "search_term": r["term"], "url_id": r["url_id"]})
                count += 1
        except Exception:
            pass
    finally:
        con.close()
    emit({"artifact_type": "chrome_history", "source": os.path.basename(path),
          "summary": f"{count} row(s)"})


# ---- location history ----------------------------------------------------

def parse_location_history(target):
    root = target if target else "/evidence"
    emitted = 0
    files = []
    if target and os.path.isfile(target):
        files = [target]
    elif os.path.isdir(root):
        for dp, dns, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                if fl.endswith((".db", ".json")) and any(
                    k in fl for k in ("location", "fused", "places")
                ):
                    files.append(os.path.join(dp, fn))
    for f in files:
        fl = f.lower()
        if fl.endswith(".db"):
            con = open_ro(f)
            if con is None:
                continue
            try:
                # common schemas: location (lat, lon, ts) or fused_data
                for cand in (
                    "SELECT latitude, longitude, timestamp FROM location",
                    "SELECT latitude_e7, longitude_e7, timestamp FROM location",
                ):
                    try:
                        for r in con.execute(cand):
                            lat = r[list(r.keys())[0]]
                            lon = r[list(r.keys())[1]]
                            ts = r["timestamp"]
                            emit({"artifact_type": "location_history",
                                  "source": os.path.basename(f),
                                  "latitude": lat, "longitude": lon,
                                  "timestamp": ts})
                            emitted += 1
                        break
                    except Exception:
                        continue
            finally:
                con.close()
        elif fl.endswith(".json"):
            txt = read_text(f)
            try:
                payload = json.loads(txt)
            except Exception:
                continue
            items = payload.get("locations") if isinstance(payload, dict) else None
            if isinstance(items, list):
                for loc in items:
                    try:
                        emit({"artifact_type": "location_history",
                              "source": os.path.basename(f),
                              "latitude_e7": loc.get("latitudeE7"),
                              "longitude_e7": loc.get("longitudeE7"),
                              "timestamp_ms": loc.get("timestampMs"),
                              "accuracy": loc.get("accuracy")})
                        emitted += 1
                    except Exception:
                        continue
    emit({"artifact_type": "location_history",
          "summary": f"{emitted} fix(es) across {len(files)} file(s)"})


# ---- accounts ------------------------------------------------------------

def parse_accounts(target):
    path = target if (target and os.path.isfile(target)) else \
        first([target], names=("accounts.db", "gallery.db"))
    con = open_ro(path)
    if con is None:
        emit({"artifact_type": "accounts", "source": path or "(none)",
              "error": "accounts.db not found"})
        return
    count = 0
    try:
        for cand in ("accounts", "extra_accounts"):
            try:
                rows = con.execute(
                    f"SELECT type, name, password FROM {cand}"
                ).fetchall()
            except Exception:
                continue
            for r in rows:
                emit({"artifact_type": "accounts", "source": os.path.basename(path),
                      "type": r["type"], "name": r["name"],
                      "password_hint": "***" if r["password"] else ""})
                count += 1
            break
    finally:
        con.close()
    emit({"artifact_type": "accounts", "source": os.path.basename(path),
          "summary": f"{count} account(s)"})


# ---- app metadata (packages.xml) -----------------------------------------

SIDeload_INSTALLERS = ("com.android.packageinstaller", "org.lsposed", "packageinstaller")

def parse_app_metadata(target):
    path = target if (target and os.path.isfile(target)) else \
        first([target], names=("packages.xml",))
    if not path:
        # V1/V2 backup copies live as packages.xml too
        emit({"artifact_type": "app_metadata", "source": "(none)",
              "error": "packages.xml not found"})
        return
    txt = read_text(path)
    try:
        root = ET.fromstring(txt)
    except Exception as e:
        emit({"artifact_type": "app_metadata", "source": os.path.basename(path),
              "error": f"xml parse: {e}"})
        return
    count = 0
    for pkg in root.findall("package"):
        name = pkg.get("name", "")
        installer = pkg.get("installerName") or pkg.get("installer") or ""
        # sideloaded when there is no installer (user-side-loaded APK) or a
        # known sideloader, and the package isn't a stock system app
        system = pkg.get("isSystem", "false") == "true"
        sideloaded = (not installer) or (installer.lower() in SIDeload_INSTALLERS)
        # flag dangerous permissions
        dangerous_perms = []
        for child in pkg.findall("sigs"):
            pass  # placeholder for signature inspection
        for perms in pkg.findall("perms"):
            for item in perms.findall("item"):
                pname = item.get("name", "")
                if any(k in pname.lower() for k in
                       ("send_sms", "read_sms", "install_packages",
                        "accessibility", "query_all_packages", "read_phone_state",
                        "read_contacts", "read_call_log", "record_audio")):
                    dangerous_perms.append(pname)
        emit({"artifact_type": "app_metadata", "source": os.path.basename(path),
              "package": name,
              "version_name": pkg.get("versionName"),
              "installer": installer or "(sideloaded)",
              "system": system,
              "sideloaded": sideloaded,
              "suspicious": sideloaded and not system,
              "dangerous_permissions": dangerous_perms})
        count += 1
    emit({"artifact_type": "app_metadata", "source": os.path.basename(path),
          "summary": f"{count} package(s)"})


# ---- wifi config ---------------------------------------------------------

def parse_wifi_config(target):
    path = target if (target and os.path.isfile(target)) else \
        first([target], names=("wificonfigstore.xml", "wifi_config_store.xml",
                                "wificonfigstore.xml.backup"))
    if not path:
        emit({"artifact_type": "wifi_config", "source": "(none)",
              "error": "WifiConfigStore.xml not found"})
        return
    txt = read_text(path)
    emit({"artifact_type": "wifi_config", "source": os.path.basename(path),
          "raw_excerpt": txt[:2000]})
    # try to pull SSID / preSharedKey / softap fragments out of the XML
    ssids = sorted(set(re.findall(r'<string name="SSID">(.+?)</string>', txt) +
                       re.findall(r'<string name="SoftAp_Ssid">(.+?)</string>', txt)))
    psks = re.findall(r'<string name="PreSharedKey">(.+?)</string>', txt)
    for s in ssids:
        emit({"artifact_type": "wifi_config", "source": os.path.basename(path),
              "ssid": s})
    for p in psks:
        emit({"artifact_type": "wifi_config", "source": os.path.basename(path),
              "pre_shared_key_present": True})
    emit({"artifact_type": "wifi_config", "source": os.path.basename(path),
          "summary": f"{len(ssids)} ssid(s), {len(psks)} psk(s)"})


# ---- firebase ------------------------------------------------------------

def parse_firebase(target):
    root = target if target else "/evidence"
    files = []
    if target and os.path.isfile(target):
        files = [target]
    elif os.path.isdir(root):
        for dp, dns, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                if fl in ("google-services.json", "google-services.xml") or \
                   "firebase" in fl or fl == "firebase-installations":
                    files.append(os.path.join(dp, fn))
    emitted = 0
    for f in files:
        fl = f.lower()
        if fl.endswith(".json"):
            txt = read_text(f)
            try:
                payload = json.loads(txt)
            except Exception:
                continue
            project_info = payload.get("project_info", {})
            for client in payload.get("client", []):
                ai = client.get("client_info", {}) or {}
                api_keys = [k.get("current_key") for k in payload.get("api_key", [])]
                emit({"artifact_type": "firebase", "source": os.path.basename(f),
                      "project_id": project_info.get("project_id"),
                      "firebase_url": project_info.get("firebase_url"),
                      "mobile_sdk_app_id": ai.get("mobile_sdk_app_id"),
                      "android_package": (ai.get("android_client_info") or {}).get("package_name"),
                      "api_keys": [k for k in api_keys if k]})
                emitted += 1
        elif fl.endswith(".xml"):
            emit({"artifact_type": "firebase", "source": os.path.basename(f),
                  "raw_excerpt": read_text(f, 1000)})
            emitted += 1
    emit({"artifact_type": "firebase",
          "summary": f"{emitted} record(s) across {len(files)} file(s)"})


# ---- dispatch ------------------------------------------------------------

def main():
    if fmt == "contacts":
        parse_contacts(target)
    elif fmt == "sms_mms":
        parse_sms_mms(target)
    elif fmt == "call_log":
        parse_call_log(target)
    elif fmt == "usage_stats":
        parse_usage_stats(target)
    elif fmt == "chrome_history":
        parse_chrome_history(target)
    elif fmt == "location_history":
        parse_location_history(target)
    elif fmt == "accounts":
        parse_accounts(target)
    elif fmt == "app_metadata":
        parse_app_metadata(target)
    elif fmt == "wifi_config":
        parse_wifi_config(target)
    elif fmt == "firebase":
        parse_firebase(target)
    else:
        emit({"error": f"unknown artifact_type {fmt!r}"})

main()
'''


def _build_command(artifact_type: str, sub: str) -> list[str]:
    """Build the container argv: python3 -c '<parser>' <type> <target>."""
    target = f"/evidence/{sub}".rstrip("/") if sub else ""
    return [
        "python3", "-c", _PARSER, artifact_type, target,
    ]


# ---------------------------------------------------------------------------
# Output hash helper (mirrors chainsaw / email_parse)
# ---------------------------------------------------------------------------


def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


class AleappParseTool(Tool):
    """Wrap the Android artifact-parsing toolchain (python3 ``sqlite3`` /
    stdlib xml + json) inside ``svetovid/base``. Mirrors ALEAPP's artifact
    coverage but with zero non-stdlib dependencies so it runs anywhere the
    base image runs."""

    name = "aleapp_parse"
    image = "svetovid/base"
    description = (
        "Parse an Android mobile-forensics artifact into structured rows. "
        "Pick artifact_type by what you triaged: contacts (contacts2.db), "
        "sms_mms (mmssms.db), call_log (calls table), usage_stats "
        "(usagestats XML + binary history), chrome_history (Chrome History "
        "db), location_history (Google/fused location), accounts "
        "(accounts.db), app_metadata (packages.xml — flags sideloaded / "
        "suspicious apps), wifi_config (WifiConfigStore.xml), firebase "
        "(google-services.json). Runs read-only over /evidence."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "artifact_type": {
                    "type": "string",
                    "enum": list(ARTIFACT_TYPES.keys()),
                    "description": "Which Android artifact to parse.",
                },
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence to the artifact file or "
                        "directory. If omitted, the parser discovers the "
                        "canonical file (e.g. contacts2.db, packages.xml) "
                        "under /evidence."
                    ),
                },
            },
            "required": ["artifact_type"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        atype = args.get("artifact_type", "")
        sub = args.get("evidence_subpath", "") or ""

        if atype not in ARTIFACT_TYPES:
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"unknown artifact_type {atype!r}; pick from {list(ARTIFACT_TYPES)}",
            )

        cmd = _build_command(atype, sub)

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

        # Capture stdout lines so we can persist a provenance copy AND parse
        # them into structured rows. (Mirrors email_parse / linux_logs.)
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
                host_fallback=True,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(
                ctx.investigation_id, f"aleapp_parse ({atype}) failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"aleapp_parse ({atype}) failed: {e}",
            )

        # The parser emits JSONL to stdout. Persist a local copy (provenance +
        # output_hash) and parse the rows into structured data.
        local_out = Path(ctx.output_dir) / f"aleapp_{atype}.jsonl"
        if stdout_lines:
            try:
                local_out.write_text("\n".join(stdout_lines) + "\n", encoding="utf-8")
            except Exception:
                pass

        rows: list[dict[str, Any]] = []
        for line in stdout_lines:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"raw": line})
        rows = rows[:2000]

        output_hash = _hash_file(local_out)
        if rows:
            summary = f"aleapp_parse ({atype}): {len(rows)} row(s)"
        else:
            summary = (
                f"aleapp_parse ({atype}) exited {res.exit_code} "
                "but produced no JSONL output"
            )

        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s, output_hash,
        ))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
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
            summary=summary, data={"artifact_type": atype, "rows": rows},
        )


# Module-level instance for tool enumeration parity with the other wrappers.
tool = AleappParseTool()
