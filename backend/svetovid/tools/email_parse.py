"""Email artifact parser tool wrapper (research item C11a/C12).

Parses the common email / messaging-cache artifacts using only the standard
Python modules already present in the ``svetovid/base`` image (python3 + the
``email``, ``mailbox`` and ``json`` stdlib modules). One tool, ``email_parse``,
takes a ``format`` selector and an ``evidence_subpath`` and returns structured
rows. Supported:

  - eml       : a single RFC-822 / .eml message via the ``email`` module
  - mbox      : a Unix mbox mailbox (Thunderbird, mutt, exports) via ``mailbox``
  - msg       : an Outlook .msg (OLE2) message — try ``extract-msg`` if present,
                otherwise report file metadata so the investigation isn't blocked
  - pst       : an Outlook .pst store — try ``libpff``/``ReadPST`` if present,
                otherwise report file metadata
  - ost       : an Outlook .ost (offline Exchange) store — same strategy as pst
  - teams_db  : a Microsoft Teams IndexedDB / LevelDB cache (.leveldb dirs)
  - slack_cache: a Slack desktop cache (.leveldb / IndexedDB dirs)

For every parsed message we return: ``from``, ``to``, ``cc``, ``subject``,
``date``, ``body_preview``, ``attachments`` (list of names), and
``auth_results`` (a dict with ``spf``, ``dkim``, ``dmarc`` parsed from the
``Received-SPF`` and ``Authentication-Results`` headers — the key signal for
phishing / BEC analysis).

CLI shape (inside the container)::

    python3 -c '<PARSER>' <format> <target>

The parser emits one JSON object per row to stdout; the wrapper collects them,
persists a provenance copy at ``/work/email_<format>.jsonl`` and parses them
into structured data. ``host_fallback=True`` lets the parser run on the host
(no Docker) so the unit tests exercise it without a sandbox.

Follows the same event-publishing pattern as chainsaw / linux_logs:
tool.start, tool.stdout/stderr, tool.end, agent.action, agent.observation,
provenance.recorded.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


# ---------------------------------------------------------------------------
# format → human description (used by the agent to pick the right format)
# ---------------------------------------------------------------------------

FORMATS: dict[str, str] = {
    "eml": "A single RFC-822 / MIME .eml message (Python email module).",
    "mbox": "A Unix mbox mailbox — Thunderbird / mutt / mail exports (mailbox module).",
    "msg": "An Outlook .msg (OLE2) message — extract-msg if available, else metadata.",
    "pst": "An Outlook .pst store — libpff / ReadPST if available, else metadata.",
    "ost": "An Outlook .ost (offline Exchange) store — libpff / ReadPST if available, else metadata.",
    "teams_db": "A Microsoft Teams IndexedDB / LevelDB cache (.leveldb dirs).",
    "slack_cache": "A Slack desktop cache (.leveldb / IndexedDB dirs).",
}


# ---------------------------------------------------------------------------
# Inline parser — a self-contained python3 program run inside svetovid/base.
# Takes <format> <target> on argv and emits JSON rows to stdout. Keeping the
# parser in python3 means we don't fight shell quoting and get reliable
# structured rows across every format.
# ---------------------------------------------------------------------------

_PARSER = r'''
import json, os, re, sys

fmt = sys.argv[1]
target = sys.argv[2]            # /evidence/<subpath> or empty for discovery
out = sys.stdout

def emit(row):
    out.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    out.flush()

def decode_header_value(val):
    """Decode an RFC-2047 header into a single string."""
    import email.header
    if val is None:
        return ""
    try:
        parts = email.header.decode_header(val)
    except Exception:
        return str(val)
    bits = []
    for text, enc in parts:
        if isinstance(text, bytes):
            try:
                bits.append(text.decode(enc or "utf-8", errors="replace"))
            except (LookupError, TypeError):
                bits.append(text.decode("utf-8", errors="replace"))
        else:
            bits.append(text)
    return "".join(bits)

def body_preview(msg, limit=500):
    """Best-effort plain-text body preview."""
    try:
        import email as _email
        try:
            tp = msg.get_payload(decode=True)
        except Exception:
            tp = None
        if tp is None:
            # multipart: walk for the first text/plain part
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        tp = part.get_payload(decode=True)
                    except Exception:
                        tp = None
                    if tp:
                        break
        if tp is None:
            # fallback: ask for the plain text payload directly
            try:
                tp = msg.get_body(preferencelist=("plain", "html")).get_content()  # py3.6+
            except Exception:
                tp = None
        if tp is None:
            return ""
        if isinstance(tp, bytes):
            for enc in (msg.get_content_charset() or "utf-8", "utf-8", "latin-1"):
                try:
                    tp = tp.decode(enc, errors="replace")
                    break
                except LookupError:
                    continue
        text = str(tp)
        # collapse whitespace for a compact preview
        text = re.sub(r"\s+", " ", text).strip()
        return text[:limit]
    except Exception as e:
        return f"(body parse error: {e})"

def get_addrs(msg, name):
    """Return a comma-joined string of an address header."""
    import email.utils
    raw = msg.get_all(name, [])
    if not raw:
        return ""
    out_addrs = []
    for r in raw:
        for nm, addr in email.utils.getaddresses([decode_header_value(r)]):
            if addr or nm:
                out_addrs.append(f"{nm} <{addr}>" if (nm and addr) else (addr or nm))
    return ", ".join(out_addrs)

def attachments(msg):
    """List attachment filenames from a parsed email message."""
    names = []
    try:
        for part in msg.walk():
            cd = part.get("Content-Disposition", "")
            if "attachment" in cd.lower() or "inline" in cd.lower():
                fn = part.get_filename()
                if fn:
                    names.append(decode_header_value(fn))
    except Exception:
        pass
    return names

def auth_results_from_msg(msg):
    """Pull SPF / DKIM / DMARC results from the message headers.

    Looks at ``Authentication-Results`` (the canonical RFC 7008 header) first,
    then falls back to ``Received-SPF`` and ``DKIM-Signature`` presence.
    """
    import email as _email
    res = {"spf": None, "dkim": None, "dmarc": None}
    ar_raw = msg.get_all("Authentication-Results", [])
    if ar_raw:
        blob = "\n".join(decode_header_value(h) for h in ar_raw)
        # spf=pass/none/fail/softfail
        m = re.search(r"\bspf\s*=\s*([a-z]+)", blob, re.I)
        if m: res["spf"] = m.group(1).lower()
        m = re.search(r"\bdkim\s*=\s*([a-z]+)", blob, re.I)
        if m: res["dkim"] = m.group(1).lower()
        m = re.search(r"\bdmarc\s*=\s*([a-z]+)", blob, re.I)
        if m: res["dmarc"] = m.group(1).lower()
    # fallbacks
    rspf = msg.get("Received-SPF")
    if res["spf"] is None and rspf:
        m = re.match(r"\s*([a-z]+)", decode_header_value(rspf), re.I)
        if m: res["spf"] = m.group(1).lower()
    if res["dkim"] is None and msg.get("DKIM-Signature"):
        res["dkim"] = "present"   # we can't verify the signature, only note it
    if res["dmarc"] is None:
        # absent Authentication-Results dmarc field ⇒ not enforced
        res["dmarc"] = "none" if ar_raw else None
    return res

def parse_eml_file(path):
    import email as _email
    with open(path, "rb") as f:
        msg = _email.message_from_binary_file(f)
    emit_row_from_msg(msg, source=os.path.basename(path), path=path)

def emit_row_from_msg(msg, source, path, extra=None):
    row = {
        "source": source,
        "path": path,
        "message_id": decode_header_value(msg.get("Message-ID", "")),
        "from": get_addrs(msg, "From"),
        "to": get_addrs(msg, "To"),
        "cc": get_addrs(msg, "Cc"),
        "reply_to": get_addrs(msg, "Reply-To"),
        "subject": decode_header_value(msg.get("Subject", "")),
        "date": decode_header_value(msg.get("Date", "")),
        "body_preview": body_preview(msg),
        "attachments": attachments(msg),
        "auth_results": auth_results_from_msg(msg),
    }
    if extra:
        row.update(extra)
    emit(row)

def parse_mbox(path):
    import mailbox
    try:
        mb = mailbox.mbox(path, create=False)
    except Exception as e:
        emit({"source": os.path.basename(path), "path": path, "error": f"mbox open failed: {e}"})
        return
    for key in mb.iterkeys():
        try:
            msg = mb.get_message(key)
            import email as _email
            if not hasattr(msg, "walk"):
                # some Mailbox message subclasses wrap a real Message
                msg = _email.message_from_string(str(msg))
            emit_row_from_msg(msg, source=os.path.basename(path), path=path,
                              extra={"mbox_key": key})
        except Exception as e:
            emit({"source": os.path.basename(path), "path": path, "error": f"message {key}: {e}"})

def parse_msg_file(path):
    """Outlook .msg — try extract-msg, else report metadata."""
    try:
        import extract_msg  # type: ignore
        try:
            m = extract_msg.Message(path)
            try:
                emit({
                    "source": os.path.basename(path),
                    "path": path,
                    "from": m.sender or "",
                    "to": m.to or "",
                    "cc": m.cc or "",
                    "subject": m.subject or "",
                    "date": str(m.date or ""),
                    "body_preview": re.sub(r"\s+", " ", (m.body or "")).strip()[:500],
                    "attachments": [a.longFilename or a.shortFilename or a.name
                                    for a in (m.attachments or []) if a],
                    "auth_results": _ar_from_text(m.header or ""),
                    "header_raw": (m.header or "")[:1500],
                })
            finally:
                try: m.close()
                except Exception: pass
            return
        except Exception as e:
            emit({"source": os.path.basename(path), "path": path,
                  "error": f"extract-msg failed: {e}", "note": "reporting metadata only"})
            # fall through to metadata
    except ImportError:
        emit({"source": os.path.basename(path), "path": path,
              "error": "extract-msg not installed", "note": "reporting metadata only"})
    _emit_metadata(path, kind="msg")

def _ar_from_text(text):
    res = {"spf": None, "dkim": None, "dmarc": None}
    if not text:
        return res
    m = re.search(r"\bspf\s*=\s*([a-z]+)", text, re.I)
    if m: res["spf"] = m.group(1).lower()
    m = re.search(r"\bdkim\s*=\s*([a-z]+)", text, re.I)
    if m: res["dkim"] = m.group(1).lower()
    m = re.search(r"\bdmarc\s*=\s*([a-z]+)", text, re.I)
    if m: res["dmarc"] = m.group(1).lower()
    return res

def _emit_metadata(path, kind):
    """Report file size / magic / path when a deep parser isn't available."""
    try:
        st = os.stat(path)
        size = st.st_size
    except Exception:
        size = None
    magic = ""
    try:
        with open(path, "rb") as f:
            magic = f.read(8).hex()
    except Exception:
        pass
    emit({"source": os.path.basename(path), "path": path, "kind": kind,
          "size": size, "magic_hex": magic,
          "note": (f"deep {kind} parser unavailable; metadata only. "
                   "Install libpff/pff-tools (ReadPST) or extract-msg for full parsing.")})

def parse_pff(path, kind):
    """PST/OST via libpff-python (pypff) if available, else metadata.

    libpff exposes the store through the ``pypff`` module; ``readpst`` (the CLI
    tool from pff-tools) can export to mbox, but we prefer the python binding
    for in-memory row extraction. If neither is present we fall back to
    metadata so the investigation isn't blocked.
    """
    try:
        import pypff  # type: ignore
    except ImportError:
        emit({"source": os.path.basename(path), "path": path, "kind": kind,
              "error": "libpff (pypff) not installed", "note": "reporting metadata only"})
        _emit_metadata(path, kind=kind)
        return
    ost = pypff.file()
    try:
        ost.open(path)
        root = ost.get_root_folder()
        count = _walk_pff(root, source=os.path.basename(path), path=path)
        emit({"source": os.path.basename(path), "path": path, "kind": kind,
              "messages_parsed": count})
    except Exception as e:
        emit({"source": os.path.basename(path), "path": path, "kind": kind,
              "error": f"pypff failed: {e}", "note": "reporting metadata only"})
        _emit_metadata(path, kind=kind)
    finally:
        try: ost.close()
        except Exception: pass

def _walk_pff(folder, source, path, count=0):
    """Recursively walk a libpff folder tree, emitting one row per message."""
    import email as _email
    for i in range(folder.get_number_of_sub_messages() if hasattr(folder, "get_number_of_sub_messages") else 0):
        try:
            m = folder.get_sub_message(i)
            headers = ""
            try:
                transport = m.get_transport_headers() or b""
                if isinstance(transport, bytes):
                    headers = transport.decode("utf-8", errors="replace")
                else:
                    headers = str(transport)
            except Exception:
                headers = ""
            msg = _email.message_from_string(headers) if headers else None
            body_txt = ""
            try:
                body = m.get_plain_text_body() or m.get_html_body() or b""
                if isinstance(body, bytes):
                    body = body.decode("utf-8", errors="replace")
                body_txt = re.sub(r"\s+", " ", str(body)).strip()[:500]
            except Exception:
                pass
            atts = []
            try:
                for j in range(m.get_number_of_attachments() if hasattr(m, "get_number_of_attachments") else 0):
                    a = m.get_attachment(j)
                    nm = getattr(a, "get_name", lambda: "")() or ""
                    if nm: atts.append(nm)
            except Exception:
                pass
            if msg:
                emit({
                    "source": source, "path": path,
                    "from": get_addrs(msg, "From"),
                    "to": get_addrs(msg, "To"),
                    "cc": get_addrs(msg, "Cc"),
                    "subject": decode_header_value(msg.get("Subject", "")),
                    "date": decode_header_value(msg.get("Date", "")),
                    "body_preview": body_txt or body_preview(msg),
                    "attachments": atts,
                    "auth_results": auth_results_from_msg(msg),
                })
            else:
                emit({"source": source, "path": path, "subject": "(no transport headers)",
                      "body_preview": body_txt, "attachments": atts,
                      "auth_results": {"spf": None, "dkim": None, "dmarc": None}})
            count += 1
        except Exception as e:
            emit({"source": source, "path": path, "error": f"message parse: {e}"})
    for i in range(folder.get_number_of_sub_folders() if hasattr(folder, "get_number_of_sub_folders") else 0):
        try:
            count = _walk_pff(folder.get_sub_folder(i), source, path, count)
        except Exception:
            pass
    return count

def parse_leveldb_dir(target, kind):
    """Best-effort key extraction from a .leveldb / IndexedDB cache dir.

    Teams and Slack both store their desktop caches in LevelDB (.ldb/.log files).
    We don't have a real LevelDB reader in svetovid/base, so we do a coarse scan:
    read the .ldb/.log files as bytes and pull printable ASCII / UTF-16 strings
    that look like message content, URLs, or JSON fragments. Rows are tagged
    ``candidate`` so the analyst knows these are heuristic hits, not parsed rows.
    """
    files = []
    if target and os.path.isfile(target):
        files = [target]
    elif target and os.path.isdir(target):
        for dp, dns, fns in os.walk(target):
            for fn in fns:
                if fn.endswith((".ldb", ".log", ".sst")):
                    files.append(os.path.join(dp, fn))
    if not files:
        emit({"source": target or "(none)", "kind": kind,
              "error": "no .ldb/.log/.sst files found under target"})
        return
    email_re = re.compile(rb"[\w.\-+]+@[\w.\-]+\.\w{2,}")
    url_re = re.compile(rb"https?://[^\s\"'<>]{4,}")
    ascii_re = re.compile(rb"[\x20-\x7e]{6,}")
    seen = set()
    for f in files:
        try:
            data = open(f, "rb").read(8 * 1024 * 1024)  # cap per file
        except Exception as e:
            emit({"source": os.path.basename(f), "kind": kind, "error": f"read failed: {e}"})
            continue
        emails = sorted(set(m.decode("ascii", "replace") for m in email_re.findall(data)))
        urls = sorted(set(m.decode("ascii", "replace") for m in url_re.findall(data)))[:50]
        # surface message-like strings containing common social-engineering words
        se_words = (b"urgent", b"wire", b"invoice", b"payment", b"password",
                    b"verify", b"account", b"login", b"click", b"attachment",
                    b"transfer", b"fund")
        msg_strings = []
        for m in ascii_re.findall(data):
            low = m.lower()
            if any(w in low for w in se_words) and len(m) <= 300:
                s = m.decode("ascii", "replace")
                if s not in seen:
                    seen.add(s)
                    msg_strings.append(s)
                if len(msg_strings) >= 80:
                    break
        emit({"source": os.path.basename(f), "path": f, "kind": kind,
              "candidate": True,
              "emails": emails[:200], "urls": urls, "message_strings": msg_strings[:80]})
    emit({"source": os.path.basename(target) if target else "(discovery)", "kind": kind,
          "note": "LevelDB heuristic extraction — rows are candidate indicators, "
                  "not parsed messages."})

def discover(target, exts):
    """Walk /evidence (or target) for files matching the given extensions."""
    found = []
    roots = [target] if target and os.path.isdir(target) else \
            ([target] if target and os.path.isfile(target) else ["/evidence"])
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dp, dns, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                if any(fl.endswith(ext) for ext in exts):
                    found.append(os.path.join(dp, fn))
    return found

# ---- dispatch ---------------------------------------------------------------
def main():
    if fmt == "eml":
        paths = discover(target, (".eml",)) if not (target and os.path.isfile(target)) else [target]
        for p in paths:
            parse_eml_file(p)
    elif fmt == "mbox":
        paths = discover(target, (".mbox",)) if not (target and os.path.isfile(target)) else [target]
        for p in paths:
            parse_mbox(p)
    elif fmt == "msg":
        paths = discover(target, (".msg",)) if not (target and os.path.isfile(target)) else [target]
        for p in paths:
            parse_msg_file(p)
    elif fmt == "pst":
        paths = discover(target, (".pst",)) if not (target and os.path.isfile(target)) else [target]
        for p in paths:
            parse_pff(p, kind="pst")
    elif fmt == "ost":
        paths = discover(target, (".ost",)) if not (target and os.path.isfile(target)) else [target]
        for p in paths:
            parse_pff(p, kind="ost")
    elif fmt == "teams_db":
        # Teams IndexedDB lives under <profile>/IndexedDB/*.leveldb (dirs)
        parse_leveldb_dir(target, kind="teams_db")
    elif fmt == "slack_cache":
        parse_leveldb_dir(target, kind="slack_cache")
    else:
        emit({"error": f"unknown format {fmt!r}"})

main()
'''


def _build_command(fmt: str, sub: str) -> list[str]:
    """Build the container argv: python3 -c '<parser>' <format> <target>."""
    target = f"/evidence/{sub}".rstrip("/") if sub else ""
    return [
        "python3", "-c", _PARSER, fmt, target,
    ]


# ---------------------------------------------------------------------------
# Output hash helper (mirrors chainsaw / linux_logs)
# ---------------------------------------------------------------------------


def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


class EmailParseTool(Tool):
    """Wrap the standard email-parsing toolchain (python3 ``email``/``mailbox``
    + optional libpff / extract-msg) inside ``svetovid/base``."""

    name = "email_parse"
    image = "svetovid/base"
    description = (
        "Parse an email or messaging-cache artifact into structured rows. "
        "Pick format by artifact: eml (single message), mbox (Unix mailbox), "
        "msg (Outlook .msg), pst/ost (Outlook stores), teams_db (Microsoft "
        "Teams LevelDB cache), slack_cache (Slack desktop cache). Returns "
        "from/to/subject/date/body_preview/attachments and SPF/DKIM/DMARC "
        "authentication results parsed from headers. Runs read-only over "
        "/evidence."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": list(FORMATS.keys()),
                    "description": "Which email / messaging-cache artifact to parse.",
                },
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence to the artifact file or "
                        "directory. If omitted, the parser discovers matching "
                        "files (e.g. *.eml, *.pst) under /evidence."
                    ),
                },
            },
            "required": ["format"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        fmt = args.get("format", "")
        sub = args.get("evidence_subpath", "") or ""

        if fmt not in FORMATS:
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"unknown format {fmt!r}; pick from {list(FORMATS)}",
            )

        cmd = _build_command(fmt, sub)

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

        # Capture stdout lines so we can persist a provenance copy AND parse
        # them into structured rows. (Mirrors how linux_logs.py collects
        # stdout_lines while still publishing tool.stdout events.)
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
                ctx.investigation_id, f"email_parse ({fmt}) failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"email_parse ({fmt}) failed: {e}",
            )

        # The parser emits JSONL to stdout. Persist a local copy (provenance +
        # output_hash) and parse the rows into structured data.
        local_out = Path(ctx.output_dir) / f"email_{fmt}.jsonl"
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
            summary = f"email_parse ({fmt}): {len(rows)} row(s)"
        else:
            summary = (
                f"email_parse ({fmt}) exited {res.exit_code} "
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
            summary=summary, data={"format": fmt, "rows": rows},
        )


# Module-level instance for tool enumeration parity with the other wrappers.
tool = EmailParseTool()
