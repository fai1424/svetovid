"""Linux log parser tool wrapper (research item C17c).

Parses the classic Linux forensic log artifacts using only the standard tools
already present in the ``svetovid/base`` image (Debian + python3 + journalctl +
grep + awk + utmpdump). One tool, ``linux_log_parse``, takes a ``log_type``
selector and an ``evidence_subpath`` and returns structured rows. Supported:

  - syslog         : /var/log/syslog or messages — general system activity
  - auth           : /var/log/auth.log or secure — sshd, sudo, su, useradd
  - journal        : systemd journal export (.journal) via journalctl --file
  - wtmp           : /var/log/wtmp binary login records via utmpdump
  - cron           : /var/log/cron or syslog cron lines — persistence via cron
  - shell_history  : ~/.bash_history, ~/.zsh_history, etc. — attacker commands
  - dpkg           : /var/log/dpkg.log — package installs (backdoors/tools)
  - systemd_unit   : /etc/systemd/system/*.service + unit status — persistence

CLI shape (inside the container) — each log type dispatches to a different
command; all write parsed JSON lines to ``/work/linux_<type>.jsonl`` which we
read back and turn into rows. ``host_fallback=True`` lets the parser run on the
host (no Docker) so the unit tests exercise it without a sandbox.

Follows the same event-publishing pattern as chainsaw / eztools:
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
# log_type → human description (also used by the agent to pick the right type)
# ---------------------------------------------------------------------------

LOG_TYPES: dict[str, str] = {
    "syslog": "General system activity log (syslog / messages).",
    "auth": "Authentication log (auth.log / secure): sshd, sudo, su, useradd.",
    "journal": "systemd journal export (.journal file) via journalctl --file.",
    "wtmp": "Binary login records (/var/log/wtmp) via utmpdump.",
    "cron": "Cron activity (cron log or cron lines in syslog).",
    "shell_history": "Shell history (~/.bash_history, ~/.zsh_history) — attacker commands.",
    "dpkg": "Debian package log (/var/log/dpkg.log) — installed backdoors/tools.",
    "systemd_unit": "Systemd unit files (/etc/systemd/system, /lib/systemd/system) — persistence.",
}


# ---------------------------------------------------------------------------
# Command builders — return argv to run inside the svetovid/base container.
# Each writes a JSONL stream of row dicts to /work/linux_<type>.jsonl.
# We do the heavy lifting in a small python3 heredoc so the parsing logic lives
# in one place and the container only needs python3 + the standard Unix tools.
# ---------------------------------------------------------------------------

# A self-contained python3 program (run inside the container) that takes
# log_type + target path on argv and emits JSON lines to stdout. Keeping the
# parser in python3 means we don't fight awk's quoting and we get reliable
# structured rows across every log type.
_PARSER = r'''
import json, os, re, sys, glob, struct

log_type = sys.argv[1]
target = sys.argv[2]            # /evidence/<subpath> or empty for discovery
out = sys.stdout

def emit(row):
    out.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    out.flush()

def is_text_log(path):
    try:
        with open(path, "rb") as f:
            chunk = f.read(4096)
        return b"\x00" not in chunk
    except Exception:
        return False

def iter_files(target, candidates):
    """Yield existing files for the given target. If target is a dir, search
    it for the candidate names; if it's a file, use it directly."""
    found = []
    if target and os.path.isfile(target):
        found.append(target)
    elif target and os.path.isdir(target):
        for dp, dns, fns in os.walk(target):
            for fn in fns:
                if fn in candidates:
                    found.append(os.path.join(dp, fn))
    else:
        # discovery: walk the usual Linux layout
        roots = ["/evidence"]
        for root in roots:
            if not os.path.isdir(root):
                continue
            for dp, dns, fns in os.walk(root):
                for fn in fns:
                    if fn in candidates:
                        found.append(os.path.join(dp, fn))
    # de-dup, preserve order
    seen = set(); ordered = []
    for p in found:
        if p not in seen:
            seen.add(p); ordered.append(p)
    return ordered

# ---- syslog / messages ------------------------------------------------------
SYSLOG_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+'
    r'(?P<proc>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$'
)
def parse_syslog_like(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = SYSLOG_RE.match(line)
            if m:
                d = m.groupdict()
                emit({
                    "source": os.path.basename(path),
                    "timestamp": d["ts"],
                    "host": d["host"],
                    "process": d["proc"],
                    "pid": d["pid"] or "",
                    "message": d["msg"],
                    "raw": line,
                })
            else:
                emit({"source": os.path.basename(path), "raw": line})

# ---- cron (syslog lines mentioning CRON) -----------------------------------
def parse_cron(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "CRON" in line:
                emit({"source": os.path.basename(path), "raw": line.rstrip("\n")})

# ---- dpkg.log ---------------------------------------------------------------
DPKG_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<action>\S+)\s+(?P<pkg>.+)$'
)
def parse_dpkg(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = DPKG_RE.match(line)
            if m:
                d = m.groupdict()
                emit({
                    "source": os.path.basename(path),
                    "timestamp": d["ts"],
                    "action": d["action"],
                    "package": d["pkg"],
                    "raw": line,
                })

# ---- shell history ----------------------------------------------------------
HIST_RE = re.compile(r'^:\s*\d+:(\d+);(?P<cmd>.*)$')
def parse_history(path):
    # zsh extended history: ": <epoch>:<elapsed>;<cmd>"
    # bash history: plain command lines
    name = os.path.basename(path)
    with open(path, encoding="utf-8", errors="replace") as f:
        prev = ""
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = HIST_RE.match(line)
            if m:
                emit({"source": name, "command": m.group("cmd"), "raw": line})
            else:
                emit({"source": name, "command": line, "raw": line})

# ---- systemd unit files -----------------------------------------------------
def parse_systemd_unit(target):
    """Emit one row per .service/.timer/.socket unit file with key fields."""
    unit_dirs = []
    if target and os.path.isdir(target):
        unit_dirs.append(target)
    else:
        for d in ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"):
            if os.path.isdir(d):
                unit_dirs.append(d)
    seen = set()
    for d in unit_dirs:
        for dp, dns, fns in os.walk(d):
            for fn in fns:
                if fn.endswith((".service", ".timer", ".socket", ".mount")):
                    p = os.path.join(dp, fn)
                    if p in seen:
                        continue
                    seen.add(p)
                    fields = {"source": fn, "path": p}
                    try:
                        with open(p, encoding="utf-8", errors="replace") as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith("ExecStart="):
                                    fields["ExecStart"] = line.split("=", 1)[1]
                                elif line.startswith("User="):
                                    fields["User"] = line.split("=", 1)[1]
                                elif line.startswith("WantedBy="):
                                    fields["WantedBy"] = line.split("=", 1)[1]
                                elif line.startswith("Description="):
                                    fields["Description"] = line.split("=", 1)[1]
                    except Exception as e:
                        fields["error"] = str(e)
                    emit(fields)

# ---- journal (.journal) via journalctl --file -------------------------------
def parse_journal(path):
    import subprocess
    # journalctl --file works on a single .journal or a directory of them
    try:
        proc = subprocess.run(
            ["journalctl", "--file", path, "-o", "json", "--no-pager", "-n", "5000"],
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        emit({"source": os.path.basename(path), "error": "journalctl not available"})
        return
    except Exception as e:
        emit({"source": os.path.basename(path), "error": f"journalctl failed: {e}"})
        return
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            emit({
                "source": os.path.basename(path),
                "timestamp": obj.get("__REALTIME_TIMESTAMP", ""),
                "unit": obj.get("_SYSTEMD_UNIT", obj.get("SYSLOG_IDENTIFIER", "")),
                "message": obj.get("MESSAGE", ""),
                "raw": line,
            })
        except Exception:
            emit({"source": os.path.basename(path), "raw": line})
    if proc.returncode != 0 and not proc.stdout:
        emit({"source": os.path.basename(path), "error": proc.stderr.strip()[:300]})

# ---- wtmp via utmpdump ------------------------------------------------------
def parse_wtmp(path):
    import subprocess
    try:
        proc = subprocess.run(
            ["utmpdump", path], capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        emit({"source": os.path.basename(path), "error": "utmpdump not available"})
        return
    except Exception as e:
        emit({"source": os.path.basename(path), "error": f"utmpdump failed: {e}"})
        return
    # utmpdump lines look like:
    # Utmp dump of /var/log/wtmp, [7] [31534] [ts/0] [ts] [pts/0] [1.2.3.4] [2024-1-1 00:00:00]
    for line in proc.stdout.splitlines():
        m = re.match(r'^\s*\[([0-9]+)\]\s*\[([^\]]*)\]\s*\[([^\]]*)\]\s*\[([^\]]*)\]\s*\[([^\]]*)\]\s*\[([^\]]*)\]\s*\[([^\]]*)\]\s*$', line)
        if m:
            num, pid, line_id, user, device, host, ts = m.groups()
            emit({
                "source": os.path.basename(path),
                "type": "utmp",
                "pid": pid.strip(),
                "line": line_id.strip(),
                "user": user.strip(),
                "device": device.strip(),
                "host": host.strip(),
                "timestamp": ts.strip(),
                "raw": line,
            })
        else:
            emit({"source": os.path.basename(path), "raw": line})

# ---- dispatch ---------------------------------------------------------------
def main():
    if log_type == "syslog":
        for p in iter_files(target, ("syslog", "syslog.1", "messages", "messages.1")):
            if is_text_log(p): parse_syslog_like(p)
    elif log_type == "auth":
        for p in iter_files(target, ("auth.log", "auth.log.1", "secure", "secure.1")):
            if is_text_log(p): parse_syslog_like(p)
    elif log_type == "journal":
        # target must point at a .journal file or a /var/log/journal dir
        paths = []
        if target and os.path.exists(target):
            paths.append(target)
        else:
            for dp, dns, fns in os.walk("/evidence"):
                for fn in fns:
                    if fn.endswith(".journal"):
                        paths.append(os.path.join(dp, fn))
        for p in paths:
            parse_journal(p)
    elif log_type == "wtmp":
        for p in iter_files(target, ("wtmp", "wtmp.1", "btmp", "btmp.1")):
            parse_wtmp(p)
    elif log_type == "cron":
        for p in iter_files(target, ("cron", "cron.log", "syslog", "syslog.1", "messages", "messages.1")):
            if is_text_log(p):
                parse_cron(p)
    elif log_type == "shell_history":
        # target is a dir or a specific history file
        cands = (".bash_history", ".zsh_history", ".sh_history", ".history")
        if target and os.path.isfile(target):
            parse_history(target)
        else:
            roots = [target] if target else ["/evidence"]
            for root in roots:
                if not os.path.isdir(root):
                    continue
                for dp, dns, fns in os.walk(root):
                    for fn in fns:
                        if fn in cands:
                            parse_history(os.path.join(dp, fn))
    elif log_type == "dpkg":
        for p in iter_files(target, ("dpkg.log", "dpkg.log.1")):
            if is_text_log(p): parse_dpkg(p)
    elif log_type == "systemd_unit":
        parse_systemd_unit(target)
    else:
        emit({"error": f"unknown log_type {log_type!r}"})

main()
'''


def _build_command(log_type: str, sub: str) -> list[str]:
    """Build the container argv: python3 -c '<parser>' <log_type> <target>."""
    target = f"/evidence/{sub}".rstrip("/") if sub else ""
    # shlex.quote the parser body so it survives the argv layering intact
    return [
        "python3", "-c", _PARSER, log_type, target,
    ]


# ---------------------------------------------------------------------------
# Output hash helper (mirrors chainsaw/eztools)
# ---------------------------------------------------------------------------


def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


class LinuxLogParseTool(Tool):
    """Wrap the standard Linux log-parsing tools (journalctl, utmpdump,
    grep/awk, python3) inside ``svetovid/base``."""

    name = "linux_log_parse"
    image = "svetovid/base"
    description = (
        "Parse a Linux forensic log artifact into structured rows. Pick "
        "log_type by artifact: auth.log (ssh/sudo/su), syslog (general), "
        "journal (.journal exports), wtmp (binary login records), cron "
        "(persistence), shell_history (attacker commands), dpkg (installed "
        "packages / backdoors), systemd_unit (.service persistence). Returns "
        "parsed JSON rows. Runs read-only over /evidence."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "log_type": {
                    "type": "string",
                    "enum": list(LOG_TYPES.keys()),
                    "description": "Which Linux log artifact to parse.",
                },
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence to the artifact file or "
                        "directory. If omitted, the parser discovers the "
                        "standard file (e.g. /var/log/auth.log) under /evidence."
                    ),
                },
            },
            "required": ["log_type"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        log_type = args.get("log_type", "")
        sub = args.get("evidence_subpath", "") or ""

        if log_type not in LOG_TYPES:
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"unknown log_type {log_type!r}; pick from {list(LOG_TYPES)}",
            )

        cmd = _build_command(log_type, sub)

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

        # Capture stdout lines so we can persist a provenance copy AND parse
        # them into structured rows. (Mirrors how sleuthkit.py collects
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
                ctx.investigation_id, f"linux_log_parse ({log_type}) failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"linux_log_parse ({log_type}) failed: {e}",
            )

        # The parser emits JSONL to stdout. Persist a local copy (provenance +
        # output_hash) and parse the rows into structured data.
        local_out = Path(ctx.output_dir) / f"linux_{log_type}.jsonl"
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
            summary = f"linux_log_parse ({log_type}): {len(rows)} row(s)"
        else:
            summary = (
                f"linux_log_parse ({log_type}) exited {res.exit_code} "
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
            summary=summary, data={"log_type": log_type, "rows": rows},
        )


# Module-level instance for tool enumeration parity with the other wrappers.
tool = LinuxLogParseTool()
