"""Tool wrapper: CRIU container-checkpoint memory-strings + keyword search.

Svetovid's memory goal (G06) targets raw RAM dumps (raw/lime/vmem) that
Volatility understands. A Kubernetes container checkpoint produced by
``container checkpoint`` (CRIU) is a different format: per-process ``pages-*.img``
files holding raw 4KiB memory pages, a small protobuf header per file, plus
``core-*.img`` / ``pstree.img`` / ``pagemap-*.img`` describing the process
tree and page→file mapping. Volatility cannot parse CRIU images, and
``forensic_keyword_search`` skips binary files (CRIU pages are full of NUL
bytes), so neither existing tool can answer "what's in this compromised
container's RAM".

This tool fills that gap for the container-compromise goal (G19). It runs a
self-contained python3 program (stdlib only, so it works in ``svetovid/base``
or on the host via ``host_fallback=True``) that:

  - concatenates the raw 4KiB page payloads from every ``pages-*.img`` under
    the evidence tree (skipping the ~512-byte protobuf image header each file
    starts with),
  - extracts printable ASCII + UTF-8 strings of ``>= min_len`` characters,
  - evaluates a Boolean/phrase query (re-using the same query grammar as
    ``forensic_search``) over the extracted strings,
  - and emits matching strings with surrounding context and which pages file
    / byte offset they came from.

It also parses ``pstree.img`` / ``core-*.img`` is intentionally NOT attempted
here (those are protobuf; we surface only process *names* when they appear as
plain strings, e.g. argv/cmdline) — the focus is keyword triage of in-RAM
artifacts: C2 URLs/IPs, extortion notes, dropped binaries, command history.

Follows the same event-publishing pattern as k8s_parse / forensic_search:
tool.start, tool.stdout/stderr, tool.end, agent.action, agent.observation,
provenance.recorded.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

# The stdlib-only program run inside svetovid/base (or on the host). It walks
# the evidence tree, concatenates raw 4KiB page payloads from every pages-*.img,
# extracts strings, and runs the Boolean query.
_EXTRACTOR = r'''
import json, os, re, sys

query = sys.argv[1]            # Boolean query, may be empty -> dump all strings
min_len = int(sys.argv[2])     # minimum printable run length
context_chars = int(sys.argv[3])
max_results = int(sys.argv[4])
evidence = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else "/evidence"

out = sys.stdout

def emit(row):
    out.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    out.flush()

# ---- locate CRIU pages files ---------------------------------------------
def find_pages_roots():
    # If the caller pointed us directly at a pages-*.img file, honor it.
    if os.path.isfile(evidence):
        fn = os.path.basename(evidence)
        if fn.startswith("pages-") and fn.endswith(".img"):
            return [os.path.dirname(evidence) or "."]
        # or at a directory of pages files directly
    roots = []
    for dp, dns, fns in os.walk(evidence):
        base = os.path.basename(dp).lower()
        # canonical: a directory literally named "checkpoint" holding pages-*.img
        if base in ("checkpoint",) and any(f.startswith("pages-") and f.endswith(".img") for f in fns):
            roots.append(dp)
    # fallback: any pages-*.img anywhere
    if not roots:
        for dp, dns, fns in os.walk(evidence):
            if any(f.startswith("pages-") and f.endswith(".img") for f in fns):
                roots.append(dp)
    # de-dup, keep shortest first (canonical checkpoint dir)
    seen = set(); ordered = []
    for r in sorted(set(roots), key=len):
        if r not in seen:
            seen.add(r); ordered.append(r)
    return ordered

def iter_pages_files():
    for root in find_pages_roots():
        for fn in sorted(os.listdir(root)):
            if fn.startswith("pages-") and fn.endswith(".img"):
                yield os.path.join(root, fn)

# CRIU pages-*.img layout: a small protobuf "entry" header at the start
# (magic "IMG_FILE" / IMG_SERVICE), then a sequence of raw page payloads.
# The header length varies by CRIU version but is always < PAGE_SIZE and the
# remaining length is always a whole multiple of 4KiB (one page per entry).
# We split on 4KiB boundaries after stripping the leading header bytes.
PAGE = 4096

def raw_pages(path):
    """Yield (file_offset, 4096-byte page) for every page payload in a pages img.

    We detect the protobuf header as the leading bytes before the first whole-
    multiple-of-PAGE alignment. Robust across CRIU versions: header is the
    remainder of (filesize % PAGE).
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size <= PAGE:
        return
    header = size % PAGE
    if header == 0:
        # Some dumps pad the header to a full page; treat first page as header.
        header = PAGE
    with open(path, "rb") as f:
        f.seek(header)
        off = header
        while True:
            chunk = f.read(PAGE)
            if len(chunk) < PAGE:
                break
            yield off, chunk
            off += PAGE

# ---- printable string extraction -----------------------------------------
# Printable ASCII run, min_len long. (Latin-1 decode keeps bytes 1:1 so offsets
# stay correct; non-ASCII garbage simply never matches the printable class.)
PRINT = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)

def extract_strings(blob, base_off):
    for m in PRINT.finditer(blob):
        yield base_off + m.start(), m.group().decode("ascii", "replace")

# ---- Boolean query grammar (same as forensic_search) ---------------------
class Term:
    def __init__(self, text):
        self.text = text.lower()
        self._re = re.compile(re.escape(self.text), re.IGNORECASE)
    def matches(self, s): return self._re.search(s) is not None
    def first_index(self, s):
        m = self._re.search(s); return m.start() if m else -1

class Node:
    def __init__(self, op, children): self.op = op; self.children = children

def _tokenize(q):
    toks = []; i = 0; n = len(q)
    while i < n:
        c = q[i]
        if c.isspace(): i += 1; continue
        if c in "()": toks.append(c); i += 1; continue
        if c == '"':
            j = i+1; buf = []
            while j < n and q[j] != '"': buf.append(q[j]); j += 1
            toks.append('"' + "".join(buf) + '"'); i = j+1 if j < n else j; continue
        j = i; buf = []
        while j < n and not q[j].isspace() and q[j] not in '()"':
            buf.append(q[j]); j += 1
        toks.append("".join(buf)); i = j
    return toks

class _P:
    def __init__(self, toks): self.toks = toks; self.pos = 0
    def _peek(self): return self.toks[self.pos] if self.pos < len(self.toks) else None
    def _next(self): t = self.toks[self.pos]; self.pos += 1; return t
    def por(self):
        left = self.pand(); ch = [left]
        while True:
            t = self._peek()
            if t is not None and (t.upper() == "OR" or t == "|"):
                self._next(); ch.append(self.pand())
            else: break
        return ch[0] if len(ch) == 1 else Node("or", ch)
    def pand(self):
        left = self.pnot(); ch = [left]
        while True:
            t = self._peek()
            if t is None or t == ")" or t.upper() == "OR": break
            if t.upper() == "AND" or t == "&":
                self._next(); ch.append(self.pnot())
            else:
                ch.append(self.pnot())
        return ch[0] if len(ch) == 1 else Node("and", ch)
    def pnot(self):
        t = self._peek()
        if t is not None and (t.upper() == "NOT" or t == "!"):
            self._next(); return Node("not", [self.patom()])
        return self.patom()
    def patom(self):
        t = self._peek()
        if t == "(":
            self._next(); tr = self.por()
            if self._peek() == ")": self._next()
            return tr
        if t is None: return Node("term", [Term("")])
        self._next()
        if t.startswith('"') and t.endswith('"') and len(t) >= 2:
            return Node("term", [Term(t[1:-1])])
        return Node("term", [Term(t)])

def compile_query(q):
    toks = _tokenize(q)
    if not toks: return None
    return _P(toks).por()

def ev(node, s):
    op = node.op
    if op == "term": return node.children[0].matches(s)
    if op == "and": return all(ev(c, s) for c in node.children)
    if op == "or": return any(ev(c, s) for c in node.children)
    if op == "not": return not ev(node.children[0], s)
    return False

def first_idx(node, s):
    if node.op == "term": return node.children[0].first_index(s)
    best = -1
    for c in node.children:
        i = first_idx(c, s)
        if i >= 0 and (best < 0 or i < best): best = i
    return best

# ---- main ----------------------------------------------------------------
def main():
    tree = compile_query(query) if query and query.strip() else None
    pages_files = list(iter_pages_files())
    emit({"artifact_type": "criu_mem", "summary":
          f"scanning {len(pages_files)} pages-*.img file(s)"})
    emitted = 0
    # global string index so we can de-dup identical strings but keep distinct
    # offsets. We keep the first match per (string) to bound output, but record
    # the source file + offset for every distinct hit.
    seen_strings = set()
    for pf in pages_files:
        for off, chunk in raw_pages(pf):
            for soff, s in extract_strings(chunk, off):
                if tree is not None and not ev(tree, s):
                    continue
                key = s
                is_new = key not in seen_strings
                if tree is not None:
                    # for a filtered query, keep all hits (with offsets)
                    idx = first_idx(tree, s)
                    start = max(0, idx - context_chars)
                    end = min(len(s), idx + context_chars)
                    ctx = s[start:end]
                    emit({"artifact_type": "criu_mem", "source": pf,
                          "file_offset": soff, "string": s[:4000], "context": ctx})
                    emitted += 1
                    if emitted >= max_results:
                        emit({"artifact_type": "criu_mem", "summary":
                              f"{emitted} match(es) (cap reached)"})
                        return
                else:
                    # no query -> dump distinct strings only (a strings index)
                    if is_new:
                        seen_strings.add(key)
                        emit({"artifact_type": "criu_mem", "source": pf,
                              "file_offset": soff, "string": s[:4000]})
                        emitted += 1
                        if emitted >= max_results:
                            emit({"artifact_type": "criu_mem", "summary":
                                  f"{emitted} distinct string(s) (cap reached)"})
                            return
    emit({"artifact_type": "criu_mem", "summary":
          f"{emitted} string(s) across {len(pages_files)} pages file(s)"})

main()
'''


def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


class CriuMemTool(Tool):
    """Search raw memory pages from a CRIU container checkpoint.

    Concatenates the 4KiB page payloads from every ``pages-*.img`` in the
    evidence tree, extracts printable strings, and evaluates a Boolean query
    over them. Answers "what was in this compromised container's RAM" — C2
    URLs/IPs, extortion notes, dropped binaries, command history — for evidence
    that Volatility (raw RAM) and forensic_keyword_search (skips binary) both
    cannot parse.
    """

    name = "criu_mem_search"
    image = "svetovid/base"
    description = (
        "Extract and search printable strings from a CRIU container-checkpoint "
        "memory dump (checkpoint/pages-*.img). Use when evidence is a Kubernetes "
        "container checkpoint (CRIU), not a raw RAM dump. Runs a Boolean query "
        "(terms, quoted phrases, AND/OR/NOT) over the extracted strings and "
        "returns matches with the source pages file + byte offset. Pass an "
        "empty query to dump the distinct printable-strings index."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Boolean query over extracted memory strings, e.g. "
                        "'http AND (curl OR wget)', '\"/tmp/\" NOT postgres', "
                        "or 'ransom'. Empty = dump the distinct strings index."
                    ),
                },
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence to the checkpoint dir (default: "
                        "auto-discover checkpoint/ containing pages-*.img)."
                    ),
                },
                "min_string_length": {
                    "type": "number",
                    "default": 5,
                    "description": "Minimum printable-run length to treat as a string.",
                },
                "context_chars": {
                    "type": "number",
                    "default": 60,
                    "description": "Context chars around each match (for filtered queries).",
                },
                "max_results": {
                    "type": "number",
                    "default": 200,
                    "description": "Maximum matches to return.",
                },
            },
            "required": ["query"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        query = args.get("query", "") or ""
        sub = args.get("evidence_subpath", "") or ""
        min_len = int(args.get("min_string_length", 5))
        ctx_chars = int(args.get("context_chars", 60))
        max_results = int(args.get("max_results", 200))

        target = f"/evidence/{sub}".rstrip("/") if sub else "/evidence"
        cmd = [
            "python3", "-c", _EXTRACTOR, query, str(min_len),
            str(ctx_chars), str(max_results), target,
        ]

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

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
                timeout_s=3600,
                mem_limit="8g",
                host_fallback=True,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(
                ctx.investigation_id, f"criu_mem_search failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"criu_mem_search failed: {e}",
            )

        local_out = Path(ctx.output_dir) / "criu_mem.jsonl"
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
        rows = rows[:200000]
        output_hash = _hash_file(local_out)

        summary = next(
            (r.get("summary") for r in reversed(rows) if isinstance(r, dict) and r.get("summary")),
            f"criu_mem_search: {len(rows)} row(s)",
        )

        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s, output_hash,
        ))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": {**args, "query": query},
            "exit_code": res.exit_code, "duration_s": res.duration_s,
            "output_hash": output_hash, "ts": E._now_iso(),
        }))

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
            output_path=str(local_out) if local_out.exists() else None,
            summary=summary, data={"rows": rows},
        )


tool = CriuMemTool()
