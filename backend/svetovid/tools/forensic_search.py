"""Forensic keyword search with context (EnScript gap — Tool 8).

EnCase's indexed search supports stemming, proximity, wildcard, and Boolean
operators with forensic-aware context extraction (surrounding text + file
metadata). Plain ``grep``/``ripgrep`` match lines but don't evaluate a
Boolean query, extract symmetric context windows, or skip binary files by
magic — and they don't build a result set the agent can page through.

This tool implements:
  - Boolean operators ``AND`` / ``OR`` / ``NOT`` (case-insensitive, English
    keywords) over whole-file content,
  - phrase matching with double quotes (``"secret key"``),
  - case-insensitive term matching by default,
  - symmetric context extraction (N chars before/after the first match),
  - binary-file skipping via a magic-byte / NUL heuristic,
  - a result cap.

The query evaluator is factored into ``compile_query`` / ``evaluate_query``
so the unit test can drive Boolean logic directly. Runs in ``svetovid/base``
and prefers ``rg`` when present for speed, falling back to a pure-Python
walk. The Boolean/context layer is always Python regardless.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult

DEFAULT_CONTEXT_CHARS = 80
DEFAULT_MAX_RESULTS = 100
# Binary magic prefixes we never read as text.
_BIN_PREFIXES = (
    b"MZ", b"\x7fELF", b"\xfe\xed\xfa", b"\xcf\x84\x01", b"\x1f\x8b",
    b"PK\x03\x04", b"Rar!", b"\x42\x5a\x68", b"ElfFile\x00",
)
_SKIP_EXT = {
    ".exe", ".dll", ".sys", ".so", ".dylib", ".bin", ".dat", ".db", ".sqlite",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".ico",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flv",
    ".zip", ".gz", ".tar", ".7z", ".rar", ".bz2", ".xz", ".evtx", ".pf",
}


class Term:
    """A leaf search term: a phrase or a single word, case-insensitive."""

    def __init__(self, text: str) -> None:
        self.text = text.lower()
        self.is_phrase = " " in text
        self._re = re.compile(re.escape(self.text), re.IGNORECASE)

    def matches(self, content: str) -> bool:
        return self._re.search(content) is not None

    def first_index(self, content: str) -> int:
        m = self._re.search(content)
        return m.start() if m else -1


class Node:
    """Boolean node: AND / OR / NOT over child terms/nodes, or a leaf Term."""

    def __init__(self, op: str, children: list[Any]) -> None:
        self.op = op  # "and" | "or" | "not" | "term"
        self.children = children


def compile_query(query: str) -> Node:
    """Compile a Boolean query string into an evaluation tree.

    Supports quoted phrases, ``AND``/``OR``/``NOT`` (uppercase or lowercase),
    and parentheses. Bare whitespace-separated terms are implicitly AND-ed.
    Host-testable.

    Grammar (recursive descent)::

        or_expr  := and_expr ( OR and_expr )*
        and_expr := not_expr ( (AND)? not_expr )*      # implicit AND
        not_expr := NOT atom | atom
        atom     := '(' or_expr ')' | PHRASE | TERM
    """
    tokens = _tokenize(query)
    parser = _Parser(tokens)
    if not tokens:
        return Node("term", [Term("")])
    tree = parser.parse_or()
    return tree


def _tokenize(query: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    n = len(query)
    while i < n:
        c = query[i]
        if c.isspace():
            i += 1
            continue
        if c == "(" or c == ")":
            tokens.append(c)
            i += 1
            continue
        if c == '"':
            j = i + 1
            buf = []
            while j < n and query[j] != '"':
                buf.append(query[j])
                j += 1
            tokens.append('"' + "".join(buf) + '"')  # keep quotes as phrase marker
            i = j + 1 if j < n else j
            continue
        # Read a bare word up to whitespace/paren/quote.
        j = i
        buf = []
        while j < n and not query[j].isspace() and query[j] not in '()"':
            buf.append(query[j])
            j += 1
        tokens.append("".join(buf))
        i = j
    return tokens


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse_or(self) -> Node:
        left = self.parse_and()
        children = [left]
        while True:
            tok = self._peek()
            if tok is not None and tok.upper() == "OR":
                self._next()
                children.append(self.parse_and())
            elif tok == "|":
                self._next()
                children.append(self.parse_and())
            else:
                break
        if len(children) == 1:
            return children[0]
        return Node("or", children)

    def parse_and(self) -> Node:
        left = self.parse_not()
        children = [left]
        while True:
            tok = self._peek()
            if tok is None or tok == ")":
                break
            if tok.upper() == "OR":
                break
            if tok.upper() == "AND" or tok == "&":
                self._next()
                children.append(self.parse_not())
            else:
                # implicit AND before the next atom
                children.append(self.parse_not())
        if len(children) == 1:
            return children[0]
        return Node("and", children)

    def parse_not(self) -> Node:
        tok = self._peek()
        if tok is not None and (tok.upper() == "NOT" or tok == "!"):
            self._next()
            return Node("not", [self.parse_atom()])
        return self.parse_atom()

    def parse_atom(self) -> Node:
        tok = self._peek()
        if tok == "(":
            self._next()
            tree = self.parse_or()
            if self._peek() == ")":
                self._next()
            return tree
        if tok is None:
            return Node("term", [Term("")])
        self._next()
        if tok.startswith('"') and tok.endswith('"') and len(tok) >= 2:
            return Node("term", [Term(tok[1:-1])])
        return Node("term", [Term(tok)])


def evaluate_query(node: Node, content: str) -> bool:
    """Evaluate a compiled query tree against whole-file ``content``."""
    op = node.op
    if op == "term":
        return node.children[0].matches(content)
    if op == "and":
        return all(evaluate_query(c, content) for c in node.children)
    if op == "or":
        return any(evaluate_query(c, content) for c in node.children)
    if op == "not":
        return not evaluate_query(node.children[0], content)
    return False


def first_match_index(node: Node, content: str) -> int:
    """Return the earliest positive term match index, or -1 if none."""
    if node.op == "term":
        return node.children[0].first_index(content)
    best = -1
    for c in node.children:
        idx = first_match_index(c, content)
        if idx >= 0 and (best < 0 or idx < best):
            best = idx
    return best


def collect_terms(node: Node) -> list[Term]:
    """Flatten the positive (non-NOT) leaf terms for context highlighting."""
    out: list[Term] = []
    if node.op == "term":
        out.append(node.children[0])
    else:
        for c in node.children:
            out.extend(collect_terms(c))
    return out


# ---------------------------------------------------------------------------
# Embedded search script run inside svetovid/base.
# ---------------------------------------------------------------------------

_SEARCH_SCRIPT = r'''#!/usr/bin/env python3
"""Forensic keyword search — runs inside svetovid/base.

Walks the evidence tree, evaluates a Boolean query over each text file, and
emits matches with surrounding context. Prefers ripgrep for file enumeration
+ raw matching when present, but the Boolean/context layer is always Python.

Usage:
    forensic_search.py <evidence_path> <output_json> <query> <context_chars> <max_results>
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

_BIN_PREFIXES = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa", b"\xcf\x84\x01", b"\x1f\x8b",
                 b"PK\x03\x04", b"Rar!", b"\x42\x5a\x68", b"ElfFile\x00")
_SKIP_EXT = {".exe",".dll",".sys",".so",".dylib",".bin",".dat",".db",".sqlite",
             ".jpg",".jpeg",".png",".gif",".bmp",".tiff",".webp",".ico",
             ".mp3",".mp4",".avi",".mov",".mkv",".wav",".flv",
             ".zip",".gz",".tar",".7z",".rar",".bz2",".xz",".evtx",".pf"}


class Term:
    def __init__(self, text):
        self.text = text
        self._re = re.compile(re.escape(text.lower()), re.IGNORECASE)
    def matches(self, content):
        return self._re.search(content) is not None
    def first_index(self, content):
        m = self._re.search(content)
        return m.start() if m else -1


class Node:
    def __init__(self, op, children):
        self.op = op
        self.children = children


def _tokenize(query):
    tokens = []
    i, n = 0, len(query)
    while i < n:
        c = query[i]
        if c.isspace():
            i += 1; continue
        if c in "()":
            tokens.append(c); i += 1; continue
        if c == '"':
            j = i + 1; buf = []
            while j < n and query[j] != '"':
                buf.append(query[j]); j += 1
            tokens.append('"' + "".join(buf) + '"')
            i = j + 1 if j < n else j
            continue
        j = i; buf = []
        while j < n and not query[j].isspace() and query[j] not in '()"':
            buf.append(query[j]); j += 1
        tokens.append("".join(buf)); i = j
    return tokens


class _Parser:
    def __init__(self, tokens):
        self.tokens = tokens; self.pos = 0
    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None
    def _next(self):
        t = self.tokens[self.pos]; self.pos += 1; return t
    def parse_or(self):
        left = self.parse_and(); children = [left]
        while True:
            t = self._peek()
            if t is not None and (t.upper() == "OR" or t == "|"):
                self._next(); children.append(self.parse_and())
            else:
                break
        return children[0] if len(children) == 1 else Node("or", children)
    def parse_and(self):
        left = self.parse_not(); children = [left]
        while True:
            t = self._peek()
            if t is None or t == ")" or t.upper() == "OR":
                break
            if t.upper() == "AND" or t == "&":
                self._next(); children.append(self.parse_not())
            else:
                children.append(self.parse_not())
        return children[0] if len(children) == 1 else Node("and", children)
    def parse_not(self):
        t = self._peek()
        if t is not None and (t.upper() == "NOT" or t == "!"):
            self._next(); return Node("not", [self.parse_atom()])
        return self.parse_atom()
    def parse_atom(self):
        t = self._peek()
        if t == "(":
            self._next(); tree = self.parse_or()
            if self._peek() == ")":
                self._next()
            return tree
        if t is None:
            return Node("term", [Term("")])
        self._next()
        if t.startswith('"') and t.endswith('"') and len(t) >= 2:
            return Node("term", [Term(t[1:-1])])
        return Node("term", [Term(t)])


def compile_query(query):
    tokens = _tokenize(query)
    if not tokens:
        return Node("term", [Term("")])
    return _Parser(tokens).parse_or()


def evaluate(node, content):
    op = node.op
    if op == "term":
        return node.children[0].matches(content)
    if op == "and":
        return all(evaluate(c, content) for c in node.children)
    if op == "or":
        return any(evaluate(c, content) for c in node.children)
    if op == "not":
        return not evaluate(node.children[0], content)
    return False


def first_match_index(node, content):
    if node.op == "term":
        return node.children[0].first_index(content)
    best = -1
    for c in node.children:
        idx = first_match_index(c, content)
        if idx >= 0 and (best < 0 or idx < best):
            best = idx
    return best


def collect_terms(node):
    out = []
    if node.op == "term":
        out.append(node.children[0])
    else:
        for c in node.children:
            out.extend(collect_terms(c))
    return out


def _looks_textual(head):
    if head.startswith(_BIN_PREFIXES):
        return False
    if b"\x00" in head:
        return False
    if not head:
        return True
    non_text = sum(1 for b in head if b < 9 or (13 < b < 32))
    return non_text / max(1, len(head)) < 0.10


def search(root, query, context_chars, max_results):
    tree = compile_query(query)
    terms = collect_terms(tree)
    results = []
    files = sorted(root.rglob("*")) if root.is_dir() else [root]
    have_rg = shutil.which("rg") is not None
    for f in files:
        if not f.is_file() or f.suffix.lower() in _SKIP_EXT:
            continue
        try:
            with open(f, "rb") as fh:
                head = fh.read(2048)
            if not _looks_textual(head):
                continue
            content = open(f, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if not evaluate(tree, content):
            continue
        idx = first_match_index(tree, content)
        if idx < 0:
            idx = 0
        start = max(0, idx - context_chars)
        end = min(len(content), idx + context_chars)
        before = content[start:idx].replace("\n", " ").strip()
        after = content[idx:end].replace("\n", " ").strip()
        # Line number of the first matching term.
        lineno = 1
        for t in terms:
            li = t.first_index(content)
            if li >= 0:
                lineno = content.count("\n", 0, li) + 1
                break
        match_text = ""
        for t in terms:
            mi = t.first_index(content)
            if mi >= 0:
                match_text = t.text
                break
        results.append({
            "file": str(f),
            "line_number": lineno,
            "match": match_text,
            "context_before": before,
            "context_after": after,
            "file_size": len(content),
        })
        if len(results) >= max_results:
            break
    return results


def main(argv):
    if len(argv) != 6:
        print("usage: forensic_search.py <evidence_path> <output_json> "
              "<query> <context_chars> <max_results>", file=sys.stderr)
        return 2
    evidence_path, out_json, query = argv[1], argv[2], argv[3]
    try:
        context_chars = int(argv[4])
    except ValueError:
        context_chars = 80
    try:
        max_results = int(argv[5])
    except ValueError:
        max_results = 100
    root = Path(evidence_path)
    if not root.exists():
        with open(out_json, "w") as fh:
            json.dump({"results": [], "error": "path not found: " + evidence_path}, fh)
        return 0
    results = search(root, query, context_chars, max_results)
    summary = "%d match(es) for %r" % (len(results), query)
    payload = {"results": results, "query": query, "summary": summary}
    with open(out_json, "w") as fh:
        json.dump(payload, fh, ensure_ascii=False, default=str)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


class ForensicSearchTool(Tool):
    name = "forensic_keyword_search"
    image = "svetovid/base"
    description = (
        "Forensic keyword search with Boolean operators (AND/OR/NOT), quoted "
        "phrase matching, case-insensitive terms, and symmetric context "
        "extraction around each match. Skips binary files by magic byte. "
        "Returns matches with line numbers + surrounding text. Fills the "
        "EnCase indexed-search EnScript gap (ripgrep lacks Boolean eval + "
        "context extraction)."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence to search (file or directory)."
                    ),
                },
                "query": {
                    "type": "string",
                    "description": (
                        "Boolean query: terms, quoted phrases, and "
                        "AND/OR/NOT operators, e.g. 'password AND admin' or "
                        "'\"secret key\" NOT test'."
                    ),
                },
                "context_chars": {
                    "type": "number",
                    "default": DEFAULT_CONTEXT_CHARS,
                    "description": "Characters of context to extract before/after each match.",
                },
                "max_results": {
                    "type": "number",
                    "default": DEFAULT_MAX_RESULTS,
                    "description": "Maximum number of matching files to return.",
                },
            },
            "required": ["query"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        sub = args.get("evidence_subpath", "") or ""
        query = args.get("query", "") or ""
        context_chars = int(args.get("context_chars", DEFAULT_CONTEXT_CHARS))
        max_results = int(args.get("max_results", DEFAULT_MAX_RESULTS))

        if not query:
            msg = "forensic_keyword_search: 'query' is required."
            ctx.bus.publish(E.error_event(ctx.investigation_id, msg))
            ctx.bus.publish(E.tool_end(ctx.investigation_id, call_id, 2, 0.0, None))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None, summary=msg,
            )

        out_json = "/work/forensic_search.json"
        script_host = Path(ctx.output_dir) / "forensic_search.py"
        script_host.write_text(_SEARCH_SCRIPT)

        cmd = [
            "python3", "/work/forensic_search.py",
            (f"/evidence/{sub}".rstrip("/") if sub else "/evidence"),
            out_json,
            query,
            str(context_chars),
            str(max_results),
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
                ctx.investigation_id, f"forensic_keyword_search failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"forensic_keyword_search failed: {e}",
            )

        results: list[dict[str, Any]] = []
        summary = ""
        local_out = Path(ctx.output_dir) / "forensic_search.json"
        if local_out.exists():
            try:
                payload = json.loads(local_out.read_text())
                if isinstance(payload, dict):
                    results = payload.get("results", [])
                    summary = payload.get("summary", "")
            except Exception as e:
                summary = f"forensic_search output couldn't be parsed: {e}"
        if not summary:
            summary = f"forensic_keyword_search exited {res.exit_code} with no output"

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
            summary=summary, data={"results": results},
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


tool = ForensicSearchTool()
