#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate docs/TOOL_INVENTORY.md from the research JSONs.

Run from the repo root:
    python3 svetovid/scripts/generate_tool_inventory.py

Reads each C-cluster item from ../agentic-dfir/agentic-dfir/results/*.json
and emits a single markdown doc listing every tool Svetovid depends on:
what it does, its license, the build-vs-buy verdict, how Svetovid installs /
invokes it, and which goals call it.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Path to the research output (../agentic-dfir/results from this repo's root).
REPO_ROOT = Path(__file__).resolve().parents[1]          # .../svetovid
WORKSPACE = REPO_ROOT.parent                              # .../agentic-dfir (the parent)
RESEARCH = WORKSPACE / "agentic-dfir" / "results"
OUT = REPO_ROOT / "docs" / "TOOL_INVENTORY.md"

# Goals each tool feeds (derived from the master scope; kept here so the
# doc stays self-contained without parsing the goal registry).
GOAL_MAP = {
    "C11":  ["G20"],
    "C11a": ["G01", "G03", "G09", "G20"],
    "C11b": ["G03"],
    "C11c": ["G03", "G09"],
    "C11d": ["G03", "G09", "G10", "G11"],
    "C11e": ["G10", "G11"],
    "C11f": ["G03"],
    "C11g": ["G03"],
    "C12":  ["G01", "G02", "G04", "G05", "G08", "G12", "G19"],
    "C12a": ["G05", "G10"],
    "C12b": ["G11"],
    "C13":  ["G02", "G06", "G08"],
    "C13a": ["G06", "G20"],
    "C13b": ["G06", "G20"],
    "C13c": ["G06", "G20"],
    "C14":  ["G07", "G08"],
    "C15":  ["G02", "G07", "G08", "G18"],
    "C16":  ["G01", "G04", "G05", "G08", "G12", "G22"],
    "C17":  ["G01", "G03", "G22"],
    "C17a": ["G01", "G07"],
    "C17b": ["G01", "G02", "G08"],
    "C17c": ["G04", "G05", "G19", "G21", "G22"],
    "C18":  ["G21"],
    "A2":   ["G01", "G02", "G07", "G22"],
}

# How Svetovid packages each tool.
INSTALL = {
    "C11":  ("docker image: svetovid/imaging (dd, dc3dd, ewfacquire)", "raw_cli (subprocess)"),
    "C11a": ("docker image: svetovid/eztools", "TSK: raw_cli; Autopsy: MCP-over-STDIO (4.22+)"),
    "C11b": ("NONE — proprietary, per-seat", "build_replacement → svetovid/eztools stack"),
    "C11c": ("NONE — proprietary, per-seat", "build_replacement → svetovid/eztools stack"),
    "C11d": ("NONE — proprietary, per-seat (AXIOM Process CLI wrappable)", "hybrid: wrap CLI + OSS stack"),
    "C11e": ("NONE — proprietary, per-seat", "hybrid: wrap UFED CLI + iLEAPP/ALEAPP for decode"),
    "C11f": ("docker image: svetovid/carving", "raw_cli"),
    "C11g": ("docker image: svetovid/carving", "raw_cli (prefer C11f Bulk Extractor)"),
    "C12":  ("docker image: svetovid/eztools", "raw_cli per sub-tool"),
    "C12a": ("docker image: svetovid/mobile", "raw_cli (ileapp.py)"),
    "C12b": ("docker image: svetovid/mobile", "raw_cli (aleapp.py)"),
    "C13":  ("docker image: svetovid/volatility", "raw_cli (--output-format jsonl)"),
    "C13a": ("prebuilt binary + docker image: svetovid/volatility", "raw_cli"),
    "C13b": ("static musl binary", "raw_cli"),
    "C13c": ("legacy binary (modern macOS unsupported)", "hybrid: legacy + sysdiagnose fallback"),
    "C14":  ("docker image: svetovid/network", "raw_cli + Zeek scripts + Arkime REST"),
    "C15":  ("docker image: svetovid/malware", "raw_cli (analyzeHeadless / yara / capa / r2)"),
    "C16":  ("docker image: svetovid/timeline", "raw_cli (Plaso) + Timesketch REST"),
    "C17":  ("pip install into backend venv", "native_lib (Python import)"),
    "C17a": ("cargo add evtx (Rust core)", "native_lib (Rust crate)"),
    "C17b": ("docker image: svetovid/eztools", "raw_cli (--jsonl)"),
    "C17c": ("pip install dissect into backend venv", "native_lib + raw_cli (target-query)"),
    "C18":  ("docker-compose stack", "REST API (turbinia_api_lib)"),
    "A2":   ("baked into svetovid/base (STIX bundle)", "read-only MCP server (mitre_attack tool)"),
}


def short_bvb(s: str) -> str:
    s = (s or "").strip()
    for sep in ("—", "–", "-", "\n"):
        if sep in s:
            head = s.split(sep, 1)[0].strip()
            if head and len(head) <= 30:
                return head
    return s


def load_items():
    out = []
    for p in sorted(RESEARCH.glob("C*.json")):
        d = json.loads(p.read_text())
        out.append(d)
    # add A2 (MITRE) — knowledge base, with a synthetic id for the inventory
    a2 = RESEARCH / "A2_MITRE_ATTACK_D3FEND_CAPEC_mapping.json"
    if a2.exists():
        a2d = json.loads(a2.read_text())
        a2d.setdefault("id", "A2")
        out.append(a2d)
    # sort: C11 → C11a → C11b → C12 → C17a → A2
    def key(d):
        iid = d.get("id", "")
        m = re.match(r"([A-Z]+)(\d+)([a-z]*)", iid)
        return (m.group(1), int(m.group(2)), m.group(3)) if m else ("Z", 999, iid)
    out.sort(key=key)
    return out


def main():
    items = load_items()
    md = []
    md.append("# Svetovid — Tool Inventory")
    md.append("")
    md.append("> Auto-generated from `../agentic-dfir/agentic-dfir/results/*.json`.")
    md.append("> Re-run `python3 scripts/generate_tool_inventory.py` to refresh.")
    md.append("")
    md.append("Every tool Svetovid depends on to fulfill its 22 investigation goals.")
    md.append("Commercial tools (X-Ways / EnCase / Magnet / Cellebrite) are listed with")
    md.append("their open-source replacement strategy — we don't bundle proprietary software.")
    md.append("")

    # Summary table — keep cells short so the table is readable
    md.append("## Summary")
    md.append("")
    md.append("| ID | Tool | License (short) | build_vs_buy | Svetovid image | Goals |")
    md.append("|----|------|-----------------|--------------|----------------|-------|")
    for d in items:
        iid = d.get("id", "?")
        name = (d.get("name") or "?").split("(")[0].strip()[:40]
        # License: pull just the first license keyword
        lic_raw = (d.get("license") or "").strip()
        # match common SPDX-ish tokens
        m = re.search(r"(GPLv?\d|GPL-\d|Apache-2|MIT|LGPL|AGPL|BSD|proprietary|Proprietary|VSL|MPL|CPL|IBM|Apache License)",
                      lic_raw)
        license_short = (m.group(1) if m else "?").replace("Apache License", "Apache-2")
        if "proprietary" in lic_raw.lower():
            license_short = "proprietary"
        # build_vs_buy: first word
        bvb_raw = (d.get("build_vs_buy") or "").strip().lower()
        if bvb_raw.startswith("wrap"):
            bvb = "wrap"
        elif "build_replacement" in bvb_raw or bvb_raw.startswith("build"):
            bvb = "build"
        elif bvb_raw.startswith("hybrid") or bvb_raw.startswith("**hybrid"):
            bvb = "hybrid"
        elif bvb_raw.startswith("n/a") or "reference" in bvb_raw:
            bvb = "n/a"
        else:
            bvb = "?"
        image, _ = INSTALL.get(iid, ("?", "?"))
        image_short = image.split("(")[0].strip()[:36]
        goals = ", ".join(GOAL_MAP.get(iid, []))
        md.append(f"| `{iid}` | {name} | {license_short} | {bvb} | `{image_short}` | {goals} |")
    md.append("")

    # Detailed entries
    md.append("## Detailed entries")
    md.append("")
    for d in items:
        iid = d.get("id", "?")
        name = d.get("name", "?")
        md.append(f"### `{iid}` — {name}")
        md.append("")
        summary = (d.get("summary") or "").strip()
        if summary:
            md.append(f"_{summary}_")
            md.append("")
        license_ = (d.get("license") or "_not recorded_").strip()
        bvb = (d.get("build_vs_buy") or "").strip()
        interface = (d.get("interface_type") or "").strip()
        # Truncate at first sentence to keep the doc readable; full reasoning
        # lives in the research report at ../agentic-dfir/report.md.
        def first_chunk(s: str, n: int = 240) -> str:
            s = s.strip()
            for sep in ("。", ". ", "\n", "；", "; "):
                if sep in s:
                    head = s.split(sep, 1)[0].strip()
                    if 10 < len(head) < n:
                        return head + ("…" if len(s) > len(head) else "")
            return s[:n] + ("…" if len(s) > n else "")
        md.append(f"- **License**: {first_chunk(license_)}")
        md.append(f"- **Interface**: {first_chunk(interface)}")
        md.append(f"- **build_vs_buy**: {first_chunk(bvb)}")
        image, invoke = INSTALL.get(iid, ("?", "?"))
        md.append(f"- **Svetovid install**: `{image}`")
        md.append(f"- **Svetovid invokes**: {invoke}")
        goals = GOAL_MAP.get(iid, [])
        if goals:
            md.append(f"- **Invoked by goals**: {', '.join(goals)}")
        # Commercial replacement strategy
        if "build_replacement" in bvb.lower() or "hybrid" in bvb.lower():
            md.append("")
            md.append("> **Replacement strategy**: Svetovid uses the open-source stack")
            md.append("> (TSK + Volatility 3 + iLEAPP/ALEAPP + Dissect + Chainsaw) by default.")
            md.append("> Wrapping a customer's already-licensed commercial install is opt-in config.")
        md.append("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(md), encoding="utf-8")
    print(f"wrote {OUT}  ({OUT.stat().st_size:,} bytes, {len(items)} tools)")


if __name__ == "__main__":
    main()
