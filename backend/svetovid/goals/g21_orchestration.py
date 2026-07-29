"""G21 — Distributed / large-scale forensic orchestration.

A *fixed-workflow* orchestration goal (like G01, NOT ReAct). It walks a case
directory that may contain many independent evidence sets — multiple disk
images (.E01/.raw), memory dumps, KAPE triage folders — and produces an
**orchestration plan** describing how a distributed forensic platform
(Turbinia, or equivalent worker pool) would parallelize the work and
aggregate the results into one normalized per-host timeline.

In M10 this goal is **plan-only**: it does not touch evidence and does not
invoke any processing tools. The seven nodes walk the evidence directory,
inventory what is present, decide which tool each evidence set needs, emit a
parallel execution plan, describe the aggregation step, and draft the report.
The actual distributed execution requires Turbinia infrastructure, which is a
runtime/config concern handled outside this goal.

Pipeline:

  triage
    → inventory_evidence   (list every evidence set with type/size/tool hint)
    → plan_parallel_jobs   (Plaso / Vol3 / KAPE per evidence set)
    → execute_workers      (emit progress events describing the plan; no exec)
    → aggregate_results    (describe the normalized per-host timeline merge)
    → draft_report         (evidence inventory + processing plan + estimates)
    → finalize             (summary)

No HITL gate is required because the goal is read-only / plan-only: it never
writes to or processes evidence.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from ..agent import events as E
from ..config import load_settings
from ..llm.client import build_chat
from .base import Goal, GoalNode


# ---------------------------------------------------------------------------
# Evidence classification
# ---------------------------------------------------------------------------

# Suffix → (evidence kind, suggested processing tool, research C-id).
# These mirror the tool taxonomy referenced by the other goals (C16 = Plaso,
# C12 = Volatility/KAPE family, C17c = artifact parsing) so the plan reads
# against the same vocabulary the rest of the UI uses.
_SUFFIX_KINDS: dict[str, tuple[str, str, str]] = {
    # disk images → Plaso timeline generation
    ".e01":  ("disk_image",  "plaso",       "C16"),
    ".ex01": ("disk_image",  "plaso",       "C16"),
    ".raw":  ("disk_image",  "plaso",       "C16"),
    ".dd":   ("disk_image",  "plaso",       "C16"),
    ".img":  ("disk_image",  "plaso",       "C16"),
    ".aff":  ("disk_image",  "plaso",       "C16"),
    # memory images → Volatility 3
    ".mem":  ("memory",      "volatility3", "C12"),
    ".vmem": ("memory",      "volatility3", "C12"),
    ".lime": ("memory",      "volatility3", "C12"),
    ".dmp":  ("memory",      "volatility3", "C12"),
    # single-file forensic artifacts → artifact parser
    ".evtx": ("evtx_logs",   "artifact_parser", "C17c"),
    ".pcap": ("network",     "artifact_parser", "C17c"),
    ".pcapng": ("network",   "artifact_parser", "C17c"),
}

# Filenames that mark a directory as a KAPE triage export (Windows live
# response). KAPE-style folders contain collections like _kape-cli-targets
# plus standard hive / log files at the top level.
_KAPE_MARKERS = ("_kape", "kape", "live_response", "triage")


class OrchestrationGoal(Goal):
    id = "G21"
    cluster = "Cross-cutting"
    label = "Distributed forensic orchestration"
    description = (
        "Orchestrate large-scale forensic processing across multiple hosts or "
        "evidence sets. Parallelizes Plaso timeline generation, Volatility "
        "analysis, and artifact parsing, then aggregates results into a "
        "normalized per-host timeline."
    )
    input_artifacts = ["B3", "B4", "B5", "B6"]
    tools = ["C18", "C16", "C17c", "C12"]
    icon = "network"

    def nodes(self) -> list[GoalNode]:
        return [
            GoalNode("triage", "Triage evidence"),
            GoalNode("inventory_evidence", "Inventory evidence sets"),
            GoalNode("plan_parallel_jobs", "Plan parallel jobs"),
            GoalNode("execute_workers", "Describe worker execution"),
            GoalNode("aggregate_results", "Aggregate results"),
            GoalNode("draft_report", "Draft orchestration report"),
            GoalNode("finalize", "Finalize"),
        ]

    async def run(self, *, investigation_id: str, case_id: str,
                  evidence_path: str, user_prompt: str, bus) -> None:
        out_dir = str(Path.home() / ".svetovid" / "cases" / case_id / investigation_id)
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        # ---- triage: discover evidence sets under the case dir ----
        await self._set_node(bus, investigation_id, "triage", "running")
        evidence_sets = await self._discover_evidence(evidence_path)
        if not evidence_sets:
            bus.publish(E.agent_thought(
                investigation_id,
                f"No recognizable evidence sets found under {evidence_path}. "
                "Goal cannot proceed.",
            ))
            await self._set_node(bus, investigation_id, "triage", "failed")
            return
        bus.publish(E.agent_thought(
            investigation_id,
            f"Discovered {len(evidence_sets)} evidence set(s) under "
            f"{evidence_path}.",
        ))
        await self._set_node(bus, investigation_id, "triage", "done")

        # ---- inventory_evidence: per-set type / size / tool hint ----
        await self._set_node(bus, investigation_id, "inventory_evidence", "running")
        inventory_md = _render_inventory(evidence_sets)
        bus.publish(E.report_section_added(
            investigation_id, "inventory", "Evidence inventory", inventory_md,
        ))
        bus.publish(E.agent_thought(
            investigation_id,
            f"Inventory complete: {_summary_counts(evidence_sets)}",
        ))
        await self._set_node(bus, investigation_id, "inventory_evidence", "done")

        # ---- plan_parallel_jobs: one job per evidence set ----
        await self._set_node(bus, investigation_id, "plan_parallel_jobs", "running")
        jobs = _build_job_plan(evidence_sets)
        plan_md = _render_job_plan(jobs)
        bus.publish(E.report_section_added(
            investigation_id, "processing_plan", "Processing plan", plan_md,
        ))
        bus.publish(E.agent_thought(
            investigation_id,
            f"Planned {len(jobs)} parallel job(s): "
            + ", ".join(f"{j['tool']}×{j['count']}" for j in jobs),
        ))
        await self._set_node(bus, investigation_id, "plan_parallel_jobs", "done")

        # ---- execute_workers: emit plan progress (no actual execution) ----
        await self._set_node(bus, investigation_id, "execute_workers", "running")
        execute_md = _render_execution_plan(jobs, evidence_sets)
        bus.publish(E.report_section_added(
            investigation_id, "execution_plan", "Worker execution plan",
            execute_md,
        ))
        # Stream a progress tick per planned job so the StepProgress / AgentTrace
        # panes show the parallel fan-out. In M10 this is plan-only; a real
        # Turbinia runtime would dispatch these as actual evidence jobs.
        for idx, es in enumerate(evidence_sets, start=1):
            bus.publish(E.agent_action(
                investigation_id,
                tool=es["tool_hint"],
                args={
                    "evidence_set": es["path"],
                    "kind": es["kind"],
                    "host": es.get("host") or "(unnamed)",
                    "planned": True,
                },
                node="execute_workers",
            ))
            bus.publish(E.tool_progress(
                investigation_id,
                f"plan_{idx}",
                pct=idx / max(1, len(evidence_sets)),
                msg=f"Would dispatch {es['tool_hint']} on {es['path']}",
            ))
        bus.publish(E.agent_thought(
            investigation_id,
            "Execution plan emitted. Actual distributed execution requires "
            "Turbinia infrastructure (runtime config); M10 is plan-only.",
        ))
        await self._set_node(bus, investigation_id, "execute_workers", "done")

        # ---- aggregate_results: describe the merge into per-host timelines ----
        await self._set_node(bus, investigation_id, "aggregate_results", "running")
        aggregate_md = _render_aggregation(evidence_sets)
        bus.publish(E.report_section_added(
            investigation_id, "aggregation", "Aggregation strategy",
            aggregate_md,
        ))
        await self._set_node(bus, investigation_id, "aggregate_results", "done")

        # ---- draft_report: narrative + estimates ----
        await self._set_node(bus, investigation_id, "draft_report", "running")
        estimate = _estimate_resources(evidence_sets, jobs)
        bus.publish(E.report_section_added(
            investigation_id, "resource_estimate", "Resource estimate",
            _render_resource_estimate(estimate),
        ))
        narrative = await self._draft_narrative(
            evidence_sets, jobs, estimate, user_prompt,
        )
        bus.publish(E.report_section_added(
            investigation_id, "narrative", "Orchestration narrative", narrative,
        ))
        await self._set_node(bus, investigation_id, "draft_report", "done")

        # ---- finalize: summary (no HITL — read-only plan) ----
        await self._set_node(bus, investigation_id, "finalize", "running")
        bus.publish(E.report_section_added(
            investigation_id, "summary", "Summary",
            f"**Orchestration plan** for {len(evidence_sets)} evidence set(s) "
            f"({estimate['total_bytes_human']}) across "
            f"{estimate['host_count']} host(s). "
            f"{len(jobs)} parallel job family/ies planned. Plan-only in M10 "
            f"— Turbinia runtime required for execution.",
        ))
        await self._set_node(bus, investigation_id, "finalize", "done")

    # -- helpers -----------------------------------------------------------

    async def _set_node(self, bus, inv_id: str, node: str, status: str) -> None:
        bus.publish(E.node_state_change(inv_id, node, status))  # type: ignore[arg-type]

    async def _discover_evidence(self, root: str) -> list[dict[str, Any]]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _walk_for_evidence, root)

    async def _draft_narrative(self, evidence_sets, jobs, estimate, user_prompt):
        """LLM-written orchestration narrative; deterministic fallback if no LLM."""
        try:
            settings = load_settings()
            provider = settings.active()
            if provider is None or not provider.is_configured() or not provider.api_key:
                return _fallback_narrative(evidence_sets, jobs, estimate, user_prompt)
            chat = build_chat(provider, streaming=False)
            context = json.dumps({
                "evidence_sets": [
                    {k: v for k, v in es.items() if k != "path"} | {"path": es["path"]}
                    for es in evidence_sets
                ],
                "job_plan": jobs,
                "estimate": estimate,
                "user_goal": user_prompt or "Orchestrate distributed forensic processing.",
            }, ensure_ascii=False, default=str)[:8000]
            resp = await chat.ainvoke([
                {"role": "system", "content": (
                    "You are a DFIR orchestration engineer. Given an evidence "
                    "inventory and a parallel processing plan, write a concise "
                    "Markdown narrative (4-6 short paragraphs) describing how "
                    "the case would be processed at scale: which tools run "
                    "where, the expected wall-clock time, and how per-host "
                    "results merge into one normalized timeline. Note that "
                    "actual execution requires Turbinia infrastructure. Do NOT "
                    "invent evidence sets not present in the data."
                )},
                {"role": "user", "content": context},
            ])
            return resp.content if isinstance(resp.content, str) else str(resp.content)
        except Exception as e:
            return _fallback_narrative(evidence_sets, jobs, estimate, user_prompt) \
                + f"\n\n<!-- LLM unavailable: {e} -->"


# ---------------------------------------------------------------------------
# Evidence discovery + classification (module-level, run in an executor)
# ---------------------------------------------------------------------------


def _walk_for_evidence(root: str) -> list[dict[str, Any]]:
    """Discover discrete evidence sets under ``root``.

    A single evidence set is either a recognized forensic image / dump file
    (each image is its own set, since they are typically large and processed
    independently) or a directory that looks like a KAPE triage export. Plain
    host directories with collected artifacts are treated as a per-host set
    keyed by the directory name.
    """
    base = Path(root)
    sets: list[dict[str, Any]] = []

    if not base.exists():
        return sets

    # 1) Recognized image / dump files anywhere under the tree. Each is its
    #    own evidence set because it represents an independent acquisition.
    for p in base.rglob("*"):
        if not p.is_file():
            continue
        suf = p.suffix.lower()
        kind = _SUFFIX_KINDS.get(suf)
        if not kind:
            continue
        ek, tool, cid = kind
        sets.append({
            "path": str(p),
            "name": p.name,
            "kind": ek,
            "tool_hint": tool,
            "tool_cid": cid,
            "size": p.stat().st_size,
            "host": _infer_host(p, base),
            "is_file": True,
        })

    # 2) Directories that look like KAPE / Windows triage folders. We walk the
    #    top level (depth 1) so a nested image doesn't double-count its parent
    #    as a triage set.
    image_paths = {s["path"] for s in sets}
    for d in sorted(p for p in base.glob("*") if p.is_dir()):
        if str(d) in image_paths:
            continue
        if _looks_like_kape(d):
            size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
            sets.append({
                "path": str(d),
                "name": d.name,
                "kind": "kape_triage",
                "tool_hint": "kape",
                "tool_cid": "C12",
                "size": size,
                "host": _infer_host(d, base),
                "is_file": False,
            })

    return sets


def _looks_like_kape(d: Path) -> bool:
    name_l = d.name.lower()
    if any(marker in name_l for marker in _KAPE_MARKERS):
        return True
    # A Windows triage folder: at least one known hive/log file directly inside.
    known = {n.lower() for n in (
        "ntuser.dat", "system", "software", "sam", "security",
        "mft", "$mft", "registry", "evtx", "logs",
    )}
    try:
        children = [c.name.lower() for c in d.iterdir()]
    except OSError:
        return False
    return any(any(kw in c for kw in known) for c in children)


def _infer_host(p: Path, base: Path) -> str:
    """Best-effort host name: the first directory component under the root."""
    try:
        rel = p.relative_to(base)
    except ValueError:
        return "(unnamed)"
    parts = rel.parts
    if p.is_file() and len(parts) >= 2:
        return parts[0]
    if p.is_dir() and len(parts) >= 1:
        return parts[0]
    return "(unnamed)"


# ---------------------------------------------------------------------------
# Rendering helpers (deterministic Markdown)
# ---------------------------------------------------------------------------


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.1f} TB"


def _summary_counts(sets: list[dict[str, Any]]) -> str:
    by_kind: dict[str, int] = {}
    for s in sets:
        by_kind[s["kind"]] = by_kind.get(s["kind"], 0) + 1
    return ", ".join(f"{v} {k}" for k, v in sorted(by_kind.items())) or "no sets"


def _render_inventory(sets: list[dict[str, Any]]) -> str:
    head = (
        "| # | Evidence set | Kind | Tool | Size | Host |\n"
        "|---|---|---|---|---|---|"
    )
    rows = []
    for i, s in enumerate(sets, start=1):
        rows.append(
            f"| {i} | `{s['name']}` | {s['kind']} | "
            f"{s['tool_hint']} ({s['tool_cid']}) | "
            f"{_human_bytes(s['size'])} | {s.get('host') or '(unnamed)'} |"
        )
    return head + "\n" + "\n".join(rows)


def _build_job_plan(sets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Roll up evidence sets into per-tool job families."""
    by_tool: dict[str, list[dict[str, Any]]] = {}
    for s in sets:
        by_tool.setdefault(s["tool_hint"], []).append(s)
    plan = []
    for tool, members in sorted(by_tool.items()):
        cid = members[0]["tool_cid"]
        plan.append({
            "tool": tool,
            "tool_cid": cid,
            "count": len(members),
            "evidence_sets": [m["path"] for m in members],
        })
    return plan


def _render_job_plan(jobs: list[dict[str, Any]]) -> str:
    if not jobs:
        return "_No processing jobs planned (empty evidence inventory)._"
    lines = [
        "| Tool | Tool C-id | Evidence sets | Notes |",
        "|---|---|---|---|",
    ]
    note = {
        "plaso": "Disk image → log2timeline / psort (per-image superclock timeline).",
        "volatility3": "Memory image → pslist/malfind/netscan; one plugin set per dump.",
        "kape": "KAPE triage folder → module-target extraction across hive/log/file artifacts.",
        "artifact_parser": "Single artifact (evtx/pcap) → bulk parse + normalize.",
    }
    for j in jobs:
        lines.append(
            f"| {j['tool']} | {j['tool_cid']} | {j['count']} | "
            f"{note.get(j['tool'], 'Per-evidence-set processing.')} |"
        )
    return "\n".join(lines)


def _render_execution_plan(jobs: list[dict[str, Any]],
                           sets: list[dict[str, Any]]) -> str:
    lines = [
        "Distributed execution plan (M10 = **plan-only**, no evidence touched):",
        "",
        "- Each evidence set is dispatched to an independent worker so large "
        "images process in parallel rather than serially.",
        "- Jobs of the same tool family (e.g. all Plaso runs) are batched onto "
        "a worker pool sized to available CPU/RAM.",
        f"- **Planned fan-out**: {len(sets)} worker dispatch(es) across "
        f"{len(jobs)} tool family/ies.",
        "",
        "Actual execution requires Turbinia (or an equivalent orchestration "
        "runtime) configured via runtime settings; this goal emits the plan "
        "that runtime would consume.",
    ]
    return "\n".join(lines)


def _render_aggregation(sets: list[dict[str, Any]]) -> str:
    hosts = sorted({s.get("host") or "(unnamed)" for s in sets})
    lines = [
        "Aggregation strategy (per-host → normalized timeline):",
        "",
        f"- **Hosts**: {', '.join(hosts) if hosts else '(none)'}",
        "- Each worker emits a normalized event stream (timestamp, host, "
        "source, description, ATT&CK tag).",
        "- The aggregator merges streams by UTC timestamp, de-duplicates "
        "overlapping sources (e.g. an .evtx event also parsed from a Plaso "
        "superclock timeline), and keys the merged timeline by host.",
        "- Cross-host pivot keys (user, process name, IP, hash) are indexed so "
        "lateral movement surfaces as a single correlated finding rather than "
        "per-host noise.",
    ]
    return "\n".join(lines)


def _estimate_resources(sets: list[dict[str, Any]],
                        jobs: list[dict[str, Any]]) -> dict[str, Any]:
    total_bytes = sum(s["size"] for s in sets)
    hosts = {s.get("host") or "(unnamed)" for s in sets}
    # Rough planning heuristics: Plaso ≈ 0.5 GB/hr per 50 GB image; Vol3 ≈
    # 30 min per 8 GB dump; KAPE ≈ 20 min per folder; artifact parse ≈ 5 min.
    minutes = 0.0
    for s in sets:
        gb = max(s["size"] / (1024 ** 3), 0.01)
        if s["tool_hint"] == "plaso":
            minutes += gb / 50.0 * 60.0
        elif s["tool_hint"] == "volatility3":
            minutes += gb / 8.0 * 30.0
        elif s["tool_hint"] == "kape":
            minutes += 20.0
        else:
            minutes += 5.0
    # Parallel speed-up: assume fan-out across len(jobs) families with a
    # conservative 0.6 efficiency factor (Amdahl-ish, since disk I/O dominates).
    families = max(len(jobs), 1)
    parallel_minutes = max(minutes / families * 1.4, 1.0)
    return {
        "total_bytes": total_bytes,
        "total_bytes_human": _human_bytes(total_bytes),
        "host_count": len(hosts),
        "evidence_count": len(sets),
        "serial_minutes": round(minutes, 1),
        "parallel_minutes": round(parallel_minutes, 1),
        "worker_count": families,
    }


def _render_resource_estimate(est: dict[str, Any]) -> str:
    return (
        f"- **Total evidence**: {est['total_bytes_human']} "
        f"({est['evidence_count']} set(s), {est['host_count']} host(s))\n"
        f"- **Estimated serial processing**: ~{est['serial_minutes']} min\n"
        f"- **Estimated parallel processing** "
        f"({est['worker_count']} worker family/ies): "
        f"~{est['parallel_minutes']} min\n"
        f"- **Driver**: Turbinia (or equivalent) runtime is required for "
        f"actual execution."
    )


def _fallback_narrative(sets, jobs, estimate, user_prompt) -> str:
    return (
        "## Distributed forensic orchestration (plan)\n\n"
        f"**Evidence scope**: {estimate['evidence_count']} set(s), "
        f"{estimate['total_bytes_human']} across {estimate['host_count']} "
        f"host(s).\n\n"
        "**Processing plan**: " + ", ".join(
            f"{j['tool']} on {j['count']} set(s)" for j in jobs
        ) + ".\n\n"
        f"**Expected wall-clock**: ~{estimate['parallel_minutes']} min "
        f"parallel vs ~{estimate['serial_minutes']} min serial.\n\n"
        "This is a **plan-only** goal in M10: no tools were executed and no "
        "evidence was touched. To run the plan, configure the Turbinia "
        "orchestration runtime (a deployment-time setting) and dispatch the "
        "job families listed above. Per-host results aggregate into a single "
        "normalized UTC timeline keyed by host, with cross-host pivots indexed "
        "for lateral-movement correlation."
    )


goal = OrchestrationGoal()
