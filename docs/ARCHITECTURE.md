# Svetovid — Architecture

> **One-paragraph version:** Tauri 2 desktop shell (Rust) launches a Python
> (FastAPI + LangGraph) backend as a sidecar, which orchestrates a multi-agent
> investigation over the user's evidence. The agent calls MCP-wrapped DFIR
> tools that run in per-call Docker containers with the evidence mounted
> read-only. A single WebSocket streams every step (thought / action /
> observation / tool output / HITL gate / provenance) to a React + Tailwind +
> shadcn UI, which renders a 3-pane Investigation screen so the user can watch
> progress live.

This doc covers M0 as built; companion docs cover the wider plan.

## High-level diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                         Svetovid desktop app                           │
│                                                                        │
│  ┌──────────────────┐    sidecar launch + health-poll    ┌──────────┐  │
│  │  Tauri shell     │ ─────────────────────────────────► │ Backend  │  │
│  │  (Rust, ~45MB)   │                                    │ (Python) │  │
│  │                  │ ◄───── WebSocket /ws (events) ──── │ FastAPI  │  │
│  │  ┌────────────┐  │                                    │  + Lang- │  │
│  │  │ React UI   │  │            REST /api/*             │   Graph  │  │
│  │  │ (Vite/TS/  │  │ ─────────────────────────────────► │          │  │
│  │  │  Tailwind) │  │                                    │  EventBus│  │
│  │  └────────────┘  │                                    └────┬─────┘  │
│  └──────────────────┘                                         │        │
└────────────────────────────────────────────────────────────────┼────────┘
                                                                 │
                                       ┌─────────────────────────┴────┐
                                       │   per-call Docker sandbox    │
                                       │   evidence ─ :ro ─► /evidence│
                                       │   output   ─ :rw ─► /work    │
                                       │                              │
                                       │  Chainsaw / Hayabusa / TSK / │
                                       │  Volatility / tshark / YARA  │
                                       │  + ATT&CK + Sigma baked in   │
                                       └──────────────────────────────┘
```

## Layer breakdown

### 1. Desktop shell (Tauri 2, Rust) — `frontend/src-tauri/`

`main.rs` does three things:
1. **Backend lifecycle** — checks if anything's listening on `:7421`; if not,
   launches the bundled PyInstaller sidecar (`binaries/svetovid-backend-<triple>`),
   then waits up to 20s for `/health`. On window close it SIGTERMs the sidecar.
2. **Plugin registration** — `tauri-plugin-dialog` (folder picker),
   `tauri-plugin-fs` (file system access), `tauri-plugin-shell`.
3. **Window** — defined in `tauri.conf.json` (1440×900 default, 1024×700 min,
   JetBrains Mono CSP-allowed).

In dev (`cargo tauri dev`) the sidecar is the user's own `uvicorn` process
(the Rust shell detects the missing bundled binary and just logs).

### 2. Backend (Python 3.11+, FastAPI, LangGraph) — `backend/svetovid/`

Entry: `svetovid.main:app`. The two surfaces:

- **REST** — `/health`, `/api/settings` (CRUD), `/api/providers/{id}/test`,
  `/api/scan`, `/api/goals`, `/api/investigations`. Plain FastAPI endpoints.
- **WebSocket** — `/ws`. A single multiplexed stream. The backend owns an
  `EventBus` (`agent/events.py`); every long-running operation publishes
  `AgentEvent`s to it, and every connected WS client receives them all
  (filtering by `investigation_id` happens client-side).

The agent layer (`agent/`) holds the shared `InvestigationState` TypedDict and
the streaming event constructors. The reusable ReAct LangGraph builder is
landed in M0.6 — for M0, G01 implements its 7-node graph directly (the
scaffolding is in place for true LLM-driven tool selection).

### 3. Goals — `backend/svetovid/goals/`

Each goal is one module `g<NN>_*.py` exporting a module-level `goal` instance
of `goals.base.Goal`. The `registry.py` auto-discovers them via
`pkgutil.iter_modules`. A goal provides:

- `id`, `cluster`, `label`, `description`, `input_artifacts`, `tools`, `icon`
- `nodes()` — the ordered LangGraph nodes for the StepProgress pane
- `detect(evidence)` — 0..1 match score for auto-highlighting on GoalSelect
- `manifest()` — static JSON for `/api/goals`
- `run(...)` — async body that streams events and produces a report

See `docs/ADDING_A_GOAL.md` for the precise contract and a copy-paste template.

### 4. Tools — `backend/svetovid/tools/`

Each tool is one module exporting `tool`, an instance of `tools.base.Tool`.
A tool provides:

- `name`, `image` (Docker image, or `None` for host)
- `schema()` — flat JSON-schema for the args the LLM passes (kept shallow
  for GLM/KIMI tool-calling reliability)
- `invoke(args, ctx)` — async body that:
  1. publishes `tool.start`
  2. runs the binary via `sandbox/docker_runner.run_in_sandbox` (Docker `:ro`
     evidence, streamed stdout/stderr)
  3. parses the structured output
  4. publishes `tool.end` + `agent.observation`
  5. publishes `provenance.recorded` (chain-of-custody)
  6. returns a `ToolResult`

Every tool wrapper enforces the same governance invariants — read-only
evidence, hashed outputs, append-only audit log.

### 5. Sandbox — `backend/svetovid/sandbox/docker_runner.py`

`run_in_sandbox(image, command, evidence_path, output_dir, ...)`:
- mounts `evidence_path` at `/evidence:ro`
- mounts `output_dir` at `/work:rw`
- `network_disabled=True` by default (cloud-API wrappers override)
- `mem_limit=4g`, `cpu_quota=2.0`, `timeout_s=1800`
- streams stdout/stderr lines via callbacks (wired to `tool.stdout` /
  `tool.stderr` events)
- on Docker absence: `host_fallback=True` runs on the host with a clear
  stderr warning (per the M0 plan's honest scope note)

### 6. Frontend — `frontend/src/`

React 18 + Vite + TypeScript + Tailwind + shadcn-style primitives. Single-page
app; the sidebar switches screens. State is split across two zustand stores:
- `lib/api.ts` for one-shot REST calls
- `lib/events.ts` for the live WS event stream + reducer

The reducer (`reduceEvent` in `events.ts`) is the **explicit, auditable
progress/status state machine**: every event type has its own case, so the
rules for "what makes the UI update" live in one place. The three Investigation
panes (AgentTrace / StepProgress / LiveReport) each consume a slice of that
state.

## The streaming protocol (the progress/status backbone)

Single WS, JSON event stream. Event types (full list in
`backend/svetovid/agent/events.py`):

| Type | When | Where it surfaces in UI |
|------|------|-------------------------|
| `scan.start` / `scan.progress` / `scan.complete` | folder scan | EvidenceSelect progress bar |
| `investigation.start` | goal launches | Investigation header |
| `goal.graph_loaded` | graph nodes posted | StepProgress stepper |
| `node.state_change` | per-node transition | StepProgress row + bullet |
| `agent.thought` / `agent.action` / `agent.observation` | ReAct loop | AgentTrace stream |
| `tool.start` / `tool.stdout` / `tool.stderr` / `tool.progress` / `tool.end` | tool exec | ToolCallCard + StepProgress sub-bar |
| `report.section_added` | report writes | LiveReport pane |
| `hitl.request` / `hitl.response` | governance gate | top bar Approve button |
| `provenance.recorded` | every tool call | bottom ticker |
| `error` | any failure | toast + AgentTrace |
| `ping` | keepalive | (dropped) |

This is what makes "the UI shows progress + status along with execution"
concrete — every backend action is a typed event the UI reduces.

## Dev workflow

```bash
# Terminal 1 — backend
cd backend && pip install -e .
uvicorn svetovid.main:app --port 7421 --reload

# Terminal 2 — frontend (Vite, browser UI)
cd frontend && npm install && npm run dev   # → http://localhost:1420

# Terminal 3 — native window (optional; Rust required)
cd frontend && cargo tauri dev
```

Tests: `cd backend && pytest` (15 tests, <1s).

## Production packaging (planned, post-M0)

```bash
# 1. Build the Python backend into a single binary
cd backend && pyinstaller --onefile --name svetovid-backend-$(rustc -vV | grep host | awk '{print $2}') \
    svetovid/run_sidecar.py

# 2. Drop it into the Tauri sidecar slot
cp dist/svetovid-backend-* ../frontend/src-tauri/binaries/

# 3. Build the desktop app
cd ../frontend && cargo tauri build
```

Output: a notarized `.app` (macOS) / signed `.exe` (Windows) with the Python
backend embedded. The Docker images stay external — Svetovid requires Docker
Desktop on the user's machine (the M0 plan documents this honestly).
