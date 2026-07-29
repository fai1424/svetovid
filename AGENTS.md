# AGENTS.md — Svetovid Development Guide

> **Read this before writing any code in this repository.**
> It tells you how the app is structured, how to run it, how to test it,
> and the conventions every new file must follow.

## What Svetovid is

An agentic DFIR (Digital Forensics & Incident Response) desktop app. The user
points it at a folder of forensic evidence, picks an investigation goal, and
an LLM agent autonomously selects forensic tools, runs them sandboxed, maps
findings to MITRE ATT&CK, and writes a report. Cross-platform (macOS + Windows),
built on Tauri 2 (Rust) + React (frontend) + Python/FastAPI/LangGraph (backend).

## Tech stack

| Layer | Technology |
|---|---|
| Desktop shell | Tauri 2 (Rust) |
| Frontend | React 18 + Vite + TypeScript + Tailwind + shadcn-style primitives |
| Backend | Python 3.11+ · FastAPI · LangGraph · WebSocket streaming |
| LLM | `langchain-openai` single client → Ollama / GLM / KIMI via `base_url` |
| Sandbox | Docker per tool call (evidence mounted `:ro`) |
| Database | SQLite (aiosqlite) for cases, investigations, events, tool calls, IOCs |
| Tests | pytest (backend), no frontend tests yet |

## How to run

```bash
# Backend (Terminal 1)
cd backend
pip install -e .
uvicorn svetovid.main:app --port 7421 --reload

# Frontend (Terminal 2)
cd frontend
npm install
npm run dev          # → http://localhost:1420

# Native desktop window (Terminal 3, requires Rust)
cd frontend
cargo tauri dev
```

**Required env vars for testing:**
```bash
export PYTHON_KEYRING_BACKEND=keyring.backends.fail.Keyring  # prevents macOS Keychain hang
export SVETOVID_HITL_AUTO_APPROVE=1                           # auto-approves HITL gates in tests
```

**For real LLM use:**
```bash
export GLM_API_KEY="your-key"          # or OLLAMA_API_KEY / KIMI_API_KEY
```

## How to test

```bash
cd backend
PYTHON_KEYRING_BACKEND=keyring.backends.fail.Keyring SVETOVID_HITL_AUTO_APPROVE=1 \
  /opt/anaconda3/bin/python3 -m pytest -q --no-header
```

Current state: **727 tests across 17 test files, ~18 seconds**.

**Test file naming convention:** `test_<area>_edge.py` for edge-case tests,
`test_<area>.py` for core tests. Never modify an existing test file unless
fixing a bug it exposes — add new files for new tests.

## Repository structure

```
svetovid/
├── AGENTS.md                          ← you are here
├── backend/
│   ├── pyproject.toml
│   ├── build_sidecar.sh               ← PyInstaller sidecar builder
│   ├── svetovid/
│   │   ├── main.py                    ← FastAPI app (REST + WS + lifespan)
│   │   ├── config.py                  ← Settings model + keyring/file/env key storage
│   │   ├── store.py                   ← SQLite case DB (aiosqlite)
│   │   ├── llm/client.py              ← OpenAI-compatible LLM client
│   │   ├── agent/
│   │   │   ├── react.py               ← LangGraph ReAct loop (dedup, token budget, retry)
│   │   │   ├── events.py              ← EventBus + 20+ typed event constructors
│   │   │   ├── state.py               ← InvestigationState TypedDict
│   │   │   └── hitl.py                ← Human-in-the-loop gate (Future-based)
│   │   ├── evidence/
│   │   │   ├── scanner.py             ← Folder walker + artifact classifier
│   │   │   └── signatures.py          ← 13 forensic file-type detectors
│   │   ├── goals/                     ← 22 investigation goals (one file each)
│   │   │   ├── base.py                ← Goal ABC + GoalNode
│   │   │   ├── registry.py            ← Auto-discovery (walks g*.py)
│   │   │   └── g01_attack_timeline.py ← Reference: fixed-pipeline goal
│   │   │   └── g02_malware_persistence.py ← Reference: ReAct goal
│   │   ├── tools/                     ← 31 tool wrappers (one file each)
│   │   │   ├── base.py                ← Tool ABC + ToolContext + ToolResult
│   │   │   ├── chainsaw.py            ← Reference tool wrapper
│   │   │   └── _reporting.py          ← Shared: emit IoC/timeline events + DB record
│   │   ├── governance/
│   │   │   ├── hashing.py             ← SHA-256/MD5 on intake
│   │   │   ├── custody.py             ← Chain-of-custody form + tamper seal
│   │   │   └── ioc_store.py           ← IOC accumulation + text extraction
│   │   ├── report/
│   │   │   ├── exporters.py           ← STIX/CASE/JSON/Markdown export
│   │   │   ├── pdf_renderer.py        ← PDF via weasyprint or HTML fallback
│   │   │   └── templates.py           ← Jinja2 report templates
│   │   ├── telemetry/
│   │   │   ├── collector.py           ← EventBus subscriber (anonymous metrics)
│   │   │   ├── uploader.py            ← Batch HTTPS uploader
│   │   │   ├── server.py              ← Standalone analytics server
│   │   │   └── client_id.py           ← Anonymous UUID
│   │   ├── sandbox/
│   │   │   └── docker_runner.py       ← Per-call Docker exec (hardened: cap_drop, etc.)
│   │   └── sandbox/images/            ← Dockerfiles for each tool image
│   └── tests/                         ← 17 test files, 727 tests
├── frontend/
│   ├── src/
│   │   ├── App.tsx                    ← Screen router + ErrorBoundary
│   │   ├── screens/                   ← 6 screens
│   │   ├── components/                ← AgentTrace, StepProgress, Timeline, Heatmap, etc.
│   │   ├── lib/                       ← api.ts, events.ts, types.ts, cn.ts
│   │   └── styles/                    ← tokens.css (design system), globals.css
│   ├── design-system/                 ← Generated design tokens (MASTER.md)
│   └── src-tauri/                     ← Rust shell (main.rs, Cargo.toml, icons)
├── docker/                            ← Dockerfile.base + build.sh
├── docs/                              ← TOOL_INVENTORY, ARCHITECTURE, ADDING_A_GOAL, etc.
└── scripts/                           ← generate_tool_inventory.py
```

## Conventions

### Adding a new investigation goal

1. Create `backend/svetovid/goals/g<NN>_<slug>.py`.
2. Export a module-level `goal` instance of a `Goal` subclass.
3. Fields: `id`, `cluster`, `label`, `description`, `input_artifacts` (B-IDs),
   `tools` (C-IDs), `icon` (lucide-react name).
4. `nodes()` returns ≥3 `GoalNode`s; first is `"triage"`, last is `"finalize"`.
5. Goals with LLM-driven tool selection use `"react_loop"` as a node name;
   goals with a fixed pipeline do NOT.
6. `run()` must publish events via `bus.publish(E.xxx(...))` for every step.
7. HITL gate: when `settings.hitl_report_release == "required"`, call
   `request_approval()` from `agent/hitl.py` — do NOT use `asyncio.sleep`.
8. See `docs/ADDING_A_GOAL.md` for the full template.

### Adding a new tool wrapper

1. Create `backend/svetovid/tools/<name>.py`.
2. Export a module-level `tool` instance of a `Tool` subclass.
3. `schema()` MUST return a **flat** JSON-schema: `type: object`, properties
   are only `string`/`number`/`boolean`/`array` — **no nested objects**. This
   is required for GLM/KIMI tool-calling reliability.
4. `invoke(args, ctx)` is async. It must:
   - Publish `E.tool_start`, `E.agent_action`
   - Run the tool (via `run_in_sandbox` for Docker, or direct Python for host tools)
   - Publish `E.tool_stdout`/`E.tool_stderr` for streaming output
   - Publish `E.tool_end` with exit_code, duration_s, output_hash
   - Publish `E.agent_observation` with a summary
   - Publish `E.provenance_recorded` for chain-of-custody
   - For tools that produce hits/findings: call `emit_hit_events()` from
     `tools/_reporting.py` to emit `report.timeline_entry` + `report.ioc` events
   - Return a `ToolResult`
5. See `tools/chainsaw.py` for the reference implementation.

### Tool event contract

Every tool call must emit these events in order:
```
tool.start → agent.action → [tool.stdout/stderr...] → tool.end →
agent.observation → provenance.recorded → [report.timeline_entry...] → [report.ioc...]
```

### Settings model

New settings go in `config.py:Settings`. They are persisted to
`~/.svetovid/config.json`. API keys are stored in OS keyring (with file
fallback). Env vars (`GLM_API_KEY`, `KIMI_API_KEY`, `OLLAMA_API_KEY`,
`VT_API_KEY`) override keyring.

### Frontend event reducer

The WebSocket event reducer (`frontend/src/lib/events.ts`) handles every event
type in an explicit `case`. When adding a new event type:
1. Add the constructor in `agent/events.py`.
2. Add the type to `frontend/src/lib/types.ts`.
3. Add the reducer case in `frontend/src/lib/events.ts`.

### Test conventions

- Every new tool gets tests in `tests/test_<area>_edge.py`.
- Use `monkeypatch` to mock Docker/network — never run real containers or APIs.
- The `isolated_home` autouse fixture (HOME → tmp_path, fail-keyring, module
  cache clear) is required for any test touching config/settings.
- HITL tests that exercise the real gate must `monkeypatch.delenv("SVETOVID_HITL_AUTO_APPROVE")`.

## Docker images

Five images, all built on `svetovid/base`:

| Image | Contents | Used by |
|---|---|---|
| `svetovid/base` | Debian + ATT&CK STIX (19,981 objects) + Sigma rules | All others |
| `svetovid/eztools` | + Chainsaw, Hayabusa, TSK, .NET 9 + EZ Tools | G01-G03 |
| `svetovid/volatility` | + Volatility 3 + symbols | G06 |
| `svetovid/malware` | + YARA + 946 rules + capa | G02, G08 |
| `svetovid/network` | + tshark, Zeek, Suricata | G07 |

Build: `./docker/build.sh` (or individual: `./docker/build.sh base`)

## Python version

Use `/opt/anaconda3/bin/python3` (Python 3.13). The system `/usr/bin/python3`
does not have the project dependencies.

## Known gotchas

- **macOS Keychain hangs** if `PYTHON_KEYRING_BACKEND` is not set — always set
  it in tests and dev.
- **HITL gates block** if `SVETOVID_HITL_AUTO_APPROVE=1` is not set in
  headless/test mode.
- **Tailwind config parser (sucrase) chokes on unquoted hyphenated keys** —
  always quote keys like `"fade-in"` in `tailwind.config.js`.
- **`@import` in CSS must come before `@tailwind`** — or PostCSS rejects it.
  Load tokens.css from `main.tsx` instead.
- **WebSocket URL must be hardcoded** for Tauri production (`ws://127.0.0.1:7421/ws`)
  because `window.location.host` is `tauri://localhost` in prod.
