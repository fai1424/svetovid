# Svetovid

> Named after Svetovid, the four-faced Slavic god of divination — except here, **22 faces**, one per DFIR investigation goal.

**Svetovid** is a cross-platform (macOS + Windows) desktop GUI that turns an LLM agent loose on a folder of forensic evidence. Point it at evidence, pick a goal, watch the agent investigate, read the report.

```
API key  →  pick folder  →  pick goal  →  watch the agent investigate  →  read the report
```

## What it does

Svetovid operationalizes the agentic-DFIR research in `../agentic-dfir/report.md`. It supports **22 investigation goals** across every DFIR domain:

| Cluster | Goals |
|---|---|
| Windows | G01 attack timeline · G02 malware/persistence · G03 deadbox examination |
| Endpoints | G04 Linux · G05 macOS |
| Memory | G06 memory forensics / malware-in-RAM |
| Network | G07 C2 / web-attack reconstruction |
| Ransomware & Email | G08 ransomware · G09 BEC / phishing |
| Mobile | G10 iOS · G11 Android |
| Cloud | G12 M365 · G13 Google Workspace · G14 AWS · G15 Azure · G16 GCP |
| SaaS & DevOps | G17 Slack · G18 GitHub / Azure DevOps / Jira |
| Containers | G19 Kubernetes / container compromise |
| Cross-cutting | G20 acquisition & chain-of-custody · G21 distributed orchestration · G22 super-timeline + ATT&CK narrative |

## Stack

| Layer | Choice |
|---|---|
| Desktop shell | **Tauri 2** (Rust), Python backend as a PyInstaller-bundled sidecar |
| Frontend | **React + Vite + TypeScript + Tailwind + shadcn/ui** |
| Backend | **Python 3.11+ · FastAPI · WebSocket streaming · LangGraph** |
| LLM | single OpenAI-compatible client → **Ollama / GLM (BigModel) / KIMI (Moonshot)** via `base_url` |
| Sandbox | **Docker per tool call**, evidence mounted `:ro` |

## Repository layout

```
svetovid/
├── backend/        Python: FastAPI + LangGraph agent + tool wrappers
├── frontend/       Tauri 2 + React + shadcn/ui
├── docker/         Shared Dockerfile.base
├── docs/           TOOL_INVENTORY.md · ARCHITECTURE.md · DESIGN_SYSTEM.md
└── README.md       (this file)
```

## Status

Under active development, milestone **M0 (Foundation)**. See `docs/ARCHITECTURE.md` for the full milestone plan (M0 → M10) and `docs/TOOL_INVENTORY.md` for every tool we depend on.

## Development

> Rust/Cargo is required only to compile the desktop binary. Day-to-day backend + frontend dev does **not** need it — run the Python backend and the Vite dev server directly.

```bash
# Backend (Python)
cd backend && pip install -e . && uvicorn svetovid.main:app --reload

# Frontend (Vite dev server — browser UI, no Tauri shell needed)
cd frontend && npm install && npm run dev

# Desktop shell (when ready — requires Rust + Tauri CLI)
cd frontend && cargo tauri dev
```

## Licensing posture

Svetovid ships the **open-source replacement stack** by default (Sleuth Kit, Volatility 3, KAPE, iLEAPP/ALEAPP, Chainsaw, Dissect, …). Wrapping a customer's already-licensed commercial install (X-Ways, EnCase, Magnet AXIOM, Cellebrite) is opt-in config — we cannot and do not bundle proprietary software.
