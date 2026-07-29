# Svetovid — Deployment Readiness & Telemetry Plan

> **Status:** MVP functionality complete (22 goals, 22 tools, 38 tests).
> **Deployable?** No — 7 blockers must be fixed first. This document lists
> every gap in priority order, with the fix for each, then specifies the
> usage-telemetry system you asked for.

---

## Part 1 — Deployment blockers (must fix before ship)

### 🔴 BLOCKER 1: CORS wide-open + zero auth (security)

**Problem:** `main.py:60` sets `allow_origins=["*"]`. Any webpage the user
visits can hit `127.0.0.1:7421` and read settings, walk the filesystem via
`/api/scan`, or start investigations. The WebSocket has no origin check
either — a malicious page can slurp the entire investigation event stream.

**Fix:**
```python
# main.py — replace the CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "tauri://localhost",       # Tauri production
        "https://tauri.localhost",  # Tauri Windows
        "http://localhost:1420",    # Vite dev
    ],
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Content-Type"],
)
```
Plus: generate a per-launch shared secret in `main.rs`, pass it to the sidecar
via env var, and require it as a `Authorization: Bearer <secret>` header on
every REST + WS request.

**Effort:** 2 hours.
**Risk if unfixed:** remote attacker on the user's network (or a malicious
webpage) can read API keys, scan arbitrary paths, and exfiltrate evidence.

---

### 🔴 BLOCKER 2: WebSocket URL breaks in production builds

**Problem:** `frontend/src/lib/events.ts:24-27` computes the WS URL from
`window.location.host`. In Tauri production, the window origin is
`tauri://localhost`, so the WS tries `wss://tauri.localhost/ws` — which is
neither the backend nor allowed by CSP. The live event stream is dead in any
non-dev build.

**Fix:**
```typescript
// events.ts — hardcode for Tauri production, proxy for dev
const WS_URL =
  window.location.hostname === "localhost"
    ? `ws://${window.location.host}/ws`           // Vite dev proxy
    : "ws://127.0.0.1:7421/ws";                    // Tauri production
```

**Effort:** 10 minutes.
**Risk if unfixed:** the Investigation screen shows nothing — the app appears
broken the moment a user opens it outside dev.

---

### 🔴 BLOCKER 3: Backend not bundled (no PyInstaller sidecar)

**Problem:** The Tauri shell launches `binaries/svetovid-backend`, but that
binary doesn't exist. `binaries/` contains only a README. There's no build
script, no `.spec` file, no CI. Even the Tauri config (`bundle.resources: []`)
doesn't reference it. A user who installs the `.app`/`.exe` gets a window with
no backend — the app silently fails.

**Fix:**
1. Write `backend/build_sidecar.sh`:
```bash
#!/usr/bin/env bash
TRIPLE=$(rustc -vV | grep host | awk '{print $2}')
cd backend
pip install pyinstaller
pyinstaller --onefile \
    --name "svetovid-backend-${TRIPLE}" \
    --add-data "svetovid:svetovid" \
    --hidden-import uvicorn.logging \
    --hidden-import uvicorn.protocols.http.auto \
    --hidden-import uvicorn.protocols.websockets.auto \
    --hidden-import uvicorn.lifespan.on \
    svetovid/run_sidecar.py
mv "dist/svetovid-backend-${TRIPLE}" "../frontend/src-tauri/binaries/"
```
2. Add to `tauri.conf.json`:
```json
"bundle": {
    "resources": ["binaries/svetovid-backend-*"],
    ...
}
```
3. Fix the binary name mismatch in `main.rs` — Tauri requires the
`-<target-triple>` suffix; `launch_sidecar()` currently looks for the bare name.

**Effort:** 4 hours (PyInstaller hidden-imports for FastAPI/LangGraph can be fiddly).
**Risk if unfixed:** app is unusable as a standalone download.

---

### 🔴 BLOCKER 4: No crash recovery for the backend

**Problem:** `main.rs` spawns the sidecar once and never monitors it. If the
Python process dies mid-investigation (OOM, unhandled exception, Docker SDK
crash), the WS reconnects to a dead port forever — the UI hangs showing
"reconnecting…" with no recovery.

**Fix:** Add a supervisor in `main.rs`:
```rust
// Spawn a watcher task that restarts the sidecar on unexpected exit
tauri::async_runtime::spawn(async move {
    loop {
        let mut guard = backend_state.0.lock().await;
        if let Some(ref mut child) = *guard {
            let status = child.wait().await;
            if !status.unwrap_or_default().success() {
                log::warn!("backend crashed ({status:?}), restarting in 2s…");
                drop(guard);
                tokio::time::sleep(Duration::from_secs(2)).await;
                *backend_state.0.lock().await = launch_sidecar();
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
});
```

**Effort:** 3 hours.
**Risk if unfixed:** any backend crash = permanent hang, app restart required.

---

### 🔴 BLOCKER 5: No case database (investigations lost on restart)

**Problem:** `aiosqlite` is in `pyproject.toml` but never imported anywhere.
Investigations exist only in the in-memory `EventBus`. Restart the app →
everything is gone. `case_id` is hardcoded `"default"`. The Cases screen shows
session data only.

**Fix:** Create `backend/svetovid/store.py`:
```python
# Schema (SQLite at ~/.svetovid/svetovid.db):
CREATE TABLE cases (id, name, created_at, status);
CREATE TABLE investigations (id, case_id, goal_id, evidence_path,
    user_prompt, status, started_at, ended_at, report_markdown);
CREATE TABLE tool_calls (id, investigation_id, tool, args_json,
    exit_code, duration_s, output_hash, ts);
CREATE TABLE events (id, investigation_id, type, ts, data_json);
```
Wire it into `_run_goal()` (persist on each event), load on Cases screen,
restore on Investigation screen.

**Effort:** 6 hours.
**Risk if unfixed:** no history, no resumption, no audit trail persistence.

---

### 🔴 BLOCKER 6: Docker UX — no status, no pre-flight, false positives

**Problem:**
- No Docker-status indicator in the UI (user discovers Docker is down only when a tool call fails mid-investigation)
- `_check_docker()` returns `True` on macOS if `docker` is on PATH even when the daemon isn't running
- No image-existence check (assumes `svetovid/eztools:latest` is present)
- Only 2 of 5 Dockerfiles have a build path in `build.sh`

**Fix:**
1. Add `/health/docker` endpoint:
```python
@app.get("/health/docker")
async def docker_status():
    return {
        "installed": shutil.which("docker") is not None,
        "running": _ping_daemon(),      # docker info --format '{{.ServerVersion}}'
        "images": _check_images(),      # {name: present} for each svetovid/* image
    }
```
2. Frontend: global status pill in the sidebar (green/red/amber)
3. Pre-flight check before `/api/investigations` — refuse to start if Docker is down and sandbox_mode=docker
4. Extend `build.sh` to build all 5 images
5. First-run bootstrap: if images are missing, show "Building tool images…" with progress

**Effort:** 4 hours.
**Risk if unfixed:** confusing failures, poor first-run experience.

---

### 🟡 SHOULD-HAVE 7: No Python logging (silent failures)

**Problem:** Zero `import logging` in the entire backend. Errors are either
raised (crashing the investigation) or silently swallowed (`except: pass`).
No log file, no rotation, no observability. A failed keyring write is invisible.

**Fix:** Add to `main.py` lifespan:
```python
import logging, logging.handlers
log_dir = APP_DIR / "logs"
log_dir.mkdir(exist_ok=True)
handler = logging.handlers.RotatingFileHandler(
    log_dir / "svetovid.log", maxBytes=10_000_000, backupCount=5
)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[handler, logging.StreamHandler()],
)
```
Replace every `except Exception: pass` with `logger.exception(...)`.

**Effort:** 2 hours.
**Risk if unfixed:** impossible to debug user-reported issues.

---

### 🟡 SHOULD-HAVE 8: Keyring silent fallback

**Problem:** If macOS Keychain denies access (common from PyInstaller binaries
without entitlements), the key silently falls through to a plaintext
`keys.json` with no user notification. Windows Credential Manager has size
limits that aren't handled.

**Fix:**
- Add macOS entitlements in `tauri.conf.json` (`macos.entitlements`)
- Surface keyring failures as a UI warning ("API key stored in plaintext")
- Cap key length; test on Windows

**Effort:** 3 hours.

---

### 🟢 NICE-TO-HAVE 9: Auto-updater

**Problem:** No `tauri-plugin-updater`, no signing key, no release manifest.
Users will run stale ATT&CK/Sigma/YARA indefinitely.

**Fix:** Add `tauri-plugin-updater` to `Cargo.toml`, generate a signing
keypair, wire `plugins.updater` in `tauri.conf.json`, publish `latest.json`
from CI.

**Effort:** 4 hours. Not blocking v0.1 — becomes critical at v0.2+.

---

### Deployment blocker summary

| # | Blocker | Severity | Effort | Impact if unfixed |
|---|---------|----------|--------|-------------------|
| 1 | CORS `*` + no auth | 🔴 BLOCKER | 2h | Remote attack surface |
| 2 | WS URL breaks in prod | 🔴 BLOCKER | 10m | App appears broken |
| 3 | No PyInstaller sidecar | 🔴 BLOCKER | 4h | No backend = unusable |
| 4 | No crash recovery | 🔴 BLOCKER | 3h | Hang on any crash |
| 5 | No case database | 🔴 BLOCKER | 6h | Data lost on restart |
| 6 | Docker UX gaps | 🔴 BLOCKER | 4h | Confusing failures |
| 7 | No Python logging | 🟡 SHOULD-HAVE | 2h | Can't debug issues |
| 8 | Keyring fallback silent | 🟡 SHOULD-HAVE | 3h | Secret in plaintext |
| 9 | No auto-updater | 🟢 NICE-TO-HAVE | 4h | Stale rules/tools |

**Total effort to deployable:** ~28 hours (3.5 days) for blockers 1–6.

---

## Part 2 — Usage telemetry & analytics

You want to collect usage data for analysis: average case handling time, user
experience metrics, tool effectiveness, etc. Here's the design.

### What to collect

| Metric | How collected | Privacy |
|--------|---------------|---------|
| **Case duration** (start → finalize) | Timestamps from `investigation.start` / `investigation.end` events | No PII |
| **Per-node duration** (triage / react_loop / draft_report / etc.) | `node.state_change` timestamps | No PII |
| **Tool call frequency + success rate** | `tool.start` / `tool.end` events (tool name, exit code, duration) | No PII |
| **Goal popularity** (which of the 22 goals users pick) | `goal_id` from `investigation.start` | No PII |
| **Evidence type distribution** (what users point at) | `scan.complete` artifact counts by family | No PII |
| **LLM provider + model used** | Provider ID from settings (not the key) | No PII |
| **Agent iteration count** (how many ReAct steps per investigation) | `iteration` from react loop | No PII |
| **Error rate + error types** | `error` events (message type, not user data) | No PII |
| **HITL approval rate** (how often humans approve vs. reject) | `hitl.request` / `hitl.response` | No PII |
| **User experience (explicit)** | Post-investigation rating prompt (1-5 stars + optional text) | User-submitted |

### What NOT to collect

- **Evidence content** — never log file contents, parsed rows, or tool output
- **API keys** — never log or transmit keys
- **File paths** — log artifact *counts* and *types*, not paths
- **LLM prompts/responses** — these may contain evidence context
- **User identity** — anonymous client ID only (UUID generated on first run)

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Svetovid backend                                            │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐   ┌────────────────┐  │
│  │ Investigation │───►│ Telemetry    │──►│ Local buffer   │  │
│  │ event stream  │    │ collector    │   │ (SQLite queue) │  │
│  │ (EventBus)    │    │ (subscriber) │   │                │  │
│  └──────────────┘    └──────────────┘   └───────┬────────┘  │
│                                                  │           │
│                                          ┌───────▼────────┐  │
│                                          │ Batch uploader │  │
│                                          │ (every 5 min   │  │
│                                          │  or on exit)   │  │
│                                          └───────┬────────┘  │
└──────────────────────────────────────────┼───────────────────┘
                                           │ HTTPS POST
                                           │ (anonymous JSON)
                                           ▼
                                   ┌───────────────┐
                                   │ Telemetry     │
                                   │ endpoint      │
                                   │ (your server) │
                                   └───────────────┘
```

### Implementation

**1. Telemetry collector** (`backend/svetovid/telemetry/collector.py`):

Subscribes to the EventBus. For each event, extracts the metrics above (no
PII, no evidence content) and writes a row to a local SQLite queue table
(`~/.svetovid/telemetry_queue.db`).

**2. Batch uploader** (`backend/svetovid/telemetry/uploader.py`):

Every 5 minutes (or on app exit), flushes the queue to a configurable HTTPS
endpoint. If the endpoint is unreachable, retains the data and retries. If
telemetry is disabled (Settings toggle), the collector never writes anything.

**3. Settings toggle** (Settings screen):

```typescript
// Add to Settings.tsx
<Field label="Anonymous usage analytics">
  <Toggle
    checked={settings.telemetry_enabled}
    onChange={(v) => update("telemetry_enabled", v)}
  />
</Field>
<p className="text-2xs text-muted-fg">
  Sends anonymous usage metrics (case duration, tool success rates, goal
  popularity). No evidence content, file paths, or API keys are ever
  transmitted. You can disable this at any time.
</p>
```

Default: **enabled** (with first-run consent dialog explaining what's collected).

**4. Post-investigation UX prompt**:

After `investigation.end`, show a small rating card:
```
  How was this investigation?  ★★★☆☆  [optional feedback...]
```
Stored locally, sent with the next telemetry batch.

**5. Telemetry endpoint** (server side — your infrastructure):

Accepts `POST /api/v1/telemetry` with a JSON array of event records. Each
record:
```json
{
  "client_id": "uuid-v4",
  "event": "investigation.complete",
  "ts": "2026-07-28T14:32:01Z",
  "props": {
    "goal_id": "G02",
    "duration_s": 612,
    "node_durations": {"triage": 5, "react_loop": 580, "draft_report": 27},
    "tool_calls": [
      {"tool": "chainsaw_hunt", "exit_code": 0, "duration_s": 3.2},
      {"tool": "yara_scan", "exit_code": 0, "duration_s": 1.8}
    ],
    "iteration_count": 8,
    "provider": "ollama",
    "model": "llama3.1:8b",
    "hitl_approved": true,
    "user_rating": 4
  }
}
```

**6. Analytics queries** (you run these on the server):

```sql
-- Average case handling time by goal
SELECT goal_id,
       AVG(duration_s) as avg_seconds,
       PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY duration_s) as median,
       COUNT(*) as sample_size
FROM investigations
GROUP BY goal_id;

-- Tool success rate
SELECT tool,
       SUM(CASE WHEN exit_code = 0 THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as success_pct,
       AVG(duration_s) as avg_duration
FROM tool_calls
GROUP BY tool;

-- Most-used goals
SELECT goal_id, COUNT(*) as uses
FROM investigations
GROUP BY goal_id
ORDER BY uses DESC;

-- User satisfaction by goal
SELECT goal_id, AVG(user_rating) as avg_rating, COUNT(user_rating) as ratings
FROM investigations
WHERE user_rating IS NOT NULL
GROUP BY goal_id;
```

### Effort

| Component | Hours |
|-----------|-------|
| Telemetry collector (EventBus subscriber) | 3 |
| Batch uploader + retry queue | 3 |
| Settings toggle + consent dialog | 1 |
| Post-investigation UX rating prompt | 2 |
| Server endpoint (simple FastAPI + SQLite/Postgres) | 3 |
| Analytics dashboard (optional — Metabase/Grafana query set) | 4 |
| **Total** | **16 hours** |

---

## Part 3 — Recommended deployment sequence

### Phase 1: Deployable MVP (week 1 — ~28 hours)

Fix blockers 1–6 + logging (#7). After this, the app is a double-clickable
native binary that works reliably.

1. Fix CORS + add shared-secret auth (2h)
2. Fix WS URL for Tauri production (10m)
3. Build PyInstaller sidecar + wire into Tauri bundle (4h)
4. Add backend supervisor / crash recovery (3h)
5. Implement case DB with aiosqlite (6h)
6. Docker status endpoint + UI pill + pre-flight check + build all images (4h)
7. Python logging with file rotation (2h)

### Phase 2: Telemetry + UX (week 2 — ~16 hours)

8. Telemetry collector + uploader (6h)
9. Post-investigation rating prompt (2h)
10. Settings toggle + consent dialog (1h)
11. Server endpoint (3h)
12. Keyring hardening (#8) (3h)

### Phase 3: Polish (week 3 — optional)

13. Auto-updater (#9) (4h)
14. Code signing + notarization (macOS) (4h)
15. Real EVTX test fixtures + integration tests (4h)
16. EZ Tools in Docker image (.NET packaging) (4h)

---

*Generated 2026-07-28. Based on a codebase audit that read every relevant
file. The blockers are real — not hypothetical — with file/line citations
available on request.*
