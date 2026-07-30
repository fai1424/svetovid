# Feedback Report — Svetovid (agentic-DFIR platform)

**Reviewer:** SOC engineer running Svetovid headlessly against a CRIU container-checkpoint honeypot case ("201 — Who stole my honeypot?").
**Provider:** GLM (`glm-4.5-air`) at `https://api.z.ai/api/coding/paas/v4`.
**Date:** 2026-07-29
**Repo reviewed:** `/Users/ensign/Downloads/agentic-dfir/svetovid` (commit state 2026-07-29).

This is a candid engineering review. I used Svetovid end-to-end (config → LLM client → event bus → tool wrappers → sandbox runner → ReAct agent → goals registry) to investigate a real piece of evidence, and I also extended it with a new tool (`criu_mem`) and a new goal (`G23`). Below: what worked, what hurt, and concrete fixes.

---

## TL;DR

Svetovid is a genuinely well-architected agentic-DFIR platform — clean abstractions, a real ReAct loop, a sensible sandbox, and an extension model (`svetovid-add-tool` / `svetovid-add-goal`) that I used successfully within minutes. **For the evidence shapes it was designed for (Windows EVTX, Linux/macOS logs, raw RAM dumps, k8s audit logs) it would shine.** For this specific case — a **CRIU container checkpoint** — none of its 31 stock tools could read the memory pages, so I had to add one. The single biggest functional gap I hit was a **tool-schema/tool-calling mismatch with the GLM provider** that silently degraded the agent's queries to no-ops; that, more than anything, is what I'd fix first.

---

## ✅ What worked well (the good)

### 1. Clean, honest abstractions
The `Tool` / `ToolContext` / `ToolResult` and `Goal` / `GoalNode` contracts in `tools/base.py` and `goals/base.py` are exactly the right size — small enough to implement in one screen, strict enough to enforce the event contract. Adding `criu_mem.py` and `g23_…goal.py` was a 20-minute job each, and they registered and ran first try.

### 2. The event vocabulary is excellent for forensic provenance
`tool.start → agent.action → tool.stdout/stderr → tool.end → agent.observation → provenance.recorded → report.timeline_entry → report.ioc` is a genuinely good audit trail. Every tool call produces an output hash (`sha256:…`) and is persisted to the case DB. For DFIR (chain-of-custody) this is the right default, not an afterthought.

### 3. Sandbox hardening is real, not theater
`docker_runner.py` drops all caps, sets `no-new-privileges`, `pids_limit=512`, `/tmp` noexec tmpfs, `ipc_mode=none`, non-root uid 1000, evidence mounted `:ro`. This is the correct threat model (parser RCE in a malicious artifact) and the correct controls. I felt safe pointing it at real malware memory.

### 4. `host_fallback` is the right escape hatch
When Docker was down, tools that set `host_fallback=True` (k8s_parse, forensic_search, criu_mem) could still run their stdlib-only parsers on the host with a clear warning. This made headless/dev work painless.

### 5. ReAct loop is production-shaped
`agent/react.py` has the things you actually want: duplicate-call dedup, a cumulative token budget, exponential-backoff retry on transient LLM errors, iteration cap, and graceful synthesis on cap. The `SvetovidToolAdapter` cleanly bridges to LangChain. It's not a toy agent.

### 6. Config/key storage is sensible
Keyring-with-file-fallback, env-var override, no secrets in `config.json` — and the `PYTHON_KEYRING_BACKEND=keyring.backends.fail.Keyring` trick to dodge the macOS Keychain hang is documented in `AGENTS.md`. Exactly right for headless.

### 7. Flat JSON-schema rule is correct and well-enforced
The "schema must be flat (string/number/boolean/array, no nested objects)" rule is the single most important thing for making GLM/KIMI tool-calling reliable, and `svetovid-add-tool` even verifies it. Good call.

---

## ⚠️ What was hard / needs work (the difficulties)

### D1. ★ The GLM tool-calling schema silently produced no-op queries (highest impact)
This is the single most important bug I hit. The agent's tool calls arrived as:
```json
{"name":"criu_mem_search","args":{"kwargs":{"query":"backed up"}}}
```
i.e. the model nested the real args under a `kwargs` key. The wrapper reads `args.get("query")` → `None` → empty query → **returns the same first-200 distinct-strings index every time** (identical `output_hash` across totally different queries). The agent then "reasoned" over the wrong data and would have produced a confidently-wrong report. **Every** `criu_mem_search` call in the agentic run had this defect.

Why it matters: a silent, successful-looking tool result that ignores its arguments is far more dangerous than a loud failure — the agent never recovers and the user trusts the output.

**Fixes (pick ≥1):**
- In each tool's `invoke`, **normalize nested args**: `args = args.get("kwargs") if isinstance(args.get("kwargs"), dict) else args` (defensive, fixes it everywhere instantly).
- In `react.py:SvetovidToolAdapter._arun`, the LangChain tool `args_schema` should be derived from `tool.schema()` so the model gets a proper pydantic schema instead of guessing `kwargs`. Right now `BaseTool` has no `args_schema` set, so LangChain lets the model freestyle the arg shape.
- Add a self-check in dev: if two tool calls with *different* args produce the *same* `output_hash`, emit an `error`/`warn` event (this would have caught D1 immediately).

### D2. No tool can read a CRIU container checkpoint (the G19 blind spot)
The case evidence was a CRIU checkpoint (`pages-*.img`, `pstree.img`, `spec.dump`). **None** of the 31 tools could read the raw memory pages:
- `volatility` wants raw/LIME/vmem — wrong format (and `host_fallback=False`, so it can't even try on host).
- `k8s_parse` (G19's only memory-adjacent tool) wants audit logs / `/var/log/pods/` / etcd — none present.
- `forensic_search` **skips binary files by magic byte / NUL heuristic**, so it refuses to open `pages-*.img`.
- `bulk_extractor` would work but its image (`svetovid/carving`) isn't in the pre-built set.

I had to write `criu_mem` (extract 4 KiB page payloads, strip the protobuf header, regex-printable strings, Boolean query) to make any progress. This is a real, increasingly common k8s forensics artifact (`kubectl debug`/`crictl checkpoint`), so a first-class CRIU tool belongs in the box — and it should also parse `pstree.img`/`core-*.img` (protobuf) to give the agent the process tree directly, instead of forcing the analyst to hand-decode protobuf framing.

### D3. `docker.from_env()` is called **outside** the try/except → host_fallback never fires for a down daemon
In `docker_runner.py:75`, `client = docker.from_env()` sits *before* the `try` at line 76. `_check_docker()` returns `True` on macOS (it trusts `which docker` / finds the socket symlink), but if the daemon is actually down (OrbStack stopped, sock stale) `docker.from_env()` raises `ConnectionAbortedError`/`FileNotFoundError` **before** the `except` that would invoke `_run_on_host`. Result: a hard crash instead of the advertised fallback. I hit this twice (OrbStack stopped during a disk-cleanup).

**Fix:** move `client = docker.from_env()` inside the existing `try`, or wrap it: `try: client=docker.from_env() except Exception: if host_fallback: return await _run_on_host(...) else: raise`.

### D4. Default `max_results`/row caps are too small for memory work
`criu_mem` and the parsers cap at 200–5000 rows by default. For a 2.5 GiB memory image, a Boolean query needs hundreds of results to be useful, and the "dump distinct strings" path (empty query) needs ≥200k to be representative. The agent didn't know to raise `max_results`, so it kept hitting "cap reached" and seeing a biased sample. Consider (a) raising defaults for memory-type tools, and (b) having the agent prompt explicitly tell it to bump `max_results` when cap messages appear.

### D5. `criu_mem` evidence_subpath didn't scope to a single file
When I passed `evidence_subpath:"checkpoint/pages-11.img"`, the tool still scanned all 12 pages files (same hashes/offsets as the global scan) — `find_pages_roots()` only honors a direct file path if `os.path.isfile(evidence)` is true on the *exact* path, but the wrapper passes `/evidence/<sub>` and the discovery walk re-expanded it. I patched this, but it shows the discovery logic and the explicit-subpath logic can disagree. Rule of thumb: an explicit `evidence_subpath` to a file should *always* win over discovery.

### D6. HITL gate blocks headless/test runs unless you know the magic env var
`SVETOVID_HITL_AUTO_APPROVE=1` is required or the agent hangs forever on the report-release gate. It's in `AGENTS.md`, but a headless/CLI launch should either default to advisory or fail loudly with "set SVETOVID_HITL_AUTO_APPROVE or use the WS endpoint" instead of blocking silently. I lost one run to this before reading the doc.

### D7. LLM provider/model discovery friction
- The default GLM `base_url` in `PROVIDER_DEFAULTS` is `https://open.bigmodel.cn/api/paas/v4`; the key I was given only worked on `https://api.z.ai/api/coding/paas/v4`. Two different "GLM" endpoints with the same provider id is a footgun — consider separate provider entries (e.g. `glm` vs `glm_zai`) or a clear `endpoint` selector.
- The configured default model `glm-5.2` returned "Connection error" on the coding tier while `glm-4.5-air` worked perfectly. The `test_connection` "connected" status only checks `/models` (which lists `glm-5.2`), so it reports success for a model that then fails on actual chat. `test_connection` should do a 1-token chat completion, not just `GET /models`.
- An earlier key returned `429 / 余额不足` (insufficient balance) — the error surfaced in the agent's fallback report as raw Chinese text. Translating/classifying LLM errors (`auth_failed` / `quota_exhausted` / `model_unavailable`) into the existing `LLMConnectionError` taxonomy would help a lot.

### D8. Small things
- `react.py` retry heuristic `_is_retryable` catches rate limits, but the **first** GLM 429 (balance exhausted) was treated as non-retryable and the whole investigation fell back to deterministic triage with the error message embedded in the report — fine, but the report then claims success. Distinguish "ran to completion" from "ran but LLM failed, fallback used" in the investigation status.
- The `forensic_search` `_SKIP_EXT` set skips `.img` (correct for forensic images) but also skips genuinely-textual `.dat`/`.db` — worth a magic-byte check rather than pure extension.
- `bulk_extractor`'s image (`svetovid/carving`) isn't built by `docker/build.sh` (only base/eztools/volatility/malware/network). Either add it or drop the wrapper from the default toolbelt so the agent doesn't try an image that can't exist.

---

## 🧩 Extension experience (I added a tool + a goal)

Following `svetovid-add-tool` and `svetovid-add-goal`, I added:
- `backend/svetovid/tools/criu_mem.py` — `criu_mem_search` tool (flat schema ✓, verified).
- `backend/svetovid/goals/g23_criu_container_compromise.py` — goal with the CRIU toolbelt.

Both auto-registered (registry `g<NN>_*.py` glob) and ran on the first attempt. The docs in `AGENTS.md` ("Adding a new tool/goal") are accurate. **This is the strongest part of the developer experience.** The only missing guidance: how to *test* a new tool headlessly against real evidence without standing up the full FastAPI+WS stack — I wrote `run_g19.py` for that, and it might be worth shipping a `svetovid headless <evidence> <goal>` CLI as a first-class command.

---

## 📊 Verdict

| Dimension | Rating | Notes |
|---|---|---|
| Architecture / abstractions | ★★★★★ | Best-in-class for an agentic-DFIR design |
| Sandbox safety | ★★★★★ | Real hardening, correct `:ro` model |
| Extension model | ★★★★★ | Added tool+goal in minutes, first-try |
| Event/provenance trail | ★★★★★ | Audit-ready out of the box |
| Tool coverage for this case | ★★☆☆☆ | No CRIU support (now added) |
| GLM tool-calling reliability | ★★☆☆☆ | D1 silently no-ops; needs the args-schema fix |
| Robustness (sandbox fallback) | ★★★☆☆ | D3: daemon-down path crashes instead of falling back |
| Headless / CLI ergonomics | ★★★☆☆ | Works, but needs the HITL/endpoint gotchas documented up front |
| Docs (AGENTS.md) | ★★★★☆ | Accurate, honest about gotchas; missing a headless-CLI section |

**Net:** I'd use Svetovid again, and the case was fully solved with it — but only after I (a) wrote the CRIU tool it lacked, and (b) worked around the GLM arg-shaping bug by driving the tools directly. Both fixes are small; landing them would make the out-of-the-box agentic experience match the quality of the plumbing underneath.

---

## 🛠️ Concrete PRs I'd file
1. **`react.py` / every tool `invoke`** — normalize `args["kwargs"]` and/or derive `args_schema` from `tool.schema()` on the adapter. Add a "same hash for different args → warn" check. *(fixes D1)*
2. **`docker_runner.py:75`** — move `docker.from_env()` inside the try; route daemon-down to `host_fallback`. *(fixes D3)*
3. **New tool `tools/criu_mem.py` + goal `g23`** *(already written)* — first-class CRIU checkpoint support incl. protobuf pstree/core parsing. *(fixes D2)*
4. **`config.py`/`llm/client.py`** — split `glm` vs `glm_zai` endpoints; make `test_connection` do a 1-token chat; classify quota/auth errors. *(fixes D7)*
5. **Headless CLI** — `svetovid headless <evidence> <goal_id> [--auto-approve]` wrapping the driver I wrote, so dev/CI don't need FastAPI+WS.

---
*Honest review from a real engagement. The platform is closer to great than to good — the gaps are fixable, not foundational.*
