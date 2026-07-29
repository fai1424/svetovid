# Adding a new investigation goal

Svetovid ships 22 investigation goals (M0 = G01; M1–M10 add G02–G22). Adding
a new one — or wiring one of the planned-but-stubbed ones — is mechanical.
This doc is the contract.

> **TL;DR:** drop a file `g<NN>_<slug>.py` into `backend/svetovid/goals/`,
> export a module-level `goal` instance, register any new tool wrappers it
> needs, and (if applicable) build the matching Docker image. Restart the
> backend; the goal auto-appears in the UI's GoalSelect screen.

## 1. The Goal contract

Every goal is a subclass of `svetovid.goals.base.Goal` with these attributes/methods:

```python
class Goal(ABC):
    id: str                       # "G02", "G19", … (matches the master scope doc)
    cluster: str                  # Windows / Endpoint / Memory / Network /
                                  # Ransomware / Email / Mobile / Cloud / SaaS /
                                  # Container / Cross-cutting
    label: str                    # short card title
    description: str              # 1–3 sentence card body
    input_artifacts: list[str]    # B-family ids this goal consumes: ["B3","B8"]
    tools: list[str]              # C-family ids this goal invokes: ["C12","A2"]
    icon: str                     # lucide-react icon name for the card

    @abstractmethod
    def nodes(self) -> list[GoalNode]:
        """Ordered LangGraph nodes for the StepProgress pane.
        Each GoalNode has .id, .label, .status='pending'.
        Convention: 4–8 nodes; include 'triage' first and 'finalize' last;
        include 'hitl_review' before 'finalize' if the goal mutates evidence
        or releases a report."""

    def detect(self, evidence: list[dict]) -> float:
        """0..1 match score against scanned evidence. Default counts overlap
        with self.input_artifacts. Override only if you need artifact-specific
        heuristics (e.g. iOS goal cares about sms.db presence specifically)."""

    def manifest(self) -> dict:
        """Static JSON for /api/goals. Don't override — base impl is correct."""

    @abstractmethod
    async def run(self, *, investigation_id, case_id, evidence_path,
                  user_prompt, bus) -> None:
        """Execute the goal. REQUIRED INVARIANTS:
          - publish E.node_state_change(node, 'running') before each node's work
          - publish E.node_state_change(node, 'done'|'failed') after
          - publish E.agent_thought / agent_action / agent_observation so the
            AgentTrace pane shows what the agent is doing
          - publish E.report_section_added for each report chunk
          - publish E.provenance_recorded for every tool call (governance)
          - honor E.hitl_request gates per the user's HITL policy
        See g01_attack_timeline.py for a complete reference implementation."""
```

## 2. Step-by-step: wire a new goal

### Step 1 — pick the ID + scope

Look up the goal in `../agentic-dfir/report.md` (Section 1, Investigation
Goals) for its input artifacts and primary tools. e.g. G19 (Kubernetes
compromise):

> primary_input_artifacts: B12; primary_tools: C16, C17c, C13, C15, C12, C18

### Step 2 — write the goal module

```python
# backend/svetovid/goals/g19_container_compromise.py
"""G19 — Container / Kubernetes compromise investigation."""
from ..agent import events as E
from ..tools.k8s_audit import K8sAuditTool
from ..tools.volatility import VolatilityTool
from ..tools.mitre_attack import MitreAttackTool
from .base import Goal, GoalNode


class ContainerCompromiseGoal(Goal):
    id = "G19"
    cluster = "Container"
    label = "K8s / container compromise"
    description = (
        "Reconstruct pod/namespace activity from k8s audit logs, runtime "
        "metadata, and etcd state. Detects container escape, image tampering, "
        "and privilege abuse."
    )
    input_artifacts = ["B12"]
    tools = ["C16", "C17c", "C13", "C15", "C12", "C18"]
    icon = "box"

    def nodes(self):
        return [
            GoalNode("triage", "Triage evidence"),
            GoalNode("audit_parse", "Parse k8s audit logs"),
            GoalNode("runtime_meta", "Collect runtime metadata"),
            GoalNode("enrich_attack", "Enrich with ATT&CK"),
            GoalNode("correlate", "Correlate into incidents"),
            GoalNode("draft_report", "Draft narrative"),
            GoalNode("hitl_review", "Review (human)"),
            GoalNode("finalize", "Finalize"),
        ]

    async def run(self, *, investigation_id, case_id, evidence_path,
                  user_prompt, bus):
        out_dir = f"~/.svetovid/cases/{case_id}/{investigation_id}"
        # ... stream node transitions + tool calls + report sections
        # Pattern: see g01_attack_timeline.py::run


goal = ContainerCompromiseGoal()
```

### Step 3 — write any new tool wrappers

If the goal needs a tool that doesn't exist yet, add one module per tool
under `backend/svetovid/tools/`. Each tool follows the `Tool` contract in
`tools/base.py` — flat JSON-schema, sandboxed invoke, publishes `tool.*`
events, returns a `ToolResult`. See `tools/chainsaw.py` for the reference
implementation.

```python
# backend/svetovid/tools/k8s_audit.py
from .base import Tool, ToolContext, ToolResult


class K8sAuditTool(Tool):
    name = "k8s_audit_parse"
    image = "svetovid/k8s"   # if you need a custom image; or reuse an existing one
    description = "Parse Kubernetes audit logs into structured events."

    def schema(self):
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {"type": "string"},
            },
        }

    async def invoke(self, args, ctx):
        # 1. publish tool.start
        # 2. run via sandbox/docker_runner (or use python libs directly)
        # 3. parse output
        # 4. publish tool.end + agent.observation + provenance.recorded
        # 5. return ToolResult(...)
        ...


tool = K8sAuditTool()
```

### Step 4 — Docker image (if needed)

If your tool needs binaries not in `svetovid/base` or `svetovid/eztools`,
add a `Dockerfile.<name>` in `backend/svetovid/sandbox/images/` that layers
on `svetovid/base:latest`. Build with:

```bash
docker build -f backend/svetovid/sandbox/images/Dockerfile.<name> \
             -t svetovid/<name>:latest .
```

For cloud-API goals (G12–G18) no Docker image is needed — the tool wrapper
calls the provider's API directly from the backend.

### Step 5 — restart the backend

```bash
cd backend && uvicorn svetovid.main:app --port 7421 --reload
```

The goal auto-appears in `GET /api/goals` and the GoalSelect screen. The
`registry.py` walks `g*.py` files at import time.

## 3. Conventions

- **Node names**: lowercase `snake_case`, ≤ 14 chars. They appear in the UI
  stepper; short names read better.
- **Tool args**: keep schemas flat — one level of properties, primitive
  types only. GLM and KIMI tool-calling gets unreliable with nested objects.
- **Report sections**: each `report.section_added` event with a distinct
  `section_id` becomes a separate section in the LiveReport pane. Use stable
  IDs (`timeline`, `narrative`, `iocs`, `summary`) so re-runs replace rather
  than duplicate.
- **HITL**: if your goal mutates evidence (G20 acquisition) or releases a
  court-bound report (any goal), include a `hitl_review` node and publish
  `E.hitl_request` before finalize.
- **Provenance**: every tool call publishes `E.provenance_recorded` with
  `{tool, image, args, exit_code, duration_s, output_hash, ts}`. The audit
  log writes this to `~/.svetovid/cases/<case>/audit.jsonl`.

## 4. Testing a new goal

M0 doesn't have a per-goal test framework yet; for now, exercise the goal via
the WS smoke-test pattern used for G01 (see the M0.B verification step in
git history). A pytest fixture suite for goals lands in M1.
