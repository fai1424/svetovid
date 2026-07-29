"""Goal plugin contract.

Every investigation goal is one Python module under ``svetovid/goals/`` that
exports a ``Goal`` subclass instance named ``goal``. The registry auto-loads
them so adding a new goal = drop in a file (see docs/ADDING_A_GOAL.md).

A goal provides:
  - ``id``:           Gxx identifier from the master scope doc
  - ``cluster``:      milestone cluster (Windows / Endpoint / Memory / ...)
  - ``label``:        one-line name for the GoalSelect card
  - ``description``:  short paragraph for the card back
  - ``input_artifacts``: which research B-ids this goal consumes
  - ``tools``:        which research C-ids this goal invokes
  - ``nodes()``:      the ordered LangGraph nodes for the StepProgress pane
  - ``detect(evidence)``: how strongly this goal matches scanned evidence (0..1)
  - ``run(...)``:     async body that streams events and produces a report
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..agent.events import EventBus


@dataclass
class GoalNode:
    """One step in the StepProgress pane."""

    id: str
    label: str
    status: str = "pending"   # pending | running | done | failed | skipped


class Goal(ABC):
    """Base class for every investigation goal."""

    id: str = ""
    cluster: str = ""
    label: str = ""
    description: str = ""
    input_artifacts: list[str] = field(default_factory=list)   # B-ids
    tools: list[str] = field(default_factory=list)             # C-ids
    icon: str = ""                                              # lucide icon name for the card

    @abstractmethod
    def nodes(self) -> list[GoalNode]:
        """Ordered nodes shown in the StepProgress pane."""

    def detect(self, evidence: list[dict[str, Any]]) -> float:
        """Return 0..1 — how strongly this goal matches the scanned evidence.
        Default: count overlap with ``input_artifacts``."""
        if not evidence or not self.input_artifacts:
            return 0.0
        present = {e["artifact_id"] for e in evidence if "artifact_id" in e}
        hits = len(present & set(self.input_artifacts))
        return min(1.0, hits / max(1, len(self.input_artifacts)))

    def manifest(self) -> dict[str, Any]:
        """Static description for the GoalSelect screen."""
        return {
            "id": self.id,
            "cluster": self.cluster,
            "label": self.label,
            "description": self.description,
            "input_artifacts": self.input_artifacts,
            "tools": self.tools,
            "icon": self.icon,
            "nodes": [{"id": n.id, "label": n.label} for n in self.nodes()],
        }

    @abstractmethod
    async def run(
        self,
        *,
        investigation_id: str,
        case_id: str,
        evidence_path: str,
        user_prompt: str,
        bus: EventBus,
    ) -> None:
        """Execute the goal. MUST emit events on ``bus`` for the UI.

        Implementations should:
          - publish ``node.state_change`` as each node runs
          - publish ``agent.thought`` / ``agent.action`` / ``agent.observation``
          - publish ``tool.*`` events for every sandboxed tool call
          - publish ``report.section_added`` incrementally
          - publish ``provenance.recorded`` for every tool call (governance)
          - honor ``hitl.request`` gates per governance policy
        """
