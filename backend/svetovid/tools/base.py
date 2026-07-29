"""Tool wrapper base contract.

Every DFIR tool we wrap (one file under ``svetovid/tools/``) follows this
contract so the agent harness can invoke it uniformly:

  - ``name``:           canonical tool name (matches the C-id short name)
  - ``image``:          Docker image to run in (or None for host tools)
  - ``schema()``:       JSON-schema for the args the agent passes (kept flat)
  - ``invoke(...)``:    async body that runs the tool (usually via docker_runner)
                        and streams ``tool.*`` events

Tools MUST be read-only with respect to evidence; they write only to the
sandbox ``output_dir``. The harness records provenance on every call.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..agent.events import EventBus


@dataclass
class ToolResult:
    call_id: str
    tool: str
    exit_code: int
    duration_s: float
    output_hash: str | None
    output_path: str | None
    summary: str
    data: Any = None


class Tool(ABC):
    """Base class for every DFIR tool wrapper."""

    name: str = ""
    image: str | None = None              # docker image; None = host tool
    description: str = ""

    @abstractmethod
    def schema(self) -> dict[str, Any]:
        """Flat JSON-schema for the tool's args (kept shallow for LLM compat)."""

    @abstractmethod
    async def invoke(self, args: dict[str, Any], ctx: "ToolContext") -> ToolResult:
        """Run the tool. Implementations should call ctx.bus.publish(...) for
        tool.start / tool.progress / tool.end events."""


@dataclass
class ToolContext:
    """Per-call context handed to ``invoke``."""

    investigation_id: str
    case_id: str
    bus: EventBus
    evidence_path: str
    output_dir: str

    def make_call_id(self) -> str:
        from ..agent.events import new_id
        return new_id("call")
