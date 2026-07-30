"""Reusable LangGraph ReAct agent loop.

The single piece that turns Svetovid from a fixed pipeline into an actual
agent: an LLM picks which tool to call next based on the evidence + its
accumulated observations, until it decides it's done (or hits the iteration
cap, or the user stops).

Usage from a goal::

    from .agent.react import build_react_graph, ReactConfig
    from .tools.chainsaw import tool as chainsaw
    from .tools.mitre_attack import tool as mitre

    graph = build_react_graph(
        tools=[chainsaw, mitre],
        system_prompt="You are a DFIR analyst investigating a Windows compromise. ...",
        config=ReactConfig(max_iterations=12),
    )
    # graph is a CompiledStateGraph; invoke it with the initial state.

Why a graph and not a hand-rolled loop:
  - LangGraph gives us a stable state machine the UI can render as a stepper.
  - It integrates cleanly with LangChain's tool-calling abstraction, which
    works across OpenAI / Ollama / GLM / KIMI via ChatOpenAI(base_url=…).
  - Interrupts (HITL, user-stop) map to LangGraph's interrupt mechanism.

Why we still publish our own events (not LangGraph's stream):
  - We need typed, fine-grained events (agent.thought / agent.action /
    agent.observation / tool.*) that match the UI contract in events.py.
  - LangGraph's stream() gives us node-level chunks; we map those into our
    event vocabulary before publishing to the EventBus.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Callable

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.graph.message import add_messages

from typing_extensions import Annotated, TypedDict

from . import events as E
from .events import EventBus
from .state import InvestigationState
from ..config import Provider, load_settings
from ..llm.client import build_chat
from ..tools.base import Tool, ToolContext


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class ReactConfig:
    """Tuning knobs for the ReAct loop.

    Defaults to UNLIMITED iterations and token budget. The duplicate-detection
    guard (called_tools set) prevents true infinite loops — if the agent keeps
    calling DIFFERENT tools with DIFFERENT args, that's genuine investigation
    progress, not a loop. Set max_iterations=0 or max_tokens_total=0 to
    explicitly disable that limit.
    """

    max_iterations: int = 0           # 0 = unlimited (dup-detection prevents loops)
    max_tokens_per_call: int = 4096
    bind_tools_strict: bool = False   # GLM/KIMI prefer non-strict tool binding
    stop_on_error: bool = False       # True = halt on any tool error; False = report + continue
    max_tokens_total: int = 0         # 0 = unlimited


# This text is appended to every goal's system prompt to give the agent
# robust error-recovery guidance. Without it, the agent wastes all its
# iterations retrying a failed tool instead of trying a different approach.
ERROR_RECOVERY_GUIDANCE = """

## Tool failure recovery rules (CRITICAL — read these)
- If a tool returns an error (exit_code != 0, or an error message), DO NOT \
retry the same tool with the same arguments. Try a different tool instead.
- To LIST FILES in the evidence directory: use forensic_keyword_search with \
query="*". Do NOT use bulk_extractor for listing — bulk_extractor scans \
binary content, not directory structure.
- To SEARCH for keywords in files: use forensic_keyword_search (it works on \
text files). Do NOT use bulk_extractor for keyword search.
- bulk_extractor is ONLY for scanning raw disk images (E01/.dd/.raw) for \
embedded features (emails, URLs, credit cards). If the evidence is loose \
files (not a disk image), do NOT call bulk_extractor.
- If Docker fails (image not found, daemon error), try forensic_search or \
mitre_attack which run on the host.
- After 2 consecutive tool failures, STOP calling tools and write your \
report based on whatever information you have gathered so far.
- The evidence folder may contain subdirectories. Use forensic_keyword_search \
with an empty query to list the top-level contents first.
"""


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class ReactState(TypedDict, total=False):
    """LangGraph state for the ReAct subgraph. Lives inside InvestigationState."""

    messages: Annotated[list, add_messages]
    iteration: int
    tool_call_in_flight: dict[str, Any] | None   # the call we're waiting on
    final_answer: str | None
    # Q7: loop-hardening state. ``called_tools`` dedupes tool calls so a
    # confused LLM can't spam the same tool with identical args forever;
    # ``total_tokens`` enforces a cumulative token budget.
    called_tools: set[tuple[str, str]]            # {(tool_name, args_json), ...}
    total_tokens: int                             # accumulated usage_metadata.total_tokens


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------


def build_react_graph(
    *,
    tools: list[Tool],
    system_prompt: str,
    config: ReactConfig,
    investigation_id: str,
    case_id: str,
    bus: EventBus,
    evidence_path: str,
    output_dir: str,
    provider: Provider | None = None,
) -> Any:
    """Build a compiled LangGraph ReAct graph for one investigation.

    The error-recovery guidance is appended to every system prompt so the agent
    knows what to do when tools fail (instead of wasting all its iterations).
    """
    # Append the universal error-recovery guidance
    system_prompt = system_prompt + ERROR_RECOVERY_GUIDANCE

    settings = load_settings()
    active = provider or settings.active()
    if active is None:
        raise RuntimeError("No active LLM provider configured.")

    chat = build_chat(active, streaming=False)

    # Convert our Tool wrappers into LangChain BaseTool adapters and prepare
    # the per-call context (sandbox dir, bus, etc.).
    ctx = ToolContext(
        investigation_id=investigation_id,
        case_id=case_id,
        bus=bus,
        evidence_path=evidence_path,
        output_dir=output_dir,
    )
    lc_tools: list[BaseTool] = [SvetovidToolAdapter(t, ctx) for t in tools]

    # Bind tools to the chat model. ``parallel=False`` because we want to
    # stream each tool call separately; parallel tool calls confuse the UI
    # (two tool.start events at once) and some local models reject them.
    try:
        bound = chat.bind_tools(lc_tools, parallel_tool_calls=False)
    except TypeError:
        # Older / local model SDKs may not support parallel_tool_calls kwarg.
        bound = chat.bind_tools(lc_tools)

    # ---- nodes ----

    async def agent_node(state: ReactState) -> dict[str, Any]:
        """LLM reasons about the state, emits a thought, and chooses an action."""
        iteration = state.get("iteration", 0) + 1
        # 0 = unlimited; only enforce the cap if it's set to a positive value
        if config.max_iterations > 0 and iteration > config.max_iterations:
            bus.publish(E.agent_thought(
                investigation_id,
                f"Reached iteration cap ({config.max_iterations}). Stopping.",
            ))
            return {"final_answer": _synthesize_final(state, system_prompt)}

        messages = list(state.get("messages", []))
        if not any(isinstance(m, SystemMessage) for m in messages):
            messages = [SystemMessage(content=system_prompt), *messages]

        # Stream the LLM's text content as agent.thought events. We don't get
        # token-level streaming here (streaming=False above) — we get the full
        # AIMessage and publish its text content + any tool calls.
        #
        # Q7: retry transient LLM failures (timeout / rate limit) with
        # exponential backoff (1s, then 4s) before giving up.
        response = None
        last_err: Exception | None = None
        backoff = (1, 4)  # seconds, applied before retries 1 and 2
        for attempt in range(3):  # 1 initial attempt + up to 2 retries
            try:
                response = await bound.ainvoke(messages)
                break
            except Exception as e:
                last_err = e
                retryable = attempt < 2 and _is_retryable(e)
                if not retryable:
                    break
                bus.publish(E.agent_thought(
                    investigation_id,
                    f"LLM call failed ({type(e).__name__}); retrying in {backoff[attempt]}s "
                    f"(attempt {attempt + 2}/3).",
                ))
                await asyncio.sleep(backoff[attempt])

        if response is None:
            err = last_err if last_err is not None else RuntimeError("no LLM response")
            bus.publish(E.error_event(investigation_id, f"LLM call failed: {err}"))
            return {"final_answer": f"Investigation halted: LLM error ({err}).",
                    "iteration": iteration}

        if not isinstance(response, AIMessage):
            bus.publish(E.error_event(
                investigation_id, f"unexpected LLM response type: {type(response)}"))
            return {"iteration": iteration}

        # Q7: accumulate token usage and enforce a cumulative budget.
        total_tokens = int(state.get("total_tokens", 0) or 0)
        usage = getattr(response, "usage_metadata", None)
        if isinstance(usage, dict) and isinstance(usage.get("total_tokens"), int):
            total_tokens += int(usage["total_tokens"])
        if config.max_tokens_total > 0 and total_tokens > config.max_tokens_total:
            bus.publish(E.agent_thought(
                investigation_id,
                f"Token budget ({config.max_tokens_total}) exceeded after {total_tokens} tokens. Stopping.",
            ))
            capped_state: ReactState = {**state, "messages": [*messages, response]}  # type: ignore[assignment]
            return {
                "messages": [response],
                "iteration": iteration,
                "total_tokens": total_tokens,
                "called_tools": set(state.get("called_tools") or []),
                "final_answer": _synthesize_final(capped_state, system_prompt),
            }

        # Publish the LLM's reasoning text (if any) as a thought.
        if response.content and isinstance(response.content, str) and response.content.strip():
            # Cap to keep the UI readable; the full text is in the message log.
            text = response.content.strip()
            bus.publish(E.agent_thought(investigation_id, text[:600]))

        # If the LLM emitted tool calls, publish them as agent.action events.
        tool_calls = response.tool_calls or []
        if not tool_calls:
            # LLM chose to stop calling tools — synthesize a final answer.
            return {
                "messages": [response],
                "iteration": iteration,
                "total_tokens": total_tokens,
                "called_tools": set(state.get("called_tools") or []),
                "final_answer": response.content if isinstance(response.content, str) else str(response.content),
            }

        # Q7: duplicate tool-call detection. If the LLM asks for the exact same
        # (tool_name, args) it already asked for, we DO NOT re-execute — instead
        # we feed back a ToolMessage reminding it the result is already in the
        # transcript. ``parallel_tool_calls=False`` means there's typically one
        # call per turn, but we handle the list generally. New calls are added
        # to ``called_tools`` so subsequent repeats are caught.
        called_tools: set[tuple[str, str]] = set(state.get("called_tools") or [])
        out_messages: list = [response]
        injected_dup = False
        for tc in tool_calls:
            name = tc.get("name", "?")
            args = tc.get("args", {}) or {}

            # D1 FIX: normalize GLM's kwargs-wrapping so dedup + logging work.
            if isinstance(args.get("kwargs"), dict):
                args = args["kwargs"]
            try:
                key = (name, json.dumps(args, sort_keys=True, default=str))
            except (TypeError, ValueError):
                key = (name, str(args))
            if key in called_tools:
                # Don't execute — nudge the LLM to reuse the prior result.
                injected_dup = True
                out_messages.append(ToolMessage(
                    content=(
                        "You already called this tool with these arguments. "
                        "Use the previous result."
                    ),
                    tool_call_id=tc.get("id", ""),
                ))
            else:
                called_tools.add(key)
                bus.publish(E.agent_action(
                    investigation_id,
                    tool=name,
                    args=args,
                ))

        return {
            "messages": out_messages,
            "iteration": iteration,
            "total_tokens": total_tokens,
            "called_tools": called_tools,
        }

    async def tool_node(state: ReactState) -> dict[str, Any]:
        """Execute the LLM's tool calls via our Tool wrappers.

        Each tool wrapper publishes tool.start / tool.stdout / tool.end itself.
        Here we just dispatch and produce ToolMessages to feed back.
        """
        messages = state.get("messages", [])
        last = messages[-1] if messages else None
        if not isinstance(last, AIMessage) or not last.tool_calls:
            return {}

        tool_map: dict[str, Tool] = {t.name: t for t in tools}
        out_messages: list[ToolMessage] = []
        for tc in last.tool_calls:
            name = tc.get("name", "")
            args = tc.get("args", {}) or {}

            # D1 FIX: GLM (and some other providers) wrap the real args under
            # a "kwargs" key instead of passing them at the top level. Normalize
            # so every tool sees its expected argument names.
            if isinstance(args.get("kwargs"), dict):
                args = args["kwargs"]

            tool = tool_map.get(name)
            if tool is None:
                bus.publish(E.error_event(
                    investigation_id, f"LLM requested unknown tool {name!r}"))
                out_messages.append(ToolMessage(
                    content=f"Error: unknown tool {name!r}. Available: {list(tool_map)}",
                    tool_call_id=tc.get("id", ""),
                ))
                continue
            try:
                result = await tool.invoke(args, ctx)
                summary = result.summary or "(no summary)"
                bus.publish(E.agent_observation(investigation_id, name, summary[:400]))
                # Feed the structured result back to the LLM as a ToolMessage.
                # Truncate large payloads to keep the context window bounded.
                content = _format_for_llm(result.data if result.data is not None else summary)
                out_messages.append(ToolMessage(
                    content=content, tool_call_id=tc.get("id", ""),
                ))
            except Exception as e:
                bus.publish(E.error_event(
                    investigation_id, f"tool {name} raised: {e}"))
                if config.stop_on_error:
                    return {"final_answer": f"Stopped: tool {name} failed ({e})."}
                out_messages.append(ToolMessage(
                    content=f"Error in tool {name}: {e}",
                    tool_call_id=tc.get("id", ""),
                ))
        return {"messages": out_messages}

    def should_continue(state: ReactState) -> str:
        if state.get("final_answer") is not None:
            return END
        messages = state.get("messages", [])
        last = messages[-1] if messages else None
        if isinstance(last, AIMessage) and last.tool_calls:
            return "tools"
        # Q7: if the last message is a ToolMessage that we injected for a
        # duplicate tool call, loop back to the agent so it can reconsider
        # (pick a different tool or synthesize an answer) instead of ENDing
        # the whole graph. This is bounded by max_iterations + token budget.
        if isinstance(last, ToolMessage):
            return "agent"
        return END

    # ---- build the graph ----
    g = StateGraph(ReactState)
    g.add_node("agent", agent_node)
    g.add_node("tools", tool_node)
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END, "agent": "agent"})
    g.add_edge("tools", "agent")
    return g.compile()


# ---------------------------------------------------------------------------
# Tool adapter — wraps our Tool contract as a LangChain BaseTool
# ---------------------------------------------------------------------------


class SvetovidToolAdapter(BaseTool):
    """Adapt a Svetovid ``Tool`` to LangChain's ``BaseTool`` interface.

    LangChain calls ``_arun`` for async invocation; we forward to our tool's
    ``invoke`` with the bound ToolContext.
    """

    name: str = ""
    description: str = ""
    # Stored as dict (not Tool) because pydantic BaseModel doesn't like
    # arbitrary-class fields without Config. We forward calls manually.
    _svetovid_tool: Any
    _ctx: Any

    def __init__(self, tool: Tool, ctx: ToolContext) -> None:
        super().__init__(
            name=tool.name,
            description=tool.description or tool.name,
        )
        # bypass pydantic (these are runtime-only refs)
        object.__setattr__(self, "_svetovid_tool", tool)
        object.__setattr__(self, "_ctx", ctx)

    def _run(self, *args, **kwargs):  # sync — not used, we always go async
        raise NotImplementedError("Svetovid tools are async-only; use ainvoke.")

    async def _arun(self, **kwargs) -> str:
        tool = object.__getattribute__(self, "_svetovid_tool")
        ctx = object.__getattribute__(self, "_ctx")
        result = await tool.invoke(kwargs, ctx)
        return _format_for_llm(result.data if result.data is not None else result.summary)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _format_for_llm(data: Any, limit: int = 4000) -> str:
    """Render tool output as a compact string the LLM can consume.

    Caps length so a single huge tool output (e.g. a 10k-row timeline) can't
    blow the context window. The full structured data is still in state.
    """
    if data is None:
        return "(no data)"
    try:
        s = json.dumps(data, ensure_ascii=False, default=str)
    except Exception:
        s = str(data)
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n… [{len(s) - limit} more chars truncated]"


def _is_retryable(exc: Exception) -> bool:
    """Heuristic: is this LLM error worth retrying (transient)?

    Catches timeouts and rate-limit / 429-style errors from the OpenAI SDK and
    httpx, which are the two transient failure modes we see against Ollama /
    GLM / KIMI. Everything else (auth, malformed request, our own logic) is
    treated as non-retryable so we don't burn the retry budget pointlessly.
    """
    name = type(exc).__name__.lower()
    # Class-name heuristics cover TimeoutError, asyncio.TimeoutError, and
    # the SDK's own *RateLimitError / APITimeoutError / APIConnectionError.
    if any(tok in name for tok in ("timeout", "ratelimit", "connection", "transient")):
        return True
    # Status-code / message heuristics (works across langchain_openai and httpx).
    needle = " ".join(str(getattr(exc, k, "") or "") for k in ("message", "args")).lower()
    if "429" in needle or "rate limit" in needle or "timeout" in needle or "timed out" in needle:
        return True
    # httpx raises *TimeoutException subclasses; langchain surfaces status_code.
    status = getattr(exc, "status_code", None)
    if status == 429:
        return True
    return False


def _synthesize_final(state: ReactState, system_prompt: str) -> str:
    """Fallback synthesis when the iteration cap is hit without a clean stop."""
    messages = state.get("messages", [])
    # Extract all tool observations (ToolMessage contents) the agent accumulated.
    observations = [
        m.content for m in messages
        if hasattr(m, "content")
        and isinstance(m.content, str)
        and len(m.content) > 20
    ]
    if not observations:
        return (
            "Investigation reached the iteration cap before completing. "
            "No findings were accumulated."
        )
    # Summarize the most recent observations to keep the summary bounded.
    recent = observations[-5:]
    return (
        "## Investigation summary (iteration cap reached)\n\n"
        "The agent reached its maximum number of reasoning steps. "
        "Here are the most recent findings:\n\n"
        + "\n\n".join(
            f"- {obs[:200]}..." if len(obs) > 200 else f"- {obs}"
            for obs in recent
        )
        + "\n\nReview the full trace and report for complete findings."
    )


__all__ = ["ReactConfig", "ReactState", "build_react_graph", "SvetovidToolAdapter"]
