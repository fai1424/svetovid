"""Reliability tests for the hardened ReAct loop (Q7 / Q25).

These exercise the loop-hardening added to ``svetovid.agent.react``:

  - **Q7 duplicate tool detection:** when the LLM asks for the same tool with
    identical args twice, the second call must NOT be dispatched to the real
    tool. Instead the agent node injects a ``ToolMessage`` telling the model
    to reuse the prior result. We build a fake chat + fake tool and assert
    the tool's ``invoke`` is only called once even though the LLM "requests"
    it on two consecutive turns.
  - **Q7 token budget:** when the accumulated ``usage_metadata.total_tokens``
    crosses ``ReactConfig.max_tokens_total``, the loop stops and synthesizes
    a final answer instead of calling the LLM again.
  - **Q25 _synthesize_final:** with real observations in the message log, the
    fallback summary must mention the accumulated findings (non-empty,
    references recent observations) rather than the old generic stub.

The fixtures mirror the hermetic setup in ``test_react.py`` (throwaway HOME,
fail-keyring) so these run offline and never touch the macOS Keychain.
"""

from __future__ import annotations

import json

import pytest


# ---------------------------------------------------------------------------
# Shared hermetic setup (same shape as test_react.py)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    (tmp_path / "h").mkdir()
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    import sys
    for m in list(sys.modules):
        if m.startswith("svetovid"):
            del sys.modules[m]
    yield


def _seed_active_provider():
    """Configure an active provider so build_react_graph() can build a chat."""
    from svetovid.config import load_settings, save_settings
    s = load_settings()
    s.active_provider = "ollama"   # seed default has base_url + model + api_key
    save_settings(s)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _FakeTool:
    """Minimal tool double compatible with the react.py ``tool_node`` path.

    Exposes ``name``, ``description``, ``invoke`` — the only attributes the
    tool_node + SvetovidToolAdapter read. ``invoke`` records call count and
    returns a fixed result.
    """

    name = "fake_lookup"
    description = "Returns its args; used for loop-hardening tests."
    image = None

    def __init__(self) -> None:
        self.invoke_count = 0
        self.calls: list[dict] = []

    async def invoke(self, args, ctx):
        self.invoke_count += 1
        self.calls.append(dict(args))
        # Mimic ToolResult's .summary / .data surface used by tool_node.
        class _R:
            summary = f"hit {self.invoke_count}"
            data = {"echoed": args, "hit": self.invoke_count}
        return _R()


class _ScriptedChat:
    """Stand-in for the bound chat model returned by ``chat.bind_tools``.

    ``ainvoke`` returns the next AIMessage from a pre-loaded script; raises
    once the script is exhausted so an unbounded loop surfaces as a failure.
    """

    def __init__(self, responses):
        # Copy so each test gets its own iterator.
        self._responses = list(responses)

    async def ainvoke(self, messages):
        if not self._responses:
            raise RuntimeError("scripted chat exhausted")
        return self._responses.pop(0)

    # bind_tools is called by build_react_graph; we return self so the bound
    # object the graph stores IS the scripted chat.
    def bind_tools(self, tools, **kwargs):
        return self


# ---------------------------------------------------------------------------
# Q7: duplicate tool call detection
# ---------------------------------------------------------------------------


def test_duplicate_tool_call_is_blocked():
    """Second identical tool call must NOT hit the real tool; an injected
    ToolMessage is fed back instead. Driven through the full compiled graph."""
    import asyncio
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    from svetovid.agent.react import build_react_graph, ReactConfig
    from svetovid.agent.events import EventBus

    _seed_active_provider()
    fake_tool = _FakeTool()

    # Scripted LLM turns:
    #   turn 1 — calls fake_lookup(x=1)  → should execute
    #   turn 2 — calls fake_lookup(x=1)  → DUPLICATE, must NOT execute
    #   turn 3 — stops (plain text answer)
    scripted = [
        AIMessage(content="querying", tool_calls=[
            {"name": "fake_lookup", "args": {"x": 1}, "id": "c1", "type": "tool_call"},
        ]),
        AIMessage(content="querying again", tool_calls=[
            {"name": "fake_lookup", "args": {"x": 1}, "id": "c2", "type": "tool_call"},
        ]),
        AIMessage(content="Final answer: done after reuse."),
    ]
    fake_chat = _ScriptedChat(scripted)

    bus = EventBus()
    graph = _build_graph_with_fake_chat(
        fake_chat, fake_tool, bus, ReactConfig(max_iterations=10),
    )

    result = asyncio.run(graph.ainvoke({"messages": [HumanMessage(content="go")]}))

    # The real tool should have been invoked exactly ONCE (the dup was blocked).
    assert fake_tool.invoke_count == 1, (
        f"expected the real tool to run once, ran {fake_tool.invoke_count} times"
    )

    # The transcript must contain the injected "already called" ToolMessage so
    # the LLM was nudged, not silently dropped.
    messages = result.get("messages", [])
    dup_msgs = [
        m for m in messages
        if isinstance(m, ToolMessage) and "already called" in str(getattr(m, "content", ""))
    ]
    assert dup_msgs, "expected an injected 'already called' ToolMessage in the transcript"

    # And the agent must have produced a final answer (graph terminated cleanly).
    assert result.get("final_answer"), "expected a non-empty final answer"


def test_different_tool_args_are_not_treated_as_duplicates():
    """Sanity: the dedup key is (name, args). Different args → both execute."""
    import asyncio
    from langchain_core.messages import AIMessage, HumanMessage
    from svetovid.agent.react import build_react_graph, ReactConfig
    from svetovid.agent.events import EventBus

    _seed_active_provider()
    fake_tool = _FakeTool()
    scripted = [
        AIMessage(content="q1", tool_calls=[
            {"name": "fake_lookup", "args": {"x": 1}, "id": "c1", "type": "tool_call"},
        ]),
        AIMessage(content="q2", tool_calls=[
            {"name": "fake_lookup", "args": {"x": 2}, "id": "c2", "type": "tool_call"},
        ]),
        AIMessage(content="done"),
    ]
    fake_chat = _ScriptedChat(scripted)
    bus = EventBus()
    graph = _build_graph_with_fake_chat(
        fake_chat, fake_tool, bus, ReactConfig(max_iterations=10),
    )

    asyncio.run(graph.ainvoke({"messages": [HumanMessage(content="go")]}))

    assert fake_tool.invoke_count == 2, (
        f"distinct args should both execute; got {fake_tool.invoke_count}"
    )
    assert fake_tool.calls == [{"x": 1}, {"x": 2}]


# ---------------------------------------------------------------------------
# Q7: token budget enforcement
# ---------------------------------------------------------------------------


def test_token_budget_stops_and_synthesizes():
    """When accumulated total_tokens exceeds max_tokens_total, the agent node
    must stop calling the LLM and synthesize a final answer from observations."""
    import asyncio
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    from svetovid.agent.react import build_react_graph, ReactConfig
    from svetovid.agent.events import EventBus

    _seed_active_provider()
    fake_tool = _FakeTool()

    # Each LLM response reports 60k tokens. With max_tokens_total=100000, the
    # FIRST response alone (60k) is under budget, but after the tool round-
    # trip the SECOND response pushes us to 120k → stop + synthesize.
    scripted = [
        AIMessage(
            content="first turn",
            tool_calls=[{"name": "fake_lookup", "args": {"q": 1}, "id": "c1", "type": "tool_call"}],
            usage_metadata={"input_tokens": 30000, "output_tokens": 30000, "total_tokens": 60000},
        ),
        AIMessage(
            content="second turn",
            tool_calls=[{"name": "fake_lookup", "args": {"q": 2}, "id": "c2", "type": "tool_call"}],
            usage_metadata={"input_tokens": 30000, "output_tokens": 30000, "total_tokens": 60000},
        ),
    ]
    fake_chat = _ScriptedChat(scripted)
    bus = EventBus()
    graph = _build_graph_with_fake_chat(
        fake_chat, fake_tool, bus, ReactConfig(max_iterations=10, max_tokens_total=100000),
    )

    result = asyncio.run(graph.ainvoke({"messages": [HumanMessage(content="go")]}))

    # Budget hit → the loop must terminate with a synthesized final answer.
    fa = result.get("final_answer") or ""
    assert fa, "expected a non-empty synthesized final answer after the token cap"
    # The synthesized text comes from _synthesize_final, which references the
    # accumulated observations — assert it isn't the old generic stub.
    assert "Investigation summary" in fa or "findings" in fa.lower(), (
        f"final answer should be a real summary, got: {fa!r}"
    )


# ---------------------------------------------------------------------------
# Q25: _synthesize_final produces non-empty output with observations
# ---------------------------------------------------------------------------


def test_synthesize_final_with_observations_is_nonempty():
    """_synthesize_final must surface the accumulated tool observations,
    not the old generic 'review the report pane' stub."""
    from langchain_core.messages import AIMessage, ToolMessage
    from svetovid.agent.react import _synthesize_final

    observations = [
        ToolMessage(
            content="Found 3 suspicious logon events from 10.0.0.5 at 02:00 UTC.",
            tool_call_id="c1",
        ),
        ToolMessage(
            content="Mimikatz signature matched in process 'lsass_helper.exe' (PID 412).",
            tool_call_id="c2",
        ),
        ToolMessage(
            content="Chainsaw hunt returned 47 hits across Security + Syslog.",
            tool_call_id="c3",
        ),
        AIMessage(content="Summarizing findings so far."),
    ]
    summary = _synthesize_final({"messages": observations}, "sys prompt")

    assert summary, "synthesize must return non-empty text"
    assert summary != _old_generic_stub()
    # It should reference at least one of the concrete observations.
    assert "suspicious logon" in summary or "Mimikatz" in summary or "Chainsaw" in summary, (
        f"summary should quote accumulated observations, got: {summary!r}"
    )
    # Sanity: long observations get truncated to <=200 chars in the bullet.
    for line in summary.splitlines():
        if line.startswith("- "):
            # truncated bullets end with "..."
            assert len(line) <= 210


def test_synthesize_final_without_observations_gives_honest_empty_message():
    """When there's genuinely nothing accumulated, the summary must say so
    clearly (still non-empty) rather than fabricate findings."""
    from svetovid.agent.react import _synthesize_final

    summary = _synthesize_final({"messages": []}, "sys")
    assert summary
    assert "No findings" in summary or "no findings" in summary.lower(), (
        f"empty-state summary should say no findings, got: {summary!r}"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_graph_with_fake_chat(fake_chat, fake_tool, bus, config):
    """Build the real react graph but swap in a scripted fake chat model.

    ``build_react_graph`` calls ``build_chat(...)`` then ``chat.bind_tools``.
    We monkeypatch ``build_chat`` to return our scripted chat, whose
    ``bind_tools`` returns itself — so the graph's ``bound.ainvoke`` is the
    scripted one. The real agent_node / tool_node / should_continue logic runs
    unchanged, which is exactly what we want to test.
    """
    from svetovid.agent import react as react_mod
    from svetovid.agent.react import build_react_graph
    original_build_chat = react_mod.build_chat
    react_mod.build_chat = lambda *a, **kw: fake_chat
    try:
        return build_react_graph(
            tools=[fake_tool],
            system_prompt="You are a test agent.",
            config=config,
            investigation_id="inv_reliability",
            case_id="case_reliability",
            bus=bus,
            evidence_path="/tmp",
            output_dir="/tmp",
        )
    finally:
        react_mod.build_chat = original_build_chat


def _old_generic_stub() -> str:
    """The pre-fix generic message, so we can assert the summary differs."""
    return (
        "Investigation reached the iteration cap before the agent signaled "
        "completion. Review the accumulated findings in the report pane."
    )
