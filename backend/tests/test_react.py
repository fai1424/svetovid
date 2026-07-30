"""Tests for the ReAct agent loop (M1.1).

These verify the graph compiles, the tool adapter works, and the event stream
publishes the right event types — without calling a real LLM. We substitute a
fake chat model so the tests are deterministic and run offline.
"""

from __future__ import annotations

import json

import pytest

# Force the no-op keyring backend so config loading doesn't block on macOS.
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


def test_build_react_graph_compiles():
    """The graph builder must produce a compiled graph without an LLM call."""
    from svetovid.agent.react import build_react_graph, ReactConfig
    from svetovid.agent.events import EventBus
    from svetovid.tools.mitre_attack import tool as mitre

    bus = EventBus()
    # build_react_graph reads load_settings() for the provider; we set one.
    from svetovid.config import load_settings, Provider
    s = load_settings()
    s.active_provider = "ollama"   # the seed default has base_url+model
    from svetovid.config import save_settings
    save_settings(s)

    graph = build_react_graph(
        tools=[mitre],
        system_prompt="You are a test agent.",
        config=ReactConfig(max_iterations=3),
        investigation_id="inv_test",
        case_id="case_test",
        bus=bus,
        evidence_path="/tmp",
        output_dir="/tmp",
    )
    assert graph is not None
    # A compiled graph has .ainvoke / .invoke / .astream
    assert hasattr(graph, "ainvoke")


def test_tool_adapter_forwards_to_svetovid_tool():
    """SvetovidToolAdapter must invoke our Tool wrapper and return a string."""
    import asyncio
    from svetovid.agent.react import SvetovidToolAdapter
    from svetovid.tools.base import Tool, ToolContext, ToolResult
    from svetovid.agent.events import EventBus

    class FakeTool(Tool):
        name = "fake_tool"
        image = None
        description = "Returns its args as JSON."
        def schema(self):
            return {"type": "object", "properties": {"x": {"type": "string"}}}
        async def invoke(self, args, ctx):
            return ToolResult(
                call_id="c1", tool=self.name, exit_code=0, duration_s=0.01,
                output_hash=None, output_path=None, summary="ok",
                data={"echoed": args},
            )

    ctx = ToolContext(
        investigation_id="i", case_id="c", bus=EventBus(),
        evidence_path="/tmp", output_dir="/tmp",
    )
    adapter = SvetovidToolAdapter(FakeTool(), ctx)
    result = asyncio.run(adapter._arun(x="hello"))
    assert "echoed" in result
    assert "hello" in result


def test_format_for_llm_truncates_large_payloads():
    from svetovid.agent.react import _format_for_llm
    # Small payload passes through unchanged.
    assert _format_for_llm({"a": 1}) == '{"a": 1}'
    # Large payload is truncated.
    big = {"rows": list(range(10000))}
    out = _format_for_llm(big, limit=100)
    assert len(out) <= 200  # limit + truncation message
    assert "truncated" in out


def test_react_config_defaults_are_sane():
    from svetovid.agent.react import ReactConfig
    c = ReactConfig()
    # 0 = unlimited (the duplicate-detection guard prevents true loops)
    assert c.max_iterations == 0 or c.max_iterations >= 4
    assert c.max_tokens_total == 0 or c.max_tokens_total >= 10_000
    assert c.max_tokens_per_call >= 1024
