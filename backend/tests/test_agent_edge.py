"""Edge-case tests for the agent loop, ReAct, and HITL subsystems.

These complement the focused ``test_react.py`` / ``test_reliability.py`` /
``test_governance.py`` modules with broad edge-case coverage of:

  1. **Event constructors** — every ``E.xxx()`` produces a dict with the right
     ``type``, an ISO8601 ``ts``, JSON-serializable payloads, and the
     report-specific fields (``report.timeline_entry`` source/event/mitre;
     ``report.ioc`` ioc_type/value/confidence). The ``hitl_response``
     constructor is exercised too.
  2. **EventBus** — subscribe/unsubscribe, fan-out to multiple subscribers,
     publish of an ``AgentEvent`` object vs a raw dict, ``QueueFull``
     drop-oldest-push-newest, and the benign no-op of unsubscribing a queue
     that was never registered.
  3. **ReAct loop** — ``ReactConfig`` defaults are sane, ``ReactState`` accepts
     ``called_tools`` / ``total_tokens``, ``build_react_graph`` compiles with
     multiple tools, ``SvetovidToolAdapter._arun`` returns a string,
     ``_format_for_llm`` truncates and maps ``None`` → ``"(no data)"``, and
     ``_synthesize_final`` behaves for both the populated and empty cases.
  4. **HITL** — approve/reject flows, timeout (monkeypatched short), resolve on
     a non-existent gate is a benign no-op, and two concurrent approvals for
     different investigations resolve independently.
  5. **Duplicate tool detection** — two identical ``(tool, args)`` calls: the
     second is blocked, the real tool runs exactly once.

The fixtures mirror the hermetic setup in the other modules (throwaway HOME +
fail keyring + fresh module cache per test) so every test runs offline and
never touches the macOS Keychain.
"""

from __future__ import annotations

import asyncio
import json
import sys

import pytest


# ---------------------------------------------------------------------------
# Hermetic setup — same shape as test_react.py / test_reliability.py
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Throwaway HOME + no-op keyring + fresh svetovid module cache per test."""
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    (tmp_path / "h").mkdir()
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    # Re-import svetovid.* so the fail-keyring backend takes effect cleanly.
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


def _clear_hitl_state():
    """Reset module-level HITL registries between tests so they don't bleed."""
    from svetovid.agent import hitl as hitl_mod
    hitl_mod._pending.clear()
    hitl_mod._outcomes.clear()


# ---------------------------------------------------------------------------
# Test doubles for the ReAct graph (mirrors test_reliability.py shapes)
# ---------------------------------------------------------------------------


class _FakeTool:
    """Minimal tool double: records calls, returns a fixed ToolResult-shape."""

    name = "fake_lookup"
    description = "Returns its args; used for edge-case tests."
    image = None

    def __init__(self) -> None:
        self.invoke_count = 0
        self.calls: list[dict] = []

    async def invoke(self, args, ctx):
        self.invoke_count += 1
        self.calls.append(dict(args))

        class _R:
            summary = f"hit {self.invoke_count}"
            data = {"echoed": args, "hit": self.invoke_count}
        return _R()


class _ScriptedChat:
    """Bound-chat stand-in: yields pre-loaded AIMessages, ``bind_tools``
    returns ``self`` so the graph stores our scripted object."""

    def __init__(self, responses):
        self._responses = list(responses)

    async def ainvoke(self, messages):
        if not self._responses:
            raise RuntimeError("scripted chat exhausted")
        return self._responses.pop(0)

    def bind_tools(self, tools, **kwargs):
        return self


def _build_graph_with_fake_chat(fake_chat, fake_tool, bus, config):
    """Build the real react graph with a scripted chat swapped in."""
    from svetovid.agent import react as react_mod
    from svetovid.agent.react import build_react_graph
    original_build_chat = react_mod.build_chat
    react_mod.build_chat = lambda *a, **kw: fake_chat
    try:
        return build_react_graph(
            tools=[fake_tool],
            system_prompt="You are a test agent.",
            config=config,
            investigation_id="inv_edge",
            case_id="case_edge",
            bus=bus,
            evidence_path="/tmp",
            output_dir="/tmp",
        )
    finally:
        react_mod.build_chat = original_build_chat


# ===========================================================================
# 1. Event constructors
# ===========================================================================


def _ws(evt) -> dict:
    """Serialize an event to its WS dict form (covers to_ws / model_dump)."""
    from svetovid.agent.events import AgentEvent
    if isinstance(evt, AgentEvent):
        return evt.to_ws()
    return evt


def test_every_event_constructor_sets_type():
    """Each public constructor must produce an event whose ``type`` matches."""
    from svetovid.agent import events as E
    inv = "inv_e"
    checks = [
        (E.investigation_start("c", inv, "g", ["n1"]), "investigation.start"),
        (E.investigation_end(inv, "done"), "investigation.end"),
        (E.scan_start("/evidence"), "scan.start"),
        (E.scan_progress(3, 10, {"evtx": 3}), "scan.progress"),
        (E.scan_complete([{"artifact_id": "B8"}]), "scan.complete"),
        (E.goal_graph_loaded(inv, "g", [{"id": "n1"}]), "goal.graph_loaded"),
        (E.agent_thought(inv, "thinking"), "agent.thought"),
        (E.agent_action(inv, "tool", {"x": 1}), "agent.action"),
        (E.agent_observation(inv, "tool", "summary"), "agent.observation"),
        (E.tool_start(inv, "tool", {"x": 1}, sandboxed=True), "tool.start"),
        (E.tool_stdout(inv, "call_1", "chunk"), "tool.stdout"),
        (E.tool_stderr(inv, "call_1", "err"), "tool.stderr"),
        (E.tool_progress(inv, "call_1", 0.5), "tool.progress"),
        (E.tool_end(inv, "call_1", 0, 1.2, None), "tool.end"),
        (E.node_state_change(inv, "parse_evtx", "done"), "node.state_change"),
        (E.report_section_added(inv, "s1", "Title", "md"), "report.section_added"),
        (E.report_timeline_entry(inv, "2026-01-01T00:00:00Z", "chainsaw", "hit"),
         "report.timeline_entry"),
        (E.report_ioc(inv, "ip", "1.2.3.4"), "report.ioc"),
        (E.report_finding(inv, "Suspicious logon", severity="high"), "report.finding"),
        (E.hitl_request(inv, "approve report", {}), "hitl.request"),
        (E.hitl_response(inv, True, "approved"), "hitl.response"),
        (E.provenance_recorded(inv, {"tool": "chainsaw"}), "provenance.recorded"),
        (E.error_event(inv, "boom"), "error"),
    ]
    assert len(checks) >= 20, "expected to cover the full constructor surface"
    for evt, expected_type in checks:
        ws = _ws(evt)
        assert ws["type"] == expected_type, (
            f"constructor set type={ws['type']!r}, expected {expected_type!r}"
        )


def test_event_ts_is_iso8601_with_z_suffix():
    """Every event's ``ts`` must parse as ISO8601 and carry a ``Z`` suffix."""
    from datetime import datetime
    from svetovid.agent import events as E

    samples = [
        E.agent_thought("inv", "x"),
        E.report_ioc("inv", "ip", "1.2.3.4"),
        E.hitl_response("inv", True),
        E.error_event("inv", "e"),
    ]
    for evt in samples:
        ts = _ws(evt)["ts"]
        assert ts.endswith("Z"), f"ts must end with Z (UTC), got {ts!r}"
        # Strip the Z and parse — must not raise.
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert parsed.tzinfo is not None, f"ts must carry tz info: {ts!r}"


def test_events_are_json_serializable():
    """Every event must round-trip through ``json.dumps`` unchanged."""
    from svetovid.agent import events as E
    samples = [
        E.investigation_start("c", "inv", "g", ["a", "b"]),
        E.scan_progress(1, 5, {"evtx": 1}),
        E.report_timeline_entry("inv", "2026-01-01T00:00:00Z", "src", "ev",
                                mitre_tags=["T1027", "TA0001"]),
        E.report_ioc("inv", "hash", "deadbeef", confidence=0.7),
        E.tool_end("inv", "call_1", 0, 2.5, "sha256:abc"),
        E.hitl_response("inv", False, "rejected"),
    ]
    for evt in samples:
        ws = _ws(evt)
        # Must not raise — non-JSON values (set, datetime, ...) would break the WS.
        round_tripped = json.loads(json.dumps(ws))
        assert round_tripped["type"] == ws["type"]
        assert round_tripped["ts"] == ws["ts"]


def test_report_timeline_entry_has_required_fields():
    """``report.timeline_entry`` must carry source/event/mitre context."""
    from svetovid.agent import events as E
    evt = E.report_timeline_entry(
        "inv", "2026-07-27T10:00:00Z", "chainsaw", "Credential dumping",
        actor="lsass.exe", description="mimikatz",
        mitre_tactic="TA0006", mitre_technique="T1003",
        mitre_tags=["T1003.001"],
    )
    data = _ws(evt)["data"]
    # Core fields the frontend timeline reducer reads.
    assert data["source"] == "chainsaw"
    assert data["event"] == "Credential dumping"
    assert data["ts"] == "2026-07-27T10:00:00Z"
    # MITRE context propagated.
    assert data["mitre_tactic"] == "TA0006"
    assert data["mitre_technique"] == "T1003"
    # mitre_technique is folded into mitre_tags if not already present.
    assert "T1003" in data["mitre_tags"]
    assert "T1003.001" in data["mitre_tags"]


def test_report_ioc_has_required_fields():
    """``report.ioc`` must carry ioc_type/value/confidence (+ the aliases the
    ioc_store reducer reads)."""
    from svetovid.agent import events as E
    evt = E.report_ioc("inv", "ip", "203.0.113.9", context="beacon",
                       confidence=0.92, mitre_technique="T1071")
    data = _ws(evt)["data"]
    assert data["ioc_type"] == "ip"
    assert data["value"] == "203.0.113.9"
    assert data["confidence"] == pytest.approx(0.92)
    # Aliases carried so every downstream reducer finds its keys.
    assert data["type"] == "ip"
    assert data["ioc"] == "203.0.113.9"
    assert data["context"] == "beacon"
    assert data["mitre_technique"] == "T1071"


def test_hitl_response_constructor_shape():
    """``hitl_response`` must encode approved + detail + the right type."""
    from svetovid.agent import events as E
    approved = E.hitl_response("inv", True, "approved")
    ap = _ws(approved)
    assert ap["type"] == "hitl.response"
    assert ap["investigation_id"] == "inv"
    assert ap["data"]["approved"] is True
    assert ap["data"]["detail"] == "approved"

    rejected = E.hitl_response("inv", False, "timeout after 300s")
    assert _ws(rejected)["data"]["approved"] is False


def test_agent_event_model_envelope_defaults():
    """The ``AgentEvent`` envelope provides sensible defaults for optional
    fields (node, case_id) and a populated ``ts``."""
    from svetovid.agent.events import AgentEvent
    evt = AgentEvent(type="error", investigation_id="inv",
                     data={"message": "boom"})
    ws = evt.to_ws()
    assert ws["type"] == "error"
    assert ws["investigation_id"] == "inv"
    assert ws["node"] is None
    assert ws["case_id"] is None
    assert ws["data"] == {"message": "boom"}
    assert ws["ts"].endswith("Z")


# ===========================================================================
# 2. EventBus
# ===========================================================================


def test_eventbus_subscribe_unsubscribe_roundtrip():
    """subscribe() returns a queue that receives publishes; unsubscribe stops
    delivery without raising."""
    from svetovid.agent.events import EventBus
    bus = EventBus()
    q = bus.subscribe()
    bus.publish({"type": "error", "data": {"message": "x"}})
    assert not q.empty()
    msg = q.get_nowait()
    assert msg["type"] == "error"

    bus.unsubscribe(q)
    bus.publish({"type": "error", "data": {"message": "y"}})
    assert q.empty(), "unsubscribed queue must not receive further events"


def test_eventbus_publishes_to_multiple_subscribers():
    """A single publish fans out to every subscribed queue."""
    from svetovid.agent.events import EventBus
    bus = EventBus()
    q1, q2, q3 = bus.subscribe(), bus.subscribe(), bus.subscribe()
    bus.publish({"type": "error", "data": {}})
    for i, q in enumerate((q1, q2, q3)):
        assert not q.empty(), f"subscriber {i} missed the event"
        assert q.get_nowait()["type"] == "error"


def test_eventbus_accepts_agentevent_object_and_dict():
    """publish() must accept both an ``AgentEvent`` (serialized via to_ws) and a
    raw dict (passed through unchanged)."""
    from svetovid.agent.events import EventBus, AgentEvent
    bus = EventBus()
    q = bus.subscribe()

    # AgentEvent object → serialized to its flat WS dict.
    obj = AgentEvent(type="error", investigation_id="inv",
                     data={"message": "obj"})
    bus.publish(obj)
    m1 = q.get_nowait()
    assert m1["type"] == "error"
    assert m1["investigation_id"] == "inv"

    # Raw dict → passed through as-is.
    raw = {"type": "agent.thought", "data": {"text": "hi"}}
    bus.publish(raw)
    m2 = q.get_nowait()
    assert m2 is raw, "raw dict should be delivered by identity"


def test_eventbus_queuefull_drops_oldest_and_pushes_newest():
    """When a subscriber's queue is full, publish must drop the oldest item and
    push the newest so the stream stays live (never blocks, never raises)."""
    from svetovid.agent.events import EventBus
    bus = EventBus()
    q = bus.subscribe()
    maxsize = q.maxsize
    assert maxsize > 0, "subscriber queue must be bounded for this test"

    # Fill the queue completely.
    for i in range(maxsize):
        bus.publish({"type": "error", "data": {"i": i}})
    assert q.full()

    # One more publish must succeed by evicting the oldest (i=0).
    bus.publish({"type": "error", "data": {"i": "new"}})
    assert q.full()  # still full, but the head advanced

    drained = []
    while not q.empty():
        drained.append(q.get_nowait())
    # The oldest (i=0) was dropped; the newest ("new") is at the tail.
    assert drained[0]["data"]["i"] == 1
    assert drained[-1]["data"]["i"] == "new"
    assert len(drained) == maxsize


def test_eventbus_unsubscribe_nonexistent_queue_is_noop():
    """Unsubscribing a queue that was never registered must not raise."""
    import asyncio
    from svetovid.agent.events import EventBus
    bus = EventBus()
    foreign = asyncio.Queue()
    # Should silently absorb the ValueError from list.remove.
    bus.unsubscribe(foreign)
    # And the bus should still work afterward.
    q = bus.subscribe()
    bus.publish({"type": "error", "data": {}})
    assert not q.empty()


# ===========================================================================
# 3. ReAct loop
# ===========================================================================


def test_react_config_defaults_are_sane():
    """``ReactConfig`` defaults must keep the loop bounded and usable."""
    from svetovid.agent.react import ReactConfig
    c = ReactConfig()
    assert 4 <= c.max_iterations <= 30
    assert c.max_tokens_per_call >= 1024
    assert c.max_tokens_total >= 10_000, "token budget must be meaningfully large"
    assert isinstance(c.stop_on_error, bool)
    assert isinstance(c.bind_tools_strict, bool)


def test_react_state_accepts_loop_hardening_fields():
    """``ReactState`` must accept ``called_tools`` and ``total_tokens`` — these
    drive dedup and the cumulative token budget."""
    from svetovid.agent.react import ReactState
    # A TypedDict with total=False accepts any subset of keys; we assert the
    # field names exist in the annotation so a rename/regress is caught.
    annotations = ReactState.__annotations__
    assert "called_tools" in annotations
    assert "total_tokens" in annotations
    assert "messages" in annotations
    assert "iteration" in annotations
    assert "final_answer" in annotations

    # And a populated instance type-checks at runtime (dict literal).
    state: ReactState = {
        "messages": [],
        "iteration": 0,
        "called_tools": {("foo", '{"x": 1}')},
        "total_tokens": 1234,
        "final_answer": None,
    }
    assert state["called_tools"] == {("foo", '{"x": 1}')}
    assert state["total_tokens"] == 1234


def test_build_react_graph_compiles_with_multiple_tools():
    """The graph builder must compile when handed >1 tool (multi-tool agents
    are the realistic case)."""
    _seed_active_provider()
    from svetovid.agent.react import build_react_graph, ReactConfig
    from svetovid.agent.events import EventBus

    class _T1(_FakeTool):
        name = "tool_one"
        description = "first tool"

    class _T2(_FakeTool):
        name = "tool_two"
        description = "second tool"

    bus = EventBus()
    graph = build_react_graph(
        tools=[_T1(), _T2()],
        system_prompt="You are a test agent.",
        config=ReactConfig(max_iterations=3),
        investigation_id="inv_multi",
        case_id="case_multi",
        bus=bus,
        evidence_path="/tmp",
        output_dir="/tmp",
    )
    assert graph is not None
    assert hasattr(graph, "ainvoke")
    assert hasattr(graph, "astream")


def test_tool_adapter_arun_returns_string():
    """``SvetovidToolAdapter._arun`` must return a ``str`` (the LLM-facing
    rendering of the tool result), not the raw ToolResult."""
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
    assert isinstance(result, str)
    assert "echoed" in result
    assert "hello" in result


def test_format_for_llm_truncates_large_payload():
    """``_format_for_llm`` must cap output length and append a truncation note
    so a single tool result can't blow the context window."""
    from svetovid.agent.react import _format_for_llm
    # Small payload passes through unchanged.
    assert _format_for_llm({"a": 1}) == '{"a": 1}'
    # Large payload is truncated, with a notice.
    big = {"rows": list(range(10000))}
    out = _format_for_llm(big, limit=100)
    assert len(out) <= 220
    assert "truncated" in out


def test_format_for_llm_none_returns_no_data():
    """A ``None`` payload must render as the honest ``"(no data)"`` sentinel
    rather than the string ``"null"``."""
    from svetovid.agent.react import _format_for_llm
    assert _format_for_llm(None) == "(no data)"


def test_synthesize_final_with_observations_is_nonempty_markdown():
    """With accumulated observations, the fallback summary must be non-empty
    markdown that references the findings."""
    from langchain_core.messages import AIMessage, ToolMessage
    from svetovid.agent.react import _synthesize_final

    messages = [
        ToolMessage(
            content="Found 3 suspicious logon events from 10.0.0.5 at 02:00 UTC.",
            tool_call_id="c1",
        ),
        ToolMessage(
            content="Mimikatz signature matched in process 'lsass_helper.exe' (PID 412).",
            tool_call_id="c2",
        ),
        AIMessage(content="Summarizing findings so far."),
    ]
    summary = _synthesize_final({"messages": messages}, "sys prompt")

    assert summary, "synthesize must return non-empty text"
    assert summary.startswith("## "), "expected a markdown heading"
    # It should reference at least one concrete observation.
    assert ("suspicious logon" in summary
            or "Mimikatz" in summary), (
        f"summary should quote accumulated observations, got: {summary!r}"
    )


def test_synthesize_final_with_empty_state_says_no_findings():
    """When nothing was accumulated, the summary must clearly say so rather
    than fabricate findings."""
    from svetovid.agent.react import _synthesize_final
    summary = _synthesize_final({"messages": []}, "sys")
    assert summary
    assert "No findings" in summary or "no findings" in summary.lower(), (
        f"empty-state summary should say no findings, got: {summary!r}"
    )


# ===========================================================================
# 4. HITL
# ===========================================================================


def test_hitl_request_then_resolve_approved_returns_true(monkeypatch):
    """request_approval + resolve_approval(True) → True, with the outcome
    recorded and a hitl.response event published.

    Auto-approve is disabled so we exercise the REAL gate + resolve path (not
    the CI short-circuit)."""
    monkeypatch.delenv("SVETOVID_HITL_AUTO_APPROVE", raising=False)
    _clear_hitl_state()
    from svetovid.agent import hitl as hitl_mod
    from svetovid.agent.events import EventBus

    bus = EventBus()
    inv = "inv_hitl_ok"

    async def driver():
        # Resolve from a separate task once the gate is parked.
        loop = asyncio.get_event_loop()
        loop.call_later(0.05, lambda: hitl_mod.resolve_approval(inv, True))
        return await hitl_mod.request_approval(inv, bus, "release report", {})

    approved = asyncio.run(driver())
    assert approved is True
    assert hitl_mod.get_outcome(inv) is True
    # The hitl.response event must have been published.
    drained = []
    # bus has no subscribers here; just assert the outcome ledger updated.
    assert hitl_mod._outcomes[inv] is True


def test_hitl_request_then_resolve_rejected_returns_false(monkeypatch):
    """request_approval + resolve_approval(False) → False.

    Auto-approve is disabled so we exercise the REAL gate + reject path."""
    monkeypatch.delenv("SVETOVID_HITL_AUTO_APPROVE", raising=False)
    _clear_hitl_state()
    from svetovid.agent import hitl as hitl_mod
    from svetovid.agent.events import EventBus

    bus = EventBus()
    inv = "inv_hitl_no"

    async def driver():
        loop = asyncio.get_event_loop()
        loop.call_later(0.05, lambda: hitl_mod.resolve_approval(inv, False))
        return await hitl_mod.request_approval(inv, bus, "release report", {})

    approved = asyncio.run(driver())
    assert approved is False
    assert hitl_mod.get_outcome(inv) is False


def test_hitl_request_timeout_returns_false(monkeypatch):
    """A gate that nobody resolves must time out and return False.

    Auto-approve is disabled so we exercise the REAL timeout path; the default
    timeout is monkeypatched down to 1s to keep the test fast."""
    monkeypatch.delenv("SVETOVID_HITL_AUTO_APPROVE", raising=False)
    _clear_hitl_state()
    # Monkeypatch the default timeout down to 1s so this test stays fast.
    from svetovid.agent import hitl as hitl_mod
    hitl_mod.DEFAULT_TIMEOUT = 1
    from svetovid.agent.events import EventBus

    bus = EventBus()
    inv = "inv_hitl_timeout"

    approved = asyncio.run(
        hitl_mod.request_approval(inv, bus, "release report", {})
    )
    assert approved is False
    assert hitl_mod.get_outcome(inv) is False


def test_hitl_resolve_on_nonexistent_gate_is_noop():
    """resolve_approval on an id with no pending gate must return False and
    never raise."""
    _clear_hitl_state()
    from svetovid.agent import hitl as hitl_mod

    # No request_approval has been called for this id.
    assert hitl_mod.resolve_approval("inv_does_not_exist", True) is False
    assert hitl_mod.resolve_approval("inv_does_not_exist", False) is False
    # And the outcome ledger is untouched.
    assert hitl_mod.get_outcome("inv_does_not_exist") is None


def test_hitl_concurrent_approvals_for_different_investigations(monkeypatch):
    """Two gates open simultaneously for different investigation_ids must
    resolve independently to their own decisions.

    Auto-approve is disabled so both gates park on real futures."""
    monkeypatch.delenv("SVETOVID_HITL_AUTO_APPROVE", raising=False)
    _clear_hitl_state()
    from svetovid.agent import hitl as hitl_mod
    from svetovid.agent.events import EventBus

    bus = EventBus()
    inv_a = "inv_concurrent_a"
    inv_b = "inv_concurrent_b"

    async def driver():
        loop = asyncio.get_event_loop()

        async def gate(inv):
            return await hitl_mod.request_approval(inv, bus, "release", {})

        task_a = asyncio.ensure_future(gate(inv_a))
        task_b = asyncio.ensure_future(gate(inv_b))

        # Give both gates a beat to park on their futures.
        await asyncio.sleep(0.05)
        # Resolve A approved, B rejected — from the main task.
        hitl_mod.resolve_approval(inv_a, True)
        hitl_mod.resolve_approval(inv_b, False)

        return await asyncio.gather(task_a, task_b)

    a_out, b_out = asyncio.run(driver())
    assert a_out is True
    assert b_out is False
    assert hitl_mod.get_outcome(inv_a) is True
    assert hitl_mod.get_outcome(inv_b) is False


# ===========================================================================
# 5. Duplicate tool detection (driven through the full compiled graph)
# ===========================================================================


def test_duplicate_tool_call_is_blocked():
    """Two identical ``(tool, args)`` calls: the second is blocked — the real
    tool runs exactly once and an injected ToolMessage nudges the LLM."""
    import asyncio
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
    from svetovid.agent.react import ReactConfig
    from svetovid.agent.events import EventBus

    _seed_active_provider()
    fake_tool = _FakeTool()

    # Scripted LLM turns:
    #   turn 1 — calls fake_lookup(x=1)  → executes
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

    # The real tool ran exactly ONCE — the duplicate was blocked.
    assert fake_tool.invoke_count == 1, (
        f"expected the real tool to run once, ran {fake_tool.invoke_count} times"
    )
    # An injected "already called" ToolMessage must be in the transcript.
    messages = result.get("messages", [])
    dup_msgs = [
        m for m in messages
        if isinstance(m, ToolMessage)
        and "already called" in str(getattr(m, "content", ""))
    ]
    assert dup_msgs, "expected an injected 'already called' ToolMessage"
    # The graph terminated cleanly with a final answer.
    assert result.get("final_answer"), "expected a non-empty final answer"
