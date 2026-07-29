"""Edge-case tests for the Svetovid tool wrappers.

These tests exercise the *contract* every tool wrapper in
``svetovid/tools/`` must satisfy, plus the per-tool whitelist / parsing /
routing logic that lives inside each ``invoke`` — without ever spinning up a
Docker container.

Strategy:
  - Schema & instantiation checks run against the module-level ``tool``
    instance of every wrapper (no I/O).
  - ``invoke`` paths that would call Docker mock
    ``svetovid.sandbox.docker_runner.run_in_sandbox`` so no container runs.
  - API tools (threat_intel, mitre_attack) are exercised with stubbed HTTP
    helpers / a fake STIX bundle.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock

import pytest

from svetovid.tools import (
    bulk_extractor,
    chainsaw,
    eztools,
    hayabusa,
    mitre_attack,
    sleuthkit,
    threat_intel,
    volatility,
    yara,
)
from svetovid.tools.base import Tool, ToolContext, ToolResult
from svetovid.tools.volatility import ALLOWED_PLUGINS
from svetovid.tools.eztools import EZ_TOOLS
from svetovid.tools.sleuthkit import TSK_SUBTOOLS
from svetovid.tools.mitre_attack import EVENT_HINTS, _load_bundle
from svetovid.sandbox.docker_runner import RunResult, run_in_sandbox  # noqa: F401

# Primitive JSON-schema types a *flat* tool schema is allowed to use.
# Nested objects are explicitly forbidden (LLM-friendly contract).
_PRIMITIVE_TYPES = {"string", "number", "integer", "boolean", "array"}

# (module, instance) for every wrapper we ship.
ALL_TOOL_INSTANCES = [
    chainsaw.tool,
    hayabusa.tool,
    volatility.tool,
    yara.tool,
    eztools.tool,
    sleuthkit.tool,
    bulk_extractor.tool,
    threat_intel.tool,
    mitre_attack.tool,
]


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Keep the case DB / keyring hermetic: redirect HOME + disable keyring."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    # The case DB is a module-level singleton; reset it so each test gets a
    # fresh connection pointed at *this* test's HOME (via APP_DIR).
    import svetovid.store as _store
    monkeypatch.setattr(_store, "_db", None)
    # The mitre bundle is lru_cached — clear it so env overrides take effect.
    _load_bundle.cache_clear()
    yield
    _load_bundle.cache_clear()


class _FakeBus:
    """Swallow every publish — we assert on ToolResult, not events."""

    def publish(self, *args, **kwargs):  # noqa: D401
        return None


def _ctx(tmp_path) -> ToolContext:
    # The wrappers write parsed output / body files into output_dir, so it
    # must actually exist on disk (not just be a path string).
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    (tmp_path / "evidence").mkdir(parents=True, exist_ok=True)
    return ToolContext(
        investigation_id="inv_edge",
        case_id="case_edge",
        bus=_FakeBus(),
        evidence_path=str(tmp_path / "evidence"),
        output_dir=str(out),
    )


@pytest.fixture
def patched_sandbox(monkeypatch, tmp_path):
    """Replace ``run_in_sandbox`` with a recorder that never runs Docker.

    Returns the list of kwarg dicts each call received, so tests can assert on
    the exact ``command`` the wrapper built.
    """
    import svetovid.sandbox.docker_runner as runner

    calls: list[dict[str, Any]] = []

    async def _fake_run(**kwargs):
        calls.append(kwargs)
        return RunResult(
            exit_code=0,
            duration_s=0.01,
            container_id="fake-container",
            output_dir=kwargs.get("output_dir", str(tmp_path)),
        )

    monkeypatch.setattr(runner, "run_in_sandbox", _fake_run)
    return calls


# ---------------------------------------------------------------------------
# 1. Schema validation — every tool exposes a flat object schema
# ---------------------------------------------------------------------------

def _assert_flat_object_schema(schema: dict[str, Any]) -> None:
    assert schema["type"] == "object", f"schema type must be object, got {schema.get('type')!r}"
    props = schema.get("properties")
    assert isinstance(props, dict) and props, "schema must declare properties"
    for name, prop in props.items():
        assert isinstance(prop, dict), f"property {name!r} is not a dict"
        ptype = prop.get("type")
        assert ptype in _PRIMITIVE_TYPES, (
            f"property {name!r} has non-primitive type {ptype!r}; nested objects are forbidden"
        )
        # Arrays are allowed but their items must also be primitive.
        if ptype == "array":
            items = prop.get("items", {})
            itype = items.get("type") if isinstance(items, dict) else None
            assert itype in _PRIMITIVE_TYPES, (
                f"array property {name!r} items must be primitive, got {itype!r}"
            )
    if "required" in schema:
        assert isinstance(schema["required"], list), "required must be a list"
        assert all(isinstance(r, str) for r in schema["required"]), "required entries must be str"
        assert set(schema["required"]).issubset(props.keys()), "required must reference real props"


@pytest.mark.parametrize("tool", ALL_TOOL_INSTANCES, ids=lambda t: t.name)
def test_schema_is_flat_object(tool):
    _assert_flat_object_schema(tool.schema())


@pytest.mark.parametrize("tool", ALL_TOOL_INSTANCES, ids=lambda t: t.name)
def test_schema_enum_members_match_whitelists(tool):
    """Where a property is an enum, its members must equal the canonical whitelist."""
    schema = tool.schema()
    props = schema["properties"]

    if tool.name == "volatility":
        assert set(props["plugin"]["enum"]) == set(ALLOWED_PLUGINS)
    elif tool.name == "eztools":
        assert set(props["tool"]["enum"]) == set(EZ_TOOLS)
    elif tool.name == "tsk":
        assert set(props["subtool"]["enum"]) == set(TSK_SUBTOOLS)
    elif tool.name == "threat_intel_lookup":
        assert set(props["indicator_type"]["enum"]) == {"hash", "ip", "domain", "url"}
        assert set(props["sources"].get("items", {}).get("type", ""))  # array of strings
        assert props["sources"]["items"]["type"] == "string"
    elif tool.name == "mitre_attack":
        assert set(props["op"]["enum"]) == {"lookup", "reverse_event"}


# ---------------------------------------------------------------------------
# 2. Tool instantiation — name / description / schema() / image contract
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tool", ALL_TOOL_INSTANCES, ids=lambda t: t.name)
def test_instance_satisfies_tool_contract(tool):
    assert isinstance(tool, Tool)
    assert isinstance(tool.name, str) and tool.name
    assert isinstance(tool.description, str) and tool.description
    assert callable(tool.schema)
    assert isinstance(tool.schema(), dict)
    # image is either a docker reference string or None for host tools.
    assert tool.image is None or isinstance(tool.image, str)


def test_host_tools_have_no_image():
    """threat_intel and mitre_attack are API/host tools — image must be None."""
    assert threat_intel.tool.image is None
    assert mitre_attack.tool.image is None


def test_docker_tools_declare_an_image():
    """The sandboxed wrappers must reference a real svetovid/* image."""
    for t in (chainsaw.tool, hayabusa.tool, volatility.tool, yara.tool,
              eztools.tool, sleuthkit.tool, bulk_extractor.tool):
        assert isinstance(t.image, str) and t.image.startswith("svetovid/")


# ---------------------------------------------------------------------------
# 3. Volatility whitelist + plugin routing
# ---------------------------------------------------------------------------

def test_volatility_whitelist_has_seventeen_plugins():
    expected = {
        "pslist", "psscan", "cmdline", "dlllist", "handles", "malfind",
        "netscan", "modules", "modscan", "callbacks", "svcscan", "filescan",
        "envars", "hashdump", "lsadump", "hivelist", "printkey",
    }
    assert set(ALLOWED_PLUGINS) == expected
    assert len(ALLOWED_PLUGINS) == 17


def test_volatility_unknown_plugin_returns_exit_2(tmp_path):
    res = asyncio.run(volatility.tool.invoke(
        {"plugin": "definitely_not_real"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 2
    assert "allowed" in res.summary.lower()
    # No docker call should have been attempted.
    assert res.output_path is None


def test_volatility_valid_plugin_fails_gracefully_without_docker(monkeypatch, tmp_path):
    """Valid plugin but Docker unavailable + host_fallback=False → graceful -1."""
    import svetovid.sandbox.docker_runner as runner

    async def _boom(**kwargs):
        raise RuntimeError("docker daemon not available")

    monkeypatch.setattr(runner, "run_in_sandbox", _boom)
    res = asyncio.run(volatility.tool.invoke(
        {"plugin": "pslist"}, _ctx(tmp_path),
    ))
    assert res.exit_code == -1
    assert "failed" in res.summary.lower()


def test_volatility_valid_plugin_uses_host_fallback_false(patched_sandbox, tmp_path):
    """A valid plugin routes to run_in_sandbox with host_fallback=False."""
    asyncio.run(volatility.tool.invoke({"plugin": "malfind"}, _ctx(tmp_path)))
    assert patched_sandbox, "run_in_sandbox was never called"
    assert patched_sandbox[0]["host_fallback"] is False
    # The command must include vol, the plugin, and the JSON output flags.
    cmd = patched_sandbox[0]["command"]
    assert cmd[0] == "vol" and "malfind" in cmd
    assert "--output-format" in cmd and "jsonl" in cmd


# ---------------------------------------------------------------------------
# 4. EZ Tools whitelist
# ---------------------------------------------------------------------------

def test_eztools_whitelist_has_nine_tools():
    expected = {
        "EvtxECmd", "MFTECmd", "PECmd", "AmcacheParser", "RECmd",
        "JLECmd", "LECmd", "RBCmd", "SrumECmd",
    }
    assert set(EZ_TOOLS) == expected
    assert len(EZ_TOOLS) == 9


def test_eztools_unknown_tool_returns_exit_2(tmp_path):
    res = asyncio.run(eztools.tool.invoke(
        {"tool": "NopeCmd", "evidence_subpath": "x"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 2
    assert "unknown" in res.summary.lower()


def test_eztools_known_tool_builds_dotnet_command(patched_sandbox, tmp_path):
    asyncio.run(eztools.tool.invoke(
        {"tool": "PECmd", "evidence_subpath": "prefetch/foo.pf"}, _ctx(tmp_path),
    ))
    cmd = patched_sandbox[0]["command"]
    assert cmd[0] == "dotnet"
    assert cmd[1] == "/opt/eztools/PECmd/PECmd.dll"
    assert "-f" in cmd and "/evidence/prefetch/foo.pf" in cmd


# ---------------------------------------------------------------------------
# 5. TSK subtools + command construction
# ---------------------------------------------------------------------------

def test_tsk_whitelist_has_six_subtools():
    expected = {"fls", "icat", "mmls", "fsstat", "ils", "mactime"}
    assert set(TSK_SUBTOOLS) == expected
    assert len(TSK_SUBTOOLS) == 6


def test_tsk_unknown_subtool_returns_exit_2(tmp_path):
    res = asyncio.run(sleuthkit.tool.invoke(
        {"subtool": "blkls", "evidence_subpath": "img.dd"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 2
    assert "unknown" in res.summary.lower()


def test_tsk_fls_recursive_with_body_file(patched_sandbox, tmp_path):
    asyncio.run(sleuthkit.tool.invoke(
        {"subtool": "fls", "evidence_subpath": "disk.dd"}, _ctx(tmp_path),
    ))
    cmd = patched_sandbox[0]["command"]
    assert cmd[0] == "fls"
    assert "-r" in cmd              # recursive
    assert "-m" in cmd and "/" in cmd  # body-file mount prefix
    assert "/evidence/disk.dd" in cmd


def test_tsk_mactime_takes_body_file_not_image(patched_sandbox, tmp_path):
    asyncio.run(sleuthkit.tool.invoke(
        {"subtool": "mactime", "evidence_subpath": "disk.dd",
         "extra_args": "/work/body.txt"},
        _ctx(tmp_path),
    ))
    cmd = patched_sandbox[0]["command"]
    assert cmd == ["mactime", "-b", "/work/body.txt"]
    # Crucially the image path must NOT be passed to mactime.
    assert "/evidence/disk.dd" not in cmd


# ---------------------------------------------------------------------------
# 6. Chainsaw Sigma level parsing
# ---------------------------------------------------------------------------

def _chainsaw_level_arg(calls) -> str:
    cmd = calls[0]["command"]
    return cmd[cmd.index("--level") + 1]


def test_chainsaw_critical_level_is_only_critical(patched_sandbox, tmp_path):
    asyncio.run(chainsaw.tool.invoke({"min_level": "critical"}, _ctx(tmp_path)))
    assert _chainsaw_level_arg(patched_sandbox) == "critical"


def test_chainsaw_medium_level_includes_above(patched_sandbox, tmp_path):
    asyncio.run(chainsaw.tool.invoke({"min_level": "medium"}, _ctx(tmp_path)))
    assert _chainsaw_level_arg(patched_sandbox) == "critical,high,medium"


def test_chainsaw_unknown_level_defaults_to_medium(patched_sandbox, tmp_path):
    """invoke() takes the level straight from args (schema isn't enforced here),
    so an unknown value falls back to the medium index."""
    asyncio.run(chainsaw.tool.invoke({"min_level": "totally-bogus"}, _ctx(tmp_path)))
    assert _chainsaw_level_arg(patched_sandbox) == "critical,high,medium"


# ---------------------------------------------------------------------------
# 7. YARA rules_set → rules path routing
# ---------------------------------------------------------------------------

def test_yara_security_rules_path(patched_sandbox, tmp_path):
    asyncio.run(yara.tool.invoke({"rules_set": "security"}, _ctx(tmp_path)))
    cmd = patched_sandbox[0]["command"]
    assert "/opt/yara-rules/index.yar" in cmd


def test_yara_signature_base_rules_path(patched_sandbox, tmp_path):
    asyncio.run(yara.tool.invoke({"rules_set": "signature-base"}, _ctx(tmp_path)))
    cmd = patched_sandbox[0]["command"]
    assert "/opt/signature-base/yara" in cmd


def test_yara_custom_rules_are_written_to_work(patched_sandbox, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    asyncio.run(yara.tool.invoke(
        {"rules_set": "custom",
         "custom_rules": 'rule Demo { strings: $a = "x" condition: $a }'},
        ToolContext(investigation_id="inv", case_id="c", bus=_FakeBus(),
                    evidence_path=str(tmp_path / "e"), output_dir=str(out)),
    ))
    cmd = patched_sandbox[0]["command"]
    assert "/work/custom_rules.yar" in cmd
    # The wrapper writes the inline rules to output_dir/custom_rules.yar.
    assert (out / "custom_rules.yar").read_text().startswith("rule Demo")


# ---------------------------------------------------------------------------
# 8. Threat-intel routing
# ---------------------------------------------------------------------------

def _armed_threat_intel() -> threat_intel.ThreatIntelTool:
    ti = threat_intel.ThreatIntelTool()
    ti._lookup_virustotal = AsyncMock(return_value={"status": "skipped", "reason": "no key"})
    ti._lookup_threatfox = AsyncMock(
        return_value={"status": "ok", "result": "malicious", "hits": 1})
    ti._lookup_malwarebazaar = AsyncMock(
        return_value={"status": "ok", "signature": "Emotet"})
    return ti


def test_threat_intel_hash_checks_malwarebazaar(tmp_path):
    ti = _armed_threat_intel()
    asyncio.run(ti.invoke(
        {"indicator_type": "hash", "indicator_value": "a" * 64}, _ctx(tmp_path),
    ))
    assert ti._lookup_malwarebazaar.called
    assert ti._lookup_threatfox.called


def test_threat_intel_ip_checks_threatfox_not_malwarebazaar(tmp_path):
    ti = _armed_threat_intel()
    asyncio.run(ti.invoke(
        {"indicator_type": "ip", "indicator_value": "203.0.113.9"}, _ctx(tmp_path),
    ))
    assert ti._lookup_threatfox.called
    assert not ti._lookup_malwarebazaar.called  # MalwareBazaar is hash-only


def test_threat_intel_unknown_indicator_type_errors(tmp_path):
    res = asyncio.run(threat_intel.tool.invoke(
        {"indicator_type": "certificate", "indicator_value": "x"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 1
    assert "unsupported" in res.summary.lower()


def test_threat_intel_skips_virustotal_without_key(monkeypatch, tmp_path):
    """No VT_API_KEY → the VT source reports 'skipped' and never makes a request."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    # Only query VT so no other source can hit the network.
    res = asyncio.run(threat_intel.tool.invoke(
        {"indicator_type": "ip", "indicator_value": "203.0.113.9",
         "sources": ["virustotal"]},
        _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    vt = res.data["sources"]["virustotal"]
    assert vt["status"] == "skipped"
    assert "VT_API_KEY" in vt["reason"]


# ---------------------------------------------------------------------------
# 9. MITRE ATT&CK lookup / reverse
# ---------------------------------------------------------------------------

def test_mitre_reverse_event_4688_maps_to_t1059(tmp_path):
    res = asyncio.run(mitre_attack.tool.invoke(
        {"op": "reverse_event", "event_id": "4688"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    ids = [c["id"] for c in res.data["candidates"]]
    assert ids == ["T1059"]
    # Sanity-check the hints table agrees.
    assert EVENT_HINTS["4688"] == ["T1059"]


def test_mitre_reverse_event_unknown_id_is_empty(tmp_path):
    res = asyncio.run(mitre_attack.tool.invoke(
        {"op": "reverse_event", "event_id": "9999"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.data["candidates"] == []


def test_mitre_lookup_nonexistent_returns_null_name(tmp_path, monkeypatch):
    # Point the bundle at a tiny file so _lookup_technique finds no match.
    monkeypatch.setenv("SVETOVID_ATTACK_BUNDLE", str(tmp_path / "nope.json"))
    _load_bundle.cache_clear()
    res = asyncio.run(mitre_attack.tool.invoke(
        {"op": "lookup", "technique_id": "T0000"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.data["name"] is None


def test_mitre_lookup_existing_technique_returns_details(tmp_path, monkeypatch):
    bundle = {
        "objects": [{
            "type": "attack-pattern",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command and script interpreters.",
            "x_mitre_deprecated": False,
            "kill_chain_phases": [{"phase_name": "execution"}],
            "external_references": [{
                "external_id": "T1059",
                "url": "https://attack.mitre.org/techniques/T1059",
            }],
        }]
    }
    bundle_path = tmp_path / "attack.json"
    bundle_path.write_text(json.dumps(bundle))
    monkeypatch.setenv("SVETOVID_ATTACK_BUNDLE", str(bundle_path))
    _load_bundle.cache_clear()

    res = asyncio.run(mitre_attack.tool.invoke(
        {"op": "lookup", "technique_id": "T1059"}, _ctx(tmp_path),
    ))
    assert res.exit_code == 0
    assert res.data["name"] == "Command and Scripting Interpreter"
    assert res.data["description"]
    assert "execution" in res.data["tactic"]
    assert res.data["url"].endswith("T1059")
    assert res.data["deprecated"] is False


# ---------------------------------------------------------------------------
# 10. ToolResult — field contract + polymorphic data
# ---------------------------------------------------------------------------

def test_toolresult_carries_all_fields():
    r = ToolResult(
        call_id="call_1", tool="chainsaw_hunt", exit_code=0, duration_s=1.25,
        output_hash="sha256:deadbeef", output_path="/out/hits.json",
        summary="3 Sigma hit(s)",
    )
    assert r.call_id == "call_1"
    assert r.tool == "chainsaw_hunt"
    assert r.exit_code == 0
    assert r.duration_s == 1.25
    assert r.output_hash == "sha256:deadbeef"
    assert r.output_path == "/out/hits.json"
    assert r.summary == "3 Sigma hit(s)"
    # `data` defaults to None when omitted.
    assert r.data is None


def test_toolresult_data_accepts_none_list_and_dict():
    base = dict(call_id="c", tool="t", exit_code=0, duration_s=0.0,
                output_hash=None, output_path=None, summary="")
    assert ToolResult(**base, data=None).data is None
    assert ToolResult(**base, data=[1, 2, 3]).data == [1, 2, 3]
    assert ToolResult(**base, data={"hits": []}).data == {"hits": []}
