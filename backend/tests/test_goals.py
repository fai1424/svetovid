"""Goal integration tests (M1.6).

Verifies every registered goal satisfies the contract (manifest serializable,
nodes well-formed, detect() works, id/cluster/label populated) — and that
G02/G03 specifically have the tools they claim.
"""

from __future__ import annotations

import json

import pytest


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


def _goals():
    from svetovid.goals.registry import registry
    return registry.all()


def test_all_goals_have_required_fields():
    for g in _goals():
        assert g.id and g.id.startswith("G"), f"bad id: {g.id}"
        assert g.cluster, f"{g.id}: missing cluster"
        assert g.label, f"{g.id}: missing label"
        assert g.description, f"{g.id}: missing description"
        assert g.input_artifacts, f"{g.id}: missing input_artifacts"
        assert g.tools, f"{g.id}: missing tools"


def test_all_goals_have_well_formed_nodes():
    for g in _goals():
        nodes = g.nodes()
        assert len(nodes) >= 3, f"{g.id}: too few nodes ({len(nodes)})"
        assert nodes[0].id == "triage", f"{g.id}: first node must be 'triage'"
        assert nodes[-1].id == "finalize", f"{g.id}: last node must be 'finalize'"
        for n in nodes:
            assert n.id and n.label, f"{g.id}: node missing id/label"
            assert n.status == "pending"


def test_all_manifests_serialize():
    for g in _goals():
        m = g.manifest()
        s = json.dumps(m)  # must not raise
        m2 = json.loads(s)
        assert m2["id"] == g.id


def test_detect_returns_zero_to_one():
    for g in _goals():
        score = g.detect([])
        assert 0.0 <= score <= 1.0
        score = g.detect([{"artifact_id": a} for a in g.input_artifacts])
        assert score == 1.0


def test_g01_uses_fixed_pipeline_nodes():
    from svetovid.goals.registry import registry
    g = registry.get("G01")
    node_ids = [n.id for n in g.nodes()]
    # G01 is the deterministic-pipeline goal (no react_loop)
    assert "sigma_hunt" in node_ids
    assert "react_loop" not in node_ids


def test_g02_uses_react_loop():
    from svetovid.goals.registry import registry
    g = registry.get("G02")
    node_ids = [n.id for n in g.nodes()]
    assert "react_loop" in node_ids, "G02 must use the agentic ReAct loop"
    assert "B6" in g.input_artifacts, "G02 should accept memory evidence"


def test_g03_targets_disk_images():
    from svetovid.goals.registry import registry
    g = registry.get("G03")
    assert "C11a" in g.tools, "G03 should use Sleuth Kit"
    assert "C11f" in g.tools, "G03 should use Bulk Extractor"


def test_g04_targets_linux_artifacts():
    """G04 is the Linux server compromise goal: Endpoint cluster, consumes B4,
    and runs through the agentic react_loop node like G02/G03."""
    from svetovid.goals.registry import registry
    g = registry.get("G04")
    assert g is not None, "G04 must be registered"
    assert g.cluster == "Endpoint", f"G04 cluster should be Endpoint, got {g.cluster!r}"
    assert "B4" in g.input_artifacts, "G04 should consume Linux evidence (B4)"
    # The agent loop is the distinguishing node pattern vs the G01 fixed pipeline
    node_ids = [n.id for n in g.nodes()]
    assert "react_loop" in node_ids, "G04 must use the agentic ReAct loop"
    # G04 wires the Linux log parser + ATT&CK mapping tools
    assert "C17c" in g.tools, "G04 should use the Linux log parser (C17c)"
    assert "A2" in g.tools, "G04 should use MITRE ATT&CK mapping (A2)"


def test_g05_targets_macos_artifacts():
    """G05 is the macOS endpoint compromise goal: Endpoint cluster, consumes
    the macOS endpoint artifact (B5), and runs through the agentic react_loop
    node pattern like G02/G03/G04."""
    from svetovid.goals.registry import registry
    g = registry.get("G05")
    assert g is not None, "G05 must be registered"
    assert g.cluster == "Endpoint", f"G05 cluster should be Endpoint, got {g.cluster!r}"
    assert "B5" in g.input_artifacts, "G05 should consume the macOS endpoint artifact (B5)"
    # The agent loop is the distinguishing node pattern vs the G01 fixed pipeline
    node_ids = [n.id for n in g.nodes()]
    assert "react_loop" in node_ids, "G05 must use the agentic ReAct loop"
    assert node_ids[0] == "triage"
    assert node_ids[-1] == "finalize"
    # G05 wires the macOS artifact parser + ATT&CK mapping tools
    assert "C16" in g.tools, "G05 should use the macOS artifact parser (C16)"
    assert "A2" in g.tools, "G05 should use MITRE ATT&CK mapping (A2)"


def test_g06_targets_memory_images():
    """G06 is the memory forensics goal: Memory cluster, consumes B6."""
    from svetovid.goals.registry import registry
    g = registry.get("G06")
    assert g is not None, "G06 must be registered"
    assert g.cluster == "Memory"
    assert "B6" in g.input_artifacts
    assert "C13" in g.tools, "G06 should use Volatility (C13)"
    node_ids = [n.id for n in g.nodes()]
    assert "react_loop" in node_ids


def test_g07_targets_network_captures():
    """G07 is the network C2 goal: Network cluster, consumes B7 (PCAP)."""
    from svetovid.goals.registry import registry
    g = registry.get("G07")
    assert g is not None, "G07 must be registered"
    assert g.cluster == "Network"
    assert "B7" in g.input_artifacts
    assert "C14" in g.tools, "G07 should use network tools (C14)"
    node_ids = [n.id for n in g.nodes()]
    assert "react_loop" in node_ids


def test_g08_ransomware_accepts_multi_evidence():
    """G08 (ransomware) is cross-cutting: consumes evtx, pcap, memory."""
    from svetovid.goals.registry import registry
    g = registry.get("G08")
    assert g is not None, "G08 must be registered"
    assert g.cluster == "Ransomware"
    # Ransomware is the broadest-input goal — accepts Windows, Linux, network, memory
    for must in ("B3", "B8", "B7", "B6"):
        assert must in g.input_artifacts, f"G08 should accept {must}"
    assert "C13" in g.tools, "G08 should check memory (C13)"
    assert "C15" in g.tools, "G08 should ID ransomware via YARA (C15)"


def test_g09_targets_email_artifacts():
    """G09 is the email/BEC/phishing goal: Email cluster, consumes B9."""
    from svetovid.goals.registry import registry
    g = registry.get("G09")
    assert g is not None, "G09 must be registered"
    assert g.cluster == "Email"
    assert "B9" in g.input_artifacts
    node_ids = [n.id for n in g.nodes()]
    assert "react_loop" in node_ids


def test_no_duplicate_goal_ids():
    ids = [g.id for g in _goals()]
    assert len(ids) == len(set(ids)), f"duplicate ids: {ids}"


def test_cluster_distribution_makes_sense():
    """By M5 we should have ≥6 clusters represented."""
    from collections import Counter
    c = Counter(g.cluster for g in _goals())
    assert c.get("Windows", 0) >= 3, f"expected ≥3 Windows goals, got {c}"
    assert c.get("Endpoint", 0) >= 2, f"expected ≥2 Endpoint goals, got {c}"
    assert c.get("Network", 0) >= 1, "expected ≥1 Network goal"
    assert c.get("Memory", 0) >= 1, "expected ≥1 Memory goal"
    assert c.get("Ransomware", 0) >= 1, "expected ≥1 Ransomware goal"
    assert c.get("Email", 0) >= 1, "expected ≥1 Email goal"


# ---- tool schema sanity (M1.2) ----


def test_all_tool_schemas_are_flat():
    """Every tool wrapper must expose a flat JSON-schema (one level of props,
    primitive types only) for GLM/KIMI tool-calling reliability."""
    from svetovid.tools.chainsaw import tool as chainsaw
    from svetovid.tools.hayabusa import tool as hayabusa
    from svetovid.tools.volatility import tool as vol
    from svetovid.tools.yara import tool as yara
    from svetovid.tools.eztools import tool as ez
    from svetovid.tools.bulk_extractor import tool as be
    from svetovid.tools.sleuthkit import tool as tsk
    from svetovid.tools.mitre_attack import tool as mitre
    from svetovid.tools.macos_logs import tool as macos
    from svetovid.tools.linux_logs import tool as linux_logs
    from svetovid.tools.network_analysis import tool as net
    from svetovid.tools.email_parse import tool as email

    for t in [chainsaw, hayabusa, vol, yara, ez, be, tsk, mitre, macos, linux_logs, net, email]:
        s = t.schema()
        assert s["type"] == "object", f"{t.name}: schema type must be 'object'"
        for name, prop in s.get("properties", {}).items():
            assert prop["type"] in ("string", "number", "boolean", "array"), \
                f"{t.name}.{name}: non-primitive type {prop['type']}"


def test_volatility_plugin_whitelist_is_sane():
    from svetovid.tools.volatility import ALLOWED_PLUGINS
    # Core triage plugins must be present
    for must in ("pslist", "malfind", "netscan", "cmdline"):
        assert must in ALLOWED_PLUGINS, f"missing critical plugin: {must}"
    assert len(ALLOWED_PLUGINS) >= 10


def test_eztools_whitelist_covers_core_parsers():
    from svetovid.tools.eztools import EZ_TOOLS
    for must in ("EvtxECmd", "MFTECmd", "PECmd", "AmcacheParser", "RECmd"):
        assert must in EZ_TOOLS, f"missing EZ tool: {must}"


def test_tsk_whitelist_has_core_subtools():
    from svetovid.tools.sleuthkit import TSK_SUBTOOLS
    for must in ("fls", "icat", "mmls", "mactime"):
        assert must in TSK_SUBTOOLS
