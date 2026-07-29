"""Security-focused tests for the Q3/Q4/Q5 hardening.

Covers:
  * Q3 — HITL gate request/resolve round-trip + timeout behaviour.
  * Q4 — Docker sandbox security parameters are present on the run() call.
  * Q5 — scan endpoint rejects system/sensitive paths.

These tests do NOT modify any existing test file; they sit alongside the
rest of the suite. They run against a throwaway HOME + the fail keyring
backend so nothing touches the real ``~/.svetovid`` or macOS Keychain.
"""

from __future__ import annotations

import asyncio
import sys
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Hermetic environment (mirrors the per-module autouse fixtures elsewhere).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    # The HITL auto-approve path would short-circuit the round-trip tests; we
    # need the REAL blocking gate for the approval/timeout assertions below.
    monkeypatch.delenv("SVETOVID_HITL_AUTO_APPROVE", raising=False)
    # Clear cached svetovid singletons so each test re-imports fresh state
    # (especially the module-level ``_pending`` / ``_outcomes`` dicts).
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]
    yield


class _FakeBus:
    """Minimal stand-in for ``agent.events.EventBus`` that records publishes."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def publish(self, event) -> None:
        self.events.append(event.to_ws() if hasattr(event, "to_ws") else event)


# ===========================================================================
# Q3 — HITL request/resolve round-trip
# ===========================================================================


def test_hitl_request_resolve_approve_round_trip():
    """A goal awaiting approval is unblocked when the human approves."""
    from svetovid.agent import hitl as hitl_mod

    bus = _FakeBus()
    investigation_id = "inv_approve_rt"

    async def drive() -> bool:
        # Kick off the gate and concurrently resolve it (mimicking the REST
        # endpoint calling resolve_approval after the human clicks Approve).
        gate = asyncio.create_task(
            hitl_mod.request_approval(
                investigation_id, bus, "Report ready",
                {"preview": "abc"},
            )
        )
        # Let the gate register its Future + publish hitl.request.
        await asyncio.sleep(0.05)
        resolved = hitl_mod.resolve_approval(investigation_id, True)
        approved = await gate
        assert resolved is True
        return approved

    approved = asyncio.run(drive())
    assert approved is True, "approve round-trip should return True"

    # The hitl.request event must have been published (UI flips to paused).
    types = [e["type"] for e in bus.events]
    assert "hitl.request" in types
    # And the hitl.response records the approval.
    resp = [e for e in bus.events if e["type"] == "hitl.response"]
    assert resp and resp[-1]["data"]["approved"] is True

    # Outcome ledger reflects the decision.
    assert hitl_mod.get_outcome(investigation_id) is True

    # The pending dict is cleaned up after resolution.
    assert investigation_id not in hitl_mod._pending


def test_hitl_request_resolve_reject_round_trip():
    """A rejection unblocks the gate with ``approved=False``."""
    from svetovid.agent import hitl as hitl_mod

    bus = _FakeBus()
    investigation_id = "inv_reject_rt"

    async def drive() -> bool:
        gate = asyncio.create_task(
            hitl_mod.request_approval(investigation_id, bus, "x", {"preview": "y"})
        )
        await asyncio.sleep(0.05)
        hitl_mod.resolve_approval(investigation_id, False)
        return await gate

    approved = asyncio.run(drive())
    assert approved is False, "reject round-trip should return False"
    assert hitl_mod.get_outcome(investigation_id) is False

    resp = [e for e in bus.events if e["type"] == "hitl.response"]
    assert resp and resp[-1]["data"]["approved"] is False


def test_hitl_timeout_returns_false_and_publishes_response():
    """When no human responds within the timeout, the gate rejects."""
    from svetovid.agent import hitl as hitl_mod

    bus = _FakeBus()
    investigation_id = "inv_timeout"

    async def drive() -> bool:
        # 0.2s timeout — no resolver will ever call resolve_approval.
        return await hitl_mod.request_approval(
            investigation_id, bus, "x", {"preview": "y"}, timeout=0.2
        )

    approved = asyncio.run(asyncio.wait_for(drive(), timeout=5.0))
    assert approved is False, "timeout should be treated as a rejection"

    # Outcome ledger records the rejection (False).
    assert hitl_mod.get_outcome(investigation_id) is False

    # The response event explains the timeout.
    resp = [e for e in bus.events if e["type"] == "hitl.response"]
    assert resp, "a hitl.response must be published on timeout"
    assert resp[-1]["data"]["approved"] is False
    assert "timeout" in resp[-1]["data"]["detail"].lower()

    # Pending dict cleaned up.
    assert investigation_id not in hitl_mod._pending


def test_hitl_resolve_with_no_pending_gate_is_noop():
    """Resolving a gate that isn't pending must not raise (idempotent)."""
    from svetovid.agent import hitl as hitl_mod

    # Nothing pending for this id.
    assert hitl_mod.resolve_approval("inv_never_started", True) is False
    # Double-resolve of a real gate is also safe.
    bus = _FakeBus()
    inv = "inv_double"

    async def drive():
        gate = asyncio.create_task(
            hitl_mod.request_approval(inv, bus, "x", {"preview": "y"})
        )
        await asyncio.sleep(0.05)
        assert hitl_mod.resolve_approval(inv, True) is True
        approved = await gate
        # Second resolve: gate already gone.
        assert hitl_mod.resolve_approval(inv, True) is False
        return approved

    assert asyncio.run(drive()) is True


def test_hitl_endpoint_is_auth_protected_and_resolves(tmp_path, monkeypatch):
    """The /hitl endpoint requires auth and actually resolves a pending gate."""
    from fastapi.testclient import TestClient
    from svetovid.main import app, AUTH_TOKEN
    import svetovid.main as main_mod
    from svetovid.agent import hitl as hitl_mod

    # Seed a pending gate synchronously (no running goal needed).
    fut = asyncio.get_event_loop().create_future() if False else None
    # We register the future manually to simulate a goal mid-gate.
    loop = asyncio.new_event_loop()
    try:
        pending_future = loop.create_future()
        hitl_mod._pending["inv_ep"] = pending_future

        with TestClient(app) as client:
            # 401 without auth.
            r = client.post("/api/investigations/inv_ep/hitl", json={"approved": True})
            assert r.status_code == 401

            auth = {"Authorization": f"Bearer {AUTH_TOKEN}"}
            r = client.post("/api/investigations/inv_ep/hitl",
                            json={"approved": True}, headers=auth)
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["resolved"] is True
            assert body["approved"] is True

            # A second call finds nothing pending (already resolved).
            r = client.post("/api/investigations/inv_ep/hitl",
                            json={"approved": False}, headers=auth)
            assert r.status_code == 200
            assert r.json()["resolved"] is False
    finally:
        loop.close()


# ===========================================================================
# Q4 — Docker sandbox security parameters
# ===========================================================================


def test_docker_run_includes_security_hardening():
    """``run_in_sandbox`` must pass the Q4 security params to containers.run."""
    # Bypass the Docker availability check so we reach the containers.run call.
    with patch("svetovid.sandbox.docker_runner._check_docker", return_value=True), \
         patch("svetovid.sandbox.docker_runner._stream_logs_blocking", return_value=0):
        import svetovid.sandbox.docker_runner as runner

        fake_client = MagicMock()
        fake_container = MagicMock()
        fake_container.id = "abc123def456"
        fake_client.containers.run.return_value = fake_container

        import docker as _docker  # noqa: F401  (ensures import works)
        with patch("docker.from_env", return_value=fake_client):
            result = asyncio.run(runner.run_in_sandbox(
                image="svetovid/base",
                command=["/bin/true"],
                evidence_path="/evidence",
                output_dir=str(__import__("pathlib").Path(__file__).parent / "_sandbox_out"),
                investigation_id="inv_q4",
            ))

        assert result.exit_code == 0
        fake_client.containers.run.assert_called_once()

        kwargs = fake_client.containers.run.call_args.kwargs
        # Q4 required security parameters:
        assert kwargs.get("cap_drop") == ["ALL"], "cap_drop must be ['ALL']"
        assert kwargs.get("security_opt") == ["no-new-privileges:true"], \
            "no-new-privileges must be set"
        assert kwargs.get("pids_limit") == 512, "pids_limit must be 512"
        tmpfs = kwargs.get("tmpfs") or {}
        assert "/tmp" in tmpfs, "tmpfs must include /tmp"
        assert "noexec" in tmpfs["/tmp"], "/tmp tmpfs must be noexec"
        assert kwargs.get("ipc_mode") == "none", "ipc_mode must be none"
        # Non-root user (nobody OR an explicit uid:gid — both satisfy the intent).
        user = kwargs.get("user")
        assert user and user != "root", f"user must be non-root, got {user!r}"


# ===========================================================================
# Q5 — Scan path validation
# ===========================================================================


def test_scan_rejects_system_paths():
    """The scan endpoint refuses to walk sensitive system directories."""
    from fastapi.testclient import TestClient
    from svetovid.main import app, AUTH_TOKEN

    auth = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    blocked = ["/etc", "/usr", "/bin", "/sbin", "/proc", "/sys"]

    with TestClient(app) as client:
        for p in blocked:
            r = client.post("/api/scan", json={"path": p}, headers=auth)
            assert r.status_code == 403, (
                f"scan of {p} should be 403, got {r.status_code}: {r.text}"
            )
            assert "system path" in r.text.lower(), f"{p}: {r.text}"


def test_scan_rejects_svetovid_home(tmp_path, monkeypatch):
    """The scan endpoint refuses to scan Svetovid's own config directory.

    We exercise the dedicated Svetovid-home check by pointing HOME at a path
    that is NOT under a system dir. (pytest's own ``tmp_path`` is under
    ``/private/var`` on macOS, which the system-path blocklist correctly
    catches first — so we relocate HOME under the repo working dir, a real
    user path, to isolate the Svetovid-home check.)
    """
    import pathlib

    # A HOME that is not itself under a blocked system path, so the only
    # blocker that fires is the Svetovid-home one.
    safe_home = pathlib.Path.cwd() / "_svetovid_home_test_home"
    safe_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(safe_home))
    # Clear cached modules so main re-reads HOME.
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]

    svetovid_home = safe_home / ".svetovid"
    svetovid_home.mkdir(parents=True, exist_ok=True)

    try:
        from fastapi.testclient import TestClient
        from svetovid.main import app, AUTH_TOKEN
        auth = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        with TestClient(app) as client:
            r = client.post("/api/scan", json={"path": str(svetovid_home)}, headers=auth)
            assert r.status_code == 403, r.text
            assert "svetovid" in r.text.lower(), r.text
    finally:
        import shutil
        shutil.rmtree(safe_home, ignore_errors=True)


def test_scan_rejects_nonexistent_path():
    """A path that doesn't exist is rejected with 400 (not 500)."""
    from fastapi.testclient import TestClient
    from svetovid.main import app, AUTH_TOKEN

    auth = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    with TestClient(app) as client:
        r = client.post("/api/scan",
                        json={"path": "/definitely/does/not/exist/xyz123"},
                        headers=auth)
        assert r.status_code == 400, r.text


def test_scan_accepts_legit_evidence_dir():
    """A normal evidence directory under the user's home scans fine."""
    from fastapi.testclient import TestClient
    from svetovid.main import app, AUTH_TOKEN

    auth = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    fixtures = str((__import__("pathlib").Path(__file__).resolve().parent / "fixtures"))

    with TestClient(app) as client:
        r = client.post("/api/scan", json={"path": fixtures}, headers=auth)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "artifacts" in body


def test_scan_endpoint_is_auth_protected():
    """The scan endpoint requires a valid bearer token."""
    from fastapi.testclient import TestClient
    from svetovid.main import app

    with TestClient(app) as client:
        r = client.post("/api/scan", json={"path": "/tmp"})
        assert r.status_code == 401
