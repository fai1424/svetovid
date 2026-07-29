"""Session-level test configuration for the Svetovid backend.

Enables HITL auto-approve + stubs out Docker/subprocess execution so tests
never launch real containers or binaries that would hang the suite.
"""

from __future__ import annotations

import os
import asyncio
from dataclasses import dataclass


def pytest_configure(config):
    os.environ.setdefault("SVETOVID_HITL_AUTO_APPROVE", "1")


def pytest_sessionstart(session):
    """Patch run_in_sandbox to return an instant 'tool unavailable' result.

    This prevents ANY subprocess or Docker call during tests. Tool wrappers
    that call run_in_sandbox get a fast failure (exit_code=127) instead of
    launching real containers or host binaries that hang for minutes.
    """
    from svetovid.sandbox import docker_runner

    @dataclass
    class FakeResult:
        exit_code: int = 127
        duration_s: float = 0.001
        container_id: str | None = None
        output_dir: str = "/tmp/test_output"

    async def _fake_run(**kwargs):
        return FakeResult()

    docker_runner.run_in_sandbox = _fake_run
    docker_runner._check_docker = lambda *a, **k: False
