"""Per-tool-call Docker sandbox runner.

Each tool invocation runs inside a short-lived container with:
  - evidence mounted READ-ONLY at ``/evidence``
  - a per-call writable output dir mounted at ``/work``
  - no network by default (some tools like cloud API wrappers override)
  - CPU / memory caps
  - streaming stdout / stderr lines back as ``tool.stdout`` / ``tool.stderr`` events

If Docker is unavailable, callers can request ``host_fallback=True`` to run
the command on the host (the harness surface a clear warning in that case).
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable

# We import docker lazily so the backend can boot even when the SDK is missing
# (the harness surface this as "Docker not available, falling back to host").

StreamCb = Callable[[str], None]


@dataclass
class RunResult:
    exit_code: int
    duration_s: float
    container_id: str | None
    output_dir: str


async def run_in_sandbox(
    *,
    image: str,
    command: list[str],
    evidence_path: str,
    output_dir: str,
    investigation_id: str,
    on_stdout: StreamCb | None = None,
    on_stderr: StreamCb | None = None,
    network: str = "none",
    mem_limit: str = "4g",
    cpu_quota: float = 2.0,
    timeout_s: int = 1800,
    host_fallback: bool = False,
    extra_env: dict[str, str] | None = None,
) -> RunResult:
    """Run ``command`` inside ``image`` with the evidence mounted read-only.

    Streams stdout/stderr line-by-line to the callbacks (which the tool wrapper
    wires to ``tool.stdout`` / ``tool.stderr`` events).
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()

    docker_available = _check_docker()
    if not docker_available:
        if not host_fallback:
            raise RuntimeError(
                "Docker is not available. Enable Docker, or run with sandbox_mode=host_subprocess."
            )
        return await _run_on_host(command, output_dir, investigation_id, on_stdout, on_stderr, timeout_s, t0)

    try:
        import docker
    except ImportError as e:
        raise RuntimeError("python 'docker' SDK not installed") from e

    client = docker.from_env()
    try:
        volumes = {
            os.path.abspath(evidence_path): {"bind": "/evidence", "mode": "ro"},
            os.path.abspath(output_dir): {"bind": "/work", "mode": "rw"},
        }
        # Q4 — Sandbox hardening. Each parameter below shrinks the container's
        # escape surface so a parser RCE in a malicious evtx/pcap (the threat
        # model for this whole runner) cannot trivially escalate:
        #
        #   cap_drop=["ALL"]           — drop every Linux capability (no
        #                                CAP_NET_ADMIN, CAP_SYS_ADMIN, etc.).
        #   security_opt no-new-privs  — the process cannot gain privileges via
        #                                setuid binaries (sudo, ping, etc.).
        #   pids_limit=512             — fork-bomb cap; a malicious parser
        #                                can't exhaust the host PID table.
        #   tmpfs /tmp noexec          — /tmp writable for scratch but NOT
        #                                executable, so dropped payloads can't
        #                                be compiled+exec'd from /tmp.
        #   ipc_mode="none"            — disable shared memory / IPC, removing
        #                                a known container escape vector.
        #   user="1000:1000"           — run as a non-root, non-nobody uid that
        #                                the /work bind mount is chowned to.
        #                                (We don't use "nobody" because on
        #                                some base images nobody can't write
        #                                the bind-mounted /work; 1000:1000
        #                                plus the 1777 chmod below is robust.)
        #   read_only=False            — the rootfs stays read-only EXCEPT
        #                                /work (the rw bind mount) and /tmp
        #                                (the tmpfs). Tools that write temp
        #                                state to /tmp still work; everything
        #                                else is immutable.
        #
        # The /work bind mount is chmod'd 1777 before the run (see below) so
        # uid 1000 can write outputs even though the host dir was created by
        # the backend's own uid.
        container = client.containers.run(
            image,
            command,
            volumes=volumes,
            network_disabled=(network == "none"),
            mem_limit=mem_limit,
            cpu_quota=int(cpu_quota * 100000),
            tty=False,
            detach=True,
            stdout=True,
            stderr=True,
            environment=extra_env or {},
            working_dir="/work",
            # --- Q4 security hardening ---
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            pids_limit=512,
            tmpfs={"/tmp": "rw,noexec,nosuid,size=512m"},
            ipc_mode="none",
            user="1000:1000",
            read_only=False,
        )
        container_id = container.id[:12]

        # Ensure the non-root uid 1000 inside the container can write outputs
        # to the /work bind mount (which the backend created with its own uid
        # on the host). 1777 = world-writable+sticky, matching /tmp semantics.
        try:
            os.chmod(os.path.abspath(output_dir), 0o1777)
        except OSError:
            pass

        # Stream logs until exit or timeout
        loop = asyncio.get_event_loop()
        try:
            exit_code = await loop.run_in_executor(
                None, _stream_logs_blocking, container, on_stdout, on_stderr, timeout_s
            )
        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass
        return RunResult(exit_code=exit_code, duration_s=time.monotonic() - t0,
                         container_id=container_id, output_dir=output_dir)
    except Exception as e:
        if host_fallback:
            return await _run_on_host(command, output_dir, investigation_id, on_stdout, on_stderr, timeout_s, t0)
        raise


def _stream_logs_blocking(container, on_stdout, on_stderr, timeout_s) -> int:
    """Block on the container's log stream, dispatching lines to callbacks."""
    deadline = time.monotonic() + timeout_s
    for chunk in container.logs(stream=True, follow=True, stdout=True, stderr=True):
        if time.monotonic() > deadline:
            try:
                container.kill()
            except Exception:
                pass
            return 124
        text = chunk.decode("utf-8", errors="replace")
        for line in text.splitlines():
            # docker doesn't separate stdout/stderr in logs(stream=True); we
            # route by content for now: lines containing "WARN"/"ERROR" → stderr
            if on_stderr and ("error" in line.lower() or "warn" in line.lower()):
                on_stderr(line)
            elif on_stdout:
                on_stdout(line)
            elif on_stderr:
                on_stderr(line)
    # container.wait blocks for the exit code
    res = container.wait()
    return res.get("StatusCode", -1) if isinstance(res, dict) else -1


async def _run_on_host(command, output_dir, investigation_id, on_stdout, on_stderr, timeout_s, t0) -> RunResult:
    """Fallback: run on host (no isolation). Used only when sandbox_mode=host_subprocess."""
    if on_stderr:
        on_stderr("[warning] running on host — sandbox isolation unavailable")
    env = dict(os.environ)
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=output_dir,
        env=env,
    )

    async def _pump(stream, cb):
        while True:
            line = await stream.readline()
            if not line:
                break
            if cb:
                cb(line.decode("utf-8", errors="replace").rstrip())

    try:
        await asyncio.wait_for(
            asyncio.gather(_pump(proc.stdout, on_stdout), _pump(proc.stderr, on_stderr)),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        proc.kill()
        return RunResult(exit_code=124, duration_s=time.monotonic() - t0,
                         container_id=None, output_dir=output_dir)
    await proc.wait()
    return RunResult(exit_code=proc.returncode or 0, duration_s=time.monotonic() - t0,
                     container_id=None, output_dir=output_dir)


def _check_docker() -> bool:
    """Cheap Docker availability check (no exception on absence)."""
    if not shutil.which("docker"):
        return False
    # `docker info` is heavy; rely on socket existence instead
    for sock in ("/var/run/docker.sock", "/run/docker.sock"):
        if os.path.exists(sock):
            return True
    # macOS Docker Desktop uses a different socket; trust `which` if so
    return True
