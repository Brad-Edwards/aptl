"""Real-Docker trust-boundary test for service-listener observation (#876).

The security review of issue #876 requires that a node's listener attestation
cannot be forged by the workload being attested -- and in a cyber range the
workload is expected to be hostile. This drives the real backend
(``DockerComposeBackend.observe_container_listeners``) against a container that
*lies*: it binds a wildcard (all-interfaces) socket while shipping a shadowed
``ss`` that reports the narrower loopback address. The observer reads the
kernel's per-netns socket tables through identity-bound host readback, without
launching an observer or executing target binaries, so it reports the wildcard, not the
lie, and the EXACT gate cannot certify a service exposed beyond its declared
boundary.

Marked ``integration``; skipped without Docker. Run:
`uv run pytest tests/test_listener_observation_integration.py -m integration`.
"""

from __future__ import annotations

import shutil
import subprocess
import re
import time
import uuid

import pytest

from aptl.core.deployment.docker_compose import DockerComposeBackend
from tests.helpers import run_owned_container

pytestmark = pytest.mark.integration


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=30
        ).returncode
        == 0
    )


# The workload binds 0.0.0.0:8080 (broad) but installs a fake `ss` that lies
# 127.0.0.1:8080 (narrow) -- the exact under-report the security review targets.
_WORKLOAD = (
    "printf '#!/bin/sh\\necho \"tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\"\\n' "
    "> /usr/local/bin/ss && chmod +x /usr/local/bin/ss && "
    'python -c "import socket,time; s=socket.socket(); '
    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
    "s.bind(('0.0.0.0', 8080)); s.listen(); print('up', flush=True); time.sleep(300)\""
)


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_shadowed_container_ss_cannot_forge_attested_listeners(tmp_path):
    semantic_name = "aptl-e2e-listener-trust-" + uuid.uuid4().hex
    backend = DockerComposeBackend(
        project_dir=tmp_path, project_name="aptl-itest-listener-trust"
    )
    # The observer resolves its target through ownership receipts, so the
    # hostile workload has to be a container this backend really owns. A
    # container started behind the backend's back is refused rather than
    # observed, which is the correct scoping: a backend must not read
    # resources outside its own workspace (#1054).
    container_id = run_owned_container(
        backend, semantic_name, ["python:3.12-slim", "sh", "-c", _WORKLOAD]
    )
    assert re.fullmatch(r"[0-9a-f]{64}", container_id)
    try:
        # Wait until the workload reports it is listening.
        for _ in range(30):
            logs = subprocess.run(
                ["docker", "logs", container_id],
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout
            if "up" in logs:
                break
            time.sleep(1)

        # The container CAN lie: its own shadowed `ss` reports the narrow address.
        lied = subprocess.run(
            ["docker", "exec", container_id, "ss"],
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
        assert "127.0.0.1:8080" in lied

        # The trusted observation reads the kernel's per-netns table instead, so it
        # reports the real wildcard bind and never the container's lie.
        observed = backend.observe_container_listeners(container_id)
        assert observed is not None
        tcp_8080 = [s for s in observed.sockets if s[0] == "tcp" and s[2] == 8080]
        assert tcp_8080, observed.sockets
        assert any(addr in ("0.0.0.0", "::") for _, addr, _ in tcp_8080)
        assert all(addr != "127.0.0.1" for _, addr, _ in tcp_8080)
    finally:
        # Only the exact native identity returned by this test's successful run.
        subprocess.run(
            ["docker", "rm", "-f", container_id],
            capture_output=True,
            text=True,
            timeout=30,
        )
