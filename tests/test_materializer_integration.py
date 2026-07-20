"""Real-Docker integration test for the generic materializer (ADR-047).

Materializes a node's declared state onto an actual base-OS container and
verifies it by read-after-write, with no product-specific code. This is the
local-Docker validation that unit fakes cannot give: it caught, for example,
that a slim base image needs `apt-get update` before install.

Marked `integration`; skipped when Docker is unavailable. Run explicitly:
`uv run pytest tests/test_materializer_integration.py -m integration`.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest
from aces_sdl.runtime_configuration import (
    RuntimeConfiguration,
    RuntimeLocalGroup,
    RuntimeLocalIdentityInventory,
    RuntimeLocalUser,
    RuntimePackage,
)

from aptl.backends.aces_base_substrate import plan_node
from aptl.backends.aces_docker_materializer import DockerMaterializationExecutor
from aptl.backends.aces_materializer_engine import materialize_node

pytestmark = pytest.mark.integration

_BASE_IMAGE = "debian:12-slim"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(
        ["docker", "info"], capture_output=True, text=True
    ).returncode == 0


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_materializer_realizes_declared_state_on_a_real_container():
    node_address = "itest.materializer-node"
    container = "aptl-itest-materializer"
    subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)

    # A node declaring real software + identity, no service units (a plain base
    # container has no init). All of it lives in the declared state, not code.
    runtime = RuntimeConfiguration(
        packages=[RuntimePackage(manager="apt", name="curl", version="*")],
        local_identity=RuntimeLocalIdentityInventory(
            groups=[RuntimeLocalGroup(name="techvault", gid=1500)],
            users=[RuntimeLocalUser(username="analyst", supplemental_groups=["techvault"])],
        ),
    )

    def start_base(addr: str, image_ref: str) -> None:
        subprocess.run(
            ["docker", "run", "-d", "--name", container, image_ref, "sleep", "1200"],
            check=True,
            capture_output=True,
            text=True,
        )

    def run_in(container_name: str, argv: list[str]):
        return subprocess.run(
            ["docker", "exec", container_name, *argv],
            capture_output=True,
            text=True,
            timeout=600,
        )

    executor = DockerMaterializationExecutor(
        run=run_in,
        container_for=lambda _addr: container,
        start_base=start_base,
    )

    try:
        _spec, ops = plan_node(node_address, os="linux", os_version="", runtime=runtime)
        result = materialize_node(node_address, ops, executor)

        # Fully verified success: the engine's own read-after-write passed.
        assert result is None, getattr(result, "error", None)

        # Independently confirm the real container state.
        assert "curl" in run_in(container, ["dpkg-query", "-W", "-f=${Package}\n", "curl"]).stdout
        assert run_in(container, ["id", "-u", "analyst"]).returncode == 0
        assert run_in(container, ["getent", "group", "techvault"]).returncode == 0
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)
