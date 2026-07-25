"""End-to-end real-Docker test: realize a node through the deployment backend.

Drives the whole ADR-048 path with a real `DockerComposeBackend`: start the
node's generic base container, materialize its declared packages/identity, and
verify by read-after-write. Product-agnostic; validates locally on Docker.

Marked `integration`; skipped without Docker. Run:
`uv run pytest tests/test_node_materialization_integration.py -m integration`.
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

from aptl.backends.aces_node_materialization import realize_node
from aptl.backends.aces_realization_model import NodeRealization
from aptl.core.deployment.docker_compose import DockerComposeBackend

pytestmark = pytest.mark.integration


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, text=True).returncode == 0


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_realize_node_through_backend_on_real_docker(tmp_path):
    container = "aptl-e2e-node"
    subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)

    backend = DockerComposeBackend(project_dir=tmp_path, project_name="aptl-itest-e2e")
    # A non-service node: packages + identity, so the minimal base (no systemd)
    # is enough. All detail is declared, not coded.
    node = NodeRealization(
        address="itest.e2e-node",
        name="e2e-node",
        aliases=(),
        profiles=(),
        backend_services=(),
        container_name=None,
        services=(),
        networks=(),
        static_addresses=(),
        os="linux",
        runtime=RuntimeConfiguration(
            packages=[RuntimePackage(manager="apt", name="curl", version="*")],
            local_identity=RuntimeLocalIdentityInventory(
                groups=[RuntimeLocalGroup(name="techvault", gid=1600)],
                users=[RuntimeLocalUser(username="analyst", supplemental_groups=["techvault"])],
            ),
        ),
    )

    try:
        result = realize_node(node, backend)
        assert result is None, getattr(result, "error", None)

        # Independently confirm real container state.
        assert "curl" in backend.container_exec(
            container, ["dpkg-query", "-W", "-f=${Package}\n", "curl"]
        ).stdout
        assert backend.container_exec(container, ["id", "-u", "analyst"]).returncode == 0
        assert backend.container_exec(container, ["getent", "group", "techvault"]).returncode == 0
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_realize_routes_image_free_spec_through_materializer(tmp_path):
    """backend.realize() with image_free=True materializes nodes (no compose-up)."""
    from aptl.core.deployment.realization import (
        DeploymentNodeRealization,
        DeploymentRealizationSpec,
    )

    container = "aptl-e2e-realize"
    subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)
    backend = DockerComposeBackend(project_dir=tmp_path, project_name="aptl-itest-realize")

    node = DeploymentNodeRealization(
        address="itest.e2e-realize",
        name="e2e-realize",
        service_name=None,
        container_name=None,
        networks=(),
        os="linux",
        runtime=RuntimeConfiguration(
            packages=[RuntimePackage(manager="apt", name="curl", version="*")],
        ),
    )
    spec = DeploymentRealizationSpec(
        profiles=(), nodes=(node,), networks=(), image_free=True
    )
    try:
        result = backend.realize(spec)
        assert result.success, result.error
        assert "curl" in backend.container_exec(
            container, ["dpkg-query", "-W", "-f=${Package}\n", "curl"]
        ).stdout
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)
