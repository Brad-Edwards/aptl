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
from raes.runtime_configuration import (
    RuntimeConfiguration,
    RuntimeLocalGroup,
    RuntimeLocalIdentityInventory,
    RuntimeLocalUser,
    RuntimePackage,
)

from aptl.backends.raes_node_materialization import realize_node
from aptl.backends.raes_realization_model import NodeRealization
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
def test_dynamic_composition_node_starts_immutably_from_config_id(tmp_path):
    """A route-3 node's base container runs the exact verified config id.

    Extends the affordance for ADR-051 route 3 / issue #876: the node is marked
    ``dynamic_composition=True``, so realizing it exercises the immutable-start
    path — ``--pull=never`` and a start from the config id availability verified
    is local — end to end on real Docker, not just in a command-builder unit
    test. ``Config.Image`` records the exact run argument, so a config id there
    (never the declared tag) proves the wrong bytes could not have started.
    """
    from aptl.backends.raes_base_substrate import base_container_spec

    container = "aptl-e2e-dyncompose"
    subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)
    backend = DockerComposeBackend(
        project_dir=tmp_path, project_name="aptl-itest-dyncompose"
    )

    node = NodeRealization(
        address="itest.e2e-dyncompose",
        name="e2e-dyncompose",
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
        ),
        dynamic_composition=True,
    )

    # Route-3 availability is a strict local lookup: the substrate must already be
    # present. Ensure it, then read the exact config id the immutable start pins.
    spec = base_container_spec(
        node.address, os=node.os, os_version=node.os_version, runtime=node.runtime
    )
    subprocess.run(["docker", "pull", spec.image_ref], capture_output=True, text=True)
    identity = backend.substrate_image_identity(spec.image_ref)
    assert identity is not None, f"substrate {spec.image_ref} not present locally"
    config_id = identity[0]
    # The apply context the provisioner derives from availability facts and threads
    # into realize(); realize_node is driven directly here, so seed it explicitly.
    backend._realization_substrate_digests = {node.address: config_id}

    def _bare(digest: str) -> str:
        return digest.split("sha256:", 1)[-1]

    try:
        result = realize_node(node, backend)
        assert result is None, getattr(result, "error", None)

        config_image = subprocess.run(
            ["docker", "inspect", "--format", "{{.Config.Image}}", container],
            capture_output=True,
            text=True,
        ).stdout.strip()
        # Started from the config id, not the declared tag.
        assert config_image
        assert config_image != spec.image_ref
        assert _bare(config_image) == _bare(config_id)

        # The declared runtime still materialized onto that immutable substrate.
        assert "curl" in backend.container_exec(
            container, ["dpkg-query", "-W", "-f=${Package}\n", "curl"]
        ).stdout
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_realize_routes_image_free_spec_through_materializer(tmp_path):
    """realize() materializes an image-free node directly (no compose-up)."""
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
    spec = DeploymentRealizationSpec(profiles=(), nodes=(node,), networks=())
    # The node is image-free by shape -- runtime state, no image, no service --
    # so nothing is left for Compose and realize() routes it straight to the
    # generic materializer. (The old whole-spec image_free flag was removed when
    # routing moved to per-node facts.)
    from aptl.core.deployment._compose_realization import _needs_compose

    assert _needs_compose(spec) is False
    try:
        result = backend.realize(spec, scenario_root=tmp_path)
        assert result.success, result.error
        assert "curl" in backend.container_exec(
            container, ["dpkg-query", "-W", "-f=${Package}\n", "curl"]
        ).stdout
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True)
