"""Full-stack real-Docker test: image-free and image-based nodes together.

TechVault's real shape is permanently mixed: some nodes convert to the
generic materializer (`runtime:`), others stay on a declared vendor
`source:` (a legitimate, transparently-declared upstream image - not a
hidden appliance image ADR-047/048 targets). `realize()` must materialize
the runtime: subset directly and start the source: subset via Compose, in
one `aptl lab start`, without either side conflicting with or silently
skipping the other.

Constructs the realization spec directly rather than through the ACES
compiler (already proven separately, e.g. test_imagefree_admission_
integration.py) so this test isolates `realize()`'s own dispatch.

Marked `integration`; skipped without Docker.
"""

from __future__ import annotations

import shutil
import subprocess
import time

import pytest
from aces_sdl.runtime_configuration import RuntimeConfiguration, RuntimePackage

from aptl.core.deployment import (
    DeploymentImageRealization,
    DeploymentNetworkAttachment,
    DeploymentNetworkRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
    DockerComposeBackend,
)

pytestmark = pytest.mark.integration

_COMPOSE = """\
services:
  image-box:
    image: postgres:16-alpine
    container_name: aptl-image-box
    environment:
      POSTGRES_PASSWORD: test
      POSTGRES_HOST_AUTH_METHOD: trust
  free-box:
    image: alpine:3.19
    container_name: aptl-free-box
    command: ["sleep", "infinity"]
"""


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, text=True).returncode == 0


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_realize_materializes_runtime_node_and_starts_image_node_together(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(_COMPOSE)
    free_container = "aptl-free-box"
    image_container = "aptl-image-box"
    subprocess.run(
        ["docker", "rm", "-f", free_container, image_container], capture_output=True, text=True
    )

    backend = DockerComposeBackend(project_dir=tmp_path, project_name="aptl-mixed-test")

    free_node = DeploymentNodeRealization(
        address="provision.node.free-box",
        name="free-box",
        service_name="free-box",
        container_name=free_container,
        networks=("mixed-net",),
        network_attachments=(
            DeploymentNetworkAttachment(network="mixed-net", ipv4_address="172.31.0.10"),
        ),
        os="linux",
        os_version="",
        runtime=RuntimeConfiguration(
            packages=[RuntimePackage(manager="apt", name="curl", version="*")]
        ),
    )
    image_node = DeploymentNodeRealization(
        address="provision.node.image-box",
        name="image-box",
        service_name="image-box",
        container_name=image_container,
        networks=("mixed-net",),
        network_attachments=(
            DeploymentNetworkAttachment(network="mixed-net", ipv4_address="172.31.0.11"),
        ),
        os="linux",
        os_version="",
        runtime=None,
    )
    spec = DeploymentRealizationSpec(
        profiles=("default",),
        nodes=(free_node, image_node),
        networks=(
            DeploymentNetworkRealization(name="mixed-net", cidr="172.31.0.0/24", gateway="172.31.0.1"),
        ),
        images=(
            DeploymentImageRealization(
                address="provision.node.image-box",
                service_name="image-box",
                source_name="postgres",
                source_version="16-alpine",
                image_ref="postgres:16-alpine",
                mode="pull",
                policy_rule="allowed-source",
            ),
        ),
    )
    # Not the whole-scenario image_free flag; this proves the per-node
    # dispatch materializes the runtime: node even when it is False.
    assert spec.image_free is False

    try:
        result = backend.realize(spec, build=False)
        assert result.success, result.error

        # Exactly one container for the runtime: node - Compose was told to
        # scale it to zero, so it never started its own "sleep infinity"
        # placeholder alongside the generic materializer's real container.
        ps = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name=^{free_container}$", "--format", "{{.Names}}"],
            capture_output=True, text=True,
        )
        assert ps.stdout.split() == [free_container]

        # The runtime: node was materialized directly (generic materializer),
        # not via Compose - it is not a Compose-managed container.
        assert "curl" in backend.container_exec(
            free_container, ["dpkg-query", "-W", "-f=${Package}\n", "curl"]
        ).stdout

        # The source: node was started via Compose as usual.
        pg_ready = None
        for _ in range(20):
            pg_ready = backend.container_exec(image_container, ["pg_isready"])
            if pg_ready.returncode == 0:
                break
            time.sleep(1)
        assert pg_ready is not None and pg_ready.returncode == 0, pg_ready.stdout

        # The generic materializer's directly-run container is connected to
        # the declared scenario network with its declared static IP, exactly
        # like a Compose-managed node - the existing post-start network
        # reconciliation step operates by container name, so it already
        # covers both realization styles without any change.
        network = "aptl-mixed-test_aptl-mixed"
        inspect = subprocess.run(
            ["docker", "inspect", free_container, "--format",
             f"{{{{(index .NetworkSettings.Networks \"{network}\").IPAddress}}}}"],
            capture_output=True, text=True,
        )
        assert inspect.stdout.strip() == "172.31.0.10", (inspect.stdout, inspect.stderr)
    finally:
        subprocess.run(
            ["docker", "rm", "-f", free_container, image_container], capture_output=True, text=True
        )
        subprocess.run(
            ["docker", "network", "rm", "aptl-mixed-test_aptl-mixed", "aptl-mixed-test_default"],
            capture_output=True, text=True,
        )
