"""Real-Docker positive/negative proof for the external platform floor."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from aptl.core.deployment._compose_boundary import _helper_command
from aptl.core.deployment.boundary import (
    BoundaryNetwork,
    BoundaryWorkload,
    PlatformBoundarySpec,
    PlatformCrossing,
)
from aptl.core.deployment.docker_compose import DockerComposeBackend

pytestmark = pytest.mark.integration

_ALPINE = (
    "alpine:3.22@sha256:"
    "14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
)
_SERVER = "aptl-appliance-egress-proxy:1"
_NETWORK = "aptl-822-boundary-proof"
_BRIDGE = "ap822proof0"
_CONTAINERS = (
    "aptl-822-proof-management",
    "aptl-822-proof-egress",
    "aptl-822-proof-participant",
)


def _run(argv: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _docker_available() -> bool:
    return shutil.which("docker") is not None and _run(
        ["docker", "info"]
    ).returncode == 0


def _policy() -> PlatformBoundarySpec:
    network = BoundaryNetwork(
        name="transit",
        bridge=_BRIDGE,
        ipv4_cidr="10.252.24.0/24",
    )
    return PlatformBoundarySpec(
        owner="aptl-822-boundary-proof",
        policy_digest="sha256:" + "e" * 64,
        networks=(network,),
        anchors=(
            (
                "participant",
                BoundaryWorkload(
                    identity="participant",
                    labels=(("org.aptl.zone", "participant"),),
                    ipv4_by_network=(("transit", "10.252.24.30"),),
                ),
            ),
            (
                "management",
                BoundaryWorkload(
                    identity="management",
                    labels=(("org.aptl.zone", "management"),),
                    ipv4_by_network=(("transit", "10.252.24.10"),),
                ),
            ),
            (
                "egress",
                BoundaryWorkload(
                    identity="egress",
                    labels=(("org.aptl.zone", "egress"),),
                    ipv4_by_network=(("transit", "10.252.24.20"),),
                ),
            ),
        ),
        crossings=(
            PlatformCrossing(
                source="management",
                destination="egress",
                protocol="tcp",
                ports=(8080,),
                purpose="live-proof",
            ),
        ),
        egress_ports=(),
    )


def _cleanup(backend: DockerComposeBackend, policy: PlatformBoundarySpec) -> None:
    backend._run_with_input(
        _helper_command("cleanup"),
        policy.canonical_json(),
        timeout=30,
    )
    for container in _CONTAINERS:
        _run(["docker", "rm", "-f", container])
    _run(["docker", "network", "rm", _NETWORK])


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_platform_floor_allows_declared_crossing_and_blocks_other_source() -> None:
    project_dir = Path(__file__).parents[1]
    backend = DockerComposeBackend(project_dir, project_name="aptl-822-proof")
    policy = _policy()
    _cleanup(backend, policy)
    try:
        build = _run(
            [
                "docker",
                "build",
                "-q",
                "-f",
                str(project_dir / "containers/appliance-egress-proxy/Dockerfile"),
                "-t",
                _SERVER,
                str(project_dir),
            ],
            timeout=600,
        )
        assert build.returncode == 0
        created = _run(
            [
                "docker",
                "network",
                "create",
                "--driver",
                "bridge",
                "--opt",
                f"com.docker.network.bridge.name={_BRIDGE}",
                "--subnet",
                "10.252.24.0/24",
                _NETWORK,
            ]
        )
        assert created.returncode == 0
        starts = (
            [
                "docker",
                "run",
                "-d",
                "--name",
                _CONTAINERS[0],
                "--network",
                _NETWORK,
                "--ip",
                "10.252.24.10",
                _ALPINE,
                "sleep",
                "infinity",
            ],
            [
                "docker",
                "run",
                "-d",
                "--name",
                _CONTAINERS[1],
                "--network",
                _NETWORK,
                "--ip",
                "10.252.24.20",
                "--entrypoint",
                "python3",
                _SERVER,
                "-m",
                "http.server",
                "8080",
            ],
            [
                "docker",
                "run",
                "-d",
                "--name",
                _CONTAINERS[2],
                "--network",
                _NETWORK,
                "--ip",
                "10.252.24.30",
                _ALPINE,
                "sleep",
                "infinity",
            ],
        )
        assert all(_run(argv).returncode == 0 for argv in starts)
        time.sleep(1)

        assert backend.realize_boundary(policy).success is True
        allowed = _run(
            [
                "docker",
                "exec",
                _CONTAINERS[0],
                "wget",
                "-q",
                "-T",
                "3",
                "-O",
                "-",
                "http://10.252.24.20:8080/",
            ],
            timeout=10,
        )
        denied = _run(
            [
                "docker",
                "exec",
                _CONTAINERS[2],
                "wget",
                "-q",
                "-T",
                "3",
                "-O",
                "-",
                "http://10.252.24.20:8080/",
            ],
            timeout=10,
        )
        assert allowed.returncode == 0
        assert denied.returncode != 0
    finally:
        _cleanup(backend, policy)
