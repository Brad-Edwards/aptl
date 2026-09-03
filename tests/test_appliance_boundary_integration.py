"""Real-Docker positive/negative proof for the external platform floor."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from aptl.core.deployment._compose_boundary import _helper_command
from aptl.core.deployment.boundary import (
    AcesAclOwnerBinding,
    AcesBoundarySpec,
    BoundaryNetwork,
    BoundaryWorkload,
    PlatformBoundarySpec,
    PlatformCrossing,
)
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.realization import DeploymentAclRealization

pytestmark = pytest.mark.integration

_ALPINE = (
    "alpine:3.22@sha256:"
    "14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
)
_SERVER = "aptl-appliance-egress-proxy:1"
_NETWORKS = (
    "aptl-822-boundary-participant",
    "aptl-822-boundary-management",
    "aptl-822-boundary-egress",
)
_BRIDGES = ("ap822part0", "ap822mgmt0", "ap822egress0")
_CONTAINERS = (
    "aptl-822-proof-management",
    "aptl-822-proof-egress",
    "aptl-822-proof-participant",
)


def _table_name(owner: str, authority: str) -> str:
    suffix = hashlib.sha256(f"{owner}:{authority}".encode()).hexdigest()[:12]
    return f"aptl_bnd_{suffix}"


def _run(argv: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _docker_available() -> bool:
    return (
        shutil.which("docker") is not None and _run(["docker", "info"]).returncode == 0
    )


def _policy() -> PlatformBoundarySpec:
    return PlatformBoundarySpec(
        owner="aptl-822-boundary-proof",
        policy_digest="sha256:" + "e" * 64,
        networks=(
            BoundaryNetwork(
                name="participant",
                bridge=_BRIDGES[0],
                ipv4_cidr="10.252.24.0/24",
            ),
            BoundaryNetwork(
                name="management",
                bridge=_BRIDGES[1],
                ipv4_cidr="10.252.26.0/24",
            ),
            BoundaryNetwork(
                name="egress",
                bridge=_BRIDGES[2],
                ipv4_cidr="10.252.27.0/24",
            ),
        ),
        zone_networks=(
            ("participant", "participant"),
            ("management", "management"),
            ("egress", "egress"),
        ),
        anchors=(
            (
                "participant",
                BoundaryWorkload(
                    identity="participant",
                    labels=(("org.aptl.zone", "participant"),),
                    ipv4_by_network=(("participant", "10.252.24.30"),),
                ),
            ),
            (
                "management",
                BoundaryWorkload(
                    identity="management",
                    labels=(("org.aptl.zone", "management"),),
                    ipv4_by_network=(("management", "10.252.26.10"),),
                ),
            ),
            (
                "egress",
                BoundaryWorkload(
                    identity="egress",
                    labels=(("org.aptl.zone", "egress"),),
                    ipv4_by_network=(
                        ("management", "10.252.26.20"),
                        ("egress", "10.252.27.20"),
                    ),
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
    for network in _NETWORKS:
        _run(["docker", "network", "rm", network])


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
        creates = tuple(
            _run(
                [
                    "docker",
                    "network",
                    "create",
                    "--driver",
                    "bridge",
                    "--opt",
                    f"com.docker.network.bridge.name={bridge}",
                    "--subnet",
                    subnet,
                    network,
                ]
            )
            for network, bridge, subnet in zip(
                _NETWORKS,
                _BRIDGES,
                ("10.252.24.0/24", "10.252.26.0/24", "10.252.27.0/24"),
                strict=True,
            )
        )
        assert all(result.returncode == 0 for result in creates)
        starts = (
            [
                "docker",
                "run",
                "-d",
                "--name",
                _CONTAINERS[0],
                "--network",
                _NETWORKS[1],
                "--ip",
                "10.252.26.10",
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
                _NETWORKS[2],
                "--ip",
                "10.252.27.20",
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
                _NETWORKS[0],
                "--ip",
                "10.252.24.30",
                _ALPINE,
                "sleep",
                "infinity",
            ],
        )
        assert all(_run(argv).returncode == 0 for argv in starts)
        attached = _run(
            [
                "docker",
                "network",
                "connect",
                "--ip",
                "10.252.26.20",
                _NETWORKS[1],
                _CONTAINERS[1],
            ]
        )
        assert attached.returncode == 0
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
                "http://10.252.26.20:8080/",
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
                "http://10.252.26.20:8080/",
            ],
            timeout=10,
        )
        assert allowed.returncode == 0
        assert denied.returncode != 0

        drift = _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "host",
                "--cap-drop=ALL",
                "--cap-add=NET_ADMIN",
                "--security-opt=no-new-privileges",
                "--entrypoint",
                "nft",
                "aptl-network-boundary-helper:2",
                "flush",
                "chain",
                "inet",
                _table_name(policy.owner, policy.authority),
                "forward",
            ]
        )
        assert drift.returncode == 0
        observation = backend._run_with_input(
            _helper_command("observe"),
            policy.canonical_json(),
            timeout=30,
        )
        assert observation.returncode != 0
    finally:
        _cleanup(backend, policy)


@pytest.mark.skipif(not _docker_available(), reason="docker daemon not available")
def test_raes_owner_acl_allows_declared_port_and_denies_remainder() -> None:
    project_dir = Path(__file__).parents[1]
    backend = DockerComposeBackend(project_dir, project_name="aptl-822-acl-proof")
    network_name = "aptl-822-acl-proof"
    bridge = "ap822acl0"
    source = "aptl-822-acl-source"
    target = "aptl-822-acl-target"
    network = BoundaryNetwork(
        name="transit",
        bridge=bridge,
        ipv4_cidr="10.252.25.0/24",
    )
    rules = (
        DeploymentAclRealization(
            owner_address="provision.node.target",
            owner_resource_type="node",
            owner_name="target",
            name="allow-web",
            order=0,
            direction="in",
            from_network="transit",
            to_network="transit",
            protocol="tcp",
            ports=(8080,),
            action="allow",
        ),
        DeploymentAclRealization(
            owner_address="provision.node.target",
            owner_resource_type="node",
            owner_name="target",
            name="deny-remainder",
            order=1,
            direction="in",
            from_network="transit",
            to_network="transit",
            protocol="any",
            ports=(),
            action="deny",
        ),
    )
    policy = AcesBoundarySpec(
        owner="aptl-822-acl-proof",
        networks=(network,),
        owner_bindings=(
            AcesAclOwnerBinding(
                owner_address="provision.node.target",
                owner_resource_type="node",
                ipv4_by_network=(("transit", "10.252.25.20"),),
            ),
        ),
        rules=rules,
    )
    backend._run_with_input(
        _helper_command("cleanup"),
        policy.canonical_json(),
        timeout=30,
    )
    for container in (source, target):
        _run(["docker", "rm", "-f", container])
    _run(["docker", "network", "rm", network_name])
    try:
        created = _run(
            [
                "docker",
                "network",
                "create",
                "--driver",
                "bridge",
                "--opt",
                f"com.docker.network.bridge.name={bridge}",
                "--subnet",
                "10.252.25.0/24",
                network_name,
            ]
        )
        assert created.returncode == 0
        assert (
            _run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    source,
                    "--network",
                    network_name,
                    "--ip",
                    "10.252.25.10",
                    _ALPINE,
                    "sleep",
                    "infinity",
                ]
            ).returncode
            == 0
        )
        assert (
            _run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    target,
                    "--network",
                    network_name,
                    "--ip",
                    "10.252.25.20",
                    "--entrypoint",
                    "sh",
                    _SERVER,
                    "-c",
                    (
                        "python3 -m http.server 8080 & "
                        "python3 -m http.server 8081 & wait"
                    ),
                ]
            ).returncode
            == 0
        )
        time.sleep(1)
        assert backend.realize_boundary(policy).success is True
        allowed = _run(
            [
                "docker",
                "exec",
                source,
                "wget",
                "-q",
                "-T",
                "3",
                "-O",
                "-",
                "http://10.252.25.20:8080/",
            ],
            timeout=10,
        )
        denied = _run(
            [
                "docker",
                "exec",
                source,
                "wget",
                "-q",
                "-T",
                "3",
                "-O",
                "-",
                "http://10.252.25.20:8081/",
            ],
            timeout=10,
        )
        assert allowed.returncode == 0
        assert denied.returncode != 0
    finally:
        backend._run_with_input(
            _helper_command("cleanup"),
            policy.canonical_json(),
            timeout=30,
        )
        for container in (source, target):
            _run(["docker", "rm", "-f", container])
        _run(["docker", "network", "rm", network_name])
