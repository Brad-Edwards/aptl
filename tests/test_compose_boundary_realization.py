"""Authority-preserving external nftables lifecycle for APP-1."""

import json
from unittest.mock import MagicMock

from aptl.core.deployment.boundary import (
    BoundaryNetwork,
    BoundaryWorkload,
    PlatformBoundarySpec,
    PlatformCrossing,
)
from aptl.core.deployment.docker_compose import DockerComposeBackend


def _spec() -> PlatformBoundarySpec:
    return PlatformBoundarySpec(
        owner="seat-17",
        policy_digest="sha256:" + "a" * 64,
        networks=(
            BoundaryNetwork(name="participant-net", bridge="br-part"),
            BoundaryNetwork(name="transit", bridge="br-transit"),
        ),
        anchors=(
            (
                "participant",
                BoundaryWorkload(
                    identity="participant-gateway",
                    labels=(("org.aptl.zone", "participant"),),
                    ipv4_by_network=(("participant-net", "10.50.1.10"),),
                ),
            ),
            (
                "management",
                BoundaryWorkload(
                    identity="management-agent",
                    labels=(("org.aptl.zone", "management"),),
                    ipv4_by_network=(("transit", "10.50.2.10"),),
                ),
            ),
            (
                "egress",
                BoundaryWorkload(
                    identity="egress-proxy",
                    labels=(("org.aptl.zone", "egress"),),
                    ipv4_by_network=(("transit", "10.50.2.20"),),
                ),
            ),
        ),
        crossings=(
            PlatformCrossing(
                source="management",
                destination="egress",
                protocol="tcp",
                ports=(3128,),
                purpose="model-proxy",
            ),
        ),
        egress_ports=(443,),
    )


def _receipt(spec: PlatformBoundarySpec) -> dict[str, object]:
    return {
        "authority": "platform",
        "owner": "seat-17",
        "enforcement_digest": spec.digest(),
        "families": ["bridge", "inet"],
        "default_deny": True,
    }


def test_boundary_is_applied_on_daemon_host_not_workload_namespace(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="seat-17")
    backend._run = MagicMock(return_value=MagicMock(returncode=0))
    backend._run_with_input = MagicMock()
    backend._run_with_input.side_effect = [
        MagicMock(returncode=0, stdout="", stderr=""),
        MagicMock(returncode=0, stdout=json.dumps(_receipt(_spec())), stderr=""),
    ]

    receipt = backend.realize_boundary(_spec())

    assert receipt.success is True
    apply_cmd = backend._run_with_input.call_args_list[0].args[0]
    assert apply_cmd[:5] == [
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
    ]
    assert "--cap-add=NET_ADMIN" in apply_cmd
    assert "--privileged" not in apply_cmd
    assert "--read-only" in apply_cmd
    assert "nsenter" not in apply_cmd
    assert "/var/run/docker.sock" not in apply_cmd


def test_boundary_readback_mismatch_fails_closed(tmp_path) -> None:
    backend = DockerComposeBackend(tmp_path, project_name="seat-17")
    backend._run = MagicMock(return_value=MagicMock(returncode=0))
    backend._run_with_input = MagicMock()
    backend._run_with_input.side_effect = [
        MagicMock(returncode=0, stdout="", stderr=""),
        MagicMock(
            returncode=0,
            stdout=json.dumps(
                {
                    **_receipt(_spec()),
                    "enforcement_digest": "sha256:" + "0" * 64,
                }
            ),
            stderr="",
        ),
    ]

    receipt = backend.realize_boundary(_spec())

    assert receipt.success is False
    assert receipt.error == "Boundary policy readback did not match desired state."
