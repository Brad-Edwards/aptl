"""Guest-side active boundary observation coverage."""

from pathlib import Path
from types import SimpleNamespace
from subprocess import CompletedProcess
from unittest.mock import patch

from aptl.appliance.guest_observation import (
    _ProbePath,
    _probe_command,
    _read_guest_boot_id,
    collect_guest_observation,
)
from aptl.core.appliance_boundary_inventory import BoundaryProbeObservation
from aptl.core.deployment.boundary_compiler import compile_platform_boundary
from tests.test_compose_platform_boundary import _binding, _inspect, _network, _policy


class _Backend:
    _docker_daemon_id = "daemon-42"

    def __init__(self) -> None:
        self._rows = [
            {"id": "participant", "name": "aptl-participant", "state": "running"},
            {"id": "management", "name": "aptl-management", "state": "running"},
            {"id": "egress", "name": "aptl-egress", "state": "running"},
        ]
        self._placements = {
            "participant": (
                "aptl-participant",
                (("seat_participant", "10.50.1.10"),),
                {"org.aptl.zone": "participant"},
            ),
            "management": (
                "aptl-management",
                (("seat_management", "10.50.2.20"),),
                {"org.aptl.zone": "management"},
            ),
            "egress": (
                "aptl-egress",
                (
                    ("seat_management", "10.50.2.30"),
                    ("seat_egress", "10.50.3.30"),
                ),
                {"org.aptl.zone": "egress"},
            ),
        }

    def host_list_lab_containers(self):
        return self._rows

    def container_inspect(self, container: str):
        name, placements, labels = self._placements[container]
        inspection = _inspect(*placements)
        inspection.update(
            {
                "Id": container,
                "Name": "/" + name,
                "Config": {"Labels": labels},
                "HostConfig": {},
            }
        )
        return inspection

    def _run(self, command, *, timeout=None):
        del command, timeout
        return SimpleNamespace(returncode=1, stdout="")


def _platform_spec():
    policy = _policy()
    networks = tuple(
        _network(name)
        for name in ("seat_participant", "seat_management", "seat_egress")
    )
    from aptl.core.deployment._compose_boundary_realization import (
        _network_observation,
    )
    from aptl.core.deployment.boundary import BoundaryWorkload

    observed_networks = tuple(
        _network_observation(name, detail)
        for name, detail in zip(
            ("seat_participant", "seat_management", "seat_egress"),
            networks,
            strict=True,
        )
    )
    workloads = (
        BoundaryWorkload(
            identity="aptl-participant",
            labels=(("org.aptl.zone", "participant"),),
            ipv4_by_network=(("seat_participant", "10.50.1.10"),),
        ),
        BoundaryWorkload(
            identity="aptl-management",
            labels=(("org.aptl.zone", "management"),),
            ipv4_by_network=(("seat_management", "10.50.2.20"),),
        ),
        BoundaryWorkload(
            identity="aptl-egress",
            labels=(("org.aptl.zone", "egress"),),
            ipv4_by_network=(
                ("seat_egress", "10.50.3.30"),
                ("seat_management", "10.50.2.30"),
            ),
        ),
    )
    return compile_platform_boundary(
        policy,
        policy_digest=_binding().policy_digest,
        networks=observed_networks,
        workloads=workloads,
        owner="seat",
    )


def test_guest_observation_requires_real_positive_and_negative_probes() -> None:
    policy = _policy()
    binding = _binding().model_copy(update={"raes_boundary_required": False})
    spec = _platform_spec()
    receipts = {
        "platform": {
            "source_digest": binding.policy_digest,
            "enforcement_digest": spec.digest(),
            "families": ("bridge", "inet"),
            "default_deny": True,
        }
    }

    def observed(_backend, path: _ProbePath, *, image: str):
        del image
        return BoundaryProbeObservation(
            identity=path.identity,
            authority="platform",
            source=path.source.name,
            destination=path.destination.name,
            protocol="tcp",
            port=path.port,
            expectation=path.expectation,
            passed=True,
        )

    with patch("aptl.appliance.guest_observation._probe_path", side_effect=observed):
        result = collect_guest_observation(
            backend=_Backend(),
            policy=policy,
            binding=binding,
            boundary_specs={"platform": spec},
            boundary_receipts=receipts,
            realization=SimpleNamespace(nodes=(), docker_authority_admissions=()),
        )

    assert result.observation_complete is True
    assert {probe.expectation for probe in result.probes} == {"reachable", "blocked"}
    assert result.guest_daemon_id == "daemon-42"
    assert result.boot_id == _read_guest_boot_id()


def test_guest_boot_identity_has_a_portable_fallback() -> None:
    observed = CompletedProcess(
        ["sysctl"], 0, stdout="{ sec = 1790000000, usec = 0 }\n", stderr=""
    )
    with (
        patch("pathlib.Path.read_text", side_effect=OSError),
        patch("aptl.appliance.guest_observation.subprocess.run", return_value=observed),
    ):
        first = _read_guest_boot_id()
        second = _read_guest_boot_id()

    assert first == second
    assert first.startswith("sha256:")


def test_probe_command_joins_only_the_observed_container_namespace() -> None:
    command = _probe_command(
        image="example.test/helper@sha256:" + "a" * 64,
        network_container="aptl-management",
        arguments=["connect", "--address", "10.50.2.30", "--port", "3128"],
    )

    assert command[:6] == [
        "docker",
        "run",
        "--rm",
        "--network",
        "container:aptl-management",
        "--cap-drop=ALL",
    ]
    assert "--privileged" not in command
    assert "/var/run/docker.sock" not in command
