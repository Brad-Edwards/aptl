"""The image and boot paths share one fatal boundary gate."""

import hashlib
import json

import pytest

from aptl.core.appliance_boundary import ApplianceBoundaryBinding
from aptl.core.appliance_boundary_gate import run_appliance_boundary_gate
from aptl.core.appliance_boundary_inventory import (
    BoundaryEnforcementObservation,
    BoundaryEndpoint,
    BoundaryProbeObservation,
    GuestBoundaryObservation,
    HostBoundaryObservation,
)


def _payload() -> bytes:
    return json.dumps(
        {
            "schema_version": "aptl.appliance-boundary/v1",
            "policy_id": "default",
            "generation": 1,
            "workbench_policy_version": "participant-workbench-profile/v1",
            "default_deny": True,
            "platform_networks": {
                "participant": "org.aptl.network=participant",
                "management": "org.aptl.network=management",
                "egress": "org.aptl.network=egress",
            },
            "platform_anchors": {
                "participant": "org.aptl.zone=participant",
                "management": "org.aptl.zone=management",
                "egress": "org.aptl.zone=egress",
            },
            "fixed_crossings": [],
            "egress_authorities": [],
            "egress_proxy_limits": {
                "max_connections": 32,
                "max_header_bytes": 4096,
                "header_timeout_seconds": 5,
                "connect_timeout_seconds": 10,
                "idle_timeout_seconds": 60,
            },
            "guest_publications": [
                {
                    "audience": "participant",
                    "address": "127.0.0.1",
                    "port": 443,
                    "protocol": "tcp",
                }
            ],
            "docker_authority": {
                "allowed_holder_labels": [],
                "require_guest_daemon": True,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _binding(payload: bytes) -> ApplianceBoundaryBinding:
    return ApplianceBoundaryBinding(
        policy_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
        payload_digest="sha256:" + "b" * 64,
        raes_plan_digest="sha256:" + "d" * 64,
        raes_boundary_required=False,
        boundary_helper_image="example.test/aptl-boundary@sha256:" + "e" * 64,
        egress_proxy_image="example.test/aptl-egress@sha256:" + "f" * 64,
        boot_id="boot-1",
        guest_daemon_id="daemon-1",
        host_observation_id="host-1",
    )


def _host(binding: ApplianceBoundaryBinding) -> HostBoundaryObservation:
    return HostBoundaryObservation(
        observation_id="host-1",
        policy_digest=binding.policy_digest,
        payload_digest=binding.payload_digest,
        boot_id="boot-1",
        complete=True,
        listeners=(
            BoundaryEndpoint(
                audience="participant",
                address="127.0.0.1",
                port=443,
                protocol="tcp",
            ),
        ),
        forbidden_reachability_passed=True,
    )


class _Adapter:
    def __init__(self, binding: ApplianceBoundaryBinding) -> None:
        self.binding = binding
        self.phases: list[str] = []

    def materialize_and_observe_boundary(self, policy, binding, *, phase):
        assert binding == self.binding
        assert policy.default_deny is True
        self.phases.append(phase)
        return GuestBoundaryObservation(
            policy_digest=binding.policy_digest,
            raes_plan_digest=binding.raes_plan_digest,
            boot_id=binding.boot_id,
            guest_daemon_id=binding.guest_daemon_id,
            workbench_policy_version="participant-workbench-profile/v1",
            enforcements=(
                BoundaryEnforcementObservation(
                    authority="platform",
                    source_digest=binding.policy_digest,
                    enforcement_digest="sha256:" + "c" * 64,
                    families=("bridge", "inet"),
                    default_deny_observed=True,
                ),
            ),
            observation_complete=True,
            probes=(
                BoundaryProbeObservation(
                    identity="declared-crossing",
                    authority="platform",
                    source="management",
                    destination="egress",
                    protocol="tcp",
                    port=3128,
                    expectation="reachable",
                    passed=True,
                ),
                BoundaryProbeObservation(
                    identity="forbidden-crossing",
                    authority="platform",
                    source="participant",
                    destination="management",
                    protocol="tcp",
                    port=443,
                    expectation="blocked",
                    passed=True,
                ),
            ),
            docker_authority_holders=(),
        )


@pytest.mark.parametrize("phase", ["image-qualification", "start"])
def test_both_phases_use_the_same_verifier(tmp_path, phase) -> None:
    payload = _payload()
    path = tmp_path / "boundary.json"
    path.write_bytes(payload)
    binding = _binding(payload)
    adapter = _Adapter(binding)

    result = run_appliance_boundary_gate(
        policy_path=path,
        binding=binding,
        host_observation=_host(binding),
        adapter=adapter,
        phase=phase,
    )

    assert result.passed is True
    assert result.inventory["phase"] == phase
    assert adapter.phases == [phase]


def test_gate_never_substitutes_for_missing_host_observation(tmp_path) -> None:
    payload = _payload()
    path = tmp_path / "boundary.json"
    path.write_bytes(payload)
    binding = _binding(payload)

    result = run_appliance_boundary_gate(
        policy_path=path,
        binding=binding,
        host_observation=None,
        adapter=_Adapter(binding),
        phase="start",
    )

    assert result.passed is False
    assert result.findings == ("boundary.host-observation-missing",)
