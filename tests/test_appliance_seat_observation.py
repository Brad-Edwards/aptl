"""Host observation helpers for the appliance seat launcher."""

from __future__ import annotations

from aptl.core.appliance_boundary import ApplianceBoundaryBinding
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from aptl.appliance.seat.observation import (
    build_host_observation,
    host_boundary_findings,
    map_publications_to_listeners,
    observation_id_for,
)
from tests.test_appliance_boundary_inventory import _policy


def _binding(observation_id: str) -> ApplianceBoundaryBinding:
    return ApplianceBoundaryBinding(
        policy_digest="sha256:" + "1" * 64,
        payload_digest="sha256:" + "2" * 64,
        raes_plan_digest="sha256:" + "4" * 64,
        raes_boundary_required=False,
        boundary_helper_image="example.test/aptl-boundary@sha256:" + "5" * 64,
        egress_proxy_image="example.test/aptl-egress@sha256:" + "6" * 64,
        boot_id="boot-42",
        guest_daemon_id="daemon-42",
        host_observation_id=observation_id,
    )


def test_observation_id_is_stable_when_complete_flag_changes() -> None:
    policy = _policy()
    binding = _binding("pending")
    listeners = (
        BoundaryEndpoint(
            audience="participant",
            address="127.0.0.1",
            port=443,
            protocol="tcp",
        ),
        BoundaryEndpoint(
            audience="recovery",
            address="127.0.0.1",
            port=9443,
            protocol="tcp",
        ),
    )
    partial = build_host_observation(
        policy=policy,
        binding=binding,
        boot_id="boot-42",
        listeners=listeners,
        forbidden_reachability_passed=True,
        complete=False,
    )
    complete = build_host_observation(
        policy=policy,
        binding=binding,
        boot_id="boot-42",
        listeners=listeners,
        forbidden_reachability_passed=True,
        complete=True,
    )

    assert observation_id_for(partial.observation) == observation_id_for(
        complete.observation
    )


def test_map_publications_to_listeners() -> None:
    policy = _policy()
    observed = (
        BoundaryEndpoint(
            audience="participant",
            address="127.0.0.1",
            port=443,
            protocol="tcp",
        ),
    )

    mapped = map_publications_to_listeners(policy, observed)

    assert len(mapped) == 1
    assert mapped[0].audience == "participant"


def test_host_boundary_findings_detect_missing_recovery_listener() -> None:
    policy = _policy()
    listeners = (
        BoundaryEndpoint(
            audience="participant",
            address="127.0.0.1",
            port=443,
            protocol="tcp",
        ),
    )
    bundle = build_host_observation(
        policy=policy,
        binding=_binding("pending"),
        boot_id="boot-42",
        listeners=listeners,
        forbidden_reachability_passed=True,
        complete=True,
    )
    binding = _binding(bundle.observation_id)

    findings = host_boundary_findings(policy, binding, bundle.observation)

    assert "boundary.host-listener-missing" in findings
