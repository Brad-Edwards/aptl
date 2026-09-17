"""Host MCP publication is explicit and keeps guest/outer ports distinct."""

import json

import pytest
from pydantic import ValidationError


def test_mcp_publication_requires_supported_policy_and_bound_port_mapping():
    from aptl.appliance.seat.observation import (
        build_host_observation,
        host_boundary_findings,
    )
    from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
    from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
    from tests.test_appliance_boundary_inventory import _policy
    from tests.test_appliance_seat_observation import _binding

    data = _policy().model_dump()
    data["guest_publications"] = [
        dict(audience="host-mcp", address="127.0.0.1", port=2222, protocol="tcp")
    ]
    with pytest.raises(ValidationError):
        ApplianceBoundaryPolicy.model_validate(data)
    data["host_mcp_contract"] = "aptl.restricted-ssh-mcp/v1"
    policy = ApplianceBoundaryPolicy.model_validate(data)
    endpoint = BoundaryEndpoint(
        audience="host-mcp",
        address="127.0.0.1",
        port=3222,
        protocol="tcp",
        guest_address="127.0.0.1",
        guest_port=2222,
    )
    observed = build_host_observation(
        binding=_binding("pending"),
        boot_id="boot-42",
        listeners=(endpoint,),
        forbidden_reachability_passed=True,
    )
    assert (
        host_boundary_findings(
            policy, _binding(observed.observation_id), observed.observation
        )
        == ()
    )
    wrong = endpoint.model_copy(update={"guest_port": 2223})
    tampered = observed.observation.model_copy(update={"listeners": (wrong,)})
    assert "boundary.host-listener-unapproved" in host_boundary_findings(
        policy, _binding(observed.observation_id), tampered
    )


def test_release_extension_requires_signed_inputs_and_retains_all_existing_artifacts():
    from aptl.appliance.models import ApplianceReleaseManifest
    from tests.test_appliance_release_manifest import _artifact, _manifest

    document = _manifest().model_dump(mode="json")
    document["delivery"].update(
        canonical_inputs_digest="sha256:" + "a" * 64,
        host_mcp_contract="aptl.restricted-ssh-mcp/v1",
    )
    with pytest.raises(ValidationError):
        ApplianceReleaseManifest.model_validate_json(json.dumps(document))
    document["artifacts"].append(
        _artifact(
            "canonical-inputs", "canonical-inputs", "artifacts/inputs.json"
        ).model_dump(mode="json")
    )
    admitted = ApplianceReleaseManifest.model_validate_json(json.dumps(document))
    assert admitted.delivery.host_mcp_contract == "aptl.restricted-ssh-mcp/v1"
    document["artifacts"] = [
        item for item in document["artifacts"] if item["kind"] != "machine-drill"
    ]
    with pytest.raises(ValidationError):
        ApplianceReleaseManifest.model_validate_json(json.dumps(document))
