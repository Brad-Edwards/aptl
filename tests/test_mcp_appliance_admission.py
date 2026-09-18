"""Production transport preserves fresh signed-launch and boundary admission."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from aptl.appliance.seat.observation import build_host_observation
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from aptl.workbench.guest_binding import ApplianceAccessObservation, GuestAdmission
from tests.test_appliance_boundary_inventory import _binding, _guest, _policy
from tests.test_mcp_access import access_record


def test_appliance_transport_checks_freshness_identity_mapping_and_live_probes(
    tmp_path,
):
    policy_data = _policy().model_dump()
    policy_data.update(
        host_mcp_contract="aptl.restricted-ssh-mcp/v1",
        guest_publications=[
            dict(audience="host-mcp", address="127.0.0.1", port=2222, protocol="tcp")
        ],
    )
    policy = type(_policy()).model_validate(policy_data)
    binding = _binding().model_copy(update={"raes_boundary_required": True})
    endpoint = BoundaryEndpoint(
        audience="host-mcp",
        address="127.0.0.1",
        port=30222,
        protocol="tcp",
        guest_address="127.0.0.1",
        guest_port=2222,
    )
    host = build_host_observation(
        binding=binding,
        boot_id=binding.boot_id,
        listeners=(endpoint,),
        forbidden_reachability_passed=True,
    )
    binding = binding.model_copy(update={"host_observation_id": host.observation_id})
    guest = _guest()
    guest = guest.model_copy(
        update={
            "enforcements": (
                *guest.enforcements,
                guest.enforcements[0].model_copy(
                    update={
                        "authority": "raes",
                        "source_digest": binding.raes_plan_digest,
                    }
                ),
            ),
            "probes": (
                *guest.probes,
                *(
                    probe.model_copy(
                        update={
                            "identity": "raes-" + probe.identity,
                            "authority": "raes",
                        }
                    )
                    for probe in guest.probes
                ),
            ),
        }
    )
    observed = ApplianceAccessObservation(
        schema_version="aptl.mcp-boundary-observation/v1",
        observed_at=datetime.now(UTC),
        binding=binding,
        host=host.observation,
        guest=guest,
    )
    path = tmp_path / "boundary.json"
    path.write_text(observed.model_dump_json())
    path.chmod(0o600)
    # This unit test starts after signature verification. It exercises the real
    # boundary verifier; synthetic observations are never release evidence.
    admission = object.__new__(GuestAdmission)
    admission.binding = SimpleNamespace(
        access=access_record(guest_boot_id="boot-42", guest_daemon_id="daemon-42"),
        appliance=SimpleNamespace(runtime_observation=path),
    )
    admission.verified_launch = SimpleNamespace(
        boundary_policy=policy,
        descriptor=SimpleNamespace(
            boundary_policy_digest=binding.policy_digest,
            payload_digest=binding.payload_digest,
            participant_routes_digest=binding.raes_plan_digest,
            boundary_helper_image=binding.boundary_helper_image,
            egress_proxy_image=binding.egress_proxy_image,
            host_observation_id=binding.host_observation_id,
        ),
    )
    admission._verify_appliance_observation()
    for changes in (
        {"observed_at": datetime.now(UTC) - timedelta(seconds=30)},
        {"binding": binding.model_copy(update={"guest_daemon_id": "other"})},
        {"guest": guest.model_copy(update={"probes": ()})},
        {
            "host": host.observation.model_copy(
                update={"listeners": (endpoint.model_copy(update={"port": 30223}),)}
            )
        },
    ):
        path.write_text(observed.model_copy(update=changes).model_dump_json())
        with pytest.raises(ValueError):
            admission._verify_appliance_observation()
