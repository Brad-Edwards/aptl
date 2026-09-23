"""Production transport preserves fresh signed-launch and boundary admission."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
import hashlib

import rfc8785

import pytest

from aptl.appliance.seat.observation import build_host_observation
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from aptl.workbench.guest_binding import ApplianceAccessObservation, GuestAdmission
from tests.test_appliance_boundary_inventory import _binding, _guest, _policy
from tests.test_mcp_access import access_record, grant
from aptl.workbench.dispatch import DispatchSelector
from aptl.workbench.guest_binding import GuestDispatchBinding, ApplianceAccessPaths
from aptl.appliance.seat.launch_descriptor import SeatLaunchDescriptor


@pytest.mark.parametrize("vm_only", [False, True])
def test_appliance_transport_checks_freshness_identity_mapping_and_live_probes(
    tmp_path,
    vm_only,
):
    from aptl.appliance.policy import full_techvault_boundary_policy

    policy_data = (
        full_techvault_boundary_policy() if vm_only else _policy()
    ).model_dump()
    policy_data.update(
        host_mcp_contract="aptl.restricted-ssh-mcp/v1",
        guest_publications=[
            dict(audience="host-mcp", address="127.0.0.1", port=2222, protocol="tcp")
        ],
    )
    policy = type(_policy()).model_validate(policy_data)
    binding = _binding().model_copy(
        update={
            "policy_digest": "sha256:" + hashlib.sha256(rfc8785.dumps(policy.model_dump(mode="json"))).hexdigest(),
            "boot_id": "host-boot-42",
            "host_boot_id": "host-boot-42",
            "guest_boot_id": "boot-42",
            "raes_boundary_required": not vm_only,
        }
    )
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
    guest = guest.model_copy(update={
        "policy_digest": binding.policy_digest,
        "enforcements": tuple(item.model_copy(update={"source_digest": binding.policy_digest})
                              for item in guest.enforcements),
    })
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
    if vm_only:
        guest = guest.model_copy(update={"enforcements": (), "probes": ()})
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
    # Construct admission through the real launch verifier and its tuple API.
    launch_path = tmp_path / "appliance-launch.json"
    descriptor = SeatLaunchDescriptor(
        schema_version="aptl.appliance-launch/v2",
        image_reference="ghcr.io/brad-edwards/aptl-seat:fixture",
        image_digest=binding.payload_digest,
        image_config_digest="sha256:" + "f" * 64,
        boundary_policy_digest=binding.policy_digest,
        participant_routes_digest=binding.raes_plan_digest,
        boundary_helper_image=binding.boundary_helper_image,
        egress_proxy_image=binding.egress_proxy_image,
        host_observation_id=binding.host_observation_id,
        host_mcp_contract="aptl.restricted-ssh-mcp/v1",
    )
    launch_path.write_text(descriptor.model_dump_json())
    (tmp_path / "boundary-policy.json").write_bytes(
        rfc8785.dumps(policy.model_dump(mode="json"))
    )
    caller = grant(profile="red")
    access = access_record(guest_boot_id="boot-42", guest_daemon_id="daemon-42")
    dispatch = GuestDispatchBinding(
        schema_version="aptl.mcp-dispatch/v1", access=access, grants=(caller,),
        project_dir=tmp_path, management_home=tmp_path,
        node_executable=Path("/usr/bin/node"), run_id="c" * 32,
        delivery="appliance", appliance=ApplianceAccessPaths(
            launch_descriptor=launch_path, runtime_observation=path,
        ),
    )
    dispatch_path = tmp_path / "dispatch.json"
    dispatch_path.write_text(dispatch.model_dump_json())
    dispatch_path.chmod(0o600)
    admission = GuestAdmission(
        dispatch_path, caller.grant_id, caller.public_key_fingerprint,
        DispatchSelector(access.instance_id, access.generation, "aptl-red"),
    )
    admission._verify_appliance_observation()
    # The supervisor's complete Docker and boundary observation cycle takes
    # longer than five seconds on a loaded appliance. Admission must retain the
    # most recent completed cycle while still rejecting genuinely stale state.
    path.write_text(
        observed.model_copy(
            update={"observed_at": datetime.now(UTC) - timedelta(seconds=10)}
        ).model_dump_json()
    )
    admission._verify_appliance_observation()
    for changes in (
        {"observed_at": datetime.now(UTC) - timedelta(seconds=30)},
        {"binding": binding.model_copy(update={"guest_daemon_id": "other"})},
        {
            "guest": guest.model_copy(
                update={"observation_complete": False} if vm_only else {"probes": ()}
            )
        },
        {
            "host": host.observation.model_copy(
                update={"listeners": (endpoint.model_copy(update={"port": 30223}),)}
            )
        },
    ):
        path.write_text(observed.model_copy(update=changes).model_dump_json())
        with pytest.raises(ValueError):
            admission._verify_appliance_observation()
