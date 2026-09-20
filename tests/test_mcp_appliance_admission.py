"""Production transport preserves fresh signed-launch and boundary admission."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from aptl.appliance.seat.observation import build_host_observation
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from aptl.workbench.guest_binding import ApplianceAccessObservation, GuestAdmission
from tests.test_appliance_boundary_inventory import _binding, _guest, _policy
from tests.test_mcp_access import access_record


def test_candidate_admission_requires_explicit_supervisor_trust(tmp_path, monkeypatch):
    from aptl.appliance.candidate import (
        prepare_candidate_launch_descriptor,
        prepare_candidate_manifest,
        seal_candidate,
    )
    from aptl.workbench.dispatch import DispatchSelector
    from aptl.workbench.guest_binding import ApplianceAccessPaths, GuestDispatchBinding
    from tests.test_appliance_candidate import _candidate
    from tests.test_mcp_access import grant

    monkeypatch.setattr(
        "aptl.appliance.candidate.validate_canonical_payload", lambda *_: None
    )
    candidate, template, private, public = _candidate(tmp_path)
    prepare_candidate_manifest(candidate, template)
    seal_candidate(candidate, private)
    descriptor = candidate.parent / "appliance-launch.json"
    prepare_candidate_launch_descriptor(
        candidate, public, descriptor, host_observation_id="sha256:" + "d" * 64
    )
    caller = grant()
    paths = ApplianceAccessPaths(
        launch_descriptor=descriptor,
        release_public_key=public,
        qualification_public_key=public,
        runtime_observation=tmp_path / "observation.json",
    )
    binding = GuestDispatchBinding(
        schema_version="aptl.mcp-dispatch/v1",
        access=access_record(),
        grants=(caller,),
        project_dir=tmp_path,
        node_executable=Path("/usr/bin/node"),
        management_home=tmp_path,
        run_id="c" * 32,
        delivery="appliance",
        appliance=paths,
    )
    path = tmp_path / "binding.json"
    path.write_text(binding.model_dump_json())
    path.chmod(0o600)
    args = (
        path,
        caller.grant_id,
        caller.public_key_fingerprint,
        DispatchSelector("instance-1", 1, "aptl-red"),
    )
    # Mere presence of candidate metadata must never downgrade production trust.
    with pytest.raises(ValueError):
        GuestAdmission(*args)
    candidate_paths = paths.model_copy(update={"candidate_trust": True})
    path.write_text(
        binding.model_copy(update={"appliance": candidate_paths}).model_dump_json()
    )
    original_launch = GuestAdmission(*args).verified_launch
    assert original_launch.release_root == candidate
    from aptl.appliance.access_service import _stage_dispatch_metadata
    import os

    snapshot = _stage_dispatch_metadata(
        GuestAdmission(*args).verified_launch,
        candidate_paths,
        tmp_path / "private-dispatch-trust",
        gid=os.getgid(),
    )
    assert snapshot.candidate_trust is True
    assert snapshot.launch_descriptor.read_bytes() == descriptor.read_bytes()
    assert not list(snapshot.launch_descriptor.parent.rglob("*.qcow2"))
    assert not list(snapshot.launch_descriptor.parent.rglob("offline-payload.tar"))
    path.write_text(
        binding.model_copy(update={"appliance": snapshot}).model_dump_json()
    )
    assert (
        GuestAdmission(*args).verified_launch.descriptor == original_launch.descriptor
    )
    for copied in snapshot.launch_descriptor.parent.rglob("*"):
        assert copied.stat().st_mode & 0o027 == 0  # no group write or other access
    # Admission no longer depends on the host-owned read-only share.
    descriptor.unlink()
    assert GuestAdmission(*args).verified_launch.release_root != candidate
    # The candidate branch still verifies signatures and consumed policy bytes.
    launch = GuestAdmission(*args).verified_launch
    policy = launch.release_root / launch.descriptor.boundary_policy_path
    policy.write_text("{}")
    with pytest.raises(ValueError):
        GuestAdmission(*args)


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
