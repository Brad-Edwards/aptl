"""Lifecycle orchestration for the appliance seat launcher."""

from __future__ import annotations

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.lifecycle import (
    StartSeatOptions,
    _establish_host_access,
    _ensure_overlay,
    _fail_closed_start,
    _seat_paths,
    image_requires_host_access,
    reconcile_seat_after_reboot,
    recover_seat,
    reset_seat,
    stage_seat,
    start_seat,
    status_seat,
    stop_seat,
)
from aptl.appliance.seat.access import GuestAccessBundle
from aptl.appliance.seat.kiosk import open_participant_kiosk
from aptl.appliance.seat.locking import seat_mutation_lock
from aptl.appliance.seat.models import SeatRecord
from aptl.appliance.seat.observation import HostObservationBundle
from aptl.appliance.seat.persistence import load_seat_record, persist_seat_record
from aptl.core import hostenv
from aptl.core.appliance_boundary import GuestPublication
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from aptl.workbench.profiles import WorkbenchConfigurationError
from tests.test_appliance_boundary_inventory import _guest, _policy

pytestmark = pytest.mark.skipif(
    hostenv.host_os() != hostenv.OS_LINUX,
    reason="appliance seat launcher lifecycle is Linux-only",
)


def test_concurrent_lifecycle_mutation_fails_before_touching_seat(
    tmp_path: Path,
) -> None:
    seat_root = tmp_path / "seat"

    def contend() -> str:
        with pytest.raises(SeatLauncherError) as exc:
            stage_seat(
                seat_root,
                seat_id="seat-01",
                image_reference="ghcr.io/owner/seat:latest",
                image_cache_dir=tmp_path / "image-cache",
            )
        return exc.value.code

    with seat_mutation_lock(seat_root), ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(contend).result(timeout=5) == "seat-lifecycle-busy"


def test_seat_lifecycle_lock_is_reentrant_in_one_operation(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"

    with seat_mutation_lock(seat_root), seat_mutation_lock(seat_root):
        assert (seat_root / ".lifecycle.lock").is_file()


def test_host_access_waits_a_bounded_time_for_the_guest(tmp_path: Path) -> None:
    from tests.test_appliance_seat_access import _bundle, _public_key, _request

    request = _request()
    seat_root = tmp_path / "seat"
    paths = _seat_paths(
        seat_root,
        seat_id=request.seat_id,
        image_reference="ghcr.io/owner/seat:latest",
        image_cache_dir=tmp_path / "image-cache",
    )
    paths.launch_dir.mkdir(parents=True)
    identity = tmp_path / "identity"
    identity.write_text("private")
    project = tmp_path / "client"
    project.mkdir()
    options = StartSeatOptions(
        readiness_timeout_seconds=1800,
        access_enrollment=request.enrollment,
        access_identity_file=identity,
        access_project_dir=project,
        access_clients=("claude",),
    )
    bundle = _bundle(_public_key())
    record = SeatRecord(
        schema_version="aptl.seat-record/v2",
        seat_id=request.seat_id,
        instance_id=request.instance_id,
        generation=request.generation,
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:" + "c" * 64,
        launch_descriptor_digest=request.launch_descriptor_digest,
        overlay_path="instances/seat-1.qcow2",
        host_observation_id=request.binding.host_observation_id,
        lifecycle_state="starting",
        taint_state="clean",
        host_boot_id=request.binding.boot_id,
        mappings=(request.outer_endpoint,),
    )
    policy = _policy().model_copy(
        update={
            "guest_publications": (
                *_policy().guest_publications,
                request.guest_endpoint,
            ),
            "host_mcp_contract": "aptl.restricted-ssh-mcp/v1",
        }
    )

    with (
        patch(
            "aptl.appliance.seat.lifecycle.wait_for_guest_access",
            return_value=bundle,
        ) as wait,
        patch("aptl.appliance.seat.lifecycle.persist_host_access_bundle"),
        patch("aptl.appliance.seat.lifecycle.configure_host_clients"),
    ):
        _establish_host_access(
            seat_root=seat_root,
            paths=paths,
            record=record,
            policy=policy,
            binding=request.binding,
            host=HostObservationBundle(
                observation=request.host_observation,
                observation_id=request.binding.host_observation_id,
            ),
            guest=_guest(),
            access_socket=paths.launch_dir / "access.sock",
            options=options,
        )

    # The caller's readiness timeout is the outer bound; the access wait never
    # exceeds it and never runs unbounded.
    timeout = wait.call_args.kwargs["timeout_seconds"]
    assert 0 < timeout <= options.readiness_timeout_seconds


def _resolved_image(tmp_path: Path, policy=None):
    """Build a resolved seat image with a real disk file on disk."""

    from aptl.appliance.seat.image import SeatImageReference
    from aptl.appliance.seat.image_config import SeatImageConfig
    from aptl.appliance.seat.image_selection import SeatImageSelection
    from aptl.appliance.seat.lifecycle import (
        ResolvedSeatImage,
        _canonical_policy_digest,
    )

    resolved_policy = policy if policy is not None else _policy()
    disk = tmp_path / "image-cache" / ("c" * 64) / "seat-disk.qcow2"
    disk.parent.mkdir(parents=True, exist_ok=True)
    disk.write_bytes(b"qcow2")
    config = SeatImageConfig.model_validate(
        {
            "schema_version": "aptl.seat-image/v1",
            "resources": {
                "architecture": "x86_64",
                "vcpus": 8,
                "memory_bytes": 16 * 1024**3,
                "disk_bytes": 100 * 1024**3,
                "hardware_virtualization": True,
                "local_adapter": "qemu-kvm",
                "supported_hypervisors": ["qemu-kvm"],
            },
            "boundary": resolved_policy.model_dump(mode="json"),
            "binding": {
                "boundary_helper_image": "example.test/helper@sha256:" + "e" * 64,
                "egress_proxy_image": "example.test/egress@sha256:" + "f" * 64,
                "raes_plan_digest": "sha256:" + "4" * 64,
            },
        }
    )
    selection = SeatImageSelection(
        reference=SeatImageReference(
            registry="ghcr.io", repository="owner/seat", tag="latest", digest=None
        ),
        digest="sha256:" + "c" * 64,
        size_bytes=5,
        path=disk,
    )
    return ResolvedSeatImage(
        selection=selection,
        config=config,
        policy_digest=_canonical_policy_digest(resolved_policy),
        config_digest="sha256:" + "9" * 64,
    )


def _listener_probe():
    return (
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


def test_host_access_decision_reads_the_image_declaration(tmp_path: Path) -> None:
    # The decision is made from the image's small config blob, before the disk
    # is downloaded at all.
    from aptl.appliance.seat.image import SeatDiskDescriptor, SeatImageReference

    base = _policy()
    mcp_policy = base.model_copy(
        update={
            "host_mcp_contract": "aptl.restricted-ssh-mcp/v1",
            "guest_publications": [
                *base.guest_publications,
                GuestPublication(
                    audience="host-mcp",
                    address="127.0.0.1",
                    port=2222,
                    protocol="tcp",
                ),
            ],
        }
    )
    image = _resolved_image(tmp_path, mcp_policy)
    descriptor = SeatDiskDescriptor(
        reference=SeatImageReference(
            registry="ghcr.io", repository="owner/seat", tag="latest", digest=None
        ),
        digest="sha256:" + "c" * 64,
        size_bytes=5,
        manifest_digest="sha256:" + "8" * 64,
        token=None,
        config_digest="sha256:" + "9" * 64,
        config_size_bytes=64,
    )
    with (
        patch(
            "aptl.appliance.seat.lifecycle.resolve_disk_descriptor",
            return_value=descriptor,
        ),
        patch(
            "aptl.appliance.seat.lifecycle.fetch_seat_image_config",
            return_value=image.config,
        ),
        patch(
            "aptl.appliance.seat.lifecycle.select_seat_image",
            side_effect=AssertionError("the disk must not be fetched to decide"),
        ),
    ):
        assert image_requires_host_access("ghcr.io/owner/seat:latest")


def test_overlay_creation_is_bound_to_image_and_launch_digests(
    tmp_path: Path,
) -> None:
    seat_root = tmp_path / "seat"
    release = seat_root / "release"
    launch = seat_root / "launch"
    release.mkdir(parents=True)
    launch.mkdir()
    public_key = launch / "release-public.pem"
    qualification_key = launch / "qualification-public.pem"
    public_key.write_text("public")
    qualification_key.write_text("qualification")
    paths = _seat_paths(
        seat_root,
        seat_id="seat-01",
        image_reference="ghcr.io/owner/seat:latest",
        image_cache_dir=tmp_path / "image-cache",
    )
    paths.launch_descriptor.write_text("launch")
    record = SeatRecord(
        schema_version="aptl.seat-record/v2",
        seat_id="seat-01",
        instance_id="a" * 32,
        generation=1,
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        launch_descriptor_digest="sha256:" + "d" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="staged",
        taint_state="clean",
        host_boot_id="boot-1",
        mappings=tuple(
            mapping.model_copy(
                update={
                    "guest_address": mapping.address,
                    "guest_port": mapping.port,
                }
            )
            for mapping in _listener_probe()
        ),
    )
    captured = []

    with (
        patch(
            "aptl.appliance.seat.lifecycle.create_seat_overlay",
            side_effect=lambda overlay, *, image_path: captured.append(
                (overlay, image_path)
            ),
        ),
        patch("aptl.appliance.seat.lifecycle.initialize_overlay_state") as initialize,
    ):
        _ensure_overlay(paths, _resolved_image(tmp_path))

    assert len(captured) == 1
    overlay, image_path = captured[0]
    assert overlay == paths.overlay_path
    # The base is the shared cached image, outside this seat root.
    assert image_path.name == "seat-disk.qcow2"
    assert seat_root not in image_path.parents
    initialize.assert_called_once_with(paths.overlay_state_dir)


def test_stage_persists_seat_record(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    seat_root.mkdir()
    release = tmp_path / "release"
    release.mkdir()
    public_key = tmp_path / "release-public.pem"
    qualification_key = tmp_path / "qualification-public.pem"
    public_key.write_text("public")
    qualification_key.write_text("qualification")

    with (
        patch(
            "aptl.appliance.seat.lifecycle.require_host_prerequisites",
            return_value=object(),
        ) as prerequisites,
        patch(
            "aptl.appliance.seat.lifecycle._load_seat_image",
            return_value=_resolved_image(tmp_path),
        ),
        patch(
            "aptl.appliance.seat.lifecycle._launch_descriptor_digest",
            return_value="sha256:" + "d" * 64,
        ),
    ):
        record = stage_seat(
            seat_root,
            seat_id="seat-01",
            image_reference="ghcr.io/owner/seat:latest",
            image_cache_dir=tmp_path / "image-cache",
        )

    assert record.lifecycle_state == "staged"
    assert prerequisites.call_args.kwargs["required_free_disk_bytes"] == 100 * 1024**3
    assert record.schema_version == "aptl.seat-record/v2"
    assert record.generation == 1
    assert {mapping.audience for mapping in record.mappings} == {
        "participant",
        "recovery",
    }
    assert all(mapping.guest_port is not None for mapping in record.mappings)
    # The launcher materializes the exact policy bytes the gate binds to.
    assert (seat_root / "launch" / "boundary-policy.json").exists()
    assert load_seat_record(seat_root) == record


def test_stage_persists_explicit_outer_mapping(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    seat_root.mkdir()
    release = tmp_path / "release"
    release.mkdir()
    public_key = tmp_path / "release-public.pem"
    qualification_key = tmp_path / "qualification-public.pem"
    public_key.write_text("public")
    qualification_key.write_text("qualification")
    mappings = (
        BoundaryEndpoint(
            audience="participant",
            address="127.0.0.1",
            port=10443,
            protocol="tcp",
            guest_address="127.0.0.1",
            guest_port=443,
        ),
        BoundaryEndpoint(
            audience="recovery",
            address="127.0.0.1",
            port=11443,
            protocol="tcp",
            guest_address="127.0.0.1",
            guest_port=9443,
        ),
    )

    with (
        patch(
            "aptl.appliance.seat.lifecycle.require_host_prerequisites",
            return_value=object(),
        ),
        patch(
            "aptl.appliance.seat.lifecycle._load_seat_image",
            return_value=_resolved_image(tmp_path),
        ),
        patch(
            "aptl.appliance.seat.lifecycle._launch_descriptor_digest",
            return_value="sha256:" + "d" * 64,
        ),
    ):
        record = stage_seat(
            seat_root,
            seat_id="seat-01",
            image_reference="ghcr.io/owner/seat:latest",
            image_cache_dir=tmp_path / "image-cache",
            mappings=mappings,
        )

    assert record.mappings == mappings


def test_start_marks_ready_when_boundary_passes(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    seat_root.mkdir()
    release = seat_root / "launch" / "release"
    release.mkdir(parents=True)
    public_key = tmp_path / "release-public.pem"
    qualification_key = tmp_path / "qualification-public.pem"
    public_key.write_text("public")
    qualification_key.write_text("qualification")

    with (
        patch(
            "aptl.appliance.seat.lifecycle.require_host_prerequisites",
            return_value=object(),
        ),
        patch(
            "aptl.appliance.seat.lifecycle._load_seat_image",
            return_value=_resolved_image(tmp_path),
        ),
        patch("aptl.appliance.seat.lifecycle._ensure_overlay"),
        patch("aptl.appliance.seat.lifecycle.require_host_exposure"),
        patch("aptl.appliance.seat.lifecycle.start_vm") as start_vm,
        patch("aptl.appliance.seat.lifecycle.write_vm_pid"),
        patch(
            "aptl.appliance.seat.lifecycle.read_vm_pid",
            side_effect=(None, 4242),
        ),
        patch("aptl.appliance.seat.lifecycle.run_appliance_boundary_gate") as gate,
        patch(
            "aptl.appliance.seat.lifecycle._launch_descriptor_digest",
            return_value="sha256:" + "d" * 64,
        ),
    ):
        start_vm.return_value.pid = 4242
        gate.return_value = type("Result", (), {"passed": True, "findings": ()})()
        record = start_seat(
            seat_root,
            seat_id="seat-01",
            image_reference="ghcr.io/owner/seat:latest",
            image_cache_dir=tmp_path / "image-cache",
            options=StartSeatOptions(
                listener_probe=_listener_probe,
                forbidden_reachability_probe=lambda: True,
                guest_readiness_probe=_guest,
                reserve_outer_mappings=False,
            ),
        )

    assert record.lifecycle_state == "ready"
    # The reservation is what the image declares it needs.
    assert start_vm.call_args.args[0].disk_reservation_bytes == 100 * 1024**3
    gate.assert_called_once()


def test_start_fails_closed_without_real_boundary_probes(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    seat_root.mkdir()
    release = seat_root / "launch" / "release"
    release.mkdir(parents=True)
    public_key = tmp_path / "release-public.pem"
    qualification_key = tmp_path / "qualification-public.pem"
    public_key.write_text("public")
    qualification_key.write_text("qualification")

    with (
        patch(
            "aptl.appliance.seat.lifecycle.require_host_prerequisites",
            return_value=object(),
        ),
        patch(
            "aptl.appliance.seat.lifecycle._load_seat_image",
            return_value=_resolved_image(tmp_path),
        ),
        patch("aptl.appliance.seat.lifecycle._ensure_overlay"),
        patch("aptl.appliance.seat.lifecycle.require_host_exposure"),
        patch("aptl.appliance.seat.lifecycle.start_vm") as start_vm,
        patch("aptl.appliance.seat.lifecycle.write_vm_pid"),
        patch("aptl.appliance.seat.lifecycle.read_vm_pid", return_value=4242),
        patch("aptl.appliance.seat.lifecycle.stop_vm") as stop,
        patch(
            "aptl.appliance.seat.lifecycle._launch_descriptor_digest",
            return_value="sha256:" + "d" * 64,
        ),
    ):
        start_vm.return_value.pid = 4242
        options = StartSeatOptions(
            listener_probe=_listener_probe,
            forbidden_reachability_probe=lambda: False,
            reserve_outer_mappings=False,
        )
        with pytest.raises(SeatLauncherError) as exc:
            start_seat(
                seat_root,
                seat_id="seat-01",
                image_reference="ghcr.io/owner/seat:latest",
                image_cache_dir=tmp_path / "image-cache",
                options=options,
            )

    assert exc.value.code == "boundary.host-forbidden-reachability"
    stop.assert_called_once_with(seat_root)


def test_start_stops_vm_and_preserves_host_access_failure(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    seat_root.mkdir()
    release = seat_root / "launch" / "release"
    release.mkdir(parents=True)
    public_key = tmp_path / "release-public.pem"
    qualification_key = tmp_path / "qualification-public.pem"
    public_key.write_text("public")
    qualification_key.write_text("qualification")

    with (
        patch(
            "aptl.appliance.seat.lifecycle.require_host_prerequisites",
            return_value=object(),
        ),
        patch(
            "aptl.appliance.seat.lifecycle._load_seat_image",
            return_value=_resolved_image(tmp_path),
        ),
        patch("aptl.appliance.seat.lifecycle._ensure_overlay"),
        patch("aptl.appliance.seat.lifecycle.require_host_exposure"),
        patch("aptl.appliance.seat.lifecycle.start_vm") as start_vm,
        patch("aptl.appliance.seat.lifecycle.write_vm_pid"),
        patch("aptl.appliance.seat.lifecycle.read_vm_pid", return_value=4242),
        patch("aptl.appliance.seat.lifecycle.stop_vm") as stop,
        patch("aptl.appliance.seat.lifecycle.run_appliance_boundary_gate") as gate,
        patch(
            "aptl.appliance.seat.lifecycle._establish_host_access",
            side_effect=WorkbenchConfigurationError("transport paths must be absolute"),
        ),
        patch(
            "aptl.appliance.seat.lifecycle._launch_descriptor_digest",
            return_value="sha256:" + "d" * 64,
        ),
    ):
        start_vm.return_value.pid = 4242
        gate.return_value = type("Result", (), {"passed": True, "findings": ()})()
        options = StartSeatOptions(
            listener_probe=_listener_probe,
            forbidden_reachability_probe=lambda: True,
            guest_readiness_probe=_guest,
            reserve_outer_mappings=False,
        )
        with pytest.raises(SeatLauncherError) as exc:
            start_seat(
                seat_root,
                seat_id="seat-01",
                image_reference="ghcr.io/owner/seat:latest",
                image_cache_dir=tmp_path / "image-cache",
                options=options,
            )

    assert exc.value.code == "invalid-host-access"
    stop.assert_called_once_with(seat_root)


def test_failed_start_still_stops_vm_when_access_revocation_fails(
    tmp_path: Path,
) -> None:
    seat_root = tmp_path / "seat"
    paths = _seat_paths(
        seat_root,
        seat_id="seat-01",
        image_reference="ghcr.io/owner/seat:latest",
        image_cache_dir=tmp_path / "image-cache",
    )
    paths.launch_dir.mkdir(parents=True)
    starting = SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="starting",
        taint_state="clean",
        host_boot_id="boot-1",
    )

    with (
        patch(
            "aptl.appliance.seat.lifecycle.invalidate_host_access",
            side_effect=OSError("revocation failed"),
        ),
        patch("aptl.appliance.seat.lifecycle.stop_vm") as stop,
        pytest.raises(SeatLauncherError) as exc,
    ):
        _fail_closed_start(seat_root, paths, starting)

    assert exc.value.code == "failed-start-cleanup"
    stop.assert_called_once_with(seat_root)
    failed = load_seat_record(seat_root)
    assert failed is not None
    assert failed.lifecycle_state == "tainted"


def test_reset_destroys_overlay_and_restage(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    overlay = seat_root / "instances" / "seat-01.qcow2"
    overlay.parent.mkdir(parents=True)
    overlay.write_bytes(b"overlay")
    record = SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="ready",
        taint_state="clean",
        host_boot_id="boot-1",
    )
    persist_seat_record(seat_root, record)
    release = tmp_path / "release"
    release.mkdir()
    public_key = tmp_path / "release-public.pem"
    qualification_key = tmp_path / "qualification-public.pem"
    public_key.write_text("public")
    qualification_key.write_text("qualification")

    with (
        patch("aptl.appliance.seat.lifecycle.stop_vm"),
        patch(
            "aptl.appliance.seat.lifecycle.stage_seat",
            return_value=record.model_copy(update={"lifecycle_state": "staged"}),
        ) as stage,
    ):
        reset_seat(
            seat_root,
            seat_id="seat-01",
            image_reference="ghcr.io/owner/seat:latest",
            image_cache_dir=tmp_path / "image-cache",
        )

    assert not overlay.exists()
    stage.assert_called_once()


def test_reconcile_after_reboot_requires_recovery(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    record = SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="ready",
        taint_state="clean",
        host_boot_id="boot-old",
    )
    persist_seat_record(seat_root, record)

    with (
        patch(
            "aptl.appliance.seat.lifecycle._read_host_boot_id",
            return_value="boot-new",
        ),
        patch("aptl.appliance.seat.lifecycle.read_vm_pid", return_value=None),
        pytest.raises(SeatLauncherError) as exc,
    ):
        reconcile_seat_after_reboot(seat_root)

    assert exc.value.code == "host-reboot-detected"


def test_stop_transitions_ready_to_staged(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    record = SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="ready",
        taint_state="clean",
        host_boot_id="boot-1",
    )
    persist_seat_record(seat_root, record)

    with patch("aptl.appliance.seat.lifecycle.stop_vm"):
        updated = stop_seat(seat_root)

    assert updated.lifecycle_state == "staged"
    assert updated.generation == record.generation + 1

    with patch("aptl.appliance.seat.lifecycle.stop_vm"):
        stopped_again = stop_seat(seat_root)
    assert stopped_again.generation == updated.generation


def test_stop_advances_a_staged_generation_that_already_issued_access(
    tmp_path: Path,
) -> None:
    seat_root = tmp_path / "seat"
    record = SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        instance_id="a" * 32,
        generation=3,
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="staged",
        taint_state="clean",
        host_boot_id="boot-1",
    )
    persist_seat_record(seat_root, record)
    (seat_root / "access" / "generation-3").mkdir(parents=True)

    with patch("aptl.appliance.seat.lifecycle.stop_vm"):
        updated = stop_seat(seat_root)

    assert updated.generation == 4


def test_status_never_includes_credentials(tmp_path: Path) -> None:
    projection = status_seat(tmp_path)

    payload = projection.model_dump(mode="json")
    assert "credential" not in str(payload).lower()
    assert projection.lifecycle_state == "empty"


def test_status_reports_vm_not_running_for_ready_seat(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    record = SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="ready",
        taint_state="clean",
        host_boot_id="boot-1",
    )
    persist_seat_record(seat_root, record)

    with patch("aptl.appliance.seat.lifecycle.read_vm_pid", return_value=None):
        projection = status_seat(seat_root)

    assert projection.diagnostics == ("vm-not-running",)


def test_stop_seat_requires_existing_record(tmp_path: Path) -> None:
    with pytest.raises(SeatLauncherError) as exc:
        stop_seat(tmp_path)

    assert exc.value.code == "corrupt-seat-state"


def test_recover_seat_resets_then_starts(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    release = tmp_path / "release"
    release.mkdir()
    public_key = tmp_path / "release-public.pem"
    qualification_key = tmp_path / "qualification-public.pem"
    public_key.write_text("public")
    qualification_key.write_text("qualification")
    ready = SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="ready",
        taint_state="clean",
        host_boot_id="boot-1",
    )

    with (
        patch("aptl.appliance.seat.lifecycle.reset_seat") as reset,
        patch("aptl.appliance.seat.lifecycle.start_seat", return_value=ready) as start,
    ):
        record = recover_seat(
            seat_root,
            seat_id="seat-01",
            image_reference="ghcr.io/owner/seat:latest",
            image_cache_dir=tmp_path / "image-cache",
        )

    reset.assert_called_once()
    start.assert_called_once()
    assert record.lifecycle_state == "ready"


def test_start_marks_recoverable_failure_when_boundary_fails(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    seat_root.mkdir()
    release = seat_root / "launch" / "release"
    release.mkdir(parents=True)
    public_key = tmp_path / "release-public.pem"
    qualification_key = tmp_path / "qualification-public.pem"
    public_key.write_text("public")
    qualification_key.write_text("qualification")
    staged = SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="staged",
        taint_state="clean",
        host_boot_id="boot-1",
    )
    persist_seat_record(seat_root, staged)

    with (
        patch(
            "aptl.appliance.seat.lifecycle.require_host_prerequisites",
            return_value=object(),
        ),
        patch(
            "aptl.appliance.seat.lifecycle._load_seat_image",
            return_value=_resolved_image(tmp_path),
        ),
        patch("aptl.appliance.seat.lifecycle._ensure_overlay"),
        patch("aptl.appliance.seat.lifecycle.require_host_exposure"),
        patch("aptl.appliance.seat.lifecycle.start_vm") as start_vm,
        patch("aptl.appliance.seat.lifecycle.write_vm_pid"),
        patch(
            "aptl.appliance.seat.lifecycle.read_vm_pid",
            side_effect=(None, 4242),
        ),
        patch(
            "aptl.appliance.seat.lifecycle.collect_loopback_listeners",
            return_value=(),
        ),
        patch(
            "aptl.appliance.seat.lifecycle.host_boundary_findings",
            return_value=("boundary.host-listener-missing",),
        ),
    ):
        start_vm.return_value.pid = 4242
        options = StartSeatOptions(reserve_outer_mappings=False)
        with pytest.raises(SeatLauncherError) as exc:
            start_seat(
                seat_root,
                seat_id="seat-01",
                image_reference="ghcr.io/owner/seat:latest",
                image_cache_dir=tmp_path / "image-cache",
                options=options,
            )

    assert exc.value.code == "boundary.host-listener-missing"
    failed = load_seat_record(seat_root)
    assert failed is not None
    assert failed.lifecycle_state == "recoverable-failure"


def test_reconcile_marks_recoverable_failure_when_vm_missing(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    record = SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        launch_descriptor_digest="sha256:" + "a" * 64,
        overlay_path="instances/seat-01.qcow2",
        host_observation_id="host-1",
        lifecycle_state="ready",
        taint_state="clean",
        host_boot_id="boot-1",
    )
    persist_seat_record(seat_root, record)

    with (
        patch(
            "aptl.appliance.seat.lifecycle._read_host_boot_id",
            return_value="boot-1",
        ),
        patch("aptl.appliance.seat.lifecycle.read_vm_pid", return_value=None),
        pytest.raises(SeatLauncherError) as exc,
    ):
        reconcile_seat_after_reboot(seat_root)

    assert exc.value.code == "vm-not-running"
    updated = load_seat_record(seat_root)
    assert updated is not None
    assert updated.lifecycle_state == "recoverable-failure"


def test_open_participant_kiosk_spawns_browser_when_not_dry_run() -> None:
    with patch("aptl.appliance.seat.kiosk.subprocess.Popen") as popen:
        plan = open_participant_kiosk(
            participant_port=8443,
            browser_command="/usr/bin/browser",
            dry_run=False,
        )

    popen.assert_called_once()
    assert plan.url == "http://127.0.0.1:8443/"
    assert plan.argv[0] == "/usr/bin/browser"
