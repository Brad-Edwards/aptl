"""Lifecycle orchestration for the appliance seat launcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from aptl.appliance.manifest import ApplianceReleaseInspection
from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.lifecycle import (
    open_participant_kiosk,
    reconcile_seat_after_reboot,
    recover_seat,
    reset_seat,
    stage_seat,
    start_seat,
    status_seat,
    stop_seat,
)
from aptl.appliance.seat.models import SeatRecord
from aptl.appliance.seat.persistence import load_seat_record, persist_seat_record
from aptl.core import hostenv
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint
from tests.test_appliance_boundary_inventory import _policy

pytestmark = pytest.mark.skipif(
    hostenv.host_os() != hostenv.OS_LINUX,
    reason="appliance seat launcher lifecycle is Linux-only",
)


def _inspection() -> ApplianceReleaseInspection:
    return ApplianceReleaseInspection(
        release_id="aptl-v5.1.1-x86_64",
        aptl_version="5.1.1",
        source_commit="1" * 40,
        manifest_digest="sha256:" + "a" * 64,
        payload_digest="sha256:" + "b" * 64,
        artifact_count=9,
        architecture="x86_64",
        minimum_host_vcpus=8,
        minimum_host_memory_bytes=16 * 1024**3,
        minimum_host_disk_bytes=100 * 1024**3,
    )


def _manifest_stub():
    from types import SimpleNamespace

    publication = SimpleNamespace(
        audience="participant",
        address="127.0.0.1",
        port=443,
        protocol="tcp",
    )
    recovery = SimpleNamespace(
        audience="recovery",
        address="127.0.0.1",
        port=9443,
        protocol="tcp",
    )
    artifact = SimpleNamespace(kind="boundary-policy", path="policy/boundary.json")
    golden = SimpleNamespace(
        kind="golden-disk",
        path="artifacts/golden.qcow2",
        sha256="sha256:" + "c" * 64,
    )
    return SimpleNamespace(
        host_prerequisites=SimpleNamespace(
            vcpus=8,
            memory_bytes=16 * 1024**3,
        ),
        boundary=SimpleNamespace(
            policy_digest="sha256:" + "1" * 64,
            boundary_helper_image="example.test/helper@sha256:" + "e" * 64,
            egress_proxy_image="example.test/egress@sha256:" + "f" * 64,
        ),
        payload_digest="sha256:" + "2" * 64,
        delivery=SimpleNamespace(participant_routes_digest="sha256:" + "4" * 64),
        artifacts=(artifact, golden),
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
        ),
        patch(
            "aptl.appliance.seat.lifecycle._load_verified_release",
            return_value=(_inspection(), _policy()),
        ),
        patch(
            "aptl.appliance.seat.lifecycle._load_release_documents",
            return_value=(_manifest_stub(), object()),
        ),
        patch("aptl.appliance.seat.lifecycle.prepare_launch_descriptor"),
        patch(
            "aptl.appliance.seat.lifecycle._launch_descriptor_digest",
            return_value="sha256:" + "d" * 64,
        ),
    ):
        record = stage_seat(
            seat_root,
            seat_id="seat-01",
            release_dir=release,
            release_public_key=public_key,
            qualification_public_key=qualification_key,
        )

    assert record.lifecycle_state == "staged"
    assert load_seat_record(seat_root) == record


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
            "aptl.appliance.seat.lifecycle._load_verified_release",
            return_value=(_inspection(), _policy()),
        ),
        patch(
            "aptl.appliance.seat.lifecycle._load_release_documents",
            return_value=(_manifest_stub(), object()),
        ),
        patch("aptl.appliance.seat.lifecycle._ensure_overlay"),
        patch("aptl.appliance.seat.lifecycle.require_host_exposure"),
        patch("aptl.appliance.seat.lifecycle.start_vm") as start_vm,
        patch("aptl.appliance.seat.lifecycle.write_vm_pid"),
        patch("aptl.appliance.seat.lifecycle.read_vm_pid", return_value=4242),
        patch("aptl.appliance.seat.lifecycle.prepare_launch_descriptor"),
        patch(
            "aptl.appliance.seat.lifecycle._launch_descriptor_digest",
            return_value="sha256:" + "d" * 64,
        ),
    ):
        start_vm.return_value.pid = 4242
        record = start_seat(
            seat_root,
            seat_id="seat-01",
            release_dir=release,
            release_public_key=public_key,
            qualification_public_key=qualification_key,
            listener_probe=_listener_probe,
        )

    assert record.lifecycle_state == "ready"


def test_reset_destroys_overlay_and_restage(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    overlay = seat_root / "instances" / "seat-01.qcow2"
    overlay.parent.mkdir(parents=True)
    overlay.write_bytes(b"overlay")
    record = SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        selected_release_id="aptl-v1",
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
            release_dir=release,
            release_public_key=public_key,
            qualification_public_key=qualification_key,
        )

    assert not overlay.exists()
    stage.assert_called_once()


def test_reconcile_after_reboot_requires_recovery(tmp_path: Path) -> None:
    seat_root = tmp_path / "seat"
    record = SeatRecord(
        schema_version="aptl.seat-record/v1",
        seat_id="seat-01",
        selected_release_id="aptl-v1",
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
        selected_release_id="aptl-v1",
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
        selected_release_id="aptl-v1",
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
        selected_release_id="aptl-v1",
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
            release_dir=release,
            release_public_key=public_key,
            qualification_public_key=qualification_key,
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
        selected_release_id="aptl-v1",
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
            "aptl.appliance.seat.lifecycle._load_verified_release",
            return_value=(_inspection(), _policy()),
        ),
        patch(
            "aptl.appliance.seat.lifecycle._load_release_documents",
            return_value=(_manifest_stub(), object()),
        ),
        patch("aptl.appliance.seat.lifecycle._ensure_overlay"),
        patch("aptl.appliance.seat.lifecycle.require_host_exposure"),
        patch("aptl.appliance.seat.lifecycle.start_vm") as start_vm,
        patch("aptl.appliance.seat.lifecycle.write_vm_pid"),
        patch("aptl.appliance.seat.lifecycle.read_vm_pid", return_value=None),
        patch(
            "aptl.appliance.seat.lifecycle.collect_loopback_listeners",
            return_value=(),
        ),
        patch(
            "aptl.appliance.seat.lifecycle.host_boundary_findings",
            return_value=("boundary.host-listener-missing",),
        ),
        pytest.raises(SeatLauncherError) as exc,
    ):
        start_vm.return_value.pid = 4242
        start_seat(
            seat_root,
            seat_id="seat-01",
            release_dir=release,
            release_public_key=public_key,
            qualification_public_key=qualification_key,
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
        selected_release_id="aptl-v1",
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
    with patch("aptl.appliance.seat.lifecycle.subprocess.Popen") as popen:
        plan = open_participant_kiosk(
            participant_port=8443,
            browser_command="/usr/bin/browser",
            dry_run=False,
        )

    popen.assert_called_once()
    assert plan.url == "https://127.0.0.1:8443/"
    assert plan.argv[0] == "/usr/bin/browser"
