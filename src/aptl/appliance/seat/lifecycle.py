"""Seat lifecycle orchestration for the host-side appliance adapter."""

from __future__ import annotations

import hashlib
from pathlib import Path

from aptl.appliance.bootstrap import initialize_overlay_state
from aptl.appliance.build import OverlayCreateRequest, create_disposable_overlay
from aptl.appliance.launch import prepare_launch_descriptor
from aptl.appliance.manifest import (
    ApplianceManifestError,
    ApplianceReleaseInspection,
    verify_release_directory,
    _load_release_documents,
)
from aptl.appliance.seat.context import SeatPaths, StartSeatOptions
from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.exposure import require_host_exposure
from aptl.appliance.seat.models import SeatRecord, SeatStatusProjection
from aptl.appliance.seat.observation import (
    build_host_observation,
    collect_loopback_listeners,
    host_boundary_findings,
    map_publications_to_listeners,
)
from aptl.appliance.seat.overlay_cleanup import remove_overlay_artifacts
from aptl.appliance.seat.paths import contained_path, validate_seat_id
from aptl.appliance.seat.persistence import load_seat_record, persist_seat_record
from aptl.appliance.seat.prereqs import require_host_prerequisites
from aptl.appliance.seat.vm import (
    VmLaunchSpec,
    build_qemu_argv,
    read_vm_pid,
    start_vm,
    stop_vm,
    write_vm_pid,
)
from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
    load_boundary_policy,
)
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint

SEAT_RECORD_SCHEMA = "aptl.seat-record/v1"
SEAT_NOT_STAGED = "seat is not staged"


def _read_host_boot_id() -> str:
    """Read the current physical-host boot identifier."""

    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SeatLauncherError("interrupted-boot", "host boot identity unavailable") from exc


def _launch_descriptor_digest(path: Path) -> str:
    """Hash the launch descriptor bytes bound into the seat record."""

    payload = path.read_bytes()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _policy_publications(
    policy: ApplianceBoundaryPolicy,
) -> tuple[BoundaryEndpoint, ...]:
    """Project signed guest publications into listener inventory endpoints."""

    return tuple(
        BoundaryEndpoint(
            audience=item.audience,
            address=item.address,
            port=item.port,
            protocol=item.protocol,
        )
        for item in policy.guest_publications
    )


def _load_verified_release(
    paths: SeatPaths,
) -> tuple[ApplianceReleaseInspection, ApplianceBoundaryPolicy]:
    """Verify the release directory and load the signed boundary policy."""

    inspection = verify_release_directory(
        paths.release_dir,
        paths.release_public_key,
        qualification_public_key_path=paths.qualification_public_key,
    )
    manifest, _signature = _load_release_documents(paths.release_dir)
    policy_path = paths.release_dir / next(
        artifact.path
        for artifact in manifest.artifacts
        if artifact.kind == "boundary-policy"
    )
    binding = ApplianceBoundaryBinding(
        policy_digest=manifest.boundary.policy_digest,
        payload_digest=manifest.payload_digest,
        raes_plan_digest=manifest.delivery.participant_routes_digest,
        raes_boundary_required=True,
        boundary_helper_image=manifest.boundary.boundary_helper_image,
        egress_proxy_image=manifest.boundary.egress_proxy_image,
        boot_id=_read_host_boot_id(),
        guest_daemon_id="pending-guest",
        host_observation_id="pending",
    )
    policy = load_boundary_policy(policy_path, binding)
    return inspection, policy


def _seat_paths(
    seat_root: Path,
    *,
    seat_id: str,
    release_dir: Path,
    release_public_key: Path,
    qualification_public_key: Path,
) -> SeatPaths:
    """Resolve contained seat paths for one launcher invocation."""

    validate_seat_id(seat_id)
    launch_dir = seat_root / "launch"
    overlay_path = contained_path(
        seat_root, f"instances/{seat_id}.qcow2", label="overlay"
    )
    return SeatPaths(
        seat_root=seat_root,
        release_dir=release_dir,
        release_public_key=release_public_key,
        qualification_public_key=qualification_public_key,
        launch_dir=launch_dir,
        launch_descriptor=launch_dir / "appliance-launch.json",
        overlay_path=overlay_path,
        overlay_state_dir=contained_path(
            seat_root, f"instances/{seat_id}.state", label="overlay state"
        ),
    )


def stage_seat(
    seat_root: Path,
    *,
    seat_id: str,
    release_dir: Path,
    release_public_key: Path,
    qualification_public_key: Path,
    prereq_overrides: dict[str, object] | None = None,
) -> SeatRecord:
    """Verify release, host prereqs, and publish a staged seat record."""

    paths = _seat_paths(
        seat_root,
        seat_id=seat_id,
        release_dir=release_dir,
        release_public_key=release_public_key,
        qualification_public_key=qualification_public_key,
    )
    inspection, policy = _load_verified_release(paths)
    manifest, _signature = _load_release_documents(paths.release_dir)
    require_host_prerequisites(
        manifest.host_prerequisites,
        seat_root=seat_root,
        **(prereq_overrides or {}),
    )
    boot_id = _read_host_boot_id()
    binding = ApplianceBoundaryBinding(
        policy_digest=manifest.boundary.policy_digest,
        payload_digest=manifest.payload_digest,
        raes_plan_digest=manifest.delivery.participant_routes_digest,
        raes_boundary_required=True,
        boundary_helper_image=manifest.boundary.boundary_helper_image,
        egress_proxy_image=manifest.boundary.egress_proxy_image,
        boot_id=boot_id,
        guest_daemon_id="pending-guest",
        host_observation_id="pending",
    )
    planned = _policy_publications(policy)
    bundle = build_host_observation(
        binding=binding.model_copy(update={"host_observation_id": "pending"}),
        boot_id=boot_id,
        listeners=planned,
        forbidden_reachability_passed=True,
        complete=True,
    )
    binding = binding.model_copy(update={"host_observation_id": bundle.observation_id})
    paths.launch_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    prepare_launch_descriptor(
        paths.release_dir,
        paths.release_public_key,
        paths.qualification_public_key,
        paths.launch_descriptor,
        host_observation_id=bundle.observation_id,
    )
    digest = _launch_descriptor_digest(paths.launch_descriptor)
    record = SeatRecord(
        schema_version=SEAT_RECORD_SCHEMA,
        seat_id=seat_id,
        selected_release_id=inspection.release_id,
        launch_descriptor_digest=digest,
        overlay_path=str(paths.overlay_path.relative_to(seat_root)),
        host_observation_id=bundle.observation_id,
        lifecycle_state="staged",
        taint_state="clean",
        host_boot_id=boot_id,
    )
    persist_seat_record(seat_root, record)
    return record


def _relative_to_root(root: Path, path: Path, *, label: str) -> str:
    """Return a contained relative POSIX path or fail closed."""

    resolved_root = root.resolve()
    resolved_path = path.resolve()
    try:
        return resolved_path.relative_to(resolved_root).as_posix()
    except ValueError as exc:
        raise SeatLauncherError(
            "corrupt-seat-state",
            f"{label} must be contained by seat root",
        ) from exc


def _ensure_overlay(paths: SeatPaths, record: SeatRecord) -> None:
    """Create the disposable overlay when the seat has none yet."""

    if paths.overlay_path.exists():
        return
    manifest, _signature = _load_release_documents(paths.release_dir)
    golden_path = next(
        artifact.path for artifact in manifest.artifacts if artifact.kind == "golden-disk"
    )
    golden_digest = next(
        artifact.sha256 for artifact in manifest.artifacts if artifact.kind == "golden-disk"
    )
    release_rel = _relative_to_root(paths.seat_root, paths.release_dir, label="release")
    request = OverlayCreateRequest(
        schema_version="aptl.overlay-create/v1",
        golden_image_path=f"{release_rel}/{golden_path}",
        golden_image_digest=golden_digest,
        launch_descriptor_path=_relative_to_root(
            paths.seat_root, paths.launch_descriptor, label="launch descriptor"
        ),
        launch_descriptor_digest=record.launch_descriptor_digest,
        overlay_path=_relative_to_root(
            paths.seat_root, paths.overlay_path, label="overlay"
        ),
    )
    create_disposable_overlay(paths.seat_root, request)
    initialize_overlay_state(paths.overlay_state_dir)


def start_seat(
    seat_root: Path,
    *,
    seat_id: str,
    release_dir: Path,
    release_public_key: Path,
    qualification_public_key: Path,
    options: StartSeatOptions | None = None,
) -> SeatRecord:
    """Create overlay when needed, start VM, and validate host exposure."""

    launch_options = options or StartSeatOptions()
    record = load_seat_record(seat_root)
    paths = _seat_paths(
        seat_root,
        seat_id=seat_id,
        release_dir=release_dir,
        release_public_key=release_public_key,
        qualification_public_key=qualification_public_key,
    )
    if record is None or record.seat_id != seat_id:
        record = stage_seat(
            seat_root,
            seat_id=seat_id,
            release_dir=release_dir,
            release_public_key=release_public_key,
            qualification_public_key=qualification_public_key,
            prereq_overrides=launch_options.prereq_overrides,
        )
    starting = record.model_copy(update={"lifecycle_state": "starting"})
    persist_seat_record(seat_root, starting)
    try:
        _ensure_overlay(paths, record)
        manifest, _signature = _load_release_documents(paths.release_dir)
        spec = VmLaunchSpec(
            overlay_path=paths.overlay_path,
            launch_mount=paths.launch_dir,
            vcpus=manifest.host_prerequisites.vcpus,
            memory_mib=manifest.host_prerequisites.memory_bytes // (1024 * 1024),
        )
        argv = build_qemu_argv(spec)
        require_host_exposure(
            vm_argv=argv, docker_daemon_running=launch_options.docker_daemon_running
        )
        if read_vm_pid(seat_root) is None:
            vm = start_vm(spec)
            write_vm_pid(seat_root, vm.pid)
        inspection, policy = _load_verified_release(paths)
        observed = collect_loopback_listeners(probe=launch_options.listener_probe)
        listeners = map_publications_to_listeners(policy, observed)
        binding = ApplianceBoundaryBinding(
            policy_digest=manifest.boundary.policy_digest,
            payload_digest=manifest.payload_digest,
            raes_plan_digest=manifest.delivery.participant_routes_digest,
            raes_boundary_required=True,
            boundary_helper_image=manifest.boundary.boundary_helper_image,
            egress_proxy_image=manifest.boundary.egress_proxy_image,
            boot_id=_read_host_boot_id(),
            guest_daemon_id="pending-guest",
            host_observation_id=record.host_observation_id,
        )
        bundle = build_host_observation(
            binding=binding,
            boot_id=binding.boot_id,
            listeners=listeners,
            forbidden_reachability_passed=True,
            complete=True,
        )
        findings = host_boundary_findings(policy, binding, bundle.observation)
        if findings:
            failed = SeatRecord(
                schema_version=SEAT_RECORD_SCHEMA,
                seat_id=seat_id,
                selected_release_id=inspection.release_id,
                launch_descriptor_digest=record.launch_descriptor_digest,
                overlay_path=record.overlay_path,
                host_observation_id=bundle.observation_id,
                lifecycle_state="recoverable-failure",
                taint_state=record.taint_state,
                host_boot_id=binding.boot_id,
            )
            persist_seat_record(seat_root, failed)
            raise SeatLauncherError(findings[0], "host boundary inventory failed")
        ready = SeatRecord(
            schema_version=SEAT_RECORD_SCHEMA,
            seat_id=seat_id,
            selected_release_id=inspection.release_id,
            launch_descriptor_digest=record.launch_descriptor_digest,
            overlay_path=record.overlay_path,
            host_observation_id=bundle.observation_id,
            lifecycle_state="ready",
            taint_state=record.taint_state,
            host_boot_id=binding.boot_id,
        )
        persist_seat_record(seat_root, ready)
        return ready
    except SeatLauncherError:
        raise
    except (ApplianceManifestError, OSError, ValueError) as exc:
        failed = starting.model_copy(update={"lifecycle_state": "recoverable-failure"})
        persist_seat_record(seat_root, failed)
        raise SeatLauncherError("failed-readiness", "seat start failed") from exc


def stop_seat(seat_root: Path) -> SeatRecord:
    """Stop the tracked VM and return the seat to staged state."""

    record = load_seat_record(seat_root)
    if record is None:
        raise SeatLauncherError("corrupt-seat-state", SEAT_NOT_STAGED)
    stop_vm(seat_root)
    updated = record.model_copy(update={"lifecycle_state": "staged"})
    persist_seat_record(seat_root, updated)
    return updated


def reset_seat(
    seat_root: Path,
    *,
    seat_id: str,
    release_dir: Path,
    release_public_key: Path,
    qualification_public_key: Path,
) -> SeatRecord:
    """Power off, destroy overlay state, and return to staged."""

    record = load_seat_record(seat_root)
    if record is None:
        raise SeatLauncherError("corrupt-seat-state", SEAT_NOT_STAGED)
    stop_vm(seat_root)
    paths = _seat_paths(
        seat_root,
        seat_id=seat_id,
        release_dir=release_dir,
        release_public_key=release_public_key,
        qualification_public_key=qualification_public_key,
    )
    remove_overlay_artifacts(paths.overlay_path, paths.overlay_state_dir)
    updated = record.model_copy(update={"lifecycle_state": "needs-reset"})
    persist_seat_record(seat_root, updated)
    return stage_seat(
        seat_root,
        seat_id=seat_id,
        release_dir=release_dir,
        release_public_key=release_public_key,
        qualification_public_key=qualification_public_key,
    )


def recover_seat(
    seat_root: Path,
    *,
    seat_id: str,
    release_dir: Path,
    release_public_key: Path,
    qualification_public_key: Path,
    options: StartSeatOptions | None = None,
) -> SeatRecord:
    """Instructor recovery: reset then start."""

    reset_seat(
        seat_root,
        seat_id=seat_id,
        release_dir=release_dir,
        release_public_key=release_public_key,
        qualification_public_key=qualification_public_key,
    )
    return start_seat(
        seat_root,
        seat_id=seat_id,
        release_dir=release_dir,
        release_public_key=release_public_key,
        qualification_public_key=qualification_public_key,
        options=options,
    )


def reconcile_seat_after_reboot(seat_root: Path) -> SeatRecord:
    """Reconcile persisted seat state after a physical-host reboot."""

    record = load_seat_record(seat_root)
    if record is None:
        raise SeatLauncherError("corrupt-seat-state", SEAT_NOT_STAGED)
    boot_id = _read_host_boot_id()
    diagnostics: list[str] = []
    if boot_id != record.host_boot_id:
        diagnostics.append("host-reboot-detected")
    if read_vm_pid(seat_root) is None and record.lifecycle_state in {
        "starting",
        "ready",
    }:
        diagnostics.append("vm-not-running")
        updated = record.model_copy(
            update={
                "lifecycle_state": "recoverable-failure",
                "host_boot_id": boot_id,
            }
        )
    else:
        updated = record.model_copy(update={"host_boot_id": boot_id})
    persist_seat_record(seat_root, updated)
    if diagnostics:
        raise SeatLauncherError(diagnostics[0], "seat requires instructor recovery")
    return updated


def status_seat(seat_root: Path) -> SeatStatusProjection:
    """Return coarse seat health without credentials or topology."""

    record = load_seat_record(seat_root)
    if record is None:
        return SeatStatusProjection(
            seat_id="unknown",
            lifecycle_state="empty",
            taint_state="clean",
            selected_release_id="",
            launch_descriptor_digest="sha256:" + "0" * 64,
            host_observation_id="",
            diagnostics=("seat-not-staged",),
        )
    diagnostics: list[str] = []
    if read_vm_pid(seat_root) is None and record.lifecycle_state == "ready":
        diagnostics.append("vm-not-running")
    return SeatStatusProjection(
        seat_id=record.seat_id,
        lifecycle_state=record.lifecycle_state,
        taint_state=record.taint_state,
        selected_release_id=record.selected_release_id,
        launch_descriptor_digest=record.launch_descriptor_digest,
        host_observation_id=record.host_observation_id,
        diagnostics=tuple(diagnostics),
    )
