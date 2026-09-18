"""Seat lifecycle orchestration for the host-side appliance adapter."""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass, replace
from functools import partial
from pathlib import Path

from aptl.appliance.bootstrap import initialize_overlay_state
from aptl.appliance.build import OverlayCreateRequest, create_disposable_overlay
from aptl.appliance.launch import prepare_launch_descriptor
from aptl.appliance.candidate import (
    ApplianceCandidateManifest,
    prepare_candidate_launch_descriptor,
    verify_candidate_directory,
)
from aptl.appliance.manifest import (
    ApplianceManifestError,
    ApplianceReleaseInspection,
    verify_release_directory,
    _load_release_documents,
)
from aptl.appliance.models import ApplianceReleaseManifest
from aptl.appliance.seat.context import SeatPaths, StartSeatOptions
from aptl.appliance.seat.access import (
    GuestAccessRequest,
    configure_host_clients,
    invalidate_host_access,
    persist_host_access_bundle,
    publish_guest_access_request,
    wait_for_guest_access,
)
from aptl.appliance.seat.allocation import (
    launch_with_automatic_mappings,
    launch_with_reserved_mappings,
)
from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.exposure import require_host_exposure
from aptl.appliance.seat.models import SeatRecord, SeatStatusProjection
from aptl.appliance.seat.observation import (
    HostObservationBundle,
    build_host_observation,
    collect_loopback_listeners,
    host_boundary_findings,
    map_publications_to_listeners,
    probe_forbidden_host_reachability,
)
from aptl.appliance.seat.overlay_cleanup import remove_overlay_artifacts
from aptl.appliance.seat.paths import contained_path, validate_seat_id
from aptl.appliance.seat.persistence import load_seat_record, persist_seat_record
from aptl.appliance.seat.prereqs import require_host_prerequisites
from aptl.appliance.seat.readiness import (
    publish_readiness_challenge,
    wait_for_guest_readiness,
)
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
from aptl.core.appliance_boundary_inventory import GuestBoundaryObservation
from aptl.core.appliance_boundary_gate import BoundaryPhase, run_appliance_boundary_gate

SEAT_RECORD_SCHEMA = "aptl.seat-record/v2"
SEAT_NOT_STAGED = "seat is not staged"
ACCESS_REQUEST_NAME = "access-request.json"


@dataclass(frozen=True)
class _ObservedGuestAdapter:
    """Adapter that submits one fresh, channel-attributed guest observation."""

    observation: GuestBoundaryObservation

    def materialize_and_observe_boundary(
        self,
        policy: ApplianceBoundaryPolicy,
        binding: ApplianceBoundaryBinding,
        *,
        phase: BoundaryPhase,
    ) -> GuestBoundaryObservation:
        del policy, binding, phase
        return self.observation


def _read_host_boot_id() -> str:
    """Read the current physical-host boot identifier."""

    try:
        return (
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        )
    except OSError as exc:
        raise SeatLauncherError(
            "interrupted-boot", "host boot identity unavailable"
        ) from exc


def _launch_descriptor_digest(path: Path) -> str:
    """Hash the launch descriptor bytes bound into the seat record."""

    payload = path.read_bytes()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _stage_public_anchor(source: Path, destination: Path) -> None:
    """Copy one bounded public trust anchor without following a leaf symlink."""

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    temporary: Path | None = None
    try:
        descriptor = os.open(source, flags)
        with os.fdopen(descriptor, "rb") as handle:
            payload = handle.read(64 * 1024 + 1)
        if not payload or len(payload) > 64 * 1024:
            raise OSError("public trust anchor has invalid size")
        temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}")
        temporary.write_bytes(payload)
        temporary.chmod(0o444)
        os.replace(temporary, destination)
    except OSError as exc:
        raise SeatLauncherError(
            "invalid-trust-anchor", "public trust anchor could not be staged"
        ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


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
            guest_address=item.address,
            guest_port=item.port,
        )
        for item in policy.guest_publications
    )


def _validated_mappings(
    policy: ApplianceBoundaryPolicy,
    requested: tuple[BoundaryEndpoint, ...] | None,
) -> tuple[BoundaryEndpoint, ...]:
    """Validate one complete outer mapping for every signed publication."""

    mappings = requested or _policy_publications(policy)
    expected = {
        (item.audience, item.address, item.port, item.protocol)
        for item in policy.guest_publications
    }
    mapped = {
        (item.audience, item.guest_address, item.guest_port, item.protocol)
        for item in mappings
    }
    outer = {(item.address, item.port, item.protocol) for item in mappings}
    if mapped != expected:
        raise SeatLauncherError(
            "invalid-mapping", "outer mappings must cover signed guest publications"
        )
    if len(outer) != len(mappings):
        raise SeatLauncherError(
            "invalid-mapping", "outer mappings contain duplicate endpoints"
        )
    return mappings


def _load_verified_release(
    paths: SeatPaths, *, candidate_trust: bool = False
) -> tuple[ApplianceReleaseInspection, ApplianceBoundaryPolicy]:
    """Verify the release directory and load the signed boundary policy."""

    if candidate_trust:
        manifest, inspection = verify_candidate_directory(
            paths.release_dir, paths.release_public_key
        )
    else:
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


def _load_delivery_manifest(
    paths: SeatPaths, *, candidate_trust: bool
) -> ApplianceCandidateManifest | ApplianceReleaseManifest:
    """Load the already-verified production or qualification-only document."""

    if candidate_trust:
        manifest, _inspection = verify_candidate_directory(
            paths.release_dir, paths.release_public_key
        )
        return manifest
    manifest, _signature = _load_release_documents(paths.release_dir)
    return manifest


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
    mappings: tuple[BoundaryEndpoint, ...] | None = None,
    generation: int = 1,
    prereq_overrides: dict[str, object] | None = None,
    candidate_trust: bool = False,
) -> SeatRecord:
    """Verify release, host prereqs, and publish a staged seat record."""

    paths = _seat_paths(
        seat_root,
        seat_id=seat_id,
        release_dir=release_dir,
        release_public_key=release_public_key,
        qualification_public_key=qualification_public_key,
    )
    inspection, policy = _load_verified_release(paths, candidate_trust=candidate_trust)
    manifest = _load_delivery_manifest(paths, candidate_trust=candidate_trust)
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
    planned = _validated_mappings(policy, mappings)
    bundle = build_host_observation(
        binding=binding.model_copy(update={"host_observation_id": "pending"}),
        boot_id=boot_id,
        listeners=planned,
        # This is the expected successful host observation identity embedded in
        # the immutable launch descriptor. Start must reproduce it from live
        # listeners and a real negative reachability probe before admission.
        forbidden_reachability_passed=True,
        complete=True,
    )
    binding = binding.model_copy(update={"host_observation_id": bundle.observation_id})
    paths.launch_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    _stage_public_anchor(
        paths.release_public_key, paths.launch_dir / "release-public.pem"
    )
    _stage_public_anchor(
        paths.qualification_public_key,
        paths.launch_dir / "qualification-public.pem",
    )
    if candidate_trust:
        prepare_candidate_launch_descriptor(
            paths.release_dir,
            paths.release_public_key,
            paths.launch_descriptor,
            host_observation_id=bundle.observation_id,
        )
    else:
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
        instance_id=secrets.token_hex(16),
        generation=generation,
        selected_release_id=inspection.release_id,
        launch_descriptor_digest=digest,
        overlay_path=str(paths.overlay_path.relative_to(seat_root)),
        host_observation_id=bundle.observation_id,
        lifecycle_state="staged",
        taint_state="clean",
        host_boot_id=boot_id,
        mappings=planned,
        trust_mode="qualification-only" if candidate_trust else "production",
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


def _ensure_overlay(
    paths: SeatPaths, record: SeatRecord, *, candidate_trust: bool
) -> None:
    """Create the disposable overlay when the seat has none yet."""

    if paths.overlay_path.exists():
        return
    manifest = _load_delivery_manifest(paths, candidate_trust=candidate_trust)
    golden_path = next(
        artifact.path
        for artifact in manifest.artifacts
        if artifact.kind == "golden-disk"
    )
    golden_digest = next(
        artifact.sha256
        for artifact in manifest.artifacts
        if artifact.kind == "golden-disk"
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


def _require_access_options(
    policy: ApplianceBoundaryPolicy, options: StartSeatOptions
) -> None:
    """Require a complete enrollment exactly when the signed policy enables it."""

    required = policy.host_mcp_contract == "aptl.restricted-ssh-mcp/v1"
    if required and options.access_enrollment is None:
        raise SeatLauncherError(
            "missing-host-access",
            "signed host MCP delivery requires a caller public key enrollment",
        )
    if options.access_enrollment is not None and (
        not required
        or options.access_identity_file is None
        or options.access_project_dir is None
        or not options.access_clients
    ):
        raise SeatLauncherError(
            "invalid-host-access", "host MCP enrollment options are incomplete"
        )


def _establish_host_access(
    *,
    seat_root: Path,
    paths: SeatPaths,
    record: SeatRecord,
    policy: ApplianceBoundaryPolicy,
    binding: ApplianceBoundaryBinding,
    host: HostObservationBundle,
    guest: GuestBoundaryObservation,
    access_socket: Path,
    options: StartSeatOptions,
) -> None:
    """Enroll one caller, receive its guest pin, and publish native configs."""

    enrollment = options.access_enrollment
    if enrollment is None:
        return
    guest_publications = [
        item for item in policy.guest_publications if item.audience == "host-mcp"
    ]
    outer_mappings = [item for item in record.mappings if item.audience == "host-mcp"]
    if len(guest_publications) != 1 or len(outer_mappings) != 1:
        raise SeatLauncherError(
            "invalid-host-access", "host MCP requires one explicit mapping"
        )
    publication = guest_publications[0]
    guest_endpoint = BoundaryEndpoint(
        audience="host-mcp",
        address=publication.address,
        port=publication.port,
        protocol=publication.protocol,
        guest_address=publication.address,
        guest_port=publication.port,
    )
    request = GuestAccessRequest(
        schema_version="aptl.guest-access-request/v1",
        nonce=secrets.token_hex(32),
        seat_id=record.seat_id,
        instance_id=record.instance_id,
        generation=record.generation,
        launch_descriptor_digest=record.launch_descriptor_digest,
        enrollment=enrollment,
        guest_endpoint=guest_endpoint,
        outer_endpoint=outer_mappings[0],
        binding=binding,
        host_observation=host.observation,
        guest_observation=guest,
    )
    publish_guest_access_request(paths.launch_dir / ACCESS_REQUEST_NAME, request)
    response = wait_for_guest_access(
        access_socket,
        request,
        process_alive=lambda: read_vm_pid(seat_root) is not None,
        timeout_seconds=min(120, options.readiness_timeout_seconds),
    )
    persist_host_access_bundle(seat_root, response)
    assert options.access_project_dir is not None
    assert options.access_identity_file is not None
    configure_host_clients(
        bundle=response,
        project_dir=options.access_project_dir,
        identity_file=options.access_identity_file,
        username=enrollment.username,
        clients=options.access_clients,
    )


def _requires_automatic_mappings(
    record: SeatRecord | None,
    seat_id: str,
    options: StartSeatOptions,
) -> bool:
    """Return whether a new seat needs collision-safe host port selection."""

    new_seat = record is None or record.seat_id != seat_id
    return new_seat and options.mappings is None and options.reserve_outer_mappings


def _start_with_selected_mappings(
    selected: tuple[BoundaryEndpoint, ...],
    *,
    seat_root: Path,
    seat_id: str,
    release_dir: Path,
    release_public_key: Path,
    qualification_public_key: Path,
    options: StartSeatOptions,
) -> SeatRecord:
    """Retry the same start with allocator-selected outer mappings."""

    selected_options: StartSeatOptions = replace(
        options,
        mappings=selected,
        reserve_outer_mappings=False,
    )
    return start_seat(
        seat_root,
        seat_id=seat_id,
        release_dir=release_dir,
        release_public_key=release_public_key,
        qualification_public_key=qualification_public_key,
        options=selected_options,
    )


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
    if _requires_automatic_mappings(record, seat_id, launch_options):
        _inspection, automatic_policy = _load_verified_release(
            paths, candidate_trust=launch_options.candidate_trust
        )
        automatic_manifest = _load_delivery_manifest(
            paths, candidate_trust=launch_options.candidate_trust
        )

        return launch_with_automatic_mappings(
            _policy_publications(automatic_policy),
            partial(
                _start_with_selected_mappings,
                seat_root=seat_root,
                seat_id=seat_id,
                release_dir=release_dir,
                release_public_key=release_public_key,
                qualification_public_key=qualification_public_key,
                options=launch_options,
            ),
            resources=(
                automatic_manifest.host_prerequisites.vcpus,
                automatic_manifest.host_prerequisites.memory_bytes,
                automatic_manifest.host_prerequisites.disk_bytes,
            ),
            seat_root=seat_root,
        )
    if record is None or record.seat_id != seat_id:
        record = stage_seat(
            seat_root,
            seat_id=seat_id,
            release_dir=release_dir,
            release_public_key=release_public_key,
            qualification_public_key=qualification_public_key,
            mappings=launch_options.mappings,
            prereq_overrides=launch_options.prereq_overrides,
            candidate_trust=launch_options.candidate_trust,
        )
    elif (
        launch_options.mappings is not None
        and record.mappings != launch_options.mappings
    ):
        raise SeatLauncherError(
            "invalid-mapping", "staged seat mappings cannot be changed during start"
        )
    expected_mode = (
        "qualification-only" if launch_options.candidate_trust else "production"
    )
    if record.trust_mode != expected_mode:
        raise SeatLauncherError(
            "trust-mode-mismatch", "staged seat trust mode differs from start"
        )
    inspection, policy = _load_verified_release(
        paths, candidate_trust=launch_options.candidate_trust
    )
    _require_access_options(policy, launch_options)
    if not record.mappings:
        record = record.model_copy(
            update={
                "schema_version": SEAT_RECORD_SCHEMA,
                "instance_id": secrets.token_hex(16),
                "mappings": _policy_publications(policy),
            }
        )
    starting = record.model_copy(update={"lifecycle_state": "starting"})
    persist_seat_record(seat_root, starting)
    try:
        _ensure_overlay(paths, record, candidate_trust=launch_options.candidate_trust)
        manifest = _load_delivery_manifest(
            paths, candidate_trust=launch_options.candidate_trust
        )
        readiness_socket = contained_path(
            paths.seat_root,
            f"runtime/{seat_id}.readiness.sock",
            label="readiness socket",
        )
        access_socket = contained_path(
            paths.seat_root,
            f"runtime/{seat_id}.access.sock",
            label="access socket",
        )
        challenge = publish_readiness_challenge(
            paths.launch_dir / "readiness-challenge.json",
            seat_id=record.seat_id,
            instance_id=record.instance_id,
            generation=record.generation,
            launch_descriptor_digest=record.launch_descriptor_digest,
        )
        spec = VmLaunchSpec(
            overlay_path=paths.overlay_path,
            launch_mount=paths.launch_dir,
            vcpus=manifest.host_prerequisites.vcpus,
            memory_mib=manifest.host_prerequisites.memory_bytes // (1024 * 1024),
            disk_reservation_bytes=manifest.host_prerequisites.disk_bytes,
            readiness_socket=readiness_socket,
            access_socket=access_socket,
            mappings=record.mappings,
        )
        argv = build_qemu_argv(spec)
        require_host_exposure(
            vm_argv=argv, docker_daemon_running=launch_options.docker_daemon_running
        )
        if read_vm_pid(seat_root) is None:
            if launch_options.reserve_outer_mappings:
                vm = launch_with_reserved_mappings(
                    record.mappings,
                    lambda: start_vm(spec),
                    resources=(
                        manifest.host_prerequisites.vcpus,
                        manifest.host_prerequisites.memory_bytes,
                        manifest.host_prerequisites.disk_bytes,
                    ),
                    seat_root=seat_root,
                )
            else:
                vm = start_vm(spec)
            write_vm_pid(seat_root, vm.pid)
        tracked_pid = read_vm_pid(seat_root)
        if tracked_pid is None:
            raise SeatLauncherError(
                "failed-launch", "tracked VM exited before listener observation"
            )
        observed = collect_loopback_listeners(
            probe=launch_options.listener_probe,
            owner_pid=tracked_pid,
        )
        listeners = map_publications_to_listeners(
            policy, observed, mappings=record.mappings
        )
        host_boot_id = _read_host_boot_id()
        binding = ApplianceBoundaryBinding(
            policy_digest=manifest.boundary.policy_digest,
            payload_digest=manifest.payload_digest,
            raes_plan_digest=manifest.delivery.participant_routes_digest,
            raes_boundary_required=True,
            boundary_helper_image=manifest.boundary.boundary_helper_image,
            egress_proxy_image=manifest.boundary.egress_proxy_image,
            boot_id=host_boot_id,
            host_boot_id=host_boot_id,
            guest_daemon_id="pending-guest",
            host_observation_id="pending",
        )
        forbidden_passed = (
            launch_options.forbidden_reachability_probe()
            if launch_options.forbidden_reachability_probe is not None
            else probe_forbidden_host_reachability(record.mappings)
        )
        bundle = build_host_observation(
            binding=binding,
            boot_id=binding.host_boot_id or binding.boot_id,
            listeners=listeners,
            forbidden_reachability_passed=forbidden_passed,
            complete=True,
        )
        binding = binding.model_copy(
            update={"host_observation_id": bundle.observation_id}
        )
        findings = host_boundary_findings(policy, binding, bundle.observation)
        if findings:
            failed = SeatRecord(
                schema_version=SEAT_RECORD_SCHEMA,
                seat_id=seat_id,
                instance_id=record.instance_id,
                generation=record.generation,
                selected_release_id=inspection.release_id,
                launch_descriptor_digest=record.launch_descriptor_digest,
                overlay_path=record.overlay_path,
                host_observation_id=bundle.observation_id,
                lifecycle_state="recoverable-failure",
                taint_state=record.taint_state,
                host_boot_id=binding.boot_id,
                mappings=record.mappings,
                trust_mode=record.trust_mode,
            )
            persist_seat_record(seat_root, failed)
            raise SeatLauncherError(findings[0], "host boundary inventory failed")
        if bundle.observation_id != record.host_observation_id:
            raise SeatLauncherError(
                "boundary.host-observation-mismatch",
                "live host boundary differs from the staged launch contract",
            )
        if launch_options.guest_readiness_probe is None:
            guest = wait_for_guest_readiness(
                readiness_socket,
                challenge,
                process_alive=lambda: read_vm_pid(seat_root) is not None,
                timeout_seconds=launch_options.readiness_timeout_seconds,
            )
        else:
            guest = launch_options.guest_readiness_probe()
        binding = binding.model_copy(
            update={
                "guest_boot_id": guest.boot_id,
                "guest_daemon_id": guest.guest_daemon_id,
            }
        )
        policy_path = paths.release_dir / next(
            artifact.path
            for artifact in manifest.artifacts
            if artifact.kind == "boundary-policy"
        )
        verdict = run_appliance_boundary_gate(
            policy_path=policy_path,
            binding=binding,
            host_observation=bundle.observation,
            adapter=_ObservedGuestAdapter(guest),
            phase="start",
        )
        if not verdict.passed:
            raise SeatLauncherError(
                verdict.findings[0], "appliance boundary readiness failed"
            )
        _establish_host_access(
            seat_root=seat_root,
            paths=paths,
            record=record,
            policy=policy,
            binding=binding,
            host=bundle,
            guest=guest,
            access_socket=access_socket,
            options=launch_options,
        )
        ready = SeatRecord(
            schema_version=SEAT_RECORD_SCHEMA,
            seat_id=seat_id,
            instance_id=record.instance_id,
            generation=record.generation,
            selected_release_id=inspection.release_id,
            launch_descriptor_digest=record.launch_descriptor_digest,
            overlay_path=record.overlay_path,
            host_observation_id=bundle.observation_id,
            lifecycle_state="ready",
            taint_state=record.taint_state,
            host_boot_id=binding.boot_id,
            mappings=record.mappings,
            trust_mode=record.trust_mode,
        )
        persist_seat_record(seat_root, ready)
        return ready
    except SeatLauncherError:
        invalidate_host_access(seat_root, reason="start-failed")
        (paths.launch_dir / ACCESS_REQUEST_NAME).unlink(missing_ok=True)
        failed = starting.model_copy(update={"lifecycle_state": "recoverable-failure"})
        persist_seat_record(seat_root, failed)
        raise
    except (
        ApplianceManifestError,
        OSError,
        ValueError,
    ) as exc:
        invalidate_host_access(seat_root, reason="start-failed")
        (paths.launch_dir / ACCESS_REQUEST_NAME).unlink(missing_ok=True)
        failed = starting.model_copy(update={"lifecycle_state": "recoverable-failure"})
        persist_seat_record(seat_root, failed)
        raise SeatLauncherError("failed-readiness", "seat start failed") from exc


def stop_seat(seat_root: Path) -> SeatRecord:
    """Stop the tracked VM and return the seat to staged state."""

    record = load_seat_record(seat_root)
    if record is None:
        raise SeatLauncherError("corrupt-seat-state", SEAT_NOT_STAGED)
    invalidate_host_access(seat_root, reason="seat-stopped")
    stop_vm(seat_root)
    (seat_root / "launch" / ACCESS_REQUEST_NAME).unlink(missing_ok=True)
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
    invalidate_host_access(seat_root, reason="seat-reset")
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
    for runtime_artifact in (
        paths.launch_descriptor,
        paths.launch_dir / "readiness-challenge.json",
        paths.launch_dir / ACCESS_REQUEST_NAME,
    ):
        try:
            runtime_artifact.unlink(missing_ok=True)
        except OSError as exc:
            raise SeatLauncherError(
                "failed-reset", "immutable launch state could not be replaced"
            ) from exc
    return stage_seat(
        seat_root,
        seat_id=seat_id,
        release_dir=release_dir,
        release_public_key=release_public_key,
        qualification_public_key=qualification_public_key,
        mappings=record.mappings,
        generation=record.generation + 1,
        candidate_trust=record.trust_mode == "qualification-only",
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
        invalidate_host_access(seat_root, reason="seat-reconciliation-failed")
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
