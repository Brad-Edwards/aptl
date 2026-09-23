"""Seat lifecycle orchestration for the host-side appliance adapter."""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from functools import partial
from pathlib import Path

import rfc8785

from aptl.appliance.seat.overlay_identity import initialize_overlay_state
from aptl.appliance.seat.access import (
    GuestAccessRequest,
    invalidate_host_access,
    persist_host_access_bundle,
    publish_guest_access_request,
    wait_for_guest_access,
)
from aptl.appliance.seat.access_clients import configure_host_clients
from aptl.appliance.seat.allocation import (
    launch_with_automatic_mappings,
    launch_with_reserved_mappings,
)
from aptl.appliance.seat.context import SeatPaths, StartSeatOptions
from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.exposure import require_host_exposure
from aptl.appliance.seat.image import (
    SeatImageError,
    fetch_seat_image_config,
    resolve_disk_descriptor,
)
from aptl.appliance.seat.image_config import SeatImageConfig
from aptl.appliance.seat.image_selection import (
    SeatImageSelection,
    select_seat_image,
)
from aptl.appliance.seat.launch_descriptor import (
    SeatLaunchDescriptor,
    canonical_launch_bytes,
)
from aptl.appliance.seat.locking import serialized_seat_mutation
from aptl.appliance.seat.models import SeatRecord, SeatStatusProjection
from aptl.appliance.seat.overlay import create_seat_overlay
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
from aptl.core.appliance_boundary_gate import BoundaryPhase, run_appliance_boundary_gate
from aptl.core.appliance_boundary_inventory import (
    BoundaryEndpoint,
    GuestBoundaryObservation,
)
from aptl.utils.strict_json import model_validate_json_strict
from aptl.validation.participant_profile_models import ParticipantProfileManifest

SEAT_RECORD_SCHEMA = "aptl.seat-record/v2"
SEAT_NOT_STAGED = "seat is not staged"
ACCESS_REQUEST_NAME = "access-request.json"
# How long a real guest may take to offer host access after boot is not
# measured here, and the previous 120s applied only to pre-qualified
# releases that no longer exist. This is a deliberately generous ceiling;
# the caller's readiness timeout still bounds it, and a guest that is
# never coming is caught by the liveness check rather than by this value.
_ACCESS_TIMEOUT_SECONDS = 600


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


def _atomic_write(destination: Path, payload: bytes) -> None:
    """Publish one immutable launcher document atomically, or not at all."""

    temporary: Path | None = None
    try:
        temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}")
        temporary.write_bytes(payload)
        temporary.chmod(0o444)
        os.replace(temporary, destination)
        temporary = None
    except OSError as exc:
        raise SeatLauncherError(
            "corrupt-seat-state", f"{destination.name} could not be written"
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


@dataclass(frozen=True)
class ResolvedSeatImage:
    """One seat image resolved to everything a launch needs from it."""

    selection: SeatImageSelection
    config: SeatImageConfig
    policy_digest: str
    config_digest: str

    @property
    def policy(self) -> ApplianceBoundaryPolicy:
        return self.config.boundary

    @property
    def runtime_disk_bytes(self) -> int:
        return self.config.resources.disk_bytes


def _canonical_policy_digest(policy: ApplianceBoundaryPolicy) -> str:
    """Digest the exact policy bytes the gate will be bound to."""

    return (
        "sha256:"
        + hashlib.sha256(rfc8785.dumps(policy.model_dump(mode="json"))).hexdigest()
    )


def _load_seat_image(
    paths: SeatPaths,
    *,
    adopt: bool = False,
    check: bool = True,
) -> ResolvedSeatImage:
    """Resolve the seat image and the declaration a launch is bound to."""

    try:
        descriptor = resolve_disk_descriptor(paths.image_reference)
        config = fetch_seat_image_config(descriptor)
        selection = select_seat_image(
            descriptor.reference,
            cache_dir=paths.image_cache_dir,
            adopt=adopt,
            check=check,
        )
    except SeatImageError as exc:
        raise SeatLauncherError("image-unavailable", str(exc)) from exc
    if descriptor.config_digest is None:  # pragma: no cover - fetch would raise
        raise SeatLauncherError("image-unavailable", "seat image declares no config")
    return ResolvedSeatImage(
        selection=selection,
        config=config,
        policy_digest=_canonical_policy_digest(config.boundary),
        config_digest=descriptor.config_digest,
    )


def _image_binding(
    image: ResolvedSeatImage,
    *,
    boot_id: str,
    host_observation_id: str = "pending",
    guest_daemon_id: str = "pending-guest",
) -> ApplianceBoundaryBinding:
    """Project the image declaration into the boundary binding."""

    return ApplianceBoundaryBinding(
        policy_digest=image.policy_digest,
        payload_digest=image.selection.digest,
        raes_plan_digest=image.config.binding.raes_plan_digest,
        raes_boundary_required=image.policy.internal_zone_isolation,
        boundary_helper_image=image.config.binding.boundary_helper_image,
        egress_proxy_image=image.config.binding.egress_proxy_image,
        boot_id=boot_id,
        guest_daemon_id=guest_daemon_id,
        host_observation_id=host_observation_id,
    )


def image_requires_host_access(image_reference: str) -> bool:
    """Read the image declaration before the full host staging admission."""

    try:
        descriptor = resolve_disk_descriptor(image_reference)
        config = fetch_seat_image_config(descriptor)
    except SeatImageError as exc:
        raise SeatLauncherError("image-unavailable", str(exc)) from exc
    return config.boundary.host_mcp_contract == "aptl.restricted-ssh-mcp/v1"


def _seat_paths(
    seat_root: Path,
    *,
    seat_id: str,
    image_reference: str,
    image_cache_dir: Path,
) -> SeatPaths:
    """Resolve contained seat paths for one launcher invocation."""

    validate_seat_id(seat_id)
    launch_dir = seat_root / "launch"
    overlay_path = contained_path(
        seat_root, f"instances/{seat_id}.qcow2", label="overlay"
    )
    return SeatPaths(
        seat_root=seat_root,
        image_reference=image_reference,
        image_cache_dir=image_cache_dir,
        launch_dir=launch_dir,
        launch_descriptor=launch_dir / "appliance-launch.json",
        boundary_policy=launch_dir / "boundary-policy.json",
        overlay_path=overlay_path,
        overlay_state_dir=contained_path(
            seat_root, f"instances/{seat_id}.state", label="overlay state"
        ),
    )


@serialized_seat_mutation
def stage_seat(
    seat_root: Path,
    *,
    seat_id: str,
    image_reference: str,
    image_cache_dir: Path,
    mappings: tuple[BoundaryEndpoint, ...] | None = None,
    generation: int = 1,
    prereq_overrides: dict[str, object] | None = None,
    adopt_image_update: bool = False,
) -> SeatRecord:
    """Resolve the image, verify host prereqs, and publish a staged record."""

    paths = _seat_paths(
        seat_root,
        seat_id=seat_id,
        image_reference=image_reference,
        image_cache_dir=image_cache_dir,
    )
    image = _load_seat_image(paths, adopt=adopt_image_update)
    require_host_prerequisites(
        image.config.resources,
        seat_root=seat_root,
        required_free_disk_bytes=image.runtime_disk_bytes,
        **(prereq_overrides or {}),
    )
    boot_id = _read_host_boot_id()
    binding = _image_binding(image, boot_id=boot_id)
    planned = _validated_mappings(image.policy, mappings)
    bundle = build_host_observation(
        binding=binding,
        boot_id=boot_id,
        listeners=planned,
        # This is the expected successful host observation identity embedded in
        # the immutable launch descriptor. Start must reproduce it from live
        # listeners and a real negative reachability probe before admission.
        forbidden_reachability_passed=True,
        complete=True,
    )
    paths.launch_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    # The gate reads the policy from disk and checks it against the digest in
    # the binding, so the launcher writes the exact bytes it digested.
    _atomic_write(
        paths.boundary_policy, rfc8785.dumps(image.policy.model_dump(mode="json"))
    )
    _write_launch_descriptor(
        paths.launch_descriptor, image, host_observation_id=bundle.observation_id
    )
    digest = _launch_descriptor_digest(paths.launch_descriptor)
    record = SeatRecord(
        schema_version=SEAT_RECORD_SCHEMA,
        seat_id=seat_id,
        instance_id=secrets.token_hex(16),
        generation=generation,
        image_reference=str(image.selection.reference),
        image_digest=image.selection.digest,
        launch_descriptor_digest=digest,
        overlay_path=str(paths.overlay_path.relative_to(seat_root)),
        host_observation_id=bundle.observation_id,
        lifecycle_state="staged",
        taint_state="clean",
        host_boot_id=boot_id,
        mappings=planned,
    )
    persist_seat_record(seat_root, record)
    return record


def _write_launch_descriptor(
    destination: Path, image: ResolvedSeatImage, *, host_observation_id: str
) -> None:
    """Write the create-once launch projection for one generation."""

    if destination.exists():
        raise SeatLauncherError(
            "corrupt-seat-state", "launch descriptor already exists for this generation"
        )
    descriptor = SeatLaunchDescriptor(
        schema_version="aptl.appliance-launch/v2",
        image_reference=str(image.selection.reference),
        image_digest=image.selection.digest,
        image_config_digest=image.config_digest,
        boundary_policy_digest=image.policy_digest,
        boundary_helper_image=image.config.binding.boundary_helper_image,
        egress_proxy_image=image.config.binding.egress_proxy_image,
        participant_routes_digest=image.config.binding.raes_plan_digest,
        host_mcp_contract=image.policy.host_mcp_contract,
        host_observation_id=host_observation_id,
    )
    _atomic_write(destination, canonical_launch_bytes(descriptor))


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


def _ensure_overlay(paths: SeatPaths, image: ResolvedSeatImage) -> None:
    """Create the disposable overlay when the seat has none yet."""

    if paths.overlay_path.exists():
        return
    # The image is shared and content-addressed, so it lives in the user's
    # cache rather than inside this seat root; the overlay references it there.
    create_seat_overlay(paths.overlay_path, image_path=image.selection.path)
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
        timeout_seconds=min(_ACCESS_TIMEOUT_SECONDS, options.readiness_timeout_seconds),
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


def _establish_validated_host_access(
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
    """Preserve host-client configuration failures as launcher diagnostics."""

    from aptl.workbench.profiles import WorkbenchConfigurationError

    try:
        _establish_host_access(
            seat_root=seat_root,
            paths=paths,
            record=record,
            policy=policy,
            binding=binding,
            host=host,
            guest=guest,
            access_socket=access_socket,
            options=options,
        )
    except WorkbenchConfigurationError as exc:
        raise SeatLauncherError("invalid-host-access", str(exc)) from exc


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
    image_reference: str,
    image_cache_dir: Path,
    options: StartSeatOptions,
) -> SeatRecord:
    """Retry the same start with allocator-selected outer mappings."""

    return start_seat(
        seat_root,
        seat_id=seat_id,
        image_reference=image_reference,
        image_cache_dir=image_cache_dir,
        options=options.with_mappings(selected),
    )


def _fail_closed_start(seat_root: Path, paths: SeatPaths, starting: SeatRecord) -> None:
    """Revoke access and stop any VM left by an unsuccessful start."""

    cleanup_failure: Exception | None = None
    try:
        invalidate_host_access(seat_root, reason="start-failed")
    except (OSError, ValueError) as exc:
        cleanup_failure = exc
    try:
        (paths.launch_dir / ACCESS_REQUEST_NAME).unlink(missing_ok=True)
    except OSError as exc:
        cleanup_failure = exc
    try:
        stop_vm(seat_root)
    except SeatLauncherError as exc:
        cleanup_failure = exc
    if cleanup_failure is not None:
        persist_seat_record(
            seat_root,
            starting.model_copy(
                update={"lifecycle_state": "tainted", "taint_state": "tainted"}
            ),
        )
        raise SeatLauncherError(
            "failed-start-cleanup", "failed seat cleanup could not be fully proved"
        ) from cleanup_failure
    persist_seat_record(
        seat_root,
        starting.model_copy(update={"lifecycle_state": "recoverable-failure"}),
    )


@serialized_seat_mutation
def start_seat(
    seat_root: Path,
    *,
    seat_id: str,
    image_reference: str,
    image_cache_dir: Path,
    options: StartSeatOptions | None = None,
) -> SeatRecord:
    """Create overlay when needed, start VM, and validate host exposure."""

    launch_options = options or StartSeatOptions()
    record = load_seat_record(seat_root)
    paths = _seat_paths(
        seat_root,
        seat_id=seat_id,
        image_reference=image_reference,
        image_cache_dir=image_cache_dir,
    )
    if _requires_automatic_mappings(record, seat_id, launch_options):
        automatic = _load_seat_image(
            paths,
            adopt=launch_options.adopt_image_update,
            check=launch_options.check_for_image_update,
        )
        return launch_with_automatic_mappings(
            _policy_publications(automatic.policy),
            partial(
                _start_with_selected_mappings,
                seat_root=seat_root,
                seat_id=seat_id,
                image_reference=image_reference,
                image_cache_dir=image_cache_dir,
                options=launch_options,
            ),
            resources=(
                automatic.config.resources.vcpus,
                automatic.config.resources.memory_bytes,
                automatic.runtime_disk_bytes,
            ),
            seat_root=seat_root,
        )
    if record is None or record.seat_id != seat_id:
        record = stage_seat(
            seat_root,
            seat_id=seat_id,
            image_reference=image_reference,
            image_cache_dir=image_cache_dir,
            mappings=launch_options.mappings,
            prereq_overrides=launch_options.prereq_overrides,
            adopt_image_update=launch_options.adopt_image_update,
        )
    elif (
        launch_options.mappings is not None
        and record.mappings != launch_options.mappings
    ):
        raise SeatLauncherError(
            "invalid-mapping", "staged seat mappings cannot be changed during start"
        )
    image = _load_seat_image(
        paths,
        adopt=launch_options.adopt_image_update,
        check=launch_options.check_for_image_update,
    )
    if record.image_digest != image.selection.digest:
        # The staged generation is bound to the image it was staged from. A
        # different image is a new generation, which reset creates.
        raise SeatLauncherError(
            "image-mismatch",
            "staged seat was created from a different image; reset the seat",
        )
    policy = image.policy
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
        _ensure_overlay(paths, image)
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
            vcpus=image.config.resources.vcpus,
            memory_mib=image.config.resources.memory_bytes // (1024 * 1024),
            disk_reservation_bytes=image.runtime_disk_bytes,
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
                        image.config.resources.vcpus,
                        image.config.resources.memory_bytes,
                        image.runtime_disk_bytes,
                    ),
                    seat_root=seat_root,
                    retained_disk_bytes=(
                        paths.overlay_path.stat().st_blocks * 512
                        if paths.overlay_path.exists()
                        else 0
                    ),
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
        binding = _image_binding(image, boot_id=host_boot_id).model_copy(
            update={"host_boot_id": host_boot_id}
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
                image_reference=record.image_reference,
                image_digest=record.image_digest,
                launch_descriptor_digest=record.launch_descriptor_digest,
                overlay_path=record.overlay_path,
                host_observation_id=bundle.observation_id,
                lifecycle_state="recoverable-failure",
                taint_state=record.taint_state,
                host_boot_id=binding.boot_id,
                mappings=record.mappings,
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
        verdict = run_appliance_boundary_gate(
            policy_path=paths.boundary_policy,
            binding=binding,
            host_observation=bundle.observation,
            adapter=_ObservedGuestAdapter(guest),
            phase="start",
        )
        if not verdict.passed:
            raise SeatLauncherError(
                verdict.findings[0], "appliance boundary readiness failed"
            )
        _establish_validated_host_access(
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
            image_reference=record.image_reference,
            image_digest=record.image_digest,
            launch_descriptor_digest=record.launch_descriptor_digest,
            overlay_path=record.overlay_path,
            host_observation_id=bundle.observation_id,
            lifecycle_state="ready",
            taint_state=record.taint_state,
            host_boot_id=binding.boot_id,
            mappings=record.mappings,
        )
        persist_seat_record(seat_root, ready)
        return ready
    except SeatLauncherError:
        _fail_closed_start(seat_root, paths, starting)
        raise
    except (
        ApplianceManifestError,
        OSError,
        ValueError,
    ) as exc:
        _fail_closed_start(seat_root, paths, starting)
        raise SeatLauncherError("failed-readiness", "seat start failed") from exc


@serialized_seat_mutation
def stop_seat(seat_root: Path) -> SeatRecord:
    """Stop the tracked VM and return the seat to staged state."""

    record = load_seat_record(seat_root)
    if record is None:
        raise SeatLauncherError("corrupt-seat-state", SEAT_NOT_STAGED)
    invalidate_host_access(seat_root, reason="seat-stopped")
    stop_vm(seat_root)
    (seat_root / "launch" / ACCESS_REQUEST_NAME).unlink(missing_ok=True)
    current_access = seat_root / "access" / f"generation-{record.generation}"
    generation_was_used = current_access.exists() or current_access.is_symlink()
    updated = record.model_copy(
        update={
            "lifecycle_state": "staged",
            # Every completed start owns a generation-bound caller grant.
            # Stopping revokes it, so the next start must not reuse that
            # generation even though it retains the same disposable overlay.
            "generation": (
                record.generation + 1
                if record.lifecycle_state != "staged" or generation_was_used
                else record.generation
            ),
        }
    )
    persist_seat_record(seat_root, updated)
    return updated


@serialized_seat_mutation
def reset_seat(
    seat_root: Path,
    *,
    seat_id: str,
    image_reference: str,
    image_cache_dir: Path,
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
        image_reference=image_reference,
        image_cache_dir=image_cache_dir,
    )
    remove_overlay_artifacts(paths.overlay_path, paths.overlay_state_dir)
    updated = record.model_copy(update={"lifecycle_state": "needs-reset"})
    persist_seat_record(seat_root, updated)
    for runtime_artifact in (
        paths.launch_descriptor,
        paths.boundary_policy,
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
        image_reference=image_reference,
        image_cache_dir=image_cache_dir,
        mappings=record.mappings,
        generation=record.generation + 1,
    )


@serialized_seat_mutation
def recover_seat(
    seat_root: Path,
    *,
    seat_id: str,
    image_reference: str,
    image_cache_dir: Path,
    options: StartSeatOptions | None = None,
) -> SeatRecord:
    """Instructor recovery: reset then start."""

    reset_seat(
        seat_root,
        seat_id=seat_id,
        image_reference=image_reference,
        image_cache_dir=image_cache_dir,
    )
    return start_seat(
        seat_root,
        seat_id=seat_id,
        image_reference=image_reference,
        image_cache_dir=image_cache_dir,
        options=options,
    )


@serialized_seat_mutation
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
            image_reference="",
            image_digest="",
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
        image_reference=record.image_reference,
        image_digest=record.image_digest,
        launch_descriptor_digest=record.launch_descriptor_digest,
        host_observation_id=record.host_observation_id,
        diagnostics=tuple(diagnostics),
    )
