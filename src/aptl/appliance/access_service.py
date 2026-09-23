"""Guest supervisor for the restricted per-seat MCP transport."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from aptl.appliance.access_service_support import (
    _access_account,
    _assign_management_state,
    _descriptor_digest,
    _ensure_host_key,
    _prepare_dispatch_ca,
    _prepare_dispatch_home,
    _stage_dispatch_metadata,
    _write_runtime_observation,
)
from aptl.appliance.seat.launch_descriptor import (
    SeatLaunchDescriptor,
    verify_seat_launch,
)
from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
from aptl.appliance.seat.access import (
    MAX_ACCESS_MESSAGE_BYTES,
    GuestAccessBundle,
    GuestAccessRequest,
    GuestRuntimeEvidence,
    publish_guest_access,
    read_guest_access_request,
)
from aptl.appliance.seat.access_clients import enrolled_key
from aptl.core.appliance_boundary_inventory import (
    GuestBoundaryObservation,
    qualify_appliance_boundary,
)
from aptl.core.config import load_config
from aptl.utils.strict_json import loads_strict
from aptl.workbench.access import SeatEndpoint
from aptl.workbench.guest_binding import (
    ApplianceAccessPaths,
    observe_guest,
    verify_guest_observation,
)
from aptl.workbench.preparation import TransportPreparation, prepare_guest_transport
from aptl.workbench.profiles import WorkbenchConfigurationError

def _load_runtime_evidence(project_dir: Path, run_id: str) -> GuestRuntimeEvidence:
    """Load the successful startup record from the contained guest run store."""

    config = load_config(project_dir / "aptl.json")
    run_root = Path(config.run_storage.local_path)
    if not run_root.is_absolute():
        run_root = project_dir / run_root
    run_root = run_root.resolve()
    if not run_root.is_relative_to(project_dir.resolve()):
        raise WorkbenchConfigurationError(
            "appliance qualification run store escapes the project"
        )
    try:
        payload = (run_root / run_id / "manifest.json").read_bytes()
        if len(payload) > MAX_ACCESS_MESSAGE_BYTES // 2:
            raise ValueError("run record exceeds qualification limit")
        run_record = loads_strict(payload)
        if not isinstance(run_record, dict):
            raise ValueError("run record is not an object")
        backend = run_record.get("backend_evidence")
        snapshot = backend.get("range_snapshot") if isinstance(backend, dict) else None
        return GuestRuntimeEvidence(
            schema_version="aptl.guest-runtime-evidence/v1",
            run_id=run_id,
            run_record=run_record,
            snapshot=snapshot,
            qualification_checks=(),
        )
    except (OSError, TypeError, ValueError) as exc:
        raise WorkbenchConfigurationError(
            "guest qualification evidence is unavailable"
        ) from exc


def _validate_request(
    request: GuestAccessRequest,
    descriptor_path: Path,
) -> tuple[SeatLaunchDescriptor, ApplianceBoundaryPolicy]:
    """Authenticate the request against the launch the host bound."""

    descriptor, boundary_policy = verify_seat_launch(descriptor_path)
    if (
        descriptor.host_mcp_contract != "aptl.restricted-ssh-mcp/v1"
        or request.launch_descriptor_digest != _descriptor_digest(descriptor_path)
        or request.binding.host_observation_id != descriptor.host_observation_id
    ):
        raise WorkbenchConfigurationError("guest access is not release-authorized")
    publications = [
        item
        for item in boundary_policy.guest_publications
        if item.audience == "host-mcp"
    ]
    endpoint = request.guest_endpoint
    if len(publications) != 1 or (
        publications[0].address,
        publications[0].port,
        publications[0].protocol,
    ) != (endpoint.address, endpoint.port, endpoint.protocol):
        raise WorkbenchConfigurationError("guest access endpoint is not signed")
    verdict = qualify_appliance_boundary(
        boundary_policy,
        request.binding,
        request.host_observation,
        request.guest_observation,
        phase="start",
    )
    if not verdict.passed:
        raise WorkbenchConfigurationError("guest access boundary admission failed")
    return descriptor, boundary_policy


def serve_appliance_access(
    *,
    request_path: Path,
    descriptor_path: Path,
    device_path: Path,
    output_dir: Path,
    run_id: str,
    project_dir: Path = Path("/opt/aptl/project"),
    state_dir: Path = Path("/var/lib/aptl/overlay"),
    username: str = "aptl-mcp",
    observe_boundary: Callable[[], GuestBoundaryObservation] | None = None,
) -> None:
    """Prepare, publish, and supervise one restricted guest SSH listener."""

    deadline = time.monotonic() + 120
    while not request_path.is_file():
        if time.monotonic() >= deadline:
            raise WorkbenchConfigurationError("guest access request deadline expired")
        time.sleep(0.1)
    request = read_guest_access_request(request_path)
    launch = _validate_request(request, descriptor_path)
    _descriptor, boundary_policy = launch
    account = _access_account(username)
    host_key = state_dir / "ssh" / "ssh_host_ed25519_key"
    _ensure_host_key(host_key)
    _assign_management_state(project_dir, uid=account.pw_uid, gid=account.pw_gid)
    _prepare_dispatch_home(Path(account.pw_dir), uid=account.pw_uid, gid=account.pw_gid)
    _prepare_dispatch_ca(project_dir, gid=account.pw_gid)
    if output_dir.is_symlink():
        raise WorkbenchConfigurationError("guest access state is unsafe")
    if output_dir.exists():
        try:
            if not output_dir.resolve().is_relative_to(state_dir.parent.resolve()):
                raise WorkbenchConfigurationError("guest access state escapes runtime")
            shutil.rmtree(output_dir)
        except OSError as exc:
            raise WorkbenchConfigurationError(
                "old guest access state could not be revoked"
            ) from exc
    runtime_observation = output_dir / "runtime-observation.json"
    output_dir.parent.mkdir(mode=0o711, parents=True, exist_ok=True)
    metadata = _stage_dispatch_metadata(
        launch,
        ApplianceAccessPaths(
            launch_descriptor=descriptor_path,
            runtime_observation=runtime_observation,
        ),
        Path(tempfile.mkdtemp(prefix="mcp-trust-", dir=output_dir.parent)),
        gid=account.pw_gid,
    )
    configuration = TransportPreparation(
        owner_id=request.enrollment.owner_id,
        seat_id=request.seat_id,
        instance_id=request.instance_id,
        generation=request.generation,
        run_id=run_id,
        guest_endpoint=SeatEndpoint(
            address=request.guest_endpoint.address,
            port=request.guest_endpoint.port,
        ),
        outer_endpoint=SeatEndpoint(
            address=request.outer_endpoint.address,
            port=request.outer_endpoint.port,
        ),
        project_dir=project_dir,
        management_home=Path(account.pw_dir),
        node_executable=Path(shutil.which("node") or "/usr/bin/node"),
        aptl_executable=Path(shutil.which("aptl") or "/usr/local/bin/aptl"),
        host_key=host_key,
        host_public_key=host_key.with_suffix(host_key.suffix + ".pub"),
        username=username,
        keys=(enrolled_key(request),),
        delivery="appliance",
        appliance=metadata,
    )
    # A full guest start can take several minutes. Complete it before
    # observing and timestamping generation-scoped discovery so the bundle is
    # still current when the host enforces its short freshness window.
    runtime_evidence = _load_runtime_evidence(project_dir, configuration.run_id)
    binding = prepare_guest_transport(configuration, output_dir)
    for path in output_dir.iterdir():
        os.chown(path, account.pw_uid, account.pw_gid)
    os.chown(output_dir, account.pw_uid, account.pw_gid)
    _write_runtime_observation(
        runtime_observation,
        request,
        request.guest_observation,
        uid=account.pw_uid,
        gid=account.pw_gid,
    )
    listener = subprocess.Popen(
        ["/usr/sbin/sshd", "-D", "-e", "-f", str(output_dir / "sshd_config")],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    try:
        time.sleep(0.25)
        if listener.poll() is not None:
            raise WorkbenchConfigurationError("guest access listener failed to start")
        bundle = GuestAccessBundle(
            schema_version="aptl.guest-access-bundle/v1",
            nonce=request.nonce,
            seat_id=request.seat_id,
            instance_id=request.instance_id,
            generation=request.generation,
            access=binding.access,
            grant=binding.grants[0],
            host_public_key=configuration.host_public_key.read_text(encoding="utf-8"),
            runtime_evidence=runtime_evidence,
        )
        publish_guest_access(device_path, bundle)
        while listener.poll() is None:
            verify_guest_observation(
                binding.access, observe_guest(binding), run_id=binding.run_id
            )
            if observe_boundary is None:
                raise WorkbenchConfigurationError(
                    "live appliance boundary observer is unavailable"
                )
            current_guest = observe_boundary()
            verdict = qualify_appliance_boundary(
                boundary_policy,
                request.binding,
                request.host_observation,
                current_guest,
                phase="start",
            )
            if not verdict.passed:
                raise WorkbenchConfigurationError(
                    "live appliance access boundary admission failed"
                )
            _write_runtime_observation(
                runtime_observation,
                request,
                current_guest,
                uid=account.pw_uid,
                gid=account.pw_gid,
            )
            time.sleep(2)
        raise WorkbenchConfigurationError("guest access listener stopped")
    finally:
        if listener.poll() is None:
            listener.terminate()
            try:
                listener.wait(timeout=10)
            except subprocess.TimeoutExpired:
                listener.kill()
                listener.wait(timeout=10)
