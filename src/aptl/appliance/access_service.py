"""Guest supervisor for the restricted per-seat MCP transport."""

from __future__ import annotations

import hashlib
import os
import pwd
import shutil
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.appliance.launch import VerifiedApplianceLaunch, verify_launch_descriptor
from aptl.appliance.seat.access import (
    GuestAccessBundle,
    GuestAccessRequest,
    GuestRuntimeEvidence,
    MAX_ACCESS_MESSAGE_BYTES,
    enrolled_key,
    publish_guest_access,
    read_guest_access_request,
)
from aptl.core._soc_ca_io import _atomic_write
from aptl.core.config import load_config
from aptl.core.appliance_boundary_inventory import (
    GuestBoundaryObservation,
    qualify_appliance_boundary,
)
from aptl.workbench.guest_binding import (
    ApplianceAccessObservation,
    ApplianceAccessPaths,
    observe_guest,
    verify_guest_observation,
)
from aptl.workbench.access import SeatEndpoint
from aptl.workbench.preparation import TransportPreparation, prepare_guest_transport
from aptl.workbench.profiles import WorkbenchConfigurationError
from aptl.utils.strict_json import loads_strict
from aptl.validation.participant_qualification import QualificationCheckEvidence

if TYPE_CHECKING:
    from aptl.appliance.candidate import VerifiedCandidateLaunch


def _descriptor_digest(path: Path) -> str:
    """Return the SHA-256 identity of one staged launch descriptor."""

    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _ensure_host_key(path: Path) -> None:
    """Generate one overlay-local host key without replacing an existing key."""

    public = path.with_suffix(path.suffix + ".pub")
    if path.exists() or public.exists():
        if not path.is_file() or not public.is_file():
            raise WorkbenchConfigurationError("guest host key state is incomplete")
        return
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    path.chmod(0o600)
    public.chmod(0o644)


def _write_runtime_observation(
    path: Path,
    request: GuestAccessRequest,
    guest: GuestBoundaryObservation,
    *,
    uid: int,
    gid: int,
) -> None:
    observation = ApplianceAccessObservation(
        schema_version="aptl.mcp-boundary-observation/v1",
        observed_at=datetime.now(UTC),
        binding=request.binding,
        host=request.host_observation,
        guest=guest,
    )
    _atomic_write(path, (observation.model_dump_json() + "\n").encode(), mode=0o600)
    os.chown(path, uid, gid)


def _assign_management_state(project: Path, *, uid: int, gid: int) -> None:
    """Give the dedicated dispatcher identity only the generated private state."""

    targets = (project / ".aptl", project / ".mcp.json")
    for target in targets:
        if target.is_symlink() or not target.exists():
            raise WorkbenchConfigurationError("guest management state is unsafe")
        if target.is_dir():
            for root, directories, files in os.walk(target, followlinks=False):
                root_path = Path(root)
                if any(
                    (root_path / name).is_symlink() for name in (*directories, *files)
                ):
                    raise WorkbenchConfigurationError(
                        "guest management state contains a symbolic link"
                    )
                os.chown(root_path, uid, gid, follow_symlinks=False)
                for name in files:
                    os.chown(root_path / name, uid, gid, follow_symlinks=False)
        else:
            os.chown(target, uid, gid, follow_symlinks=False)


def _qualification_checks(
    project_dir: Path,
) -> tuple[QualificationCheckEvidence, ...]:
    """Run the packaged full-TechVault MCP qualification plan in the guest."""

    from aptl.validation.participant_mcp_smoke import (
        McpRegistration,
        run_participant_mcp_smoke,
    )
    from aptl.validation.participant_profile import load_participant_profile

    profile = load_participant_profile(
        project_dir,
        Path("participant-profiles/techvault-full-v1/profile.json"),
    )
    document = loads_strict((project_dir / ".mcp.json").read_bytes())
    servers = document.get("mcpServers") if isinstance(document, dict) else None
    if not isinstance(servers, dict):
        raise WorkbenchConfigurationError("guest MCP qualification config is invalid")
    node = Path(shutil.which("node") or "/usr/bin/node")
    registrations = {}
    for server_id in profile.mcp_server_ids:
        specification = servers.get(server_id)
        if not isinstance(specification, dict) or not isinstance(
            specification.get("env"), dict
        ):
            raise WorkbenchConfigurationError(
                "guest MCP qualification surface is incomplete"
            )
        artifact = next(
            server.artifact_ref
            for workbench in profile.workbench_profiles
            for server in workbench.servers
            if server.server_id == server_id
        )
        registrations[server_id] = McpRegistration(
            argv=(str(node), str(project_dir / artifact)),
            cwd=project_dir,
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", "/var/lib/aptl"),
                "LANG": "C.UTF-8",
                "APTL_MCP_DISABLE_DOTENV": "1",
                **{
                    str(key): str(value)
                    for key, value in specification["env"].items()
                    if isinstance(key, str) and isinstance(value, str)
                },
            },
        )
    return run_participant_mcp_smoke(profile, registrations)


def _load_runtime_evidence(
    project_dir: Path, run_id: str, *, qualification: bool
) -> GuestRuntimeEvidence:
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
            qualification_checks=(
                _qualification_checks(project_dir) if qualification else ()
            ),
        )
    except (OSError, TypeError, ValueError) as exc:
        raise WorkbenchConfigurationError(
            "guest qualification evidence is unavailable"
        ) from exc


def _validate_request(
    request: GuestAccessRequest,
    descriptor_path: Path,
    release_key: Path,
    qualification_key: Path,
    *,
    candidate_trust: bool,
) -> VerifiedApplianceLaunch | VerifiedCandidateLaunch:
    """Authenticate the request against the selected signed trust path."""

    if candidate_trust:
        from aptl.appliance.candidate import verify_candidate_launch_descriptor

        launch = verify_candidate_launch_descriptor(descriptor_path, release_key)
    else:
        launch = verify_launch_descriptor(
            descriptor_path, release_key, qualification_key
        )
    descriptor = launch.descriptor
    if (
        descriptor.host_mcp_contract != "aptl.restricted-ssh-mcp/v1"
        or request.launch_descriptor_digest != _descriptor_digest(descriptor_path)
        or request.binding.host_observation_id != descriptor.host_observation_id
    ):
        raise WorkbenchConfigurationError("guest access is not release-authorized")
    publications = [
        item
        for item in launch.boundary_policy.guest_publications
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
        launch.boundary_policy,
        request.binding,
        request.host_observation,
        request.guest_observation,
        phase="start",
    )
    if not verdict.passed:
        raise WorkbenchConfigurationError("guest access boundary admission failed")
    return launch


def serve_appliance_access(
    *,
    request_path: Path,
    descriptor_path: Path,
    release_public_key: Path,
    qualification_public_key: Path,
    device_path: Path,
    output_dir: Path,
    project_dir: Path = Path("/opt/aptl/project"),
    state_dir: Path = Path("/var/lib/aptl/overlay"),
    username: str = "aptl-mcp",
    observe_boundary: Callable[[], GuestBoundaryObservation] | None = None,
    candidate_trust: bool = False,
) -> None:
    """Prepare, publish, and supervise one restricted guest SSH listener."""

    deadline = time.monotonic() + 120
    while not request_path.is_file():
        if time.monotonic() >= deadline:
            raise WorkbenchConfigurationError("guest access request deadline expired")
        time.sleep(0.1)
    request = read_guest_access_request(request_path)
    launch = _validate_request(
        request,
        descriptor_path,
        release_public_key,
        qualification_public_key,
        candidate_trust=candidate_trust,
    )
    try:
        account = pwd.getpwnam(username)
    except KeyError as exc:
        raise WorkbenchConfigurationError(
            "guest access account is unavailable"
        ) from exc
    host_key = state_dir / "ssh" / "ssh_host_ed25519_key"
    _ensure_host_key(host_key)
    _assign_management_state(project_dir, uid=account.pw_uid, gid=account.pw_gid)
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
    configuration = TransportPreparation(
        owner_id=request.enrollment.owner_id,
        seat_id=request.seat_id,
        instance_id=request.instance_id,
        generation=request.generation,
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
        appliance=ApplianceAccessPaths(
            launch_descriptor=descriptor_path,
            release_public_key=release_public_key,
            qualification_public_key=qualification_public_key,
            runtime_observation=runtime_observation,
        ),
    )
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
            runtime_evidence=_load_runtime_evidence(
                project_dir, binding.run_id, qualification=candidate_trust
            ),
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
                launch.boundary_policy,
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
