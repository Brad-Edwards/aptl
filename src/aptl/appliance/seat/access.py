"""Authenticated per-generation host access for an appliance seat."""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import stat
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import rfc8785
from pydantic import BaseModel, ConfigDict, Field, model_validator

from aptl.core._soc_ca_io import _atomic_write
from aptl.core.appliance_boundary import ApplianceBoundaryBinding
from aptl.core.appliance_boundary_inventory import (
    BoundaryEndpoint,
    GuestBoundaryObservation,
    HostBoundaryObservation,
)
from aptl.utils.strict_json import model_validate_json_strict
from aptl.workbench.access import CallerGrant, Identifier, SeatAccessRecord
from aptl.workbench.preparation import EnrolledKey
from aptl.workbench.profiles import WorkbenchConfigurationError
from aptl.validation.participant_qualification_evidence import (
    QualificationCheckEvidence,
)

MAX_ACCESS_MESSAGE_BYTES = 2 * 1024 * 1024


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SeatAccessEnrollment(_StrictModel):
    """Public caller enrollment attached to one seat generation."""

    owner_id: Identifier
    grant_id: Identifier
    public_key: str = Field(min_length=32, max_length=16 * 1024)
    profile: Literal["red", "blue"]
    expires_at: datetime
    username: Literal["aptl-mcp"] = "aptl-mcp"

    @model_validator(mode="after")
    def bounded_expiry(self) -> "SeatAccessEnrollment":
        """Require a current, short-lived enrollment before the VM starts."""

        now = datetime.now(UTC)
        if (
            self.expires_at.tzinfo is None
            or not 0 < (self.expires_at - now).total_seconds() <= 86400
        ):
            raise ValueError("seat access must expire within 24 hours")
        return self


class GuestAccessRequest(_StrictModel):
    """Host-to-guest public enrollment bound to a passed start observation."""

    schema_version: Literal["aptl.guest-access-request/v1"]
    nonce: str = Field(pattern=r"^[a-f0-9]{64}$")
    seat_id: Identifier
    instance_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    generation: int = Field(ge=1)
    launch_descriptor_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    enrollment: SeatAccessEnrollment
    guest_endpoint: BoundaryEndpoint
    outer_endpoint: BoundaryEndpoint
    binding: ApplianceBoundaryBinding
    host_observation: HostBoundaryObservation
    guest_observation: GuestBoundaryObservation

    @model_validator(mode="after")
    def exact_mcp_mapping(self) -> "GuestAccessRequest":
        """Require the declared endpoints to describe one exact TCP mapping."""

        guest = self.guest_endpoint
        outer = self.outer_endpoint
        if (
            guest.audience != "host-mcp"
            or outer.audience != "host-mcp"
            or guest.protocol != "tcp"
            or outer.protocol != "tcp"
            or outer.guest_address != guest.address
            or outer.guest_port != guest.port
            or self.host_observation.observation_id != self.binding.host_observation_id
        ):
            raise ValueError("guest access mapping does not match host observation")
        return self


class GuestRuntimeEvidence(_StrictModel):
    """Guest-produced successful run record and its exact range snapshot."""

    schema_version: Literal["aptl.guest-runtime-evidence/v1"]
    run_id: str = Field(min_length=1, max_length=128)
    run_record: dict[str, object]
    snapshot: dict[str, object]
    qualification_checks: tuple[QualificationCheckEvidence, ...] = ()

    @model_validator(mode="after")
    def correlated_success(self) -> "GuestRuntimeEvidence":
        backend = self.run_record.get("backend_evidence")
        if (
            self.run_record.get("schema_version") != "aptl.run-record/v1"
            or self.run_record.get("outcome") != "success"
            or not isinstance(backend, dict)
            or backend.get("range_snapshot") != self.snapshot
            or not isinstance(self.snapshot.get("containers"), list)
            or not isinstance(self.snapshot.get("networks"), list)
            or len({item.check_id for item in self.qualification_checks})
            != len(self.qualification_checks)
        ):
            raise ValueError("guest runtime evidence is not a correlated success")
        return self


class GuestAccessBundle(_StrictModel):
    """Guest-to-host secret-free material returned on the VM-owned channel."""

    schema_version: Literal["aptl.guest-access-bundle/v1"]
    nonce: str = Field(pattern=r"^[a-f0-9]{64}$")
    seat_id: Identifier
    instance_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    generation: int = Field(ge=1)
    access: SeatAccessRecord
    grant: CallerGrant
    host_public_key: str = Field(min_length=32, max_length=16 * 1024)
    runtime_evidence: GuestRuntimeEvidence

    @model_validator(mode="after")
    def matching_identity(self) -> "GuestAccessBundle":
        """Bind every returned record to the same seat generation."""

        expected = (self.seat_id, self.instance_id, self.generation)
        if any(
            (item.seat_id, item.instance_id, item.generation) != expected
            for item in (self.access, self.grant)
        ):
            raise ValueError("guest access bundle identity mismatch")
        return self


def publish_guest_access_request(path: Path, request: GuestAccessRequest) -> None:
    """Create one immutable public enrollment after boundary admission passes."""

    payload = rfc8785.dumps(request.model_dump(mode="json"))
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o400,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path, follow_symlinks=False)
    except OSError as exc:
        raise WorkbenchConfigurationError(
            "guest access request could not be published"
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def read_guest_access_request(path: Path) -> GuestAccessRequest:
    """Read a bounded immutable request without following its final component."""

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OSError("request is not regular")
            payload = handle.read(MAX_ACCESS_MESSAGE_BYTES + 1)
        if len(payload) > MAX_ACCESS_MESSAGE_BYTES:
            raise ValueError("request exceeds access channel limit")
        return model_validate_json_strict(GuestAccessRequest, payload)
    except (OSError, ValueError) as exc:
        raise WorkbenchConfigurationError("guest access request is invalid") from exc


def encode_guest_access_bundle(bundle: GuestAccessBundle) -> bytes:
    """Encode one canonical newline-framed response."""

    payload = rfc8785.dumps(bundle.model_dump(mode="json")) + b"\n"
    if len(payload) > MAX_ACCESS_MESSAGE_BYTES:
        raise WorkbenchConfigurationError("guest access bundle is too large")
    return payload


def publish_guest_access(device_path: Path, bundle: GuestAccessBundle) -> None:
    """Write the access bundle to the dedicated VM-owned virtio port."""

    payload = encode_guest_access_bundle(bundle)
    flags = os.O_WRONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(device_path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISCHR(info.st_mode):
            os.close(descriptor)
            raise OSError("access endpoint is not a character device")
        with os.fdopen(descriptor, "wb", buffering=0) as device:
            device.write(payload)
    except OSError as exc:
        raise WorkbenchConfigurationError(
            "guest access bundle could not be published"
        ) from exc


def wait_for_guest_access(
    socket_path: Path,
    request: GuestAccessRequest,
    *,
    process_alive: Callable[[], bool],
    timeout_seconds: float = 120,
) -> GuestAccessBundle:
    """Receive one bounded bundle tied to the current request and live VM."""

    deadline = time.monotonic() + timeout_seconds
    connection: socket.socket | None = None
    try:
        while connection is None:
            if not process_alive():
                raise WorkbenchConfigurationError("VM exited before guest access")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WorkbenchConfigurationError("guest access deadline expired")
            candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            candidate.settimeout(min(1.0, remaining))
            try:
                candidate.connect(str(socket_path))
                connection = candidate
            except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
                candidate.close()
                time.sleep(min(0.1, max(0.0, remaining)))
        payload = bytearray()
        while b"\n" not in payload:
            if len(payload) >= MAX_ACCESS_MESSAGE_BYTES:
                raise ValueError("guest access bundle exceeds channel limit")
            connection.settimeout(min(1.0, max(0.1, deadline - time.monotonic())))
            chunk = connection.recv(
                min(64 * 1024, MAX_ACCESS_MESSAGE_BYTES - len(payload))
            )
            if not chunk:
                raise ValueError("guest access channel closed before a response")
            payload.extend(chunk)
        if b"\n" in payload[:-1]:
            raise ValueError("guest access framing is invalid")
        bundle = model_validate_json_strict(GuestAccessBundle, bytes(payload[:-1]))
        expected = (
            request.nonce,
            request.seat_id,
            request.instance_id,
            request.generation,
        )
        actual = (bundle.nonce, bundle.seat_id, bundle.instance_id, bundle.generation)
        if actual != expected:
            raise ValueError("guest access response belongs to another start")
        return bundle
    except (OSError, ValueError) as exc:
        raise WorkbenchConfigurationError("guest access response was invalid") from exc
    finally:
        if connection is not None:
            connection.close()


def persist_host_access_bundle(seat_root: Path, bundle: GuestAccessBundle) -> Path:
    """Publish private generation-scoped host discovery without credentials."""

    root = seat_root / "access" / f"generation-{bundle.generation}"
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    for name, payload in {
        "access.json": bundle.access.model_dump_json() + "\n",
        "grant.json": bundle.grant.model_dump_json() + "\n",
        "ssh_host_ed25519_key.pub": bundle.host_public_key.rstrip() + "\n",
        "runtime-evidence.json": bundle.runtime_evidence.model_dump_json() + "\n",
    }.items():
        _atomic_write(root / name, payload.encode(), mode=0o600)
    return root


def invalidate_host_access(seat_root: Path, *, reason: str) -> None:
    """Make every published generation unusable before a lifecycle transition."""

    root = seat_root / "access"
    if not root.is_dir() or root.is_symlink():
        return
    for generation in root.iterdir():
        if not generation.is_dir() or generation.is_symlink():
            continue
        access_path = generation / "access.json"
        if access_path.is_file() and not access_path.is_symlink():
            try:
                record = SeatAccessRecord.model_validate_json(access_path.read_bytes())
                invalid = record.model_copy(update={"lifecycle_state": "needs-reset"})
                _atomic_write(
                    access_path,
                    (invalid.model_dump_json() + "\n").encode(),
                    mode=0o600,
                )
            except (OSError, ValueError):
                access_path.unlink(missing_ok=True)
        (generation / "grant.json").unlink(missing_ok=True)
        _atomic_write(generation / "invalidated", (reason + "\n").encode(), mode=0o600)


def configure_host_clients(
    *,
    bundle: GuestAccessBundle,
    project_dir: Path,
    identity_file: Path,
    username: str,
    clients: tuple[str, ...],
) -> tuple[Path, ...]:
    """Publish native Claude/Codex config using the VM-returned host pin."""

    from aptl.workbench.access_clients import client_entries
    from aptl.workbench.client_files import (
        _private_directory,
        _read,
        publish_client_config,
    )
    from aptl.workbench.dispatch import key_fingerprint, normalize_public_key

    if (
        not clients
        or len(set(clients)) != len(clients)
        or any(client not in {"claude", "codex"} for client in clients)
    ):
        raise WorkbenchConfigurationError("select one or more supported MCP clients")
    root = project_dir.resolve(strict=True)
    public_key = normalize_public_key(bundle.host_public_key)
    fingerprint = key_fingerprint(public_key)
    if bundle.access.host_key_fingerprint != fingerprint:
        raise WorkbenchConfigurationError("guest access host pin is inconsistent")
    ssh = shutil.which("ssh")
    if ssh is None:
        raise WorkbenchConfigurationError("OpenSSH client is required")
    _private_directory(root, ".aptl")
    known = (
        root
        / ".aptl"
        / (
            f"{bundle.seat_id}-{bundle.generation}-"
            f"{fingerprint[7:19].replace('/', '_')}.known_hosts"
        )
    )
    endpoint = bundle.access.outer_endpoint
    content = f"[{endpoint.address}]:{endpoint.port} {public_key}\n".encode()
    existing = _read(root, known.relative_to(root).as_posix())
    if existing is not None and existing.encode() != content:
        raise WorkbenchConfigurationError("existing transport pin conflicts")
    _atomic_write(known, content, mode=0o600)
    entries = client_entries(
        bundle.access,
        bundle.grant,
        ssh_executable=Path(ssh),
        identity_file=identity_file,
        known_hosts=known,
        username=username,
    )
    return tuple(
        publish_client_config(root, client, bundle.access, entries)
        for client in clients
    )


def enrolled_key(request: GuestAccessRequest) -> EnrolledKey:
    """Project the public request into the existing restricted transport model."""

    item = request.enrollment
    return EnrolledKey(
        grant_id=item.grant_id,
        public_key=item.public_key,
        profile=item.profile,
        expires_at=item.expires_at,
    )
