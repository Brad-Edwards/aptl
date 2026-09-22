"""Bounded, per-start guest readiness records over a VM-owned channel."""

from __future__ import annotations

import os
import secrets
import socket
import stat
import time
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import rfc8785
from pydantic import BaseModel, ConfigDict, Field

from aptl.appliance.seat._device import write_character_device
from aptl.appliance.seat.errors import SeatLauncherError
from aptl.core.appliance_boundary_inventory import GuestBoundaryObservation
from aptl.utils.strict_json import model_validate_json_strict

MAX_READINESS_BYTES = 256 * 1024


class _StrictModel(BaseModel):
    """Closed immutable base for per-start readiness records."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class GuestReadinessChallenge(_StrictModel):
    """Fresh host challenge mounted into exactly one launched seat VM."""

    schema_version: Literal["aptl.guest-readiness-challenge/v1"]
    seat_id: str = Field(min_length=1, max_length=80)
    instance_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    generation: int = Field(ge=1)
    launch_descriptor_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    nonce: str = Field(pattern=r"^[a-f0-9]{64}$")


class GuestReadinessEnvelope(_StrictModel):
    """Guest observation attributed to one fresh host launch challenge."""

    schema_version: Literal["aptl.guest-readiness/v1"]
    seat_id: str = Field(min_length=1, max_length=80)
    instance_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    generation: int = Field(ge=1)
    launch_descriptor_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    nonce: str = Field(pattern=r"^[a-f0-9]{64}$")
    observation: GuestBoundaryObservation


def publish_readiness_challenge(
    path: Path,
    *,
    seat_id: str,
    instance_id: str,
    generation: int,
    launch_descriptor_digest: str,
) -> GuestReadinessChallenge:
    """Atomically publish a fresh challenge before starting one VM generation."""

    challenge = GuestReadinessChallenge(
        schema_version="aptl.guest-readiness-challenge/v1",
        seat_id=seat_id,
        instance_id=instance_id,
        generation=generation,
        launch_descriptor_digest=launch_descriptor_digest,
        nonce=secrets.token_hex(32),
    )
    payload = rfc8785.dumps(challenge.model_dump(mode="json"))
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
        os.replace(temporary, path)
        path.chmod(0o400)
    except OSError as exc:
        raise SeatLauncherError(
            "failed-readiness", "guest readiness challenge could not be staged"
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)
    return challenge


def encode_guest_readiness(
    challenge: GuestReadinessChallenge,
    observation: GuestBoundaryObservation,
) -> bytes:
    """Encode one bounded canonical guest response for the virtio channel."""

    envelope = GuestReadinessEnvelope(
        schema_version="aptl.guest-readiness/v1",
        seat_id=challenge.seat_id,
        instance_id=challenge.instance_id,
        generation=challenge.generation,
        launch_descriptor_digest=challenge.launch_descriptor_digest,
        nonce=challenge.nonce,
        observation=observation,
    )
    payload = rfc8785.dumps(envelope.model_dump(mode="json")) + b"\n"
    if len(payload) > MAX_READINESS_BYTES:
        raise ValueError("guest readiness response exceeds the channel limit")
    return payload


def load_guest_readiness_challenge(path: Path) -> GuestReadinessChallenge:
    """Read one bounded regular challenge from the read-only launch share."""

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OSError("challenge is not regular")
            payload = handle.read(64 * 1024 + 1)
        if len(payload) > 64 * 1024:
            raise ValueError("challenge is too large")
        return model_validate_json_strict(GuestReadinessChallenge, payload)
    except (OSError, ValueError) as exc:
        raise SeatLauncherError(
            "boundary.guest-challenge-invalid",
            "guest readiness challenge was invalid",
        ) from exc


def publish_guest_readiness(
    challenge_path: Path,
    device_path: Path,
    observation: GuestBoundaryObservation,
) -> None:
    """Write one complete response to the VM-owned virtio serial device."""

    challenge = load_guest_readiness_challenge(challenge_path)
    payload = encode_guest_readiness(challenge, observation)
    try:
        write_character_device(device_path, payload)
    except OSError as exc:
        raise SeatLauncherError(
            "boundary.guest-readiness-write-failed",
            "guest readiness response could not be published",
        ) from exc


def _validate_response(
    payload: bytes,
    challenge: GuestReadinessChallenge,
) -> GuestBoundaryObservation:
    """Validate one complete response against the current start challenge."""

    if not payload.endswith(b"\n") or b"\n" in payload[:-1]:
        raise ValueError("guest readiness response framing is invalid")
    envelope = model_validate_json_strict(GuestReadinessEnvelope, payload[:-1])
    expected = (
        challenge.seat_id,
        challenge.instance_id,
        challenge.generation,
        challenge.launch_descriptor_digest,
        challenge.nonce,
    )
    observed = (
        envelope.seat_id,
        envelope.instance_id,
        envelope.generation,
        envelope.launch_descriptor_digest,
        envelope.nonce,
    )
    if observed != expected:
        raise ValueError("guest readiness response is stale or belongs to another seat")
    return envelope.observation


def wait_for_guest_readiness(
    socket_path: Path,
    challenge: GuestReadinessChallenge,
    *,
    process_alive: Callable[[], bool],
    timeout_seconds: float = 1800,
) -> GuestBoundaryObservation:
    """Wait for one bounded current response while the tracked VM remains alive."""

    deadline = time.monotonic() + timeout_seconds
    connection: socket.socket | None = None
    try:
        while connection is None:
            if not process_alive():
                raise SeatLauncherError("failed-launch", "VM exited before readiness")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SeatLauncherError(
                    "boundary.guest-observation-missing",
                    "guest readiness deadline expired",
                )
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
            if len(payload) >= MAX_READINESS_BYTES:
                raise ValueError("guest readiness response exceeds the channel limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SeatLauncherError(
                    "boundary.guest-observation-missing",
                    "guest readiness deadline expired",
                )
            connection.settimeout(min(1.0, remaining))
            try:
                chunk = connection.recv(
                    min(64 * 1024, MAX_READINESS_BYTES - len(payload))
                )
            except socket.timeout:
                if not process_alive():
                    raise SeatLauncherError(
                        "failed-launch", "VM exited before readiness"
                    ) from None
                continue
            if not chunk:
                raise ValueError("guest readiness channel closed before a response")
            payload.extend(chunk)
        return _validate_response(bytes(payload), challenge)
    except SeatLauncherError:
        raise
    except (OSError, ValueError) as exc:
        raise SeatLauncherError(
            "boundary.guest-observation-invalid",
            "guest readiness response was invalid",
        ) from exc
    finally:
        if connection is not None:
            connection.close()
