"""Idempotent per-overlay identity and bootstrap credential creation."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import rfc8785
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ApplianceBootstrapError(RuntimeError):
    """Per-overlay identity could not be established safely."""


class OverlayIdentity(BaseModel):
    """Guest-only identity created exactly once for one disposable overlay."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["aptl.overlay-identity/v1"]
    instance_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    bootstrap_credential: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")


def _ensure_state_directory(path: Path) -> None:
    if path.is_symlink():
        raise ApplianceBootstrapError("overlay state directory must not be a symlink")
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ApplianceBootstrapError("overlay state directory is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise ApplianceBootstrapError("overlay state path is not a directory")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ApplianceBootstrapError("overlay state directory must be owner-only")


def _read_existing(path: Path) -> OverlayIdentity:
    try:
        info = path.stat(follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            raise ApplianceBootstrapError("overlay identity must not be a symlink")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ApplianceBootstrapError("overlay identity must be owner-only")
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            payload = handle.read()
        return OverlayIdentity.model_validate_json(payload)
    except ApplianceBootstrapError:
        raise
    except (OSError, ValidationError, ValueError) as exc:
        raise ApplianceBootstrapError("overlay identity is invalid") from exc


def _new_identity(entropy: Callable[[int], bytes]) -> OverlayIdentity:
    identity_bytes = entropy(32)
    credential_bytes = entropy(32)
    if len(identity_bytes) != 32 or len(credential_bytes) != 32:
        raise ApplianceBootstrapError("overlay entropy source returned invalid data")
    return OverlayIdentity(
        schema_version="aptl.overlay-identity/v1",
        instance_id=f"sha256:{hashlib.sha256(identity_bytes).hexdigest()}",
        bootstrap_credential=base64.urlsafe_b64encode(credential_bytes)
        .decode("ascii")
        .rstrip("="),
    )


def _persist_create_once(path: Path, identity: OverlayIdentity) -> bool:
    temporary = path.with_name(f".identity.{os.getpid()}-{secrets.token_hex(8)}")
    payload = rfc8785.dumps(identity.model_dump(mode="json"))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(temporary, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
            return True
        except FileExistsError:
            return False
    except OSError as exc:
        raise ApplianceBootstrapError(
            "overlay identity could not be persisted"
        ) from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def initialize_overlay_state(
    state_dir: Path,
    *,
    entropy: Callable[[int], bytes] = os.urandom,
) -> OverlayIdentity:
    """Create identity once per overlay and reuse it on ordinary reboot."""

    _ensure_state_directory(state_dir)
    identity_path = state_dir / "identity.json"
    if identity_path.exists() or identity_path.is_symlink():
        return _read_existing(identity_path)
    candidate = _new_identity(entropy)
    if _persist_create_once(identity_path, candidate):
        return candidate
    return _read_existing(identity_path)
