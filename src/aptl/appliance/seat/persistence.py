"""Owner-only atomic persistence for the host seat contract."""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

import rfc8785
from pydantic import ValidationError

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.models import SeatRecord


def _ensure_seat_root(seat_root: Path) -> None:
    """Create or validate an owner-only seat root directory."""

    if seat_root.is_symlink():
        raise SeatLauncherError(
            "corrupt-seat-state", "seat root must not be a symlink"
        )
    try:
        seat_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        seat_root.chmod(0o700)
        info = seat_root.stat(follow_symlinks=False)
    except OSError as exc:
        raise SeatLauncherError(
            "corrupt-seat-state", "seat root is unavailable"
        ) from exc
    if not stat.S_ISDIR(info.st_mode):
        raise SeatLauncherError("corrupt-seat-state", "seat root is not a directory")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise SeatLauncherError(
            "corrupt-seat-state", "seat root must be owner-only"
        )


def seat_state_path(seat_root: Path) -> Path:
    """Return the canonical seat-state path under one seat root."""

    return seat_root / "seat-state.json"


def load_seat_record(seat_root: Path) -> SeatRecord | None:
    """Load persisted seat metadata when present and valid."""

    path = seat_state_path(seat_root)
    if not path.exists():
        return None
    try:
        info = path.stat(follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            raise SeatLauncherError(
                "corrupt-seat-state", "seat state must not be a symlink"
            )
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise SeatLauncherError(
                "corrupt-seat-state", "seat state must be owner-only"
            )
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            payload = handle.read()
        return SeatRecord.model_validate_json(payload)
    except SeatLauncherError:
        raise
    except (OSError, ValidationError, ValueError) as exc:
        raise SeatLauncherError("corrupt-seat-state", "seat state is invalid") from exc


def persist_seat_record(seat_root: Path, record: SeatRecord) -> None:
    """Atomically publish seat metadata."""

    _ensure_seat_root(seat_root)
    path = seat_state_path(seat_root)
    temporary = path.with_name(f".seat-state.{os.getpid()}-{secrets.token_hex(8)}")
    payload = rfc8785.dumps(record.model_dump(mode="json"))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(temporary, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise SeatLauncherError(
            "corrupt-seat-state", "seat state could not be persisted"
        ) from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
