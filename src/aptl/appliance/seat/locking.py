"""Cross-process serialization for one seat's lifecycle mutations."""

from __future__ import annotations

import errno
import os
import stat
import threading
from collections.abc import Callable
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import ParamSpec, TypeVar, cast

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.persistence import _ensure_seat_root

P = ParamSpec("P")
R = TypeVar("R")
_LOCK_NAME = ".lifecycle.lock"
_THREAD_STATE = threading.local()


def _held_locks() -> dict[str, tuple[int, int]]:
    """Return this thread's reentrant lock descriptors and depths."""

    held = getattr(_THREAD_STATE, "held_locks", None)
    if held is None:
        held = {}
        _THREAD_STATE.held_locks = held
    return cast(dict[str, tuple[int, int]], held)


@contextmanager
def seat_mutation_lock(seat_root: Path):
    """Hold the owner-only lifecycle lock for exactly one seat root."""

    _ensure_seat_root(seat_root)
    key = str(seat_root.resolve())
    held = _held_locks()
    existing = held.get(key)
    if existing is not None:
        descriptor, depth = existing
        held[key] = (descriptor, depth + 1)
        try:
            yield
        finally:
            held[key] = (descriptor, depth)
        return

    path = seat_root / _LOCK_NAME
    try:
        import fcntl
    except ModuleNotFoundError as exc:
        raise SeatLauncherError(
            "unsupported-host-os", "seat lifecycle locking requires POSIX"
        ) from exc
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise OSError("seat lifecycle lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise SeatLauncherError(
                    "seat-lifecycle-busy",
                    "another seat lifecycle operation is active",
                ) from exc
            raise
    except SeatLauncherError:
        os.close(descriptor)
        raise
    except OSError as exc:
        if "descriptor" in locals():
            os.close(descriptor)
        raise SeatLauncherError(
            "seat-lock-unavailable", "seat lifecycle lock is unavailable"
        ) from exc

    held[key] = (descriptor, 1)
    try:
        yield
    finally:
        del held[key]
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def serialized_seat_mutation(
    function: Callable[P, R],
) -> Callable[P, R]:
    """Serialize a lifecycle function whose first argument is ``seat_root``."""

    @wraps(function)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        seat_root = args[0] if args else kwargs.get("seat_root")
        if not isinstance(seat_root, Path):
            raise TypeError("seat_root must be a pathlib.Path")
        with seat_mutation_lock(seat_root):
            return function(*args, **kwargs)

    return wrapped
