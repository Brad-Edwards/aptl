"""Seat identifier validation and contained path resolution."""

from __future__ import annotations

import re
from pathlib import Path

from aptl.appliance.seat.errors import SeatLauncherError

_SEAT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def validate_seat_id(seat_id: str) -> str:
    """Reject seat identifiers that can escape the seat root via path segments."""

    if not _SEAT_ID.fullmatch(seat_id):
        raise SeatLauncherError(
            "invalid-seat-id",
            "seat id must be a bounded lowercase identifier",
        )
    return seat_id


def contained_path(seat_root: Path, relative: str, *, label: str) -> Path:
    """Resolve one relative path and require it stays under seat_root."""

    root = seat_root.resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise SeatLauncherError(
            "invalid-seat-id",
            f"{label} must remain contained by seat root",
        ) from exc
    return candidate
