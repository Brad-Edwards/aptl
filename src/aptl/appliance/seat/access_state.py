"""Validation for replacing revoked appliance access generations."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.workbench.access import SeatAccessRecord
from aptl.workbench.profiles import WorkbenchConfigurationError

if TYPE_CHECKING:
    from aptl.appliance.seat.access import GuestAccessBundle

_ACCESS_RECORD_NAME = "access.json"
_ALLOWED_INVALIDATED_FILES = {
    _ACCESS_RECORD_NAME,
    "invalidated",
    "runtime-evidence.json",
    "ssh_host_ed25519_key.pub",
}


def _validate_generation_root(root: Path) -> None:
    """Require an owner-only directory with an explicitly revoked file set."""

    info = root.stat(follow_symlinks=False)
    if (
        root.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise OSError("existing access generation is unsafe")
    children = {child.name for child in root.iterdir()}
    if "invalidated" not in children or not children <= _ALLOWED_INVALIDATED_FILES:
        raise OSError("existing access generation is still active")


def _validate_generation_files(root: Path) -> None:
    """Require every invalidated generation entry to be owner-only and regular."""

    for child in root.iterdir():
        info = child.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise OSError("existing access generation is unsafe")


def _read_access_record(path: Path) -> SeatAccessRecord:
    """Read a bounded owner-only access record without following a leaf link."""

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        payload = handle.read(64 * 1024 + 1)
    if not payload or len(payload) > 64 * 1024:
        raise OSError("existing access record has invalid size")
    return SeatAccessRecord.model_validate_json(payload)


def _validate_generation_identity(root: Path, bundle: GuestAccessBundle) -> None:
    """Require the revoked record to identify the generation being refreshed."""

    previous = _read_access_record(root / _ACCESS_RECORD_NAME)
    expected = (
        bundle.access.owner_id,
        bundle.seat_id,
        bundle.instance_id,
        bundle.generation,
    )
    observed = (
        previous.owner_id,
        previous.seat_id,
        previous.instance_id,
        previous.generation,
    )
    if previous.lifecycle_state != "needs-reset" or observed != expected:
        raise OSError("invalidated access generation identity changed")


def remove_matching_invalidated_generation(
    root: Path, bundle: GuestAccessBundle
) -> None:
    """Permit refresh only over this seat's revoked matching generation."""

    if not root.exists() and not root.is_symlink():
        return
    try:
        _validate_generation_root(root)
        _validate_generation_files(root)
        _validate_generation_identity(root, bundle)
        shutil.rmtree(root)
    except (OSError, ValueError) as exc:
        raise WorkbenchConfigurationError(
            "existing access generation cannot be refreshed"
        ) from exc
