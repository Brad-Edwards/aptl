"""Shared deterministic-USTAR archive mechanics.

Generalized out of :mod:`aptl.appliance.offline` (EXP-008 preflight: "reuse or
generalize only their archive mechanics; do not add another checksum helper").
Two archives built from identical member bytes and identical
``(relative, is_dir, mode)`` inputs are byte-identical, because every member's
uid/gid/uname/gname/mtime is normalized and the archive uses ``USTAR_FORMAT``.

This module owns ONLY the reproducible member metadata, the no-follow read
open, and the streaming content hash. Callers keep their own containment,
validation, and create-once publication policy — those differ between the
appliance's closed staging allowlist and research export's reference-driven
closure, and must not be conflated.
"""

from __future__ import annotations

import hashlib
import os
import tarfile
from pathlib import Path
from typing import BinaryIO

_HASH_CHUNK = 1024 * 1024


def deterministic_tarinfo(
    relative: str, *, is_dir: bool, size: int, mode: int
) -> tarfile.TarInfo:
    """Return reproducible USTAR metadata for one member.

    All owner and time metadata is normalized so the archive bytes depend only
    on ``relative``, whether it is a directory, its ``mode``, and (for regular
    files) the member ``size`` and content. Directory members always carry
    ``size == 0``.
    """
    info = tarfile.TarInfo(relative)
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    if is_dir:
        info.type = tarfile.DIRTYPE
        info.mode = mode
        info.size = 0
    else:
        info.type = tarfile.REGTYPE
        info.mode = mode
        info.size = size
    return info


def open_nofollow(path: Path | str) -> BinaryIO:
    """Open one regular file read-only without following a final symlink.

    ``O_NOFOLLOW`` makes a symlink at ``path`` raise ``OSError`` (``ELOOP``)
    rather than being followed. This guards a single already-resolved leaf; use
    :mod:`aptl.utils.pathsafe` when the whole relative path is untrusted.
    """
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.fdopen(os.open(path, flags), "rb")


def hash_file_nofollow(path: Path | str) -> tuple[str, int]:
    """Return the streaming ``sha256:<hex>`` identity and byte size of ``path``.

    Reads in bounded chunks through a single no-follow handle so nothing is
    buffered whole and no symlink is followed.
    """
    digest = hashlib.sha256()
    size = 0
    with open_nofollow(path) as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
            digest.update(chunk)
            size += len(chunk)
    return f"sha256:{digest.hexdigest()}", size


__all__ = ["deterministic_tarinfo", "open_nofollow", "hash_file_nofollow"]
