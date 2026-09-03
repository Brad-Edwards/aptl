"""No-follow read/list operations for :mod:`aptl.utils.pathsafe`.

The read half of the pathsafe trio: open a contained regular file, read its
bytes, list a contained directory, or open a contained directory descriptor —
each walking every path component ``O_NOFOLLOW`` (openat-style) so a symlinked
component anywhere on the path is rejected rather than followed. Built on the
shared primitives in :mod:`aptl.utils._pathsafe_core`.

The public surface is re-exported from :mod:`aptl.utils.pathsafe`; import from
there, not from this private module.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import BinaryIO

from aptl.utils._pathsafe_core import (
    REASON_NOT_REGULAR_FILE,
    PathContainmentError,
    _open_base_fd,
    _open_dir_nofollow,
    _open_dir_nofollow_or_create,
    _reason_for,
    _split_components,
    _walk,
)


def _open_leaf_read_nofollow(component: str, parent_fd: int) -> int:
    """Open component read-only under parent_fd, no-follow, rejecting a non-regular-file target."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(component, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise PathContainmentError(
            _reason_for(exc, component, parent_fd),
            f"rejected path component {component!r}: {exc}",
        ) from exc
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise PathContainmentError(REASON_NOT_REGULAR_FILE, "target is not a regular file")
    return fd


def open_contained_nofollow(base_dir: Path | str, relative_path: str | Path) -> BinaryIO:
    """Open ``relative_path`` under ``base_dir`` with one-open, no-follow semantics.

    Walks each path component with ``os.open(..., O_NOFOLLOW, dir_fd=parent)``
    so a symlinked directory component or leaf is rejected rather than
    silently followed, and opens the final regular file exactly once.
    Returns a binary file object bound to that single open handle — read or
    hash directly from it; never reopen the original path afterward (that
    would reintroduce the TOCTOU race this function exists to close).

    Raises :class:`PathContainmentError` for: an absolute ``relative_path``;
    a NUL byte; an empty, ``.``, or ``..`` path component; any symlinked
    component (including the leaf); a missing component; or a leaf that is
    not a regular file. Every intermediate directory descriptor is closed;
    only the leaf descriptor is returned (open) on success.
    """
    components = _split_components(relative_path)
    base_fd = _open_base_fd(base_dir)
    try:
        leaf_fd = _walk(
            components, base_fd, open_dir=_open_dir_nofollow, open_leaf=_open_leaf_read_nofollow
        )
    finally:
        os.close(base_fd)
    return os.fdopen(leaf_fd, "rb")


def read_contained_nofollow(base_dir: Path | str, relative_path: str | Path) -> bytes:
    """Return the exact bytes of ``relative_path`` under ``base_dir``.

    One-open convenience over :func:`open_contained_nofollow`: reads from
    the very handle that was opened no-follow, so nothing can be swapped
    between validation and read (TOCTOU-proof by construction).
    """
    with open_contained_nofollow(base_dir, relative_path) as handle:
        return handle.read()


def _open_leaf_dir_nofollow(component: str, parent_fd: int) -> int:
    """Open ``component`` as a directory under ``parent_fd``, no-follow.

    The listing companion to :func:`_open_leaf_read_nofollow`: the leaf must be
    a real directory, and a symlink at the leaf is rejected exactly like any
    other symlinked component.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        return os.open(component, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise PathContainmentError(
            _reason_for(exc, component, parent_fd),
            f"rejected path component {component!r}: {exc}",
        ) from exc


def listdir_contained_nofollow(base_dir: Path | str, relative_path: str | Path) -> list[str]:
    """Return the sorted entry names of ``relative_path`` under ``base_dir``.

    Walks each path component no-follow (openat-style) exactly like
    :func:`open_contained_nofollow`, then lists the leaf directory through the
    descriptor that was opened — never by re-resolving the path — so a symlinked
    component anywhere on the path (including the leaf directory itself) raises
    :class:`PathContainmentError` instead of enumerating an attacker-chosen
    directory. Names are sorted for deterministic iteration.

    Raises :class:`PathContainmentError` for an absolute, empty, ``.``, or
    ``..`` component; a symlinked component; a missing component; or a leaf that
    is not a directory (surfaced as its ``os.open`` failure reason).
    """
    components = _split_components(relative_path)
    base_fd = _open_base_fd(base_dir)
    try:
        dir_fd = _walk(
            components, base_fd, open_dir=_open_dir_nofollow, open_leaf=_open_leaf_dir_nofollow
        )
    finally:
        os.close(base_fd)
    try:
        return sorted(os.listdir(dir_fd))
    finally:
        os.close(dir_fd)


def open_dir_contained_nofollow(
    base_dir: Path | str, relative_dir: str | Path, *, create: bool = False
) -> int:
    """Return a descriptor for ``relative_dir`` under ``base_dir``, walked no-follow.

    Every component (including the leaf directory) is opened with
    ``O_DIRECTORY | O_NOFOLLOW`` under its parent's descriptor, so a symlinked
    intermediate — the classic ``index -> /elsewhere`` swap — is rejected rather
    than followed. With ``create=True`` missing directory components are created
    as real directories (never replacing an existing symlink). The caller owns
    the returned descriptor and must close it.

    Raises :class:`PathContainmentError` for an absolute/``.``/``..``/empty/NUL
    component, a symlinked component, or (when ``create`` is false) a missing one.
    """
    components = _split_components(relative_dir)
    opener = _open_dir_nofollow_or_create if create else _open_dir_nofollow
    base_fd = _open_base_fd(base_dir)
    try:
        return _walk(components, base_fd, open_dir=opener, open_leaf=opener)
    finally:
        os.close(base_fd)
