"""Shared no-follow containment primitives for :mod:`aptl.utils.pathsafe`.

This is the leaf of the pathsafe trio: the untrusted-path validation
(:func:`_split_components`), the ``REASON_*`` codes and
:class:`PathContainmentError`, the trusted base-fd opener, and the
component-by-component walkers used by both the read side
(:mod:`aptl.utils._pathsafe_read`) and the write side
(:mod:`aptl.utils.pathsafe`). It imports neither, so there is no cycle.

The public surface is re-exported from :mod:`aptl.utils.pathsafe`; import from
there, not from this private module.
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable
from pathlib import Path

REASON_NOT_RELATIVE = "not_relative"
REASON_NUL_BYTE = "nul_byte"
REASON_EMPTY_COMPONENT = "empty_component"
REASON_DOT_COMPONENT = "dot_component"
REASON_TRAVERSAL = "traversal"
REASON_SYMLINK = "symlink"
REASON_NOT_FOUND = "not_found"
REASON_NOT_REGULAR_FILE = "not_regular_file"
REASON_BASE_DIR_UNAVAILABLE = "base_dir_unavailable"
REASON_OPEN_FAILED = "open_failed"


class PathContainmentError(Exception):
    """Raised when ``relative_path`` cannot be safely opened under ``base_dir``.

    ``reason`` is a short, stable, machine-checkable code (one of this
    module's ``REASON_*`` constants) so callers can translate this single
    typed error into their own domain-specific message without parsing
    prose out of ``str(exc)``.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _split_components(relative_path: str | Path) -> list[str]:
    """Validate and split ``relative_path`` into literal ``/``-separated
    components, rejecting anything that could escape or be ambiguous.

    Splits on literal ``/`` rather than going through ``pathlib`` so a
    double slash or trailing slash surfaces as the empty component it
    lexically is, instead of being silently collapsed away.
    """
    text = str(relative_path)
    if "\x00" in text:
        raise PathContainmentError(REASON_NUL_BYTE, "path must not contain NUL bytes")
    if not text:
        raise PathContainmentError(REASON_EMPTY_COMPONENT, "path must not be empty")
    if text.startswith("/"):
        raise PathContainmentError(REASON_NOT_RELATIVE, f"path must be relative: {text!r}")
    components = text.split("/")
    for component in components:
        if component == "":
            raise PathContainmentError(
                REASON_EMPTY_COMPONENT, f"path contains an empty component: {text!r}"
            )
        if component == "..":
            raise PathContainmentError(
                REASON_TRAVERSAL, f"path contains a '..' component: {text!r}"
            )
        if component == ".":
            raise PathContainmentError(
                REASON_DOT_COMPONENT, f"path contains a '.' component: {text!r}"
            )
    return components


def _reason_for(exc: OSError, component: str, parent_fd: int) -> str:
    """Classify a failed component open into a stable ``REASON_*`` code.

    ``ELOOP`` is the unambiguous no-follow-hit-a-symlink signal for a leaf
    open (no ``O_DIRECTORY``). For an intermediate directory open, Linux's
    ``O_DIRECTORY | O_NOFOLLOW`` combination surfaces a symlinked component
    as ``ENOTDIR`` instead of ``ELOOP`` (empirically verified), which is
    indistinguishable from an ordinary "not a directory" without a further
    check. Since the access has *already been rejected* either way by the
    failed ``os.open()``, a no-follow ``fstatat`` purely to choose the more
    honest reason code is safe — it cannot reopen, follow, or grant access
    to anything; it only makes the error message accurate.
    """
    if exc.errno == errno.ELOOP:
        return REASON_SYMLINK
    if exc.errno not in (errno.ENOENT, errno.ENOTDIR):
        return REASON_OPEN_FAILED
    return _reason_for_missing_component(component, parent_fd)


def _reason_for_missing_component(component: str, parent_fd: int) -> str:
    """Distinguish a genuinely missing path component from an existing symlink at that path.

    Called only for the ``ENOENT``/``ENOTDIR`` case, where a symlinked
    intermediate component surfaces as ``ENOTDIR`` rather than ``ELOOP``
    (see :func:`_reason_for`).
    """
    try:
        st = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return REASON_NOT_FOUND
    return REASON_SYMLINK if stat.S_ISLNK(st.st_mode) else REASON_NOT_FOUND


def _open_base_fd(base_dir: Path | str) -> int:
    """Open base_dir as a read-only directory file descriptor, the trusted root every walk starts from."""
    try:
        return os.open(base_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        raise PathContainmentError(
            REASON_BASE_DIR_UNAVAILABLE, f"base directory unavailable: {exc}"
        ) from exc


def _walk(
    components: list[str],
    base_fd: int,
    *,
    open_dir: Callable[[str, int], int],
    open_leaf: Callable[[str, int], int],
) -> int:
    """Walk ``components`` under ``base_fd``, closing intermediate fds.

    Every fd opened along the way except the final leaf is closed before
    returning or raising, so only the caller-owned leaf descriptor (on
    success) survives. ``base_fd`` is never closed here — that remains the
    caller's responsibility.
    """
    current_fd = base_fd
    try:
        for index, component in enumerate(components):
            is_leaf = index == len(components) - 1
            opener = open_leaf if is_leaf else open_dir
            next_fd = opener(component, current_fd)
            if current_fd != base_fd:
                os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        if current_fd != base_fd:
            os.close(current_fd)
        raise


def _walk_to_parent(
    dir_components: list[str],
    base_fd: int,
    *,
    open_dir: Callable[[str, int], int],
) -> int:
    """Walk the directory components under ``base_fd``, returning the leaf's parent fd.

    Like :func:`_walk` but stops at the parent directory of the leaf and returns
    that descriptor OPEN (creating intermediate dirs when ``open_dir`` does),
    closing every earlier intermediate. When ``dir_components`` is empty the leaf
    lives directly under ``base_dir``, so ``base_fd`` itself is the parent and is
    returned unchanged — the caller must never close it here. Any non-``base_fd``
    parent it returns is caller-owned and must be closed by the caller.
    """
    current_fd = base_fd
    try:
        for component in dir_components:
            next_fd = open_dir(component, current_fd)
            if current_fd != base_fd:
                os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        if current_fd != base_fd:
            os.close(current_fd)
        raise


def _open_dir_nofollow(component: str, parent_fd: int) -> int:
    """Open component as a directory under parent_fd, no-follow; raise PathContainmentError on any failure."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        return os.open(component, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise PathContainmentError(
            _reason_for(exc, component, parent_fd),
            f"rejected path component {component!r}: {exc}",
        ) from exc


def _open_dir_nofollow_or_create(component: str, parent_fd: int) -> int:
    """Open ``component`` no-follow, creating it as a real directory if
    (and only if) it does not already exist. A pre-existing symlink or
    non-directory at this path is rejected exactly like
    :func:`_open_dir_nofollow` — creation never overwrites or follows an
    existing entry.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        return os.open(component, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise PathContainmentError(
            _reason_for(exc, component, parent_fd),
            f"rejected path component {component!r}: {exc}",
        ) from exc
    try:
        os.mkdir(component, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        # lost a create race with another writer; fall through to open
        pass
    except OSError as exc:
        raise PathContainmentError(
            _reason_for(exc, component, parent_fd),
            f"cannot create directory {component!r}: {exc}",
        ) from exc
    try:
        return os.open(component, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise PathContainmentError(
            _reason_for(exc, component, parent_fd),
            f"rejected path component {component!r}: {exc}",
        ) from exc
