"""Shared descriptor-relative, no-follow path containment.

ADR-047 "Authorized artifact resolution": resolving a path and checking its
prefix (``Path.resolve()`` + ``is_relative_to()``) is not enough, because a
symlink can be swapped in between that check and a later open — the classic
TOCTOU race. This module walks an untrusted relative path component-by-
component with ``os.open(..., os.O_NOFOLLOW, dir_fd=<parent fd>)``
(openat-style), so:

- every intermediate directory component, AND the leaf, are opened
  no-follow. A symlinked component anywhere in the path (including the
  leaf) raises :class:`PathContainmentError` (``ELOOP`` under
  ``O_NOFOLLOW``) instead of being silently followed.
- the target is opened exactly ONCE. Callers hash/read/write bytes through
  the same handle that was opened, so nothing can swap the underlying file
  between a "check" and a later independent re-open by path.

``base_dir`` is the trusted starting point (an already-established
project/store root, e.g. from ``AptlConfig`` or a caller-resolved project
directory) — only ``relative_path``, the untrusted part, is walked
no-follow. Absolute paths, and ``..``/``.``/empty path components, and NUL
bytes are rejected before any syscall runs.

This is the ONE shared containment helper (ADR-047 "Scenario containment
precedent" / "Persistence" security layers): ``scenario_catalog`` and the
run store's create-once persistence both reuse it rather than each
maintaining their own lexical path checker.
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

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


def _open_leaf_create_exclusive_nofollow(component: str, parent_fd: int) -> int:
    """Create-exclusive-open component under parent_fd, no-follow, for the create-once write path."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        return os.open(component, flags, 0o600, dir_fd=parent_fd)
    except FileExistsError:
        # A distinct, un-wrapped signal: the leaf already exists (whether a
        # regular file, a directory, or a symlink — O_EXCL fires before
        # O_NOFOLLOW is even consulted for an existing path per open(2)).
        # Callers decide the idempotency policy from here.
        raise
    except OSError as exc:
        raise PathContainmentError(
            _reason_for(exc, component, parent_fd),
            f"rejected leaf component {component!r}: {exc}",
        ) from exc


def create_exclusive_nofollow(
    base_dir: Path | str, relative_path: str | Path, data: bytes
) -> None:
    """Create ``relative_path`` under ``base_dir`` and write ``data`` once.

    Intermediate directory components are created if missing (still walked
    no-follow — an existing symlinked intermediate is rejected, never
    followed or replaced). The leaf is opened with
    ``O_CREAT | O_EXCL | O_NOFOLLOW`` under its parent directory's
    descriptor, so a pre-existing symlink anywhere on the path — including
    right at the leaf — cannot redirect the write outside ``base_dir``, and
    two processes racing to create the same path cannot silently clobber
    one another.

    Raises :class:`PathContainmentError` for the same structural/symlink
    reasons as :func:`open_contained_nofollow`. Raises ``FileExistsError``
    (unwrapped) when the leaf already exists — the create-once caller
    decides the idempotency policy (e.g. compare-then-accept on a byte
    match via :func:`read_contained_nofollow`).
    """
    components = _split_components(relative_path)
    base_fd = _open_base_fd(base_dir)
    try:
        leaf_fd = _walk(
            components,
            base_fd,
            open_dir=_open_dir_nofollow_or_create,
            open_leaf=_open_leaf_create_exclusive_nofollow,
        )
    finally:
        os.close(base_fd)
    try:
        os.write(leaf_fd, data)
        os.fsync(leaf_fd)
    finally:
        os.close(leaf_fd)
