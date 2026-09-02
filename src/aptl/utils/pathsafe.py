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

The implementation is split across three modules to stay within the
per-file size budget while keeping one public import surface: the shared
validation/walk primitives live in :mod:`aptl.utils._pathsafe_core`, the
read/list operations in :mod:`aptl.utils._pathsafe_read`, and the
create-once write path below. All public names are re-exported here — always
import from ``aptl.utils.pathsafe``, never from the private sibling modules.
"""

from __future__ import annotations

import errno
import itertools
import os
from pathlib import Path

from aptl.utils._pathsafe_core import (
    REASON_BASE_DIR_UNAVAILABLE,
    REASON_DOT_COMPONENT,
    REASON_EMPTY_COMPONENT,
    REASON_NOT_FOUND,
    REASON_NOT_REGULAR_FILE,
    REASON_NOT_RELATIVE,
    REASON_NUL_BYTE,
    REASON_OPEN_FAILED,
    REASON_SYMLINK,
    REASON_TRAVERSAL,
    PathContainmentError,
    _open_base_fd,
    _open_dir_nofollow_or_create,
    _split_components,
    _walk_to_parent,
)
from aptl.utils._pathsafe_read import (
    listdir_contained_nofollow,
    open_contained_nofollow,
    open_dir_contained_nofollow,
    read_contained_nofollow,
)

__all__ = [
    "REASON_BASE_DIR_UNAVAILABLE",
    "REASON_DOT_COMPONENT",
    "REASON_EMPTY_COMPONENT",
    "REASON_NOT_FOUND",
    "REASON_NOT_REGULAR_FILE",
    "REASON_NOT_RELATIVE",
    "REASON_NUL_BYTE",
    "REASON_OPEN_FAILED",
    "REASON_SYMLINK",
    "REASON_TRAVERSAL",
    "PathContainmentError",
    "create_exclusive_nofollow",
    "listdir_contained_nofollow",
    "open_contained_nofollow",
    "open_dir_contained_nofollow",
    "read_contained_nofollow",
    "write_all",
]

#: Per-process monotonic counter for unique temporary publish names. Combined
#: with the PID it makes create-once temp inodes collision-free without needing
#: a wall clock or randomness.
_TMP_COUNTER = itertools.count()


def write_all(fd: int, data: bytes) -> None:
    """Write every byte of ``data`` to ``fd``, looping over short writes.

    ``os.write`` is permitted to accept fewer bytes than offered (POSIX), so a
    single call is not a durable-write primitive. A refusal to make progress
    (``0`` bytes on a non-empty buffer) is an error rather than a silent partial
    seal.
    """
    view = memoryview(data)
    total = 0
    length = len(view)
    while total < length:
        written = os.write(fd, view[total:])
        if written <= 0:
            raise OSError(errno.EIO, "short write while sealing archive file")
        total += written


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

    The final name becomes visible only when it is complete: ``data`` is written
    in full (short writes are looped over) and ``fsync``-ed to a temporary inode,
    which is then atomically linked into place with no-replace semantics, and the
    parent directory is ``fsync``-ed so the new entry survives a crash. A partial
    write or crash therefore never publishes a half-written final file or a false
    "exists" state (ADR-050 "A seal marker is never observable partially"); the
    temporary inode is always cleaned up.

    Raises :class:`PathContainmentError` for the same structural/symlink
    reasons as :func:`open_contained_nofollow`. Raises ``FileExistsError``
    (unwrapped) when the leaf already exists — the create-once caller
    decides the idempotency policy (e.g. compare-then-accept on a byte
    match via :func:`read_contained_nofollow`).
    """
    components = _split_components(relative_path)
    dir_components = components[:-1]
    leaf_component = components[-1]
    base_fd = _open_base_fd(base_dir)
    parent_fd = base_fd
    try:
        parent_fd = _walk_to_parent(
            dir_components, base_fd, open_dir=_open_dir_nofollow_or_create
        )
        _atomic_publish(parent_fd, leaf_component, data)
        # Durably link the new entry into its directory: an fsync of the file
        # alone does not guarantee the dirent is persisted.
        os.fsync(parent_fd)
    finally:
        if parent_fd != base_fd:
            os.close(parent_fd)
        os.close(base_fd)


def _atomic_publish(parent_fd: int, leaf_component: str, data: bytes) -> None:
    """Write ``data`` to a temp inode under ``parent_fd``, fsync, then link it
    into place as ``leaf_component`` with no-replace semantics.

    The temporary name is unlinked whether the publish succeeds or fails, so a
    failed/aborted write never strands a partial file. ``FileExistsError`` from
    the final link (the leaf already exists) propagates unwrapped for the
    create-once caller's idempotency policy.
    """
    tmp_name = f".{leaf_component}.{os.getpid()}.{next(_TMP_COUNTER)}.tmp"
    tmp_fd = _create_temp_leaf(tmp_name, parent_fd)
    try:
        try:
            write_all(tmp_fd, data)
            os.fsync(tmp_fd)
        finally:
            os.close(tmp_fd)
        # Atomic, no-replace publication: linkat fails with EEXIST if the final
        # name already exists, so two racing writers cannot clobber each other
        # and a create-once conflict surfaces as FileExistsError.
        os.link(
            tmp_name,
            leaf_component,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
    finally:
        try:
            os.unlink(tmp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass


def _create_temp_leaf(tmp_name: str, parent_fd: int) -> int:
    """Create-exclusive-open the temporary publish inode under ``parent_fd``.

    Retries once under a fresh name if a stale temp with the same name exists
    (a crashed same-PID predecessor); any other failure is a containment error.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        try:
            return os.open(tmp_name, flags, 0o600, dir_fd=parent_fd)
        except FileExistsError:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
            retry_name = f"{tmp_name}.{next(_TMP_COUNTER)}"
            return os.open(retry_name, flags, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        # A non-EEXIST failure of the first open, or any failure of the retry
        # (including an EEXIST on the fresh unique name), is a containment error.
        raise PathContainmentError(
            REASON_OPEN_FAILED, f"cannot create temporary publish inode: {exc}"
        ) from exc
