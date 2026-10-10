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
create-once and private-replace write paths below. All public names are
re-exported here — always import from ``aptl.utils.pathsafe``, never from the
private sibling modules.
"""

from __future__ import annotations

import errno
import itertools
import os
import stat
from pathlib import Path

from aptl.utils._pathsafe_core import (
    REASON_BASE_DIR_UNAVAILABLE,
    REASON_DOT_COMPONENT,
    REASON_EMPTY_COMPONENT,
    REASON_NOT_FOUND,
    REASON_NOT_PRIVATE,
    REASON_NOT_REGULAR_FILE,
    REASON_NOT_RELATIVE,
    REASON_NUL_BYTE,
    REASON_OPEN_FAILED,
    REASON_SYMLINK,
    REASON_TRAVERSAL,
    PathContainmentError,
    _open_base_fd,
    _open_dir_nofollow,
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
    "REASON_NOT_PRIVATE",
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
    "remove_contained_nofollow",
    "replace_private_nofollow",
    "write_all",
]

#: Per-process monotonic counter for unique temporary publish names. Combined
#: with the PID it makes create-once temp inodes collision-free without needing
#: a wall clock or randomness.
_TMP_COUNTER = itertools.count()

#: Mode bits that let anyone but the owner reach a directory, and the bits that
#: let them rename entries in it. :func:`replace_private_nofollow` clears the
#: first on the leaf's parent and the second on every directory above it.
_GROUP_OR_OTHER_ACCESS = 0o077
_GROUP_OR_OTHER_WRITE = 0o022


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


def replace_private_nofollow(
    base_dir: Path | str, relative_path: str | Path, data: bytes
) -> None:
    """Atomically create or replace one owner-only file under ``base_dir``.

    The rewrite counterpart of :func:`create_exclusive_nofollow`, for host
    transport state that is regenerated on every run, such as a generated
    environment file. Directory components are walked, and created ``0o700``
    when missing, exactly as that function does, so a symlinked component is
    refused (``REASON_SYMLINK``) and never followed. Then:

    - Docker and Compose read the file again by path, so no directory between
      ``base_dir`` and the leaf may let anyone but its owner rename entries.
      A group- or world-writable component loses those write bits through its
      descriptor; one that someone else owns is refused
      (``REASON_NOT_PRIVATE``).
    - the leaf's parent must belong to the caller. A group- or world-accessible
      mode is tightened to owner-only; a parent owned by someone else, or one
      whose mode will not stay private, is refused (``REASON_NOT_PRIVATE``).
    - ``base_dir`` itself is trusted and never re-moded, so a leaf directly
      inside it gets no such treatment, and a writable ``base_dir`` is outside
      this boundary.
    - an existing leaf must be a regular file. A symlink (``REASON_SYMLINK``)
      or any other file type (``REASON_NOT_REGULAR_FILE``) is refused and left
      in place.
    - ``data`` is written in full and ``fsync``-ed to a fresh ``0o600``
      temporary inode, which is renamed over the leaf relative to the same
      parent descriptor. ``rename`` replaces a directory entry and never
      follows it, so a leaf swapped in after the check is replaced rather than
      written through, and the old file's mode, owner and other hard links
      never carry over to the new content.

    A failed or interrupted write removes the temporary inode and leaves the
    previous file, if any, unchanged.
    """
    components = _split_components(relative_path)
    leaf_component = components[-1]
    base_fd = _open_base_fd(base_dir)
    parent_fd = base_fd
    try:
        parent_fd = _walk_to_parent(
            components[:-1], base_fd, open_dir=_open_restricted_dir
        )
        if parent_fd != base_fd:
            _restrict_directory(parent_fd, _GROUP_OR_OTHER_ACCESS, owned=True)
        _existing_regular_leaf(parent_fd, leaf_component, "replace")
        tmp_name = _write_temp_leaf(parent_fd, leaf_component, data)
        try:
            os.rename(
                tmp_name, leaf_component, src_dir_fd=parent_fd, dst_dir_fd=parent_fd
            )
        except BaseException:
            _discard_temp_leaf(tmp_name, parent_fd)
            raise
        os.fsync(parent_fd)
    finally:
        if parent_fd != base_fd:
            os.close(parent_fd)
        os.close(base_fd)


def _open_restricted_dir(component: str, parent_fd: int) -> int:
    """Open or create one directory component that only its owner can rename in."""

    fd = _open_dir_nofollow_or_create(component, parent_fd)
    try:
        _restrict_directory(fd, _GROUP_OR_OTHER_WRITE, owned=False)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _restrict_directory(dir_fd: int, forbidden: int, *, owned: bool) -> None:
    """Clear ``forbidden`` mode bits on an opened directory, or refuse it.

    Clearing bits needs ownership. ``owned`` also demands ownership when no
    bit needs clearing, as it does for the leaf's parent.
    """

    status = os.fstat(dir_fd)
    mode = stat.S_IMODE(status.st_mode)
    if (owned or mode & forbidden) and status.st_uid != os.geteuid():
        raise PathContainmentError(
            REASON_NOT_PRIVATE, "directory is not owned by the current user"
        )
    if mode & forbidden:
        os.fchmod(dir_fd, mode & ~forbidden)
        if stat.S_IMODE(os.fstat(dir_fd).st_mode) & forbidden:
            raise PathContainmentError(
                REASON_NOT_PRIVATE, "directory mode cannot be restricted"
            )


def remove_contained_nofollow(base_dir: Path | str, relative_path: str | Path) -> bool:
    """Durably remove one regular file under ``base_dir``, walked no-follow.

    Every directory component is opened ``O_DIRECTORY | O_NOFOLLOW`` under its
    parent's descriptor and the leaf is inspected and unlinked relative to that
    same descriptor, so a symlink swapped in anywhere on the path can never
    redirect the removal. Returns ``True`` when a file was removed and ``False``
    when the leaf or any parent is already absent, which an idempotent cleanup
    treats as complete. The parent directory is ``fsync``-ed after a removal so
    the change survives a crash before the caller records completion.

    Raises :class:`PathContainmentError` for a structurally invalid path, a
    symlinked component or leaf (``REASON_SYMLINK``), or a leaf that is not a
    regular file (``REASON_NOT_REGULAR_FILE``); nothing is removed then.
    """
    components = _split_components(relative_path)
    leaf_component = components[-1]
    base_fd = _open_base_fd(base_dir)
    parent_fd = base_fd
    try:
        try:
            parent_fd = _walk_to_parent(
                components[:-1], base_fd, open_dir=_open_dir_nofollow
            )
        except PathContainmentError as exc:
            if exc.reason == REASON_NOT_FOUND:
                return False
            raise
        return _unlink_regular_leaf(parent_fd, leaf_component)
    finally:
        if parent_fd != base_fd:
            os.close(parent_fd)
        os.close(base_fd)


def _unlink_regular_leaf(parent_fd: int, leaf_component: str) -> bool:
    """Unlink a regular leaf relative to ``parent_fd``; absent is ``False``."""

    if not _existing_regular_leaf(parent_fd, leaf_component, "remove"):
        return False
    try:
        os.unlink(leaf_component, dir_fd=parent_fd)
    except FileNotFoundError:
        return False
    os.fsync(parent_fd)
    return True


def _existing_regular_leaf(parent_fd: int, leaf_component: str, action: str) -> bool:
    """Return whether a regular leaf exists; refuse a symlink or other type."""

    try:
        status = os.stat(leaf_component, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(status.st_mode):
        raise PathContainmentError(
            REASON_SYMLINK, f"refusing to {action} symlinked leaf {leaf_component!r}"
        )
    if not stat.S_ISREG(status.st_mode):
        raise PathContainmentError(
            REASON_NOT_REGULAR_FILE,
            f"refusing to {action} non-regular leaf {leaf_component!r}",
        )
    return True


def _atomic_publish(parent_fd: int, leaf_component: str, data: bytes) -> None:
    """Write ``data`` to a temp inode under ``parent_fd``, fsync, then link it
    into place as ``leaf_component`` with no-replace semantics.

    The temporary name is unlinked whether the publish succeeds or fails, so a
    failed/aborted write never strands a partial file. ``FileExistsError`` from
    the final link (the leaf already exists) propagates unwrapped for the
    create-once caller's idempotency policy.
    """
    tmp_name = _write_temp_leaf(parent_fd, leaf_component, data)
    try:
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
        _discard_temp_leaf(tmp_name, parent_fd)


def _write_temp_leaf(parent_fd: int, leaf_component: str, data: bytes) -> str:
    """Write and fsync ``data`` to a fresh temp inode beside ``leaf_component``.

    Returns the temporary name. If writing fails or is interrupted, the
    temporary inode is removed before the error propagates.
    """
    tmp_name = f".{leaf_component}.{os.getpid()}.{next(_TMP_COUNTER)}.tmp"
    tmp_fd, tmp_name = _create_temp_leaf(tmp_name, parent_fd)
    try:
        try:
            write_all(tmp_fd, data)
            os.fsync(tmp_fd)
        finally:
            os.close(tmp_fd)
    except BaseException:
        _discard_temp_leaf(tmp_name, parent_fd)
        raise
    return tmp_name


def _discard_temp_leaf(tmp_name: str, parent_fd: int) -> None:
    """Remove a temporary publish inode; an already-absent one is fine."""

    try:
        os.unlink(tmp_name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass


def _create_temp_leaf(tmp_name: str, parent_fd: int) -> tuple[int, str]:
    """Create-exclusive-open the temporary publish inode under ``parent_fd``.

    Retries once under a fresh name if a stale temp with the same name exists
    (a crashed same-PID predecessor); any other failure is a containment error.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        try:
            return os.open(tmp_name, flags, 0o600, dir_fd=parent_fd), tmp_name
        except FileExistsError:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
            retry_name = f"{tmp_name}.{next(_TMP_COUNTER)}"
            return os.open(retry_name, flags, 0o600, dir_fd=parent_fd), retry_name
    except OSError as exc:
        # A non-EEXIST failure of the first open, or any failure of the retry
        # (including an EEXIST on the fresh unique name), is a containment error.
        raise PathContainmentError(
            REASON_OPEN_FAILED, f"cannot create temporary publish inode: {exc}"
        ) from exc
