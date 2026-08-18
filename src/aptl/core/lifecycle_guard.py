"""Shared project-wide ownership for mutating lab lifecycle operations.

The fixed ``.aptl/lifecycle/.lock`` file is only a rendezvous point. Ownership
comes from the operating system lock held on its descriptor, never from file
existence or persisted PID metadata. Acquisitions are non-blocking so callers
can return an actionable busy result instead of hanging behind a long startup.
"""

from __future__ import annotations

import errno
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from aptl.core.config import find_config
from aptl.core.lifecycle_policy import LifecycleBusyError
from aptl.utils.pathsafe import PathContainmentError, open_dir_contained_nofollow

try:  # pragma: no cover - platform-specific import
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - Windows
    fcntl = None

try:  # pragma: no cover - platform-specific import
    import msvcrt
except ModuleNotFoundError:  # pragma: no cover - POSIX
    msvcrt = None

_LIFECYCLE_DIR = ".aptl/lifecycle"
_LOCK_FILE = ".lock"


class LifecycleLockUnavailableError(RuntimeError):
    """Raised when the owner lock cannot be established safely."""


@dataclass
class _HeldLifecycleLock:
    fd: int
    depth: int


_HELD_LOCKS: dict[tuple[str, int], _HeldLifecycleLock] = {}
_HELD_LOCKS_GUARD = threading.Lock()


def canonical_lifecycle_project_root(project_dir: Path) -> Path:
    """Resolve the config-owning project root without mutating project state."""

    candidate = Path(project_dir).resolve()
    for directory in (candidate, *candidate.parents):
        if find_config(directory) is not None:
            return directory
    return candidate


@contextmanager
def lifecycle_mutation_lock(project_dir: Path) -> Iterator[Path]:
    """Hold the project lifecycle owner lock, reentrant in the current thread.

    A different thread or process receives :class:`LifecycleBusyError`
    immediately. The lock file is created below the trusted project directory
    through descriptor-relative, no-follow path handling. POSIX locks are
    forced to owner-only permissions; Windows creation inherits the project's
    ACL while rejecting every reparse-point component by handle.
    """

    root = canonical_lifecycle_project_root(project_dir)
    key = (str(root), threading.get_ident())
    with _HELD_LOCKS_GUARD:
        held = _HELD_LOCKS.get(key)
        if held is not None:
            held.depth += 1
            reused = True
        else:
            reused = False

    if not reused:
        fd: int | None = None
        try:
            fd = _open_lock_fd(root)
            _try_lock(fd)
        except LifecycleBusyError:
            if fd is not None:
                os.close(fd)
            raise
        except (PathContainmentError, OSError) as exc:
            if fd is not None:
                os.close(fd)
            raise LifecycleLockUnavailableError(
                "safe lifecycle ownership is unavailable"
            ) from exc
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise
        assert fd is not None
        with _HELD_LOCKS_GUARD:
            _HELD_LOCKS[key] = _HeldLifecycleLock(fd=fd, depth=1)

    try:
        yield root
    finally:
        with _HELD_LOCKS_GUARD:
            entry = _HELD_LOCKS[key]
            entry.depth -= 1
            if entry.depth == 0:
                _unlock(entry.fd)
                os.close(entry.fd)
                del _HELD_LOCKS[key]


def _open_lock_fd(project_dir: Path) -> int:
    """Open the fixed owner-only lock without following a POSIX symlink."""

    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        return _open_windows_lock_fd(project_dir)

    lifecycle_fd = open_dir_contained_nofollow(project_dir, _LIFECYCLE_DIR, create=True)
    try:
        fd = os.open(
            _LOCK_FILE,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=lifecycle_fd,
        )
    finally:
        os.close(lifecycle_fd)
    os.fchmod(fd, 0o600)
    return fd


def _open_windows_lock_fd(project_dir: Path) -> int:
    """Open the Windows lock component-by-component without following reparses."""

    open_handles: list[int] = []
    lock_handle: int | None = None
    try:
        root_handle = _windows_open_root_handle(project_dir)
        open_handles.append(root_handle)
        _windows_reject_reparse_point(root_handle)

        parent_handle = root_handle
        for component in (".aptl", "lifecycle"):
            child_handle = _windows_open_relative_handle(
                parent_handle, component, directory=True
            )
            open_handles.append(child_handle)
            _windows_reject_reparse_point(child_handle)
            parent_handle = child_handle

        lock_handle = _windows_open_relative_handle(
            parent_handle, _LOCK_FILE, directory=False
        )
        _windows_reject_reparse_point(lock_handle)
        fd = _windows_handle_to_fd(lock_handle)
        lock_handle = None  # the C runtime descriptor now owns the handle
    finally:
        if lock_handle is not None:
            _windows_close_handle(lock_handle)
        for handle in reversed(open_handles):
            _windows_close_handle(handle)

    if os.fstat(fd).st_size == 0:
        os.write(fd, b"\0")
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def _windows_open_root_handle(project_dir: Path) -> int:
    """Open the trusted project root itself, exposing any root reparse point."""

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE

    handle = create_file(
        str(project_dir),
        0x00100187,  # SYNCHRONIZE | read/write attributes | add/list children
        0x00000007,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        None,
        3,  # OPEN_EXISTING
        0x02200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in (None, invalid_handle):
        raise ctypes.WinError(ctypes.get_last_error())
    return int(handle)


def _windows_open_relative_handle(
    parent_handle: int, component: str, *, directory: bool
) -> int:
    """Open or create one child relative to an already-validated directory."""

    import ctypes
    from ctypes import wintypes

    class UnicodeString(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    class ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(UnicodeString)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class IoStatusValue(ctypes.Union):
        _fields_ = [("Status", ctypes.c_long), ("Pointer", wintypes.LPVOID)]

    class IoStatusBlock(ctypes.Structure):
        _anonymous_ = ("value",)
        _fields_ = [("value", IoStatusValue), ("Information", ctypes.c_size_t)]

    name_buffer = ctypes.create_unicode_buffer(component)
    name_bytes = component.encode("utf-16-le")
    object_name = UnicodeString(
        Length=len(name_bytes),
        MaximumLength=len(name_bytes) + 2,
        Buffer=ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    attributes = ObjectAttributes(
        Length=ctypes.sizeof(ObjectAttributes),
        RootDirectory=wintypes.HANDLE(parent_handle),
        ObjectName=ctypes.pointer(object_name),
        Attributes=0x00000040,  # OBJ_CASE_INSENSITIVE
        SecurityDescriptor=None,
        SecurityQualityOfService=None,
    )
    io_status = IoStatusBlock()
    handle = wintypes.HANDLE()

    ntdll = ctypes.WinDLL("ntdll")
    nt_create_file = ntdll.NtCreateFile
    nt_create_file.argtypes = (
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(ObjectAttributes),
        ctypes.POINTER(IoStatusBlock),
        wintypes.LPVOID,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    )
    nt_create_file.restype = ctypes.c_long
    options = 0x00200020 | (0x00000001 if directory else 0x00000040)
    desired_access = 0x00100187 if directory else 0x00100183
    status = nt_create_file(
        ctypes.byref(handle),
        desired_access,
        ctypes.byref(attributes),
        ctypes.byref(io_status),
        None,
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        0x00000007,
        3,  # FILE_OPEN_IF
        options,  # synchronous, open-reparse, and expected object type
        None,
        0,
    )
    if status < 0:
        rtl_status_to_error = ntdll.RtlNtStatusToDosError
        rtl_status_to_error.argtypes = (ctypes.c_long,)
        rtl_status_to_error.restype = wintypes.ULONG
        raise ctypes.WinError(rtl_status_to_error(status))
    return int(handle.value)


def _windows_reject_reparse_point(handle: int) -> None:
    """Reject symlinks, junctions, and every other Windows reparse object."""

    import ctypes
    from ctypes import wintypes

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("ReparseTag", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_info = kernel32.GetFileInformationByHandleEx
    get_info.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    get_info.restype = wintypes.BOOL
    info = FileAttributeTagInfo()
    if not get_info(
        wintypes.HANDLE(handle),
        9,  # FileAttributeTagInfo
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    if info.FileAttributes & 0x00000400:  # FILE_ATTRIBUTE_REPARSE_POINT
        raise OSError("lifecycle lock path contains a reparse point")


def _windows_handle_to_fd(handle: int) -> int:
    """Transfer an owned Windows file handle to a Python descriptor."""

    if msvcrt is None:  # pragma: no cover - guarded by the Windows call site
        raise OSError("Windows descriptor support is unavailable")
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    return msvcrt.open_osfhandle(handle, flags)


def _windows_close_handle(handle: int) -> None:
    """Close a raw Windows handle that was not transferred to a descriptor."""

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    if not close_handle(wintypes.HANDLE(handle)):
        raise ctypes.WinError(ctypes.get_last_error())


def _try_lock(fd: int) -> None:
    """Acquire the platform lock without waiting."""

    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif msvcrt is not None:  # pragma: no cover - Windows
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:  # pragma: no cover - unsupported runtime
            raise OSError("no cross-process file-lock implementation is available")
    except OSError as exc:
        if exc.errno not in (None, errno.EACCES, errno.EAGAIN):
            raise
        raise LifecycleBusyError(
            "another lifecycle owner is active for this project"
        ) from exc


def _unlock(fd: int) -> None:
    """Release the platform lock held on ``fd``."""

    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
    elif msvcrt is not None:  # pragma: no cover - Windows
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
