"""Cross-process reservation of explicit outer seat endpoint mappings."""

from __future__ import annotations

import errno
import os
import re
import shutil
import socket
import sys
import tempfile
import time
from collections.abc import Callable
from contextlib import contextmanager
from typing import Iterator, TypeVar
from pathlib import Path

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint

_LOCK_NAME = "\0aptl-seat-mapping-allocation-v1"
_RESOURCE_PREFIX = b"name=opt/aptl/resource-reservation,string="
_RESOURCE_VALUE = re.compile(rb"^(\d+):(\d+):(\d+)$")
_MIN_HOST_MEMORY_HEADROOM_BYTES = 8 * 1024**3
T = TypeVar("T")


class _FileAllocatorLock:
    """Advisory allocator lock for non-Linux development hosts."""

    def __init__(self, descriptor: int) -> None:
        self.descriptor = descriptor

    def close(self) -> None:
        import fcntl

        try:
            fcntl.flock(self.descriptor, fcntl.LOCK_UN)
        finally:
            os.close(self.descriptor)


def _bind_endpoint(address: str, port: int, protocol: str) -> socket.socket:
    """Bind and, for TCP, listen on one candidate host endpoint."""

    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    candidate = socket.socket(family, kind)
    try:
        candidate.bind((address, port))
        if kind == socket.SOCK_STREAM:
            candidate.listen(1)
        return candidate
    except BaseException:
        candidate.close()
        raise


def _endpoint_socket(mapping: BoundaryEndpoint) -> socket.socket:
    """Create a reservation socket for one declared boundary endpoint."""

    return _bind_endpoint(mapping.address, mapping.port, mapping.protocol)


def _acquire_allocator_lock(deadline: float) -> socket.socket | _FileAllocatorLock:
    """Acquire the host-network-wide APTL allocation mutex."""

    if sys.platform != "linux":
        import fcntl

        lock_path = Path(tempfile.gettempdir()) / (
            f"aptl-seat-mapping-allocation-v1-{os.getuid()}.lock"
        )
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lock_path, flags, 0o600)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return _FileAllocatorLock(descriptor)
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    os.close(descriptor)
                    raise SeatLauncherError(
                        "mapping-allocation-busy", "seat mapping allocation is busy"
                    ) from exc
                time.sleep(0.05)

    lock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    while True:
        try:
            lock.bind(_LOCK_NAME)
            return lock
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE or time.monotonic() >= deadline:
                lock.close()
                raise SeatLauncherError(
                    "mapping-allocation-busy", "seat mapping allocation is busy"
                ) from exc
            time.sleep(0.05)


@contextmanager
def reserve_outer_mappings(
    mappings: tuple[BoundaryEndpoint, ...],
    *,
    timeout_seconds: float = 10,
) -> Iterator[None]:
    """Serialize APTL allocators and reserve every explicit endpoint."""

    deadline = time.monotonic() + timeout_seconds
    lock = _acquire_allocator_lock(deadline)
    reservations: list[socket.socket] = []
    try:
        try:
            reservations = [_endpoint_socket(mapping) for mapping in mappings]
        except OSError as exc:
            raise SeatLauncherError(
                "mapping-unavailable", "an explicit outer endpoint is unavailable"
            ) from exc
        yield
    finally:
        for reservation in reservations:
            reservation.close()
        lock.close()


def _mapping_is_occupied(mapping: BoundaryEndpoint) -> bool:
    """Return whether another process currently owns the endpoint."""

    try:
        candidate = _endpoint_socket(mapping)
    except OSError:
        return True
    candidate.close()
    return False


def _running_resource_reservations(
    proc_root: Path = Path("/proc"),
) -> tuple[int, int, int]:
    """Sum explicit APTL QEMU resource contracts visible in procfs."""

    totals = [0, 0, 0]
    try:
        processes = tuple(proc_root.iterdir())
    except OSError as exc:
        raise SeatLauncherError(
            "resource-admission-unavailable", "cannot inspect running seat resources"
        ) from exc
    for process in processes:
        if not process.name.isdecimal():
            continue
        try:
            payload = (process / "cmdline").read_bytes()
        except OSError as exc:
            try:
                command = (process / "comm").read_text(encoding="utf-8").strip()
            except OSError:
                command = ""
            if command.startswith("qemu-system-"):
                raise SeatLauncherError(
                    "resource-admission-unavailable",
                    "cannot inspect a running QEMU resource reservation",
                ) from exc
            continue
        if not payload or len(payload) > 128 * 1024:
            continue
        arguments = payload.rstrip(b"\0").split(b"\0")
        if not arguments or not arguments[0].rsplit(b"/", 1)[-1].startswith(
            b"qemu-system-"
        ):
            continue
        reservations = [
            item.removeprefix(_RESOURCE_PREFIX)
            for item in arguments
            if item.startswith(_RESOURCE_PREFIX)
        ]
        if len(reservations) != 1:
            continue
        match = _RESOURCE_VALUE.fullmatch(reservations[0])
        if match is None:
            continue
        for index, value in enumerate(match.groups()):
            totals[index] += int(value)
    return tuple(totals)


def _require_resource_capacity(
    resources: tuple[int, int, int],
    *,
    seat_root: Path,
    retained_disk_bytes: int = 0,
    reservations: tuple[int, int, int] | None = None,
    capacity: tuple[int, int, int] | None = None,
    available: tuple[int, int, int] | None = None,
) -> None:
    """Admit one seat only when all declared concurrent reservations fit."""

    requested = resources
    if min(requested) <= 0 or retained_disk_bytes < 0:
        raise SeatLauncherError(
            "resource-admission-unavailable", "seat resource contract is invalid"
        )
    used = _running_resource_reservations() if reservations is None else reservations
    if capacity is None:
        cpus = (
            len(os.sched_getaffinity(0))
            if hasattr(os, "sched_getaffinity")
            else os.cpu_count() or 0
        )
        try:
            memory = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
            disk_usage = shutil.disk_usage(seat_root)
            disk = disk_usage.total
            disk_free = disk_usage.free
            memory_available = 0
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemAvailable:"):
                    memory_available = int(line.split()[1]) * 1024
                    break
        except (OSError, ValueError):
            memory = disk = disk_free = memory_available = 0
        capacity = (cpus, memory, disk)
        available = (cpus, memory_available, disk_free)
    elif available is None:
        available = capacity
    if any(
        consumed + needed > limit
        for consumed, needed, limit in zip(used, requested, capacity, strict=True)
    ):
        raise SeatLauncherError(
            "resource-capacity-exhausted",
            "concurrent seat resource reservations exceed host capacity",
        )
    host_memory_headroom = max(_MIN_HOST_MEMORY_HEADROOM_BYTES, capacity[1] // 10)
    remaining_disk = max(0, requested[2] - retained_disk_bytes)
    if (
        requested[0] > available[0]
        or requested[1] + host_memory_headroom > available[1]
        or remaining_disk > available[2]
    ):
        raise SeatLauncherError(
            "resource-capacity-exhausted",
            "available host resources cannot satisfy the seat reservation and host memory headroom",
        )


def launch_with_reserved_mappings(
    mappings: tuple[BoundaryEndpoint, ...],
    launcher: Callable[[], T],
    *,
    ownership_timeout_seconds: float = 10,
    resources: tuple[int, int, int] | None = None,
    seat_root: Path | None = None,
    reservations: tuple[int, int, int] | None = None,
    capacity: tuple[int, int, int] | None = None,
    available: tuple[int, int, int] | None = None,
    retained_disk_bytes: int = 0,
) -> T:
    """Hold the allocator lock until the launched VM owns every endpoint."""

    deadline = time.monotonic() + ownership_timeout_seconds
    lock = _acquire_allocator_lock(deadline)
    try:
        if resources is not None:
            if seat_root is None:
                raise SeatLauncherError(
                    "resource-admission-unavailable", "seat root is required"
                )
            _require_resource_capacity(
                resources,
                seat_root=seat_root,
                retained_disk_bytes=retained_disk_bytes,
                reservations=reservations,
                capacity=capacity,
                available=available,
            )
        reservations = []
        try:
            reservations = [_endpoint_socket(mapping) for mapping in mappings]
        except OSError as exc:
            raise SeatLauncherError(
                "mapping-unavailable", "an explicit outer endpoint is unavailable"
            ) from exc
        finally:
            for reservation in reservations:
                reservation.close()
        handle = launcher()
        poll = getattr(handle, "poll", None)
        while time.monotonic() < deadline:
            if callable(poll) and poll() is not None:
                raise SeatLauncherError("failed-launch", "VM exited during port bind")
            if all(_mapping_is_occupied(mapping) for mapping in mappings):
                return handle
            time.sleep(0.05)
        raise SeatLauncherError(
            "failed-launch", "VM did not take ownership of outer endpoints"
        )
    finally:
        lock.close()


def launch_with_automatic_mappings(
    publications: tuple[BoundaryEndpoint, ...],
    launcher: Callable[[tuple[BoundaryEndpoint, ...]], T],
    *,
    timeout_seconds: float = 1200,
    resources: tuple[int, int, int] | None = None,
    seat_root: Path | None = None,
) -> T:
    """Select ephemeral loopback ports and hold the host lock through admission.

    The reservation sockets remain open until immediately before QEMU is
    invoked. The caller returns only after it has re-observed the launched VM's
    listeners, so a competing APTL launcher cannot reuse the selected ports in
    the handoff window.
    """

    deadline = time.monotonic() + timeout_seconds
    lock = _acquire_allocator_lock(deadline)
    reservations: list[socket.socket] = []
    try:
        if resources is not None:
            if seat_root is None:
                raise SeatLauncherError(
                    "resource-admission-unavailable", "seat root is required"
                )
            _require_resource_capacity(resources, seat_root=seat_root)
        mappings: list[BoundaryEndpoint] = []
        for publication in publications:
            reservation = _bind_endpoint("127.0.0.1", 0, publication.protocol)
            reservations.append(reservation)
            mappings.append(
                BoundaryEndpoint(
                    audience=publication.audience,
                    address="127.0.0.1",
                    port=reservation.getsockname()[1],
                    protocol=publication.protocol,
                    guest_address=publication.address,
                    guest_port=publication.port,
                )
            )
        selected = tuple(mappings)
        for reservation in reservations:
            reservation.close()
        reservations.clear()
        return launcher(selected)
    finally:
        for reservation in reservations:
            reservation.close()
        lock.close()
