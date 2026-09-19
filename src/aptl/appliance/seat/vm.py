"""QEMU/KVM adapter for one disposable appliance overlay."""

from __future__ import annotations

import ipaddress
import json
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint

# Intentional RFC 1918 guest-only network.
QEMU_SLIRP_SUBNET = "10.0.2.0/24"
# Fixed address inside that private subnet.
DEFAULT_QEMU_GUEST_ADDRESS = "10.0.2.15"
# Ubuntu's supported cloud image is UEFI-only.  Keep firmware immutable so all
# disposable state remains on the seat overlay.
OVMF_CODE_PATH = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")


class VmProcess(Protocol):
    """Minimal VM lifecycle surface used by seat orchestration."""

    @property
    def pid(self) -> int: ...

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


@dataclass(frozen=True)
class VmLaunchSpec:
    """Fixed-argv launch contract for one seat overlay."""

    overlay_path: Path
    launch_mount: Path
    vcpus: int
    memory_mib: int
    disk_reservation_bytes: int = 0
    management_socket: Path | None = None
    readiness_socket: Path | None = None
    access_socket: Path | None = None
    guest_adapter_address: str = DEFAULT_QEMU_GUEST_ADDRESS
    mappings: tuple[BoundaryEndpoint, ...] = field(
        default_factory=lambda: (
            BoundaryEndpoint(
                audience="participant",
                address="127.0.0.1",
                port=443,
                protocol="tcp",
                guest_address="127.0.0.1",
                guest_port=443,
            ),
            BoundaryEndpoint(
                audience="recovery",
                address="127.0.0.1",
                port=9443,
                protocol="tcp",
                guest_address="127.0.0.1",
                guest_port=9443,
            ),
        )
    )

    def __post_init__(self) -> None:
        """Reject ambiguous or incomplete forwarding declarations."""

        outer = [(item.address, item.port, item.protocol) for item in self.mappings]
        if len(outer) != len(set(outer)):
            raise ValueError("duplicate outer endpoint in VM mappings")
        if any(
            item.guest_address is None or item.guest_port is None
            for item in self.mappings
        ):
            raise ValueError("VM mappings require explicit guest endpoints")
        if any(item.protocol != "tcp" for item in self.mappings):
            raise ValueError("VM mappings currently support TCP only")
        if self.disk_reservation_bytes < 0:
            raise ValueError("disk reservation cannot be negative")
        adapter = ipaddress.ip_address(self.guest_adapter_address)
        if adapter not in ipaddress.ip_network(QEMU_SLIRP_SUBNET) or adapter.is_loopback:
            raise ValueError("guest adapter address must use the private slirp subnet")


@dataclass
class SubprocessVm:
    """Subprocess-backed VM handle."""

    process: subprocess.Popen[bytes]

    @property
    def pid(self) -> int:
        return self.process.pid

    def poll(self) -> int | None:
        return self.process.poll()

    def terminate(self) -> None:
        self.process.send_signal(signal.SIGTERM)

    def wait(self, timeout: float | None = None) -> int:
        return self.process.wait(timeout=timeout)


VmRunner = type[SubprocessVm] | None


@dataclass(frozen=True)
class VmProcessIdentity:
    """Process identity that remains safe when a numeric PID is reused."""

    pid: int
    start_time_ticks: int
    executable: str


def build_qemu_argv(spec: VmLaunchSpec) -> tuple[str, ...]:
    """Return hardened fixed argv for one local-KVM seat."""

    management_socket = spec.management_socket or spec.overlay_path.with_suffix(".qmp")
    readiness_socket = spec.readiness_socket or spec.overlay_path.with_suffix(
        ".readiness.sock"
    )
    access_socket = spec.access_socket or spec.overlay_path.with_suffix(".access.sock")
    for path in (
        spec.overlay_path,
        spec.launch_mount,
        management_socket,
        readiness_socket,
        access_socket,
    ):
        if any(character in str(path) for character in (",", "\n", "\x00")):
            raise ValueError("path contains a QEMU option separator")
    launch_path = str(spec.launch_mount.resolve())
    forwards = ",".join(
        (
            f"hostfwd={mapping.protocol}:{mapping.address}:{mapping.port}-"
            f"{spec.guest_adapter_address}:{mapping.guest_port}"
        )
        for mapping in spec.mappings
    )
    resource_arguments: tuple[str, ...] = ()
    if spec.disk_reservation_bytes:
        resource_arguments = (
            "-fw_cfg",
            (
                "name=opt/aptl/resource-reservation,string="
                f"{spec.vcpus}:{spec.memory_mib * 1024 * 1024}:"
                f"{spec.disk_reservation_bytes}"
            ),
        )
    return (
        "qemu-system-x86_64",
        "-enable-kvm",
        "-cpu",
        "host",
        "-smp",
        str(spec.vcpus),
        "-m",
        str(spec.memory_mib),
        *resource_arguments,
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={OVMF_CODE_PATH}",
        "-drive",
        f"file={spec.overlay_path},format=qcow2,if=virtio,cache=none,aio=threads,readonly=off",
        "-fsdev",
        f"local,id=aptl-launch,path={launch_path},readonly=on,security_model=none",
        "-device",
        "virtio-9p-pci,fsdev=aptl-launch,mount_tag=aptl-launch",
        "-device",
        "virtio-serial-pci",
        "-chardev",
        f"socket,id=aptl-readiness,path={readiness_socket},server=on,wait=off",
        "-device",
        "virtserialport,chardev=aptl-readiness,name=org.aptl.readiness",
        "-chardev",
        f"socket,id=aptl-access,path={access_socket},server=on,wait=off",
        "-device",
        "virtserialport,chardev=aptl-access,name=org.aptl.access",
        "-device",
        "virtio-rng-pci",
        "-qmp",
        f"unix:{management_socket},server=on,wait=off",
        "-netdev",
        f"user,id=participant,net={QEMU_SLIRP_SUBNET},dhcpstart={spec.guest_adapter_address},{forwards}",
        "-device",
        "virtio-net-pci,netdev=participant",
        "-serial",
        "none",
        "-nographic",
    )


def start_vm(
    spec: VmLaunchSpec,
    *,
    runner: VmRunner = None,
) -> SubprocessVm:
    """Start one VM process from a hardened argv list."""

    argv = list(build_qemu_argv(spec))
    management_socket = spec.management_socket or spec.overlay_path.with_suffix(".qmp")
    readiness_socket = spec.readiness_socket or spec.overlay_path.with_suffix(
        ".readiness.sock"
    )
    access_socket = spec.access_socket or spec.overlay_path.with_suffix(".access.sock")
    for socket_path in (management_socket, readiness_socket, access_socket):
        socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        socket_path.unlink(missing_ok=True)
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    if process.poll() is not None:
        raise SeatLauncherError("failed-launch", "VM exited during launch")
    if runner is None:
        return SubprocessVm(process=process)
    return runner(process=process)


def vm_pid_path(seat_root: Path) -> Path:
    """Return the VM pid file path for one seat root."""

    return seat_root / "vm.pid"


def _tracked_pid_alive(pid: int) -> bool:
    """Return whether ``pid`` still refers to a live process."""

    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _read_process_identity(pid: int) -> VmProcessIdentity | None:
    """Read an immutable-enough process identity from procfs or POSIX ps."""

    try:
        stat_payload = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        after_name = stat_payload.rsplit(")", 1)[1].split()
        start_time_ticks = int(after_name[19])
        executable = os.readlink(f"/proc/{pid}/exe")
        return VmProcessIdentity(
            pid=pid,
            start_time_ticks=start_time_ticks,
            executable=executable,
        )
    except (IndexError, OSError, ValueError):
        pass
    try:
        observed = subprocess.run(
            ["ps", "-o", "lstart=", "-o", "comm=", "-p", str(pid)],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        start_text, executable = observed[:24], observed[24:].strip()
        start_time_ticks = int(time.mktime(time.strptime(start_text)))
        if not executable:
            return None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return VmProcessIdentity(
        pid=pid,
        start_time_ticks=start_time_ticks,
        executable=executable,
    )


def read_vm_pid(seat_root: Path) -> int | None:
    """Return the live VM pid only when its persisted process identity matches."""

    path = vm_pid_path(seat_root)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if set(payload) != {"pid", "start_time_ticks", "executable"}:
            return None
        expected = VmProcessIdentity(
            pid=int(payload["pid"]),
            start_time_ticks=int(payload["start_time_ticks"]),
            executable=str(payload["executable"]),
        )
    except (OSError, TypeError, ValueError):
        return None
    if expected.pid <= 0 or not _tracked_pid_alive(expected.pid):
        return None
    return expected.pid if _read_process_identity(expected.pid) == expected else None


def write_vm_pid(seat_root: Path, pid: int | None) -> None:
    """Atomically persist or clear the tracked VM process identity."""

    path = vm_pid_path(seat_root)
    if pid is None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return
    identity = _read_process_identity(pid)
    if identity is None:
        raise SeatLauncherError("failed-launch", "VM process identity unavailable")
    temporary = path.with_name(f".{path.name}.{os.getpid()}")
    temporary.write_text(
        json.dumps(
            {
                "pid": identity.pid,
                "start_time_ticks": identity.start_time_ticks,
                "executable": identity.executable,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    os.replace(temporary, path)


def stop_vm(seat_root: Path, *, timeout: float = 20.0) -> bool:
    """Terminate the tracked VM process when present."""

    pid = read_vm_pid(seat_root)
    if pid is None:
        return False
    try:
        os.kill(pid, signal.SIGTERM)
        deadline = timeout
        while deadline > 0:
            try:
                os.kill(pid, 0)
            except OSError:
                write_vm_pid(seat_root, None)
                return True
            import time

            time.sleep(0.2)
            deadline -= 0.2
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    write_vm_pid(seat_root, None)
    return True
