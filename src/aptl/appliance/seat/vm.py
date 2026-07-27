"""QEMU/KVM adapter for one disposable appliance overlay."""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


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
    participant_port: int = 443
    recovery_port: int = 9443


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


def build_qemu_argv(spec: VmLaunchSpec) -> tuple[str, ...]:
    """Return hardened fixed argv for one local-KVM seat."""

    launch_path = str(spec.launch_mount.resolve())
    return (
        "qemu-system-x86_64",
        "-enable-kvm",
        "-cpu",
        "host",
        "-smp",
        str(spec.vcpus),
        "-m",
        str(spec.memory_mib),
        "-drive",
        f"file={spec.overlay_path},format=qcow2,if=virtio,cache=none,aio=threads,readonly=off",
        "-fsdev",
        f"local,id=aptl-launch,path={launch_path},readonly=on,security_model=none",
        "-device",
        "virtio-9p-pci,fsdev=aptl-launch,mount_tag=aptl-launch",
        "-virtio-serial-pci",
        "-device",
        "virtio-rng-pci",
        "-netdev",
        (
            f"user,id=participant,hostfwd=tcp:127.0.0.1:{spec.participant_port}-:"
            f"{spec.participant_port},hostfwd=tcp:127.0.0.1:{spec.recovery_port}-:"
            f"{spec.recovery_port}"
        ),
        "-device",
        "virtio-net-pci,netdev=participant",
        "-serial",
        "none",
        "-monitor",
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
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    return SubprocessVm(process=process)


def vm_pid_path(seat_root: Path) -> Path:
    return seat_root / "vm.pid"


def read_vm_pid(seat_root: Path) -> int | None:
    path = vm_pid_path(seat_root)
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8").strip()
        pid = int(text)
    except (OSError, ValueError):
        return None
    if pid <= 0:
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    return pid


def write_vm_pid(seat_root: Path, pid: int | None) -> None:
    path = vm_pid_path(seat_root)
    if pid is None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return
    path.write_text(f"{pid}\n", encoding="utf-8")
    path.chmod(0o600)


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
