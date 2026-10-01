"""Rootless VM network namespace and outbound NAT startup."""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from aptl.appliance.seat.errors import SeatLauncherError

PRIVATE_NETWORK_SUBNET = "10.0.3.0/24"
PRIVATE_NETWORK_DNS = "10.0.3.3"


def _sandbox_pid(info_fd: int, deadline: float) -> int:
    """Read and validate bubblewrap's process report."""
    report = bytearray()
    while time.monotonic() < deadline and len(report) < 4096:
        if not select.select([info_fd], [], [], max(0, deadline - time.monotonic()))[0]:
            break
        chunk = os.read(info_fd, 4096 - len(report))
        if not chunk:
            break
        report.extend(chunk)
    try:
        sandbox_pid = json.loads(report)["child-pid"]
    except (KeyError, TypeError, ValueError) as exc:
        raise SeatLauncherError("failed-launch", "private VM process was not reported") from exc
    if not isinstance(sandbox_pid, int) or sandbox_pid <= 0:
        raise SeatLauncherError("failed-launch", "private VM process was not reported")
    return sandbox_pid


def _qemu_descendant(sandbox_pid: int) -> int | None:
    """Find QEMU beneath bubblewrap, which may fork a monitor process."""
    descendants = [sandbox_pid]
    while descendants:
        pid = descendants.pop()
        try:
            command_name = Path(f"/proc/{pid}/comm").read_text().strip()
            if command_name.startswith("qemu-system-"):
                return pid
            children = Path(f"/proc/{pid}/task/{pid}/children").read_text()
            descendants.extend(int(child) for child in children.split())
        except OSError:
            continue
    return None


def _private_qemu_pid(info_fd: int) -> int:
    """Read the sandbox's reported guest PID, including when it forks a monitor."""
    deadline = time.monotonic() + 10
    sandbox_pid = _sandbox_pid(info_fd, deadline)
    while time.monotonic() < deadline:
        pid = _qemu_descendant(sandbox_pid)
        if pid is not None:
            return pid
        time.sleep(0.05)
    raise SeatLauncherError("failed-launch", "private VM process did not start")


def _start_outbound_network(guest_pid: int, exit_read: int) -> subprocess.Popen[bytes]:
    """Wait for the private NAT adapter and stop it if readiness fails."""
    ready_read, ready_write = os.pipe()
    network: subprocess.Popen[bytes] | None = None
    try:
        network = subprocess.Popen(
            [
                "slirp4netns", "--configure", f"--cidr={PRIVATE_NETWORK_SUBNET}",
                f"--ready-fd={ready_write}", f"--exit-fd={exit_read}",
                str(guest_pid), "tap0",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=(ready_write, exit_read),
            start_new_session=True,
        )
        os.close(ready_write)
        ready_write = -1
        ready = (
            os.read(ready_read, 1)
            if select.select([ready_read], [], [], 10)[0]
            else b""
        )
        if ready != b"1" or network.poll() is not None:
            raise SeatLauncherError("failed-launch", "private VM outbound network did not start")
        return network
    except (OSError, SeatLauncherError):
        if network is not None and network.poll() is None:
            network.terminate()
        raise
    finally:
        os.close(ready_read)
        if ready_write >= 0:
            os.close(ready_write)


def _start_private_vm(argv: list[str], overlay_path: Path) -> tuple[subprocess.Popen[bytes], int]:
    """Keep the desktop port private while giving QEMU ordinary outbound NAT."""

    resolver_fd, resolver_name = tempfile.mkstemp(
        prefix=".seat-resolv-", dir=overlay_path.parent,
    )
    exit_read, exit_write = os.pipe()
    info_read, info_write = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    try:
        with os.fdopen(resolver_fd, "w", encoding="ascii") as resolver:
            resolver.write(f"nameserver {PRIVATE_NETWORK_DNS}\n")
        process = subprocess.Popen(
            [
                "bwrap", "--unshare-net", "--dev-bind", "/", "/",
                "--ro-bind", resolver_name, "/etc/resolv.conf",
                "--sync-fd", str(exit_write), "--info-fd", str(info_write), *argv,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=(exit_write, info_write),
            start_new_session=True,
        )
        os.close(exit_write)
        exit_write = -1
        os.close(info_write)
        info_write = -1
        guest_pid = _private_qemu_pid(info_read)
        os.close(info_read)
        info_read = -1
        _start_outbound_network(guest_pid, exit_read)
        return process, guest_pid
    except (OSError, SeatLauncherError) as exc:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        raise SeatLauncherError("failed-launch", "private VM network did not start") from exc
    finally:
        if exit_read >= 0:
            os.close(exit_read)
        if exit_write >= 0:
            os.close(exit_write)
        if info_read >= 0:
            os.close(info_read)
        if info_write >= 0:
            os.close(info_write)
        Path(resolver_name).unlink(missing_ok=True)
