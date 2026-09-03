"""VM adapter tests for the appliance seat launcher."""

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aptl.appliance.seat.vm import (
    SubprocessVm,
    VmLaunchSpec,
    read_vm_pid,
    start_vm,
    stop_vm,
    write_vm_pid,
)


def test_subprocess_vm_delegates_to_process() -> None:
    process = MagicMock()
    process.pid = 4242
    process.poll.return_value = None
    vm = SubprocessVm(process=process)

    assert vm.pid == 4242
    assert vm.poll() is None
    vm.terminate()
    process.send_signal.assert_called_once_with(signal.SIGTERM)
    vm.wait(timeout=1.0)
    process.wait.assert_called_once_with(timeout=1.0)


def test_write_and_read_vm_pid_roundtrip(tmp_path: Path) -> None:
    write_vm_pid(tmp_path, os.getpid())

    assert read_vm_pid(tmp_path) == os.getpid()


def test_read_vm_pid_rejects_missing_stale_and_invalid(tmp_path: Path) -> None:
    assert read_vm_pid(tmp_path) is None

    write_vm_pid(tmp_path, 999_999)
    assert read_vm_pid(tmp_path) is None

    pid_path = tmp_path / "vm.pid"
    pid_path.write_text("not-a-pid\n", encoding="utf-8")
    assert read_vm_pid(tmp_path) is None

    pid_path.write_text("0\n", encoding="utf-8")
    assert read_vm_pid(tmp_path) is None


def test_write_vm_pid_clears_file(tmp_path: Path) -> None:
    write_vm_pid(tmp_path, os.getpid())
    write_vm_pid(tmp_path, None)

    assert not (tmp_path / "vm.pid").exists()


def test_start_vm_uses_hardened_subprocess_options(tmp_path: Path) -> None:
    launch_mount = tmp_path / "launch"
    launch_mount.mkdir()
    overlay = tmp_path / "overlay.qcow2"
    overlay.write_bytes(b"overlay")
    spec = VmLaunchSpec(
        overlay_path=overlay,
        launch_mount=launch_mount,
        vcpus=2,
        memory_mib=512,
    )

    with patch("aptl.appliance.seat.vm.subprocess.Popen") as popen:
        popen.return_value = MagicMock(pid=5150)
        vm = start_vm(spec)

    assert vm.pid == 5150
    argv = popen.call_args.args[0]
    assert argv[0] == "qemu-system-x86_64"
    assert "-enable-kvm" in argv
    kwargs = popen.call_args.kwargs
    assert kwargs["stdin"] == subprocess.DEVNULL


def test_stop_vm_returns_false_when_untracked(tmp_path: Path) -> None:
    assert stop_vm(tmp_path) is False


def test_stop_vm_clears_pid_when_process_exits(tmp_path: Path) -> None:
    def fake_kill(pid: int, sig: int) -> None:
        if sig == 0:
            raise OSError("process gone")
        assert pid == 7777

    with (
        patch("aptl.appliance.seat.vm.read_vm_pid", return_value=7777),
        patch("aptl.appliance.seat.vm.os.kill", side_effect=fake_kill),
    ):
        assert stop_vm(tmp_path) is True

    write_vm_pid(tmp_path, None)
    assert read_vm_pid(tmp_path) is None


def test_stop_vm_sends_sigkill_when_process_survives(tmp_path: Path) -> None:
    signals: list[int] = []

    def fake_kill(pid: int, sig: int) -> None:
        assert pid == 8888
        signals.append(sig)
        if sig == 0:
            return

    with (
        patch("aptl.appliance.seat.vm.read_vm_pid", return_value=8888),
        patch("aptl.appliance.seat.vm.os.kill", side_effect=fake_kill),
        patch("time.sleep"),
    ):
        assert stop_vm(tmp_path, timeout=0.1) is True

    assert signal.SIGTERM in signals
    assert signal.SIGKILL in signals
