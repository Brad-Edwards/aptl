"""VM adapter tests for the appliance seat launcher."""

from __future__ import annotations

import os
import signal
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aptl.appliance.seat.vm import (
    SubprocessVm,
    VmLaunchSpec,
    VmProcessIdentity,
    build_qemu_argv,
    read_vm_pid,
    start_vm,
    stop_vm,
    write_vm_pid,
)
from aptl.core.appliance_boundary_inventory import BoundaryEndpoint


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


def test_process_identity_falls_back_to_posix_ps_without_procfs() -> None:
    current = __import__("aptl.appliance.seat.vm", fromlist=["_read_process_identity"])

    with patch("pathlib.Path.read_text", side_effect=OSError):
        identity = current._read_process_identity(os.getpid())

    assert identity is not None
    assert identity.pid == os.getpid()
    assert identity.start_time_ticks > 0
    assert identity.executable


def test_read_vm_pid_rejects_reused_process_identity(tmp_path: Path) -> None:
    write_vm_pid(tmp_path, os.getpid())
    current = __import__("aptl.appliance.seat.vm", fromlist=["_read_process_identity"])
    identity = current._read_process_identity(os.getpid())
    assert identity is not None
    reused = VmProcessIdentity(
        pid=identity.pid,
        start_time_ticks=identity.start_time_ticks + 1,
        executable=identity.executable,
    )

    with patch("aptl.appliance.seat.vm._read_process_identity", return_value=reused):
        assert read_vm_pid(tmp_path) is None


def test_read_vm_pid_rejects_missing_stale_and_invalid(tmp_path: Path) -> None:
    assert read_vm_pid(tmp_path) is None

    (tmp_path / "vm.pid").write_text(
        '{"executable":"/usr/bin/qemu","pid":999999,"start_time_ticks":1}\n',
        encoding="utf-8",
    )
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
        popen.return_value.poll.return_value = None
        vm = start_vm(spec)

    assert vm.pid == 5150
    argv = popen.call_args.args[0]
    assert argv[0] == "qemu-system-x86_64"
    assert "-enable-kvm" in argv
    kwargs = popen.call_args.kwargs
    assert kwargs["stdin"] == subprocess.DEVNULL


def test_qemu_argv_uses_private_management_socket(tmp_path: Path) -> None:
    launch_mount = tmp_path / "launch"
    launch_mount.mkdir()
    overlay = tmp_path / "overlay.qcow2"
    overlay.write_bytes(b"overlay")
    management_socket = tmp_path / "runtime" / "vm.qmp"

    argv = build_qemu_argv(
        VmLaunchSpec(
            overlay_path=overlay,
            launch_mount=launch_mount,
            management_socket=management_socket,
            vcpus=2,
            memory_mib=512,
        )
    )

    qmp = argv[argv.index("-qmp") + 1]
    assert qmp == f"unix:{management_socket},server=on,wait=off"
    assert "-monitor" not in argv


def test_qemu_argv_publishes_resource_reservation(tmp_path: Path) -> None:
    launch_mount = tmp_path / "launch"
    launch_mount.mkdir()
    overlay = tmp_path / "overlay.qcow2"
    overlay.write_bytes(b"overlay")

    argv = build_qemu_argv(
        VmLaunchSpec(
            overlay_path=overlay,
            launch_mount=launch_mount,
            vcpus=8,
            memory_mib=16384,
            disk_reservation_bytes=100 * 1024**3,
        )
    )

    assert argv[argv.index("-fw_cfg") + 1] == (
        "name=opt/aptl/resource-reservation,string=8:17179869184:107374182400"
    )


def test_qemu_argv_attaches_private_guest_readiness_channel(tmp_path: Path) -> None:
    launch_mount = tmp_path / "launch"
    launch_mount.mkdir()
    overlay = tmp_path / "overlay.qcow2"
    overlay.write_bytes(b"overlay")
    readiness_socket = tmp_path / "runtime" / "readiness.sock"

    argv = build_qemu_argv(
        VmLaunchSpec(
            overlay_path=overlay,
            launch_mount=launch_mount,
            readiness_socket=readiness_socket,
            vcpus=2,
            memory_mib=512,
        )
    )

    chardev = argv[argv.index("-chardev") + 1]
    assert chardev == (
        f"socket,id=aptl-readiness,path={readiness_socket},server=on,wait=off"
    )
    assert "virtserialport,chardev=aptl-readiness,name=org.aptl.readiness" in argv


def test_start_vm_rejects_immediate_qemu_exit(tmp_path: Path) -> None:
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

    with (
        patch("aptl.appliance.seat.vm.subprocess.Popen") as popen,
        pytest.raises(Exception, match="VM exited during launch"),
    ):
        popen.return_value.poll.return_value = 1
        start_vm(spec)


def test_qemu_argv_declares_virtio_serial_as_a_device(tmp_path: Path) -> None:
    launch_mount = tmp_path / "launch"
    launch_mount.mkdir()
    overlay = tmp_path / "overlay.qcow2"
    overlay.write_bytes(b"overlay")

    argv = build_qemu_argv(
        VmLaunchSpec(
            overlay_path=overlay,
            launch_mount=launch_mount,
            vcpus=2,
            memory_mib=512,
        )
    )

    assert "-virtio-serial-pci" not in argv
    serial_index = argv.index("virtio-serial-pci")
    assert argv[serial_index - 1] == "-device"


def test_installed_qemu_accepts_virtio_serial_device_syntax() -> None:
    qemu = shutil.which("qemu-system-x86_64")
    if qemu is None:
        pytest.skip("qemu-system-x86_64 is not installed")

    result = subprocess.run(
        [qemu, "-device", "virtio-serial-pci", "-version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr


def test_qemu_argv_uses_explicit_outer_to_guest_mappings(tmp_path: Path) -> None:
    launch_mount = tmp_path / "launch"
    launch_mount.mkdir()
    overlay = tmp_path / "overlay.qcow2"
    overlay.write_bytes(b"overlay")
    mappings = (
        BoundaryEndpoint(
            audience="participant",
            address="127.0.0.1",
            port=10443,
            protocol="tcp",
            guest_address="127.0.0.1",
            guest_port=443,
        ),
        BoundaryEndpoint(
            audience="recovery",
            address="127.0.0.1",
            port=11443,
            protocol="tcp",
            guest_address="127.0.0.1",
            guest_port=9443,
        ),
    )

    argv = build_qemu_argv(
        VmLaunchSpec(
            overlay_path=overlay,
            launch_mount=launch_mount,
            vcpus=2,
            memory_mib=512,
            mappings=mappings,
        )
    )

    netdev = argv[argv.index("-netdev") + 1]
    assert "net=10.0.2.0/24" in netdev
    assert "dhcpstart=10.0.2.15" in netdev
    assert "hostfwd=tcp:127.0.0.1:10443-10.0.2.15:443" in netdev
    assert "hostfwd=tcp:127.0.0.1:11443-10.0.2.15:9443" in netdev


def test_vm_launch_spec_rejects_duplicate_outer_mappings(tmp_path: Path) -> None:
    mapping = BoundaryEndpoint(
        audience="participant",
        address="127.0.0.1",
        port=10443,
        protocol="tcp",
        guest_address="127.0.0.1",
        guest_port=443,
    )

    with pytest.raises(ValueError, match="duplicate outer endpoint"):
        VmLaunchSpec(
            overlay_path=tmp_path / "overlay.qcow2",
            launch_mount=tmp_path / "launch",
            vcpus=2,
            memory_mib=512,
            mappings=(mapping, mapping),
        )


def test_vm_launch_spec_rejects_unimplemented_udp_mapping(tmp_path: Path) -> None:
    mapping = BoundaryEndpoint(
        audience="participant",
        address="127.0.0.1",
        port=10443,
        protocol="udp",
        guest_address="127.0.0.1",
        guest_port=443,
    )

    with pytest.raises(ValueError, match="TCP only"):
        VmLaunchSpec(
            overlay_path=tmp_path / "overlay.qcow2",
            launch_mount=tmp_path / "launch",
            vcpus=2,
            memory_mib=512,
            mappings=(mapping,),
        )


def test_qemu_argv_rejects_option_separator_in_paths(tmp_path: Path) -> None:
    spec = VmLaunchSpec(
        overlay_path=tmp_path / "overlay,unsafe.qcow2",
        launch_mount=tmp_path / "launch",
        vcpus=2,
        memory_mib=512,
    )

    with pytest.raises(ValueError, match="QEMU option separator"):
        build_qemu_argv(spec)


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
