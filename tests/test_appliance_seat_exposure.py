"""Host exposure inventory tests for the appliance seat launcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from aptl.appliance.seat.exposure import (
    audit_host_process_inventory,
    audit_vm_argv,
    require_host_exposure,
)
from aptl.appliance.seat.vm import VmLaunchSpec, build_qemu_argv
from aptl.core import hostenv

pytestmark = pytest.mark.skipif(
    hostenv.host_os() != hostenv.OS_LINUX,
    reason="appliance seat launcher exposure checks are Linux-only",
)


def test_audit_host_process_inventory_probes_docker_by_default() -> None:
    with patch(
        "aptl.appliance.seat.exposure._docker_daemon_running",
        return_value=True,
    ) as probe:
        report = audit_host_process_inventory()

    probe.assert_called_once()
    assert report.passed is False
    assert "host.exposure.docker-daemon-present" in report.findings


def test_audit_vm_argv_allows_writable_overlay_drive(tmp_path: Path) -> None:
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
        )
    )

    report = audit_vm_argv(argv)

    assert report.passed is True
    assert "readonly=off" in argv[argv.index("-drive") + 1]
    require_host_exposure(vm_argv=argv, docker_daemon_running=False)


def test_audit_vm_argv_rejects_writable_fsdev_share() -> None:
    argv = (
        "qemu-system-x86_64",
        "-fsdev",
        "local,id=share,path=/srv/share,readonly=off,security_model=none",
    )

    report = audit_vm_argv(argv)

    assert report.passed is False
    assert "host.exposure.forbidden-vm-share:readonly=off" in report.findings


def test_audit_vm_argv_rejects_forbidden_usb_flag() -> None:
    argv = ("qemu-system-x86_64", "-enable-kvm", "-usb", "off")

    report = audit_vm_argv(argv)

    assert report.passed is False
    assert "host.exposure.forbidden-vm-flag:-usb" in report.findings

