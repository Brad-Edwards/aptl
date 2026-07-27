"""Prerequisite checks for the appliance seat launcher."""

from __future__ import annotations

from pathlib import Path

import pytest

from aptl.appliance.models import HostPrerequisites
from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.prereqs import check_host_prerequisites, require_host_prerequisites
from aptl.core import hostenv

pytestmark = pytest.mark.skipif(
    hostenv.host_os() != hostenv.OS_LINUX,
    reason="appliance seat launcher prerequisites are Linux-only",
)


def _requirements() -> HostPrerequisites:
    return HostPrerequisites(
        architecture="x86_64",
        vcpus=8,
        memory_bytes=16 * 1024**3,
        disk_bytes=100 * 1024**3,
        hardware_virtualization=True,
        local_adapter="qemu-kvm",
        supported_hypervisors=("qemu>=8.2",),
    )


def test_prereqs_pass_with_injected_probes(tmp_path: Path) -> None:
    report = check_host_prerequisites(
        _requirements(),
        seat_root=tmp_path,
        memory_bytes=32 * 1024**3,
        free_disk_bytes=200 * 1024**3,
        kvm_available=True,
        qemu_img_available=True,
        qemu_system_available=True,
    )

    assert report.passed is True


def test_prereqs_fail_closed_on_missing_kvm(tmp_path: Path) -> None:
    report = check_host_prerequisites(
        _requirements(),
        seat_root=tmp_path,
        memory_bytes=32 * 1024**3,
        kvm_available=False,
        qemu_img_available=True,
        qemu_system_available=True,
    )

    assert report.passed is False
    assert any(item.code == "no-kvm" for item in report.findings)


def test_require_host_prerequisites_raises(tmp_path: Path) -> None:
    with pytest.raises(SeatLauncherError) as exc:
        require_host_prerequisites(
            _requirements(),
            seat_root=tmp_path,
            memory_bytes=1024,
            kvm_available=True,
            qemu_img_available=True,
            qemu_system_available=True,
        )

    assert exc.value.code == "low-memory"


def test_prereqs_fail_on_low_disk_and_missing_tools(tmp_path: Path) -> None:
    report = check_host_prerequisites(
        _requirements(),
        seat_root=tmp_path,
        memory_bytes=32 * 1024**3,
        free_disk_bytes=1024,
        kvm_available=True,
        qemu_img_available=False,
        qemu_system_available=False,
    )

    assert report.passed is False
    codes = {item.code for item in report.findings if not item.passed}
    assert "low-disk" in codes
    assert "missing-qemu-img" in codes
    assert "missing-qemu-system" in codes
