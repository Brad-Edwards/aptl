"""Host prerequisite checks for appliance seat launch."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aptl.appliance.models import HostPrerequisites
from aptl.appliance.seat.errors import SeatLauncherError
from aptl.appliance.seat.vm import OVMF_CODE_PATH
from aptl.core import hostenv


@dataclass(frozen=True)
class PrereqFinding:
    """One bounded host prerequisite result."""

    code: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class PrereqReport:
    """Aggregate prerequisite admission for one seat launch attempt."""

    passed: bool
    findings: tuple[PrereqFinding, ...]


def _read_available_memory_bytes() -> int:
    """Read currently available memory from ``/proc/meminfo`` when available."""

    try:
        with Path("/proc/meminfo").open(encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def _kvm_available() -> bool:
    """Return whether the host exposes a readable ``/dev/kvm`` device."""

    return Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK)


def _tool_available(command: tuple[str, ...]) -> bool:
    """Return whether a launcher tool responds successfully to a version probe."""

    try:
        result = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def check_host_prerequisites(
    requirements: HostPrerequisites,
    *,
    seat_root: Path,
    memory_bytes: int | None = None,
    available_vcpus: int | None = None,
    total_disk_bytes: int | None = None,
    free_disk_bytes: int | None = None,
    required_free_disk_bytes: int | None = None,
    kvm_available: bool | None = None,
    qemu_img_available: bool | None = None,
    qemu_system_available: bool | None = None,
    ovmf_available: bool | None = None,
) -> PrereqReport:
    """Validate host resources and launcher tools against the signed manifest."""

    findings: list[PrereqFinding] = []
    if hostenv.host_os() != hostenv.OS_LINUX:
        findings.append(
            PrereqFinding(
                code="unsupported-host-os",
                passed=False,
                detail="seat launcher requires Linux",
            )
        )
    if requirements.hardware_virtualization:
        kvm_ok = _kvm_available() if kvm_available is None else kvm_available
        findings.append(
            PrereqFinding(
                code="no-kvm",
                passed=kvm_ok,
                detail="hardware virtualization is unavailable",
            )
        )
    total_memory = (
        _read_available_memory_bytes() if memory_bytes is None else memory_bytes
    )
    findings.append(
        PrereqFinding(
            code="low-memory",
            passed=total_memory >= requirements.memory_bytes,
            detail="host memory is below the signed minimum",
        )
    )
    if available_vcpus is not None:
        cpu_capacity = available_vcpus
    elif hasattr(os, "sched_getaffinity"):
        cpu_capacity = len(os.sched_getaffinity(0))
    else:
        cpu_capacity = os.cpu_count() or 0
    findings.append(
        PrereqFinding(
            code="low-cpu",
            passed=cpu_capacity >= requirements.vcpus,
            detail="available CPU capacity is below the signed minimum",
        )
    )
    try:
        disk_usage = shutil.disk_usage(seat_root)
        disk_capacity = (
            disk_usage.total if total_disk_bytes is None else total_disk_bytes
        )
        available_disk = disk_usage.free if free_disk_bytes is None else free_disk_bytes
    except OSError:
        disk_capacity = available_disk = 0
    findings.append(
        PrereqFinding(
            code="low-disk-capacity",
            passed=disk_capacity >= requirements.disk_bytes,
            detail="host disk capacity is below the signed minimum",
        )
    )
    required_free_disk = (
        requirements.disk_bytes
        if required_free_disk_bytes is None
        else required_free_disk_bytes
    )
    findings.append(
        PrereqFinding(
            code="low-disk",
            passed=available_disk >= required_free_disk,
            detail="free disk is below the signed runtime ceiling",
        )
    )
    qemu_img_ok = (
        _tool_available(("qemu-img", "--version"))
        if qemu_img_available is None
        else qemu_img_available
    )
    findings.append(
        PrereqFinding(
            code="missing-qemu-img",
            passed=qemu_img_ok,
            detail="qemu-img is required for overlay management",
        )
    )
    qemu_system_ok = (
        _tool_available(("qemu-system-x86_64", "--version"))
        if qemu_system_available is None
        else qemu_system_available
    )
    findings.append(
        PrereqFinding(
            code="missing-qemu-system",
            passed=qemu_system_ok,
            detail="qemu-system-x86_64 is required for seat launch",
        )
    )
    ovmf_ok = OVMF_CODE_PATH.is_file() if ovmf_available is None else ovmf_available
    findings.append(
        PrereqFinding(
            code="missing-uefi-firmware",
            passed=ovmf_ok,
            detail=f"read-only UEFI firmware is required at {OVMF_CODE_PATH}",
        )
    )
    passed = all(item.passed for item in findings)
    return PrereqReport(passed=passed, findings=tuple(findings))


def require_host_prerequisites(
    requirements: HostPrerequisites,
    *,
    seat_root: Path,
    **overrides: object,
) -> PrereqReport:
    """Fail closed when host prerequisites are not met."""

    report = check_host_prerequisites(requirements, seat_root=seat_root, **overrides)
    if not report.passed:
        failed = tuple(item for item in report.findings if not item.passed)
        if len(failed) == 1:
            raise SeatLauncherError(failed[0].code, failed[0].detail)
        summary = "; ".join(f"{item.code}: {item.detail}" for item in failed)
        raise SeatLauncherError("host-prerequisites-failed", summary)
    return report
