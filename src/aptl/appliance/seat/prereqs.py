"""Host prerequisite checks for appliance seat launch."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aptl.appliance.models import HostPrerequisites
from aptl.appliance.seat.errors import SeatLauncherError
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


def _read_total_memory_bytes() -> int:
    try:
        with Path("/proc/meminfo").open(encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def _kvm_available() -> bool:
    return Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK)


def _tool_available(command: tuple[str, ...]) -> bool:
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
    free_disk_bytes: int | None = None,
    kvm_available: bool | None = None,
    qemu_img_available: bool | None = None,
    qemu_system_available: bool | None = None,
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
    total_memory = _read_total_memory_bytes() if memory_bytes is None else memory_bytes
    findings.append(
        PrereqFinding(
            code="low-memory",
            passed=total_memory >= requirements.memory_bytes,
            detail="host memory is below the signed minimum",
        )
    )
    try:
        available_disk = (
            shutil.disk_usage(seat_root).free
            if free_disk_bytes is None
            else free_disk_bytes
        )
    except OSError:
        available_disk = 0
    findings.append(
        PrereqFinding(
            code="low-disk",
            passed=available_disk >= requirements.disk_bytes,
            detail="free disk is below the signed minimum",
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
        failed = next(item for item in report.findings if not item.passed)
        raise SeatLauncherError(failed.code, failed.detail)
    return report
