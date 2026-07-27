"""Host exposure inventory for the appliance seat launcher."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from aptl.appliance.seat.errors import SeatLauncherError
from aptl.core import hostenv


FORBIDDEN_VM_FLAGS = (
    "-usb",
    "-spice",
    "clipboard",
    "share=on",
)
FORBIDDEN_VM_WRITABLE_SHARE_FLAGS = (
    "readonly=off",
    "security_model=mapped-xattr",
)


@dataclass(frozen=True)
class HostExposureReport:
    """Bounded host exposure inventory for instructor diagnostics."""

    passed: bool
    findings: tuple[str, ...]


def _fsdev_options(argv: tuple[str, ...]) -> tuple[str, ...]:
    """Return QEMU -fsdev option strings from a fixed argv list."""

    options: list[str] = []
    index = 0
    while index < len(argv):
        if argv[index] == "-fsdev" and index + 1 < len(argv):
            options.append(argv[index + 1])
            index += 2
            continue
        index += 1
    return tuple(options)


def audit_vm_argv(argv: tuple[str, ...]) -> HostExposureReport:
    """Reject VM launch arguments that widen the physical-host boundary."""

    findings: list[str] = []
    joined = " ".join(argv)
    for flag in FORBIDDEN_VM_FLAGS:
        if flag in joined:
            findings.append(f"host.exposure.forbidden-vm-flag:{flag}")
    fsdev_joined = " ".join(_fsdev_options(argv))
    for flag in FORBIDDEN_VM_WRITABLE_SHARE_FLAGS:
        if flag in fsdev_joined:
            findings.append(f"host.exposure.forbidden-vm-share:{flag}")
    return HostExposureReport(passed=not findings, findings=tuple(findings))


def audit_host_process_inventory(
    *,
    docker_daemon_running: bool | None = None,
) -> HostExposureReport:
    """Ensure the seat host does not require Docker for launcher operations."""

    findings: list[str] = []
    if hostenv.host_os() != hostenv.OS_LINUX:
        return HostExposureReport(passed=True, findings=())
    docker_running = (
        _docker_daemon_running()
        if docker_daemon_running is None
        else docker_daemon_running
    )
    if docker_running:
        findings.append("host.exposure.docker-daemon-present")
    return HostExposureReport(passed=not findings, findings=tuple(findings))


def _docker_daemon_running() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def require_host_exposure(
    *,
    vm_argv: tuple[str, ...],
    docker_daemon_running: bool | None = None,
) -> HostExposureReport:
    """Fail closed when host exposure violates the appliance contract."""

    vm_report = audit_vm_argv(vm_argv)
    process_report = audit_host_process_inventory(
        docker_daemon_running=docker_daemon_running
    )
    findings = vm_report.findings + process_report.findings
    report = HostExposureReport(passed=not findings, findings=findings)
    if not report.passed:
        raise SeatLauncherError(report.findings[0], "host exposure inventory failed")
    return report
