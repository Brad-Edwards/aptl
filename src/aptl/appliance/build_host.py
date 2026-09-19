"""Bounded appliance build-host prerequisite diagnostics."""

from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aptl.core import hostenv


@dataclass(frozen=True)
class BuildHostFinding:
    """One non-secret build-host capability result."""

    code: str
    passed: bool


@dataclass(frozen=True)
class BuildHostReport:
    """Aggregate build-host diagnostics; this command never installs tools."""

    passed: bool
    findings: tuple[BuildHostFinding, ...]


def _tool_works(name: str) -> bool:
    """Return whether a required fixed-argv tool answers a version probe."""

    executable = shutil.which(name)
    if executable is None:
        return False
    try:
        result = subprocess.run(
            [executable, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def check_build_host(
    *, build_root: Path, required_disk_bytes: int = 300 * 1024**3
) -> BuildHostReport:
    """Report local capacity and tools required by the offline image builder."""

    build_root.mkdir(parents=True, exist_ok=True)
    findings = [
        BuildHostFinding("unsupported-host-os", hostenv.host_os() == hostenv.OS_LINUX),
        BuildHostFinding("unsupported-architecture", platform.machine() == "x86_64"),
        BuildHostFinding(
            "low-build-disk",
            shutil.disk_usage(build_root).free >= required_disk_bytes,
        ),
    ]
    for tool in (
        "qemu-img",
        "qemu-system-x86_64",
        "virt-customize",
        "virt-resize",
        "virt-sysprep",
    ):
        findings.append(BuildHostFinding(f"missing-{tool}", _tool_works(tool)))
    return BuildHostReport(
        passed=all(finding.passed for finding in findings),
        findings=tuple(findings),
    )
