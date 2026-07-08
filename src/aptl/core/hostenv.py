"""Host + Docker environment detection.

Cross-platform capability layer for the ``aptl lab`` control plane. aptl runs
on Linux, macOS, and Windows, and against either a native Linux Docker engine
or Docker Desktop. Host-touching steps (kernel checks, file-ownership repair,
key permissions) must branch on *which* OS and *which* Docker mode they are
running under instead of assuming Linux-native semantics.

Named ``hostenv`` rather than ``platform`` to avoid shadowing the stdlib
``platform`` module for anyone reading or extending this package.
"""

import subprocess
import sys

from aptl.utils.logging import get_logger

log = get_logger("hostenv")

OS_LINUX = "linux"
OS_MACOS = "macos"
OS_WINDOWS = "windows"
OS_UNKNOWN = "unknown"

DOCKER_LINUX_NATIVE = "linux_native"
DOCKER_DESKTOP = "docker_desktop"
DOCKER_VM = "docker_vm"
DOCKER_UNKNOWN = "unknown"


def host_os() -> str:
    """Return the host operating system.

    One of :data:`OS_LINUX`, :data:`OS_MACOS`, :data:`OS_WINDOWS`, or
    :data:`OS_UNKNOWN`. Derived from ``sys.platform`` (same signal the
    existing ``kill.py`` process-scan gate uses).
    """
    plat = sys.platform
    detected = OS_UNKNOWN
    if plat.startswith("linux"):
        detected = OS_LINUX
    elif plat == "darwin":
        detected = OS_MACOS
    elif plat.startswith("win"):
        detected = OS_WINDOWS
    return detected


def is_linux() -> bool:
    """Return True when the host OS is Linux."""
    return host_os() == OS_LINUX


def is_macos() -> bool:
    """Return True when the host OS is macOS."""
    return host_os() == OS_MACOS


def is_windows() -> bool:
    """Return True when the host OS is Windows."""
    return host_os() == OS_WINDOWS


def docker_mode() -> str:
    """Return whether Docker is native Linux, Desktop, or another Docker VM.

    Probes ``docker info`` for its ``OperatingSystem`` field: Docker Desktop
    reports the literal string ``Docker Desktop`` on every host OS, whereas a
    native Linux engine reports the distribution (e.g. ``Ubuntu 24.04.4 LTS``).
    On non-Linux hosts, a non-Desktop Linux engine string still represents a
    Docker VM from the host's perspective, such as Colima/Lima on macOS.

    Returns one of :data:`DOCKER_LINUX_NATIVE`, :data:`DOCKER_DESKTOP`,
    :data:`DOCKER_VM`, or :data:`DOCKER_UNKNOWN`. Detection failures (Docker
    absent or not running) yield :data:`DOCKER_UNKNOWN` so callers can fail
    safe.
    """
    return _docker_mode_from_operating_system(_docker_operating_system(), host_os())


def _docker_operating_system() -> str | None:
    """Return Docker's reported operating system, or None when unavailable."""
    try:
        result = _run_docker_info()
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("Could not probe docker info: %s", exc)
        return None
    if result.returncode != 0:
        log.warning(
            "docker info returned non-zero: %s",
            result.stderr.strip() or "no stderr",
        )
        return None

    operating_system = result.stdout.strip()
    return operating_system or None


def _run_docker_info() -> subprocess.CompletedProcess[str]:
    """Run the Docker CLI probe used for engine-mode detection."""
    return subprocess.run(
        ["docker", "info", "--format", "{{.OperatingSystem}}"],
        capture_output=True,
        text=True,
        timeout=15,
    )


def _docker_mode_from_operating_system(
    operating_system: str | None,
    detected_host_os: str,
) -> str:
    """Classify a Docker operating-system string into an aptl Docker mode."""
    mode = DOCKER_UNKNOWN
    if operating_system == "Docker Desktop":
        mode = DOCKER_DESKTOP
    elif operating_system and detected_host_os == OS_LINUX:
        mode = DOCKER_LINUX_NATIVE
    elif operating_system:
        mode = DOCKER_VM
    return mode


def is_docker_desktop() -> bool:
    """Return True when Docker is running as Docker Desktop."""
    return docker_mode() == DOCKER_DESKTOP


def needs_host_ownership_fix() -> bool:
    """Return True when container-written bind-mount files need host chown.

    Only a Docker engine reached from a Linux host is treated as native for
    ownership repair. Docker Desktop and other Docker VM layers on macOS or
    Windows map ownership across the host boundary differently, and an
    unknown/absent engine must not trigger any privileged action. So this is
    True only for
    :data:`DOCKER_LINUX_NATIVE`.
    """
    return docker_mode() == DOCKER_LINUX_NATIVE
