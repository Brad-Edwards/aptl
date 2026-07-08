"""System requirements checking.

Validates that the host system meets the prerequisites for running the
APTL lab (e.g., vm.max_map_count for OpenSearch/Wazuh Indexer).
"""

import subprocess
from dataclasses import dataclass

from aptl.core import hostenv
from aptl.utils.logging import get_logger

log = get_logger("sysreqs")

_DEFAULT_MIN_MAP_COUNT = 262144


@dataclass
class SysReqResult:
    """Result of a system requirement check."""

    passed: bool
    current_value: int
    required_value: int
    error: str = ""
    applicable: bool = True


def check_max_map_count(minimum: int = _DEFAULT_MIN_MAP_COUNT) -> SysReqResult:
    """Check that vm.max_map_count meets the required minimum.

    OpenSearch (used by Wazuh Indexer) requires vm.max_map_count >= 262144.
    This function runs ``sysctl vm.max_map_count`` and parses the output.

    Args:
        minimum: Minimum acceptable value. Defaults to 262144.

    Returns:
        SysReqResult indicating whether the check passed, plus current
        and required values.
    """
    docker_mode = hostenv.docker_mode()
    if docker_mode != hostenv.DOCKER_LINUX_NATIVE:
        return _not_applicable_result(
            minimum,
            f"vm.max_map_count is managed inside the Docker VM ({docker_mode})",
        )

    try:
        result = subprocess.run(
            ["sysctl", "vm.max_map_count"],
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, OSError) as exc:
        return _not_applicable_result(minimum, str(exc))

    if result.returncode != 0:
        error_msg = result.stderr.strip() or "sysctl command failed"
        if _sysctl_not_applicable(error_msg):
            return _not_applicable_result(
                minimum, f"vm.max_map_count sysctl not applicable: {error_msg}"
            )
        log.error("sysctl returned non-zero: %s", error_msg)
        return SysReqResult(
            passed=False,
            current_value=0,
            required_value=minimum,
            error=error_msg,
        )

    # Parse output: "vm.max_map_count = 262144"
    stdout = result.stdout.strip()
    try:
        # Split on '=' and take the numeric part
        parts = stdout.split("=")
        if len(parts) != 2:
            raise ValueError(f"Unexpected format: {stdout}")
        current_value = int(parts[1].strip())
    except (ValueError, IndexError) as exc:
        log.error("Failed to parse sysctl output '%s': %s", stdout, exc)
        return SysReqResult(
            passed=False,
            current_value=0,
            required_value=minimum,
            error=f"Failed to parse sysctl output: {stdout}",
        )

    passed = current_value >= minimum

    if passed:
        log.info("vm.max_map_count is adequate (%d >= %d)", current_value, minimum)
    else:
        log.warning(
            "vm.max_map_count is too low (%d < %d)", current_value, minimum
        )

    return SysReqResult(
        passed=passed,
        current_value=current_value,
        required_value=minimum,
    )


def _not_applicable_result(minimum: int, reason: str) -> SysReqResult:
    """Return a passing result for a host check that does not apply."""
    log.info("Skipping vm.max_map_count host check: %s", reason)
    return SysReqResult(
        passed=True,
        current_value=0,
        required_value=minimum,
        error=reason,
        applicable=False,
    )


def _sysctl_not_applicable(error_msg: str) -> bool:
    """Return whether sysctl output means the key is unavailable on this host."""
    normalized = error_msg.lower()
    return any(
        phrase in normalized
        for phrase in (
            "unknown oid",
            "no such file or directory",
            "not found",
            "cannot stat",
        )
    )
