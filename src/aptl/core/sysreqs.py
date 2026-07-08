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
    mode = hostenv.docker_mode()
    if mode == hostenv.DOCKER_LINUX_NATIVE:
        result = _check_linux_native_max_map_count(minimum)
    else:
        result = _not_applicable_result(
            minimum,
            f"vm.max_map_count is managed inside the Docker VM ({mode})",
        )
    return result


def _check_linux_native_max_map_count(minimum: int) -> SysReqResult:
    """Run and evaluate the Linux-native vm.max_map_count check."""
    sysctl_result = _run_max_map_count_sysctl(minimum)
    if isinstance(sysctl_result, SysReqResult):
        return sysctl_result
    return _evaluate_sysctl_result(sysctl_result, minimum)


def _run_max_map_count_sysctl(minimum: int) -> subprocess.CompletedProcess | SysReqResult:
    """Run sysctl or return a not-applicable result when it is unavailable."""
    try:
        return subprocess.run(
            ["sysctl", "vm.max_map_count"],
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, OSError) as exc:
        return _not_applicable_result(minimum, str(exc))


def _evaluate_sysctl_result(
    result: subprocess.CompletedProcess,
    minimum: int,
) -> SysReqResult:
    """Translate a sysctl process result into a requirement result."""
    if result.returncode != 0:
        return _failed_sysctl_result(result.stderr, minimum)

    stdout = result.stdout.strip()
    try:
        current_value = _parse_sysctl_value(stdout)
    except ValueError as exc:
        log.error("Failed to parse sysctl output '%s': %s", stdout, exc)
        return SysReqResult(
            passed=False,
            current_value=0,
            required_value=minimum,
            error=f"Failed to parse sysctl output: {stdout}",
        )
    return _max_map_count_result(current_value, minimum)


def _failed_sysctl_result(stderr: str, minimum: int) -> SysReqResult:
    """Return a failed or not-applicable result for nonzero sysctl output."""
    error_msg = stderr.strip() or "sysctl command failed"
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


def _parse_sysctl_value(stdout: str) -> int:
    """Extract the integer value from ``sysctl vm.max_map_count`` output."""
    # Parse output: "vm.max_map_count = 262144"
    parts = stdout.split("=")
    if len(parts) != 2:
        raise ValueError(f"Unexpected format: {stdout}")
    return int(parts[1].strip())


def _max_map_count_result(current_value: int, minimum: int) -> SysReqResult:
    """Build the final result for a parsed vm.max_map_count value."""
    passed = current_value >= minimum
    if passed:
        log.info("vm.max_map_count is adequate (%d >= %d)", current_value, minimum)
    else:
        log.warning("vm.max_map_count is too low (%d < %d)", current_value, minimum)

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
