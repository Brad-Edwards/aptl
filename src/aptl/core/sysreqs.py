"""System requirements checking.

Validates that the host system meets the prerequisites for running the
APTL lab (e.g., vm.max_map_count for OpenSearch/Wazuh Indexer).
"""

import subprocess
from dataclasses import dataclass

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
    try:
        result = subprocess.run(
            ["sysctl", "vm.max_map_count"],
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, OSError) as exc:
        log.error("Failed to run sysctl: %s", exc)
        return SysReqResult(
            passed=False,
            current_value=0,
            required_value=minimum,
            error=str(exc),
        )

    if result.returncode != 0:
        error_msg = result.stderr.strip() or "sysctl command failed"
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
