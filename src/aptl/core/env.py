"""Environment variable loading and validation.

Parses .env files and builds typed EnvVars for use throughout the startup
process. Does not use python-dotenv; the format is simple enough to parse
directly.
"""

from dataclasses import dataclass
from pathlib import Path

from aptl.utils.logging import get_logger

log = get_logger("env")

_REQUIRED_VARS = [
    "INDEXER_USERNAME",
    "INDEXER_PASSWORD",
    "API_USERNAME",
    "API_PASSWORD",
]


@dataclass
class EnvVars:
    """Typed container for environment variables loaded from .env."""

    indexer_username: str
    indexer_password: str
    api_username: str
    api_password: str
    dashboard_username: str = "kibanaserver"
    dashboard_password: str = ""
    wazuh_cluster_key: str = ""


def load_dotenv(path: Path) -> dict[str, str]:
    """Parse KEY=VALUE lines from a .env file.

    Skips comments (lines starting with #), blank lines, and lines
    without an = sign.  Strips optional 'export' prefix, whitespace,
    and surrounding quotes (single or double) from values.

    Args:
        path: Path to the .env file.

    Returns:
        Dictionary mapping variable names to string values.

    Raises:
        FileNotFoundError: If the .env file does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f".env file not found: {path}")

    result: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()

        # Skip blanks and comments
        if not line or line.startswith("#"):
            continue

        # Skip lines without =
        if "=" not in line:
            log.debug("Skipping line without '=': %s", line)
            continue

        # Strip optional 'export ' prefix
        if line.startswith("export "):
            line = line[len("export "):]

        # Split on first = only (values can contain =)
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        # Strip surrounding quotes
        if len(value) >= 2:
            if (value[0] == '"' and value[-1] == '"') or (
                value[0] == "'" and value[-1] == "'"
            ):
                value = value[1:-1]

        result[key] = value

    log.debug("Loaded %d variables from %s", len(result), path)
    return result


def validate_required_env(
    env: dict[str, str], required: list[str]
) -> list[str]:
    """Check that all required variables are present and non-empty.

    Args:
        env: Dictionary of environment variables.
        required: List of variable names that must be present and non-empty.

    Returns:
        List of variable names that are missing or empty. Empty list means
        all requirements are satisfied.
    """
    missing = []
    for var in required:
        if var not in env or not env[var]:
            missing.append(var)
    return missing


def env_vars_from_dict(env: dict[str, str]) -> EnvVars:
    """Build a typed EnvVars instance from a raw env dict.

    Validates that all required variables are present and non-empty before
    constructing the dataclass.

    Args:
        env: Dictionary of environment variables (from load_dotenv).

    Returns:
        Populated EnvVars instance.

    Raises:
        ValueError: If any required variable is missing or empty.
    """
    missing = validate_required_env(env, _REQUIRED_VARS)
    if missing:
        raise ValueError(
            f"Required environment variables missing or empty: {', '.join(missing)}"
        )

    return EnvVars(
        indexer_username=env["INDEXER_USERNAME"],
        indexer_password=env["INDEXER_PASSWORD"],
        api_username=env["API_USERNAME"],
        api_password=env["API_PASSWORD"],
        dashboard_username=env.get("DASHBOARD_USERNAME", "kibanaserver"),
        dashboard_password=env.get("DASHBOARD_PASSWORD", ""),
        wazuh_cluster_key=env.get("WAZUH_CLUSTER_KEY", ""),
    )
