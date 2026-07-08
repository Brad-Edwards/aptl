"""Environment variable loading and validation.

Parses .env files and builds typed EnvVars for use throughout the startup
process. Does not use python-dotenv; the format is simple enough to parse
directly.
"""

import os
import secrets
import string
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from aptl.utils.logging import get_logger
from aptl.utils.placeholders import contains_placeholder

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


@dataclass(frozen=True)
class DotenvHydrationResult:
    """Result of ensuring a project ``.env`` has runnable lab credentials."""

    path: Path
    created: bool
    updated_keys: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        """Return True when the file was created or any value was updated."""
        return self.created or bool(self.updated_keys)


_ALNUM = string.ascii_letters + string.digits
_EXPORT_PREFIX = "export "
_WAZUH_FILEBEAT_TEMPLATE = Path("config/wazuh_cluster/filebeat_wazuh_module.yml")
_WAZUH_DASHBOARD_TEMPLATE = Path("config/wazuh_dashboard/wazuh.yml")


def _random_alnum(length: int) -> str:
    """Return a random ASCII alphanumeric token."""
    return "".join(secrets.choice(_ALNUM) for _ in range(length))


def _fixed(value: str) -> Callable[[Path, dict[str, str]], str]:
    """Wrap a fixed non-secret lab default for hydration specs."""
    return lambda _project_dir, _values: value


def _copy_value(source_key: str) -> Callable[[Path, dict[str, str]], str]:
    """Return a resolver that mirrors another hydrated env value."""
    return lambda _project_dir, values: values[source_key]


def _read_yaml_mapping(path: Path) -> dict[str, object]:
    """Read a YAML file that must contain a mapping at the document root."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping in {path}")
    return data


def _required_template_value(path: Path, key: str, value: object) -> str:
    """Return a template value or fail if it cannot safely hydrate .env."""
    if not isinstance(value, str) or _needs_hydration(value):
        raise ValueError(f"{path} does not define a usable {key}")
    return value


def _wazuh_indexer_template_value(
    project_dir: Path,
    key: str,
) -> str:
    """Read Wazuh indexer credentials from the checked-in Filebeat template."""
    path = project_dir / _WAZUH_FILEBEAT_TEMPLATE
    output = _read_yaml_mapping(path).get("output.elasticsearch")
    if not isinstance(output, dict):
        raise ValueError(f"{path} does not define output.elasticsearch")
    return _required_template_value(path, key, output.get(key))


def _wazuh_api_template_value(
    project_dir: Path,
    key: str,
) -> str:
    """Read Wazuh API credentials from the checked-in dashboard template."""
    path = project_dir / _WAZUH_DASHBOARD_TEMPLATE
    hosts = _read_yaml_mapping(path).get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise ValueError(f"{path} does not define hosts")
    first_host = hosts[0]
    if not isinstance(first_host, dict) or not first_host:
        raise ValueError(f"{path} does not define a usable host")
    host_config = next(iter(first_host.values()))
    if not isinstance(host_config, dict):
        raise ValueError(f"{path} does not define a usable host config")
    return _required_template_value(path, key, host_config.get(key))


def _indexer_template_value(key: str) -> Callable[[Path, dict[str, str]], str]:
    """Return a resolver for a Filebeat Wazuh indexer template field."""
    return lambda project_dir, _values: _wazuh_indexer_template_value(project_dir, key)


def _api_template_value(key: str) -> Callable[[Path, dict[str, str]], str]:
    """Return a resolver for a Wazuh dashboard API template field."""
    return lambda project_dir, _values: _wazuh_api_template_value(project_dir, key)


# The current stack still has a mix of .env-driven values and service
# fixtures baked into checked-in templates or Compose. Hydration therefore
# writes values that are actually accepted by the running containers today:
# randomize values Compose consumes directly, keep fixed values where the
# service still has a checked-in hash/default that must match.
_HYDRATED_ENV_SPECS: tuple[
    tuple[str, Callable[[Path, dict[str, str]], str]], ...
] = (
    ("INDEXER_USERNAME", _indexer_template_value("username")),
    ("INDEXER_PASSWORD", _indexer_template_value("password")),
    ("DASHBOARD_USERNAME", _fixed("kibanaserver")),
    ("DASHBOARD_PASSWORD", _copy_value("DASHBOARD_USERNAME")),
    ("API_USERNAME", _api_template_value("username")),
    ("API_PASSWORD", _api_template_value("password")),
    ("WAZUH_CLUSTER_KEY", lambda _project_dir, _values: secrets.token_hex(16)),
    ("APTL_API_TOKEN", lambda _project_dir, _values: secrets.token_hex(32)),
    ("MISP_API_KEY", lambda _project_dir, _values: _random_alnum(40)),
    ("GRAFANA_ADMIN_USER", _fixed("admin")),
    ("GRAFANA_ADMIN_PASSWORD", lambda _project_dir, _values: secrets.token_urlsafe(24)),
)


def _needs_hydration(value: str | None) -> bool:
    """Return True for missing, empty, or template placeholder values."""
    return not value or contains_placeholder(value)


def _line_key(line: str) -> str | None:
    """Return the env key represented by a line, if the line assigns one."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    if stripped.startswith(_EXPORT_PREFIX):
        stripped = stripped[len(_EXPORT_PREFIX):]
    key, _, _ = stripped.partition("=")
    return key.strip() or None


def _parse_dotenv_assignment(line: str) -> tuple[str, str] | None:
    """Parse one dotenv assignment line."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if "=" not in stripped:
        log.debug("Skipping line without '=': %s", stripped)
        return None
    if stripped.startswith(_EXPORT_PREFIX):
        stripped = stripped[len(_EXPORT_PREFIX):]

    key, _, value = stripped.partition("=")
    return key.strip(), _unquote_dotenv_value(value.strip())


def _unquote_dotenv_value(value: str) -> str:
    """Strip matching single or double quotes around a dotenv value."""
    if len(value) < 2:
        return value
    if value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _assignment(key: str, value: str) -> str:
    """Render a simple KEY=VALUE assignment for generated credentials."""
    return f"{key}={value}"


def _render_hydrated_dotenv(
    original: str,
    values: dict[str, str],
) -> str:
    """Render updated dotenv content, preserving unrelated existing lines."""
    seen: set[str] = set()
    lines: list[str] = []
    for line in original.splitlines():
        key = _line_key(line)
        if key in values:
            lines.append(_assignment(key, values[key]))
            seen.add(key)
        else:
            lines.append(line)

    missing = [key for key, _ in _HYDRATED_ENV_SPECS if key not in seen]
    if missing:
        if lines and lines[-1].strip():
            lines.append("")
        if lines:
            lines.append("# Added by aptl lab start credential hydration.")
        else:
            lines.extend([
                "# APTL Lab Credentials",
                "# Generated by aptl lab start. This file is gitignored.",
                "",
            ])
        lines.extend(_assignment(key, values[key]) for key in missing)
    return "\n".join(lines) + "\n"


def _write_dotenv(path: Path, content: str) -> None:
    """Atomically write a generated dotenv file with owner-only mode."""
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as tmp:
            tmp.write(content)
        os.replace(tmp_path, path)
        if os.name == "posix":
            path.chmod(0o600)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def hydrate_dotenv(path: Path) -> DotenvHydrationResult:
    """Create or repair a project ``.env`` with runnable lab credentials.

    Existing non-placeholder values are preserved. Missing, empty, or
    ``.env.example``-style placeholders are populated with values that match
    the current Docker Compose/templates contract.
    """
    created = not path.exists()
    original = "" if created else path.read_text(encoding="utf-8")
    current = {} if created else load_dotenv(path)
    values = {key: current.get(key, "") for key, _ in _HYDRATED_ENV_SPECS}
    updated: list[str] = []

    for key, factory in _HYDRATED_ENV_SPECS:
        if _needs_hydration(current.get(key)):
            values[key] = factory(path.parent, values)
            updated.append(key)

    if created or updated:
        _write_dotenv(path, _render_hydrated_dotenv(original, values))
    return DotenvHydrationResult(
        path=path,
        created=created,
        updated_keys=tuple(updated),
    )


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
        assignment = _parse_dotenv_assignment(line)
        if assignment is not None:
            key, value = assignment
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


# Variables that, if present in .env, must not be the example placeholder.
# Two reasons a var lands here:
#   - Consumers (MISP server, MCPs, sync service) accept the value without
#     their own placeholder check, so a fall-through would run the lab with
#     the documented placeholder as a real credential.
#   - The value is rendered verbatim into a generated service config file at
#     `aptl lab start` (ADR-028): `API_PASSWORD` → the Wazuh Dashboard
#     `wazuh.yml`, `WAZUH_CLUSTER_KEY` → `wazuh_manager.conf`'s `<cluster>`
#     block. ADR-028 requires every value rendered from `.env` to go through
#     this check, so a fresh `.env` copied from `.env.example` fails before
#     any placeholder secret reaches a generated file.
# `WAZUH_CLUSTER_KEY` is optional; an absent/empty value is not a placeholder
# and is allowed (clustering ships disabled), only an example marker fails.
_NO_PLACEHOLDER_VARS = (
    "INDEXER_PASSWORD",
    "DASHBOARD_PASSWORD",
    "API_PASSWORD",
    "WAZUH_CLUSTER_KEY",
    "APTL_API_TOKEN",
    "MISP_API_KEY",
    "THEHIVE_SECRET",
    "SHUFFLE_API_KEY",
    "GRAFANA_ADMIN_PASSWORD",
)


def find_placeholder_env_values(env: dict[str, str]) -> list[str]:
    """Return the names of any sensitive vars whose value is a placeholder.

    Returns an empty list when every sensitive var in ``env`` carries a
    real-looking value or is absent. Caller decides whether to fail
    closed; this function never raises. Marker definitions live in
    :mod:`aptl.utils.placeholders` so every layer rejects the same set.
    """
    return [
        var for var in _NO_PLACEHOLDER_VARS
        if contains_placeholder(env.get(var))
    ]


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
