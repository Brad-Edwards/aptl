"""Config file credential syncing.

Replaces placeholder credentials in Wazuh configuration files with
real values from the .env file. Equivalent to the sed commands in
start-lab.sh.
"""

import re
from pathlib import Path

from aptl.utils.logging import get_logger

log = get_logger("credentials")

# Matches: password: "anything" (with optional surrounding whitespace)
_PASSWORD_PATTERN = re.compile(r'(password:\s*)"[^"]*"')

# Matches: <key>anything</key>
_KEY_PATTERN = re.compile(r"<key>[^<]*</key>")


def sync_dashboard_config(config_path: Path, api_password: str) -> None:
    """Replace the API password in the Wazuh Dashboard config (wazuh.yml).

    Finds lines matching ``password: "..."`` and replaces the quoted
    value with the provided password.

    Args:
        config_path: Path to the wazuh.yml file.
        api_password: The real API password to inject.

    Raises:
        FileNotFoundError: If config_path does not exist.
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Dashboard config not found: {config_path}")

    content = config_path.read_text()

    new_content, count = _PASSWORD_PATTERN.subn(
        lambda m: f'{m.group(1)}"{api_password}"', content
    )

    if count == 0:
        log.warning(
            "No password pattern found in %s; file left unchanged", config_path
        )
    else:
        log.info("Replaced %d password occurrence(s) in %s", count, config_path)

    config_path.write_text(new_content)


def sync_manager_config(config_path: Path, cluster_key: str) -> None:
    """Replace the cluster key in the Wazuh Manager config.

    Finds ``<key>...</key>`` elements and replaces their content with
    the provided cluster key.

    Args:
        config_path: Path to the wazuh_manager.conf file.
        cluster_key: The real cluster key to inject.

    Raises:
        FileNotFoundError: If config_path does not exist.
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Manager config not found: {config_path}")

    content = config_path.read_text()

    new_content, count = _KEY_PATTERN.subn(
        lambda _: f"<key>{cluster_key}</key>", content
    )

    if count == 0:
        log.warning(
            "No <key> pattern found in %s; file left unchanged", config_path
        )
    else:
        log.info("Replaced %d <key> occurrence(s) in %s", count, config_path)

    config_path.write_text(new_content)
