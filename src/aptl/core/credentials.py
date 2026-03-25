"""Config file credential syncing.

Replaces placeholder credentials in Wazuh configuration files with
real values from the .env file.
"""

import re
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from aptl.utils.logging import get_logger

log = get_logger("credentials")

# Matches: password: "anything" (with optional surrounding whitespace)
_PASSWORD_PATTERN = re.compile(r'(password:\s*)"[^"]*"')

# Matches: <key>anything</key> (used only within pre-extracted <cluster> blocks)
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

    # Escape characters that would break YAML double-quoted strings.
    safe_pw = api_password.replace("\\", "\\\\").replace('"', '\\"')
    new_content, count = _PASSWORD_PATTERN.subn(
        lambda m: f'{m.group(1)}"{safe_pw}"', content
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

    # Find <cluster> blocks by string search (O(n), no backtracking),
    # then replace <key> only within each block.
    count = 0
    result: list[str] = []
    pos = 0
    while True:
        block_start = content.find("<cluster>", pos)
        if block_start == -1:
            result.append(content[pos:])
            break
        block_end = content.find("</cluster>", block_start)
        if block_end == -1:
            result.append(content[pos:])
            break
        block_end += len("</cluster>")
        # Append everything before this block unchanged
        result.append(content[pos:block_start])
        # Replace <key> only within this <cluster> block
        block = content[block_start:block_end]
        safe_key = xml_escape(cluster_key)
        new_block, n = _KEY_PATTERN.subn(
            lambda _: f"<key>{safe_key}</key>", block
        )
        count += n
        result.append(new_block)
        pos = block_end

    new_content = "".join(result)

    if count == 0:
        log.warning(
            "No <cluster><key> pattern found in %s; file left unchanged",
            config_path,
        )
    else:
        log.info(
            "Replaced %d cluster <key> occurrence(s) in %s", count, config_path
        )

    config_path.write_text(new_content)
