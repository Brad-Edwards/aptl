"""Config file credential syncing.

Replaces placeholder credentials in Wazuh configuration files with
real values from the .env file.

The two functions own construction of their canonical project-relative
target paths and validate containment against the resolved project
root before any I/O. Symlinks under the canonical location pointing
outside the project are rejected. See ADR-007's "Security Guardrail:
Project-Rooted Credential Writes" section for the architectural
rationale (issue #266).
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

# Canonical project-relative target paths. Hardcoded so the writer
# owns the path-construction boundary; callers pass only the trusted
# project root.
_DASHBOARD_RELPATH = Path("config/wazuh_dashboard/wazuh.yml")
_MANAGER_RELPATH = Path("config/wazuh_cluster/wazuh_manager.conf")


def _resolve_within_project(
    project_dir: Path, relative_path: Path,
) -> Path:
    """Resolve ``project_dir / relative_path`` and assert containment.

    Both sides are resolved (symlinks followed) before the
    ``is_relative_to`` check so a symlink under the canonical relative
    location cannot escape the project root.

    Raises:
        ValueError: if the resolved target is not contained under the
            resolved project root.
    """
    project_root = project_dir.resolve()
    target = (project_dir / relative_path).resolve()
    if not target.is_relative_to(project_root):
        raise ValueError(
            f"Resolved config path {target} escapes project root"
            f" {project_root}; refusing to read or write."
        )
    return target


def sync_dashboard_config(project_dir: Path, api_password: str) -> None:
    """Replace the API password in the Wazuh Dashboard config (wazuh.yml).

    Finds lines matching ``password: "..."`` and replaces the quoted
    value with the provided password. The target is always
    ``<project_dir>/config/wazuh_dashboard/wazuh.yml``; the caller does
    not pass the file path.

    Args:
        project_dir: APTL project root.
        api_password: The real API password to inject.

    Raises:
        ValueError: If the resolved target escapes the project root
            (e.g., a symlink at the canonical location pointing
            outside ``project_dir``).
        FileNotFoundError: If the canonical config file does not exist.
    """
    config_path = _resolve_within_project(project_dir, _DASHBOARD_RELPATH)
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


def sync_manager_config(project_dir: Path, cluster_key: str) -> None:
    """Replace the cluster key in the Wazuh Manager config.

    Finds ``<key>...</key>`` elements inside ``<cluster>`` blocks and
    replaces their content with the provided cluster key. The target is
    always ``<project_dir>/config/wazuh_cluster/wazuh_manager.conf``;
    the caller does not pass the file path.

    Args:
        project_dir: APTL project root.
        cluster_key: The real cluster key to inject.

    Raises:
        ValueError: If the resolved target escapes the project root.
        FileNotFoundError: If the canonical config file does not exist.
    """
    config_path = _resolve_within_project(project_dir, _MANAGER_RELPATH)
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
            lambda _, _safe_key=safe_key: f"<key>{_safe_key}</key>", block
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
