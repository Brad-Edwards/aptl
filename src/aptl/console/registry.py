"""Discovery and role-tagging of the lab's MCP servers.

The console does not invent its own server list — it reads ``.mcp.json``
(the same file an external AI client would use) and decorates each entry
with a red/blue/purple role and an availability check. Operators can
override the auto-assigned role with an ``"aptlRole"`` key on any server
entry in ``.mcp.json``.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Optional

from aptl.console.models import McpServerSpec, Role
from aptl.utils.logging import get_logger

log = get_logger("console.registry")

# Default role for a server, keyed by a substring of its configured name.
# Order matters: the first matching substring wins. Anything unmatched is
# NEUTRAL (usable by any side). Overridable per-entry via "aptlRole".
_ROLE_HINTS: tuple[tuple[str, Role], ...] = (
    ("kali", Role.RED),
    ("red", Role.RED),
    ("reverse", Role.PURPLE),
    ("network", Role.NEUTRAL),
    ("wazuh", Role.BLUE),
    ("indexer", Role.BLUE),
    ("shuffle", Role.BLUE),
    ("soar", Role.BLUE),
    ("misp", Role.BLUE),
    ("threatintel", Role.BLUE),
    ("thehive", Role.BLUE),
    ("casemgmt", Role.BLUE),
)

_DESCRIPTIONS: tuple[tuple[str, str], ...] = (
    ("kali", "Kali red-team box: run offensive tooling over SSH"),
    ("reverse", "Malware-analysis sandbox for reverse engineering"),
    ("network", "Network topology and connectivity inspection"),
    ("wazuh", "Wazuh SIEM: query alerts and agent telemetry"),
    ("indexer", "Wazuh indexer: raw OpenSearch log queries"),
    ("shuffle", "Shuffle SOAR: inspect and trigger playbooks"),
    ("soar", "SOAR: inspect and trigger playbooks"),
    ("misp", "MISP threat intelligence"),
    ("threatintel", "Threat-intelligence lookups"),
    ("thehive", "TheHive case management"),
    ("casemgmt", "Case management"),
)


def _classify(name: str) -> Role:
    lowered = name.lower()
    for hint, role in _ROLE_HINTS:
        if hint in lowered:
            return role
    return Role.NEUTRAL


def _describe(name: str) -> str:
    lowered = name.lower()
    for hint, desc in _DESCRIPTIONS:
        if hint in lowered:
            return desc
    return "MCP server"


def _resolve_command(command: str, project_dir: Path) -> Optional[Path]:
    """Resolve an MCP launch command to an existing path, or None.

    Handles three shapes seen in ``.mcp.json``: an absolute/relative path
    (``./tools/bin/foo``), a bare interpreter on PATH (``node``, ``python``),
    and a project-relative binary.
    """
    if not command:
        return None
    if command.startswith(("./", "../", "/")) or "/" in command:
        candidate = (project_dir / command).resolve() if not command.startswith("/") else Path(command)
        return candidate if candidate.exists() else None
    found = shutil.which(command)
    return Path(found) if found else None


def _entrypoint_exists(args: list[str], project_dir: Path) -> bool:
    """If the first arg looks like a script path, require it to exist."""
    for arg in args:
        if arg.startswith("-"):
            continue
        if arg.endswith((".js", ".py", ".mjs", ".cjs")) or arg.startswith(("./", "../")):
            path = (project_dir / arg).resolve() if not arg.startswith("/") else Path(arg)
            return path.exists()
        # First positional arg that is not obviously a script: stop checking.
        return True
    return True


def _availability(command: str, args: list[str], project_dir: Path) -> tuple[bool, str]:
    resolved = _resolve_command(command, project_dir)
    if resolved is None:
        return False, f"launch command not found: {command or '(empty)'}"
    if not _entrypoint_exists(args, project_dir):
        return False, "entrypoint missing — build the MCP servers (./mcp/build-all-mcps.sh)"
    return True, ""


class McpRegistry:
    """An immutable snapshot of the discovered MCP servers."""

    def __init__(self, servers: list[McpServerSpec]) -> None:
        self._servers = servers
        self._by_name = {s.name: s for s in servers}

    @property
    def servers(self) -> list[McpServerSpec]:
        return list(self._servers)

    def get(self, name: str) -> Optional[McpServerSpec]:
        return self._by_name.get(name)

    def names(self) -> list[str]:
        return [s.name for s in self._servers]

    def default_for_role(self, role: Role) -> list[str]:
        """The MCP servers a fresh session of ``role`` should start with.

        Red gets red + neutral, blue gets blue + neutral, purple gets
        everything, neutral gets only neutral. Unavailable servers are
        still offered (so the operator sees them) — availability is a
        runtime concern, not a selection one.
        """
        if role is Role.PURPLE:
            return self.names()
        wanted: set[Role] = {Role.NEUTRAL}
        if role in (Role.RED, Role.BLUE):
            wanted.add(role)
        return [s.name for s in self._servers if s.role in wanted]


def _config_path(project_dir: Path) -> Optional[Path]:
    """Locate the MCP config: APTL_MCP_CONFIG, then .mcp.json, then example."""
    override = os.environ.get("APTL_MCP_CONFIG")
    if override:
        p = Path(override)
        return p if p.exists() else None
    for name in (".mcp.json", ".mcp.json.example"):
        candidate = project_dir / name
        if candidate.exists():
            return candidate
    return None


def load_registry(project_dir: Path) -> McpRegistry:
    """Build the MCP registry for ``project_dir``.

    Never raises on a malformed or missing config — an empty registry is a
    valid (if unhelpful) state, and the UI surfaces it.
    """
    path = _config_path(project_dir)
    if path is None:
        log.warning("No MCP config found under %s", project_dir)
        return McpRegistry([])

    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Failed to read MCP config %s: %s", path, exc)
        return McpRegistry([])

    entries = raw.get("mcpServers", {})
    servers: list[McpServerSpec] = []
    for name, entry in sorted(entries.items()):
        if not isinstance(entry, dict):
            continue
        command = str(entry.get("command", ""))
        args = [str(a) for a in entry.get("args", [])]
        env = {str(k): str(v) for k, v in (entry.get("env") or {}).items()}
        role_override = entry.get("aptlRole")
        role = _classify(name)
        if isinstance(role_override, str):
            try:
                role = Role(role_override.lower())
            except ValueError:
                log.warning("Ignoring invalid aptlRole %r on %s", role_override, name)
        available, reason = _availability(command, args, project_dir)
        servers.append(
            McpServerSpec(
                name=name,
                role=role,
                command=command,
                args=args,
                env=env,
                description=str(entry.get("aptlDescription", _describe(name))),
                available=available,
                unavailable_reason=reason,
            )
        )
    log.info("Loaded %d MCP servers from %s", len(servers), path)
    return McpRegistry(servers)
