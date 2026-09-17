"""Native project client serializers with conservative managed-entry updates."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from aptl.workbench.access import CallerGrant, SeatAccessRecord, authorize_server
from aptl.workbench.profiles import WorkbenchConfigurationError, profile_for

MANAGED_CONFLICT = "managed client configuration conflict"

_BEGIN = "# BEGIN APTL MANAGED MCP\n"
_END = "# END APTL MANAGED MCP\n"


def client_entries(
    record: SeatAccessRecord,
    grant: CallerGrant,
    *,
    ssh_executable: Path,
    identity_file: Path,
    known_hosts: Path,
    username: str,
) -> dict[str, dict[str, object]]:
    """Render fixed SSH argv; no service secrets or provider state cross the guest."""
    paths = (ssh_executable, identity_file, known_hosts)
    if any(
        not path.is_absolute() or any(c in str(path) for c in "\r\n\0")
        for path in paths
    ):
        raise WorkbenchConfigurationError("transport paths must be absolute")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise WorkbenchConfigurationError("invalid transport account")
    endpoint = record.outer_endpoint
    args = [
        "-F",
        "/dev/null",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "UserKnownHostsFile=" + json.dumps(str(known_hosts)),
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-i",
        str(identity_file),
        "-p",
        str(endpoint.port),
        "-l",
        username,
        endpoint.address,
    ]
    entries = {}
    for server in profile_for(grant.profile).servers:
        authorize_server(record, grant, server.server_id)
        selector = (
            f"aptl-mcp-v1 {record.instance_id} {record.generation} {server.server_id}"
        )
        name = f"aptl-{record.seat_id}-{server.server_id.removeprefix('aptl-')}"
        entries[name] = {"command": str(ssh_executable), "args": [*args, selector]}
    return entries


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, Any]:
    """Reject duplicate JSON object keys before merging client configuration."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise WorkbenchConfigurationError("duplicate client configuration key")
        result[key] = value
    return result


def _check_ownership(
    servers: dict[str, Any], entries: dict[str, Any], previous: dict[str, Any]
) -> None:
    """Reject edits to managed entries and collisions with manual entries."""
    if any(servers.get(name) != value for name, value in previous.items()):
        raise WorkbenchConfigurationError(MANAGED_CONFLICT)
    if (entries.keys() & servers.keys()) - previous.keys():
        raise WorkbenchConfigurationError("manual client configuration conflict")


def render_claude(
    existing: str, entries: dict[str, Any], *, previous: dict[str, Any] | None = None
) -> str:
    """Preserve all manual values and refuse modified previously managed entries."""
    document = json.loads(existing or "{}", object_pairs_hook=_unique_object)
    if not isinstance(document, dict) or not isinstance(
        document.get("mcpServers", {}), dict
    ):
        raise WorkbenchConfigurationError("invalid Claude client configuration")
    servers = document.setdefault("mcpServers", {})
    owned = previous or {}
    _check_ownership(servers, entries, owned)
    for name in owned:
        del servers[name]
    servers.update(entries)
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _toml_block(entries: dict[str, Any]) -> str:
    """Render the uniquely delimited managed MCP section."""
    lines = [_BEGIN.rstrip()]
    for name, value in sorted(entries.items()):
        lines.extend(
            [
                f"[mcp_servers.{json.dumps(name)}]",
                "command = " + json.dumps(value["command"]),
                "args = " + json.dumps(value["args"]),
                "startup_timeout_sec = 120",
                "tool_timeout_sec = 180",
                "",
            ]
        )
    return "\n".join(lines) + _END


def render_codex(
    existing: str, entries: dict[str, Any], *, previous: dict[str, Any] | None = None
) -> str:
    """Retain user TOML bytes; replace only the exact owned block at EOF."""
    document = tomllib.loads(existing)
    servers = document.get("mcp_servers", {})
    if not isinstance(servers, dict):
        raise WorkbenchConfigurationError("invalid Codex client configuration")
    owned = previous or {}
    normalized = {
        name: {**value, "startup_timeout_sec": 120, "tool_timeout_sec": 180}
        for name, value in owned.items()
    }
    _check_ownership(servers, entries, normalized)
    if owned:
        block = _toml_block(owned)
        if not existing.endswith(block) or existing.count(_BEGIN) != 1:
            raise WorkbenchConfigurationError(MANAGED_CONFLICT)
        existing = existing[: -len(block)]
    elif _BEGIN in existing or _END in existing:
        raise WorkbenchConfigurationError(MANAGED_CONFLICT)
    result = (
        existing
        + ("\n" if existing and not existing.endswith("\n") else "")
        + _toml_block(entries)
    )
    # Inline-table or dotted-key collisions must fail before publication.
    tomllib.loads(result)
    return result
