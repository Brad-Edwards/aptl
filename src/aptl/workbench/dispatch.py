"""Restricted SSH policy and the guest-side MCP admission state machine."""

from __future__ import annotations

import base64
import hashlib
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from aptl.workbench.profiles import ServerProfile, WorkbenchConfigurationError

_SELECTOR = re.compile(
    r"aptl-mcp-v1 ([a-z0-9][a-z0-9._-]{0,63}) ([1-9]\d{0,9}) (aptl-[a-z]+)", re.ASCII
)


@dataclass(frozen=True)
class DispatchSelector:
    """The complete participant-controlled forced-command selector."""

    instance_id: str
    generation: int
    server_id: str

    @classmethod
    def parse(cls, command: str) -> DispatchSelector:
        """Parse the bounded forced-command selector without shell interpretation."""
        match = _SELECTOR.fullmatch(command)
        if match is None:
            raise WorkbenchConfigurationError("invalid MCP transport selector")
        return cls(match[1], int(match[2]), match[3])


class ProtocolAdmission:
    """Allow only initialized calls to one canonical server's exact tool set."""

    def __init__(self, server: ServerProfile) -> None:
        self.server = server
        self.initialized = False
        self.inventory_admitted = False

    def admit_inventory(self, result: dict[str, Any]) -> None:
        """Require the backend to expose exactly the canonical tool inventory."""
        tools = result.get("tools")
        if not isinstance(tools, list) or any(
            not isinstance(tool, dict) for tool in tools
        ):
            raise WorkbenchConfigurationError("invalid MCP tool inventory")
        names = [tool.get("name") for tool in tools]
        if (
            len(names) != len(self.server.tool_names)
            or any(not isinstance(name, str) for name in names)
            or set(names) != set(self.server.tool_names)
        ):
            raise WorkbenchConfigurationError("MCP tool inventory changed")
        self.inventory_admitted = True

    def request(self, value: dict[str, Any]) -> None:
        """Validate an initialized request against the admitted protocol surface."""
        method, params = _request_fields(value)
        if method == "initialize":
            if self.initialized or "id" not in value:
                raise WorkbenchConfigurationError("MCP already initialized")
            self.initialized = True
            return
        if not self.initialized or not self.inventory_admitted:
            raise WorkbenchConfigurationError("MCP inventory has not been admitted")
        if method == "tools/call":
            self._tool_call(params)
        elif method not in {
            "tools/list",
            "ping",
            "notifications/initialized",
            "notifications/cancelled",
        }:
            raise WorkbenchConfigurationError("MCP method is not authorized")
        if not str(method).startswith("notifications/") and "id" not in value:
            raise WorkbenchConfigurationError("MCP request ID required")

    def _tool_call(self, params: dict[str, Any]) -> None:
        """Restrict tool invocation to canonical names and supported arguments."""
        if (
            params.get("name") not in self.server.tool_names
            or not isinstance(params.get("arguments", {}), dict)
            or set(params) - {"name", "arguments", "_meta"}
        ):
            raise WorkbenchConfigurationError("MCP tool call is not authorized")


def _policy_path(path: Path) -> str:
    # The policy is executed by sshd and /bin/sh, so keep its management paths
    # literal and narrowly representable. This is not a participant path API.
    """Require literal absolute management paths safe for the SSH policy."""
    value = str(path)
    if not path.is_absolute() or not re.fullmatch(r"/[A-Za-z0-9/_.-]+", value):
        raise WorkbenchConfigurationError("invalid transport management path")
    return value


def sshd_policy(
    *,
    port: int,
    username: str,
    host_key: Path,
    authorized_keys: Path,
    address: str = "127.0.0.1",
) -> str:
    """Policy for a dedicated /bin/sh account with management-owned home/files."""
    if not 0 < port <= 65535 or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise WorkbenchConfigurationError("invalid transport listener")
    import ipaddress

    address = str(ipaddress.ip_address(address))
    if not ipaddress.ip_address(address).is_loopback:
        raise WorkbenchConfigurationError("transport listener must be loopback")
    return "\n".join(
        [
            f"ListenAddress {address}",
            f"Port {port}",
            f"HostKey {_policy_path(host_key)}",
            f"AuthorizedKeysFile {_policy_path(authorized_keys)}",
            f"AllowUsers {username}",
            "AuthenticationMethods publickey",
            "PubkeyAuthentication yes",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "HostbasedAuthentication no",
            "UsePAM no",
            "PermitRootLogin no",
            "PermitEmptyPasswords no",
            "DisableForwarding yes",
            "AllowAgentForwarding no",
            "AllowTcpForwarding no",
            "AllowStreamLocalForwarding no",
            "X11Forwarding no",
            "PermitTunnel no",
            "PermitTTY no",
            "PermitUserRC no",
            "PermitUserEnvironment no",
            "StrictModes yes",
            "MaxSessions 1",
            "MaxStartups 8:30:16",
            "LoginGraceTime 30",
            "ClientAliveInterval 15",
            "ClientAliveCountMax 2",
            "LogLevel ERROR",
            "",
        ]
    )


def restricted_key(
    *, public_key: str, executable: Path, binding: Path, grant_id: str
) -> str:
    """Bind a transport public key to an operator-owned forced command."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", grant_id):
        raise WorkbenchConfigurationError("invalid transport grant")
    public_key = normalize_public_key(public_key)
    command = shlex.join(
        [
            _policy_path(executable),
            "mcp-access",
            "dispatch",
            "--binding",
            _policy_path(binding),
            "--grant-id",
            grant_id,
            "--key-fingerprint",
            key_fingerprint(public_key),
        ]
    )
    return f'restrict,command="{command}" {public_key}\n'


def key_fingerprint(public_key: str) -> str:
    """Compute OpenSSH's SHA256 pin from a validated Ed25519 public key."""
    public_key = normalize_public_key(public_key)
    fields = public_key.split()
    try:
        load_ssh_public_key(public_key.encode("ascii"))
        digest = hashlib.sha256(base64.b64decode(fields[1], validate=True)).digest()
    except ValueError as exc:
        raise WorkbenchConfigurationError("invalid transport public key") from exc
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def normalize_public_key(public_key: str) -> str:
    """Parse and normalize a public key without accepting key options."""
    value = public_key.strip()
    fields = value.split()
    if (
        len(value) > 4096
        or any(c in value for c in "\r\n\0")
        or len(fields) < 2
        or fields[0] != "ssh-ed25519"
    ):
        raise WorkbenchConfigurationError("one Ed25519 public key is required")
    key = " ".join(fields[:2])
    try:
        load_ssh_public_key(key.encode("ascii"))
    except ValueError as exc:
        raise WorkbenchConfigurationError("invalid transport public key") from exc
    return key


def _request_fields(value: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Validate the request envelope before advancing the admission state."""
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise WorkbenchConfigurationError("invalid MCP request")
    method = value.get("method")
    params = value.get("params", {})
    if not isinstance(params, dict) or set(value) - {
        "jsonrpc",
        "id",
        "method",
        "params",
    }:
        raise WorkbenchConfigurationError("invalid MCP request")
    return method, params
