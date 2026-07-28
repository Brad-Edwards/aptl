"""Bounded installed-agent and real MCP inventory adapter."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aptl.utils.placeholders import contains_placeholder
from aptl.core.config import validate_installed_participant_model_id
from aptl.workbench.decision_schema import admit_decision_response_schema
from aptl.workbench.process import (
    AgentExecutionError,
    BoundedProcessRunner,
    ProcessResult,
    ProcessRunner,
)
from aptl.workbench.runtime import AgentLaunch, DecisionAgentLaunch

__all__ = [
    "AgentExecutionError",
    "BoundedProcessRunner",
    "ClaudeCodeManagedAgentAdapter",
    "ProcessResult",
    "ProcessRunner",
    "probe_mcp_server",
]

_BASE_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
    "NO_COLOR": "1",
}
_MODEL_CREDENTIAL = "ANTHROPIC_API_KEY"
_MCP_INVENTORY_TIMEOUT_SECONDS = 10
_MAX_CONFIG_BYTES = 1_000_000
_POSIX_OWNERSHIP_REQUIRED = (
    "installed agent execution requires POSIX ownership semantics"
)
InventoryProbe = Callable[[str, str, list[str], dict[str, str]], tuple[str, ...]]


@dataclass
class _ClaudeHandle:
    """Mutable state for one admitted managed-agent launch."""

    launch: AgentLaunch
    servers: dict[str, dict[str, object]]
    environment: dict[str, str]
    config_sha256: str
    inventory: dict[str, tuple[str, ...]] = field(default_factory=dict)
    ready: bool = False
    closed: bool = False


async def _probe(
    command: str, args: list[str], environment: dict[str, str]
) -> tuple[str, ...]:
    """Probe one MCP stdio server and return its advertised tool names."""
    parameters = StdioServerParameters(command=command, args=args, env=environment)
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=_MCP_INVENTORY_TIMEOUT_SECONDS),
        ) as session:
            await session.initialize()
            result = await session.list_tools()
            return tuple(tool.name for tool in result.tools)


def probe_mcp_server(
    server_id: str,
    command: str,
    args: list[str],
    environment: dict[str, str],
) -> tuple[str, ...]:
    """Perform a real MCP initialize + tools/list exchange over stdio."""
    try:
        return asyncio.run(_probe(command, args, environment))
    except Exception as exc:
        raise AgentExecutionError(
            f"MCP inventory probe failed for {server_id}"
        ) from exc


class ClaudeCodeManagedAgentAdapter:
    """Invoke Claude Code with only one verified profile's strict MCP tools."""

    def __init__(
        self,
        *,
        claude_executable: Path,
        work_dir: Path,
        runner: ProcessRunner | None = None,
        inventory_probe: InventoryProbe = probe_mcp_server,
        timeout_seconds: float = 120.0,
        max_output_bytes: int = 1_000_000,
        max_prompt_chars: int = 16_000,
    ) -> None:
        """Initialize the admitted executable and bounded process adapter."""

        if timeout_seconds <= 0 or max_output_bytes <= 0 or max_prompt_chars <= 0:
            raise AgentExecutionError("agent limits are invalid")
        self._executable = _admitted_executable(claude_executable)
        self._work_dir = _prepare_work_dir(work_dir)
        self._runner = runner or BoundedProcessRunner()
        self._inventory_probe = inventory_probe
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes
        self._max_prompt_chars = max_prompt_chars

    @staticmethod
    def launch(launch: AgentLaunch, credentials: Mapping[str, str]) -> object:
        """Admit a generated strict config and create a minimal secret lease."""
        if isinstance(launch, DecisionAgentLaunch) and launch.provider != "claude":
            raise AgentExecutionError("agent launch provider does not match adapter")
        try:
            validate_installed_participant_model_id("claude", launch.model)
        except ValueError as exc:
            raise AgentExecutionError("agent model selection is invalid") from exc
        if isinstance(launch, DecisionAgentLaunch):
            servers: dict[str, dict[str, object]] = {}
            config_sha256 = ""
        else:
            servers, config_sha256 = _load_server_config(launch.client_config_path)
        required_aliases = _credential_aliases(servers)
        admitted = (_MODEL_CREDENTIAL, *sorted(required_aliases))
        environment = dict(_BASE_ENVIRONMENT)
        for name in admitted:
            value = credentials.get(name)
            if not value or contains_placeholder(value):
                raise AgentExecutionError("agent credential lease is incomplete")
            environment[name] = value
        return _ClaudeHandle(
            launch,
            servers,
            environment,
            config_sha256,
            ready=isinstance(launch, DecisionAgentLaunch),
        )

    def list_tools(self, handle: object) -> Mapping[str, tuple[str, ...]]:
        """Probe every selected stdio server instead of trusting the descriptor."""
        active = _require_handle(handle)
        if active.closed:
            raise AgentExecutionError("agent profile is closed")
        if isinstance(active.launch, DecisionAgentLaunch):
            active.ready = True
            return {}
        _assert_config_unchanged(active)
        inventory: dict[str, tuple[str, ...]] = {}
        for server_id, server in active.servers.items():
            environment = _server_environment(server, active.environment)
            inventory[server_id] = self._inventory_probe(
                server_id,
                str(server["command"]),
                list(server["args"]),
                environment,
            )
        active.inventory = inventory
        active.ready = True
        return inventory

    def respond(
        self,
        handle: object,
        message: str,
        *,
        response_schema: Mapping[str, object] | None = None,
    ) -> str:
        """Run one bounded non-persistent agent request with prompt on stdin."""
        active = _require_handle(handle)
        if active.closed or not active.ready:
            raise AgentExecutionError("agent profile is not ready")
        _assert_config_unchanged(active)
        schema_json = admit_decision_response_schema(
            active.launch,
            response_schema,
        )
        if not message or len(message) > self._max_prompt_chars:
            raise AgentExecutionError(
                "participant message exceeds the configured limit"
            )
        result = self._runner.run(
            self._argv(self._executable, active, schema_json),
            env=dict(active.environment),
            cwd=self._work_dir,
            stdin=message.encode(),
            timeout_seconds=self._timeout_seconds,
            max_output_bytes=self._max_output_bytes,
        )
        if result.returncode != 0:
            raise AgentExecutionError("agent request failed")
        return _parse_agent_result(result.stdout)

    @staticmethod
    def close(handle: object) -> None:
        """Invalidate the selected environment after one-shot children exit."""
        active = _require_handle(handle)
        active.environment.clear()
        active.inventory.clear()
        active.ready = False
        active.closed = True

    @staticmethod
    def _argv(
        executable: Path,
        handle: _ClaudeHandle,
        response_schema_json: str | None,
    ) -> tuple[str, ...]:
        """Build the strict Claude Code invocation for an admitted profile."""

        base = (
            str(executable),
            "--print",
            "--bare",
            "--disable-slash-commands",
            "--no-chrome",
            "--no-session-persistence",
            "--output-format",
            "json",
            "--max-budget-usd",
            "1.00",
            "--permission-mode",
            "dontAsk",
            "--tools",
            "",
        )
        if isinstance(handle.launch, DecisionAgentLaunch):
            if response_schema_json is None:
                raise AgentExecutionError("agent response schema is required")
            return (
                *base,
                "--model",
                handle.launch.model,
                "--json-schema",
                response_schema_json,
            )
        allowed = ",".join(
            f"mcp__{server_id}__{tool}"
            for server_id, tools in handle.inventory.items()
            for tool in tools
        )
        return (
            *base,
            "--model",
            handle.launch.model,
            "--allowedTools",
            allowed,
            "--mcp-config",
            str(handle.launch.client_config_path),
            "--strict-mcp-config",
        )


def _admitted_executable(path: Path) -> Path:
    """Resolve and validate a trusted installed-agent executable."""
    if not hasattr(os, "getuid"):
        raise AgentExecutionError(_POSIX_OWNERSHIP_REQUIRED)
    if not path.is_absolute():
        raise AgentExecutionError("agent executable must be absolute")
    resolved = path.resolve(strict=True)
    file_stat = resolved.stat()
    if (
        not resolved.is_file()
        or not os.access(resolved, os.X_OK)
        or file_stat.st_uid not in {0, os.getuid()}
        or file_stat.st_mode & 0o002
        or (
            file_stat.st_mode & 0o020
            and not _group_is_private_to_current_user(file_stat.st_gid)
        )
    ):
        raise AgentExecutionError("agent executable is not admissible")
    return resolved


def _group_is_private_to_current_user(group_id: int) -> bool:
    """Whether a writable executable group contains no other principals."""

    try:
        import grp
        import pwd

        current_user = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(group_id)
        primary_group_users = {
            entry.pw_name for entry in pwd.getpwall() if entry.pw_gid == group_id
        }
    except (KeyError, OSError):
        return False
    group_users = {*group.gr_mem, *primary_group_users}
    return group_users <= {current_user}


def _prepare_work_dir(path: Path) -> Path:
    """Create and validate the private managed-agent work directory."""
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise AgentExecutionError("agent work directory is unavailable") from exc
    _require_private_directory(parent)
    resolved = path.resolve()
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise AgentExecutionError("agent work directory is unavailable") from exc
    _require_private_directory(path)
    return resolved


def _require_private_directory(path: Path) -> None:
    """Reject a directory that is not private and owned by this process."""
    if not hasattr(os, "getuid"):
        raise AgentExecutionError(_POSIX_OWNERSHIP_REQUIRED)
    stat = path.stat()
    if (
        path.is_symlink()
        or not path.is_dir()
        or stat.st_uid not in {0, os.getuid()}
        or stat.st_mode & 0o022
        or not os.access(path, os.W_OK | os.X_OK)
    ):
        raise AgentExecutionError("agent work directory is not admissible")


def _load_server_config(
    path: Path,
) -> tuple[dict[str, dict[str, object]], str]:
    """Load and validate a private generated MCP client configuration."""
    raw = _read_private_config(path)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentExecutionError("generated MCP config is unreadable") from exc
    if set(document) != {"mcpServers"} or not isinstance(document["mcpServers"], dict):
        raise AgentExecutionError("generated MCP config has an invalid shape")
    servers = document["mcpServers"]
    if not servers:
        raise AgentExecutionError("generated MCP config has no servers")
    for server in servers.values():
        if not _valid_server_entry(server):
            raise AgentExecutionError("generated MCP server config is invalid")
    return servers, hashlib.sha256(raw).hexdigest()


def _read_private_config(path: Path) -> bytes:
    """Read a bounded private file without following symbolic links."""
    if not hasattr(os, "getuid"):
        raise AgentExecutionError(_POSIX_OWNERSHIP_REQUIRED)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise AgentExecutionError("generated MCP config is unreadable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.getuid()}
            or metadata.st_mode & 0o077
        ):
            raise AgentExecutionError("generated MCP config is not private")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 65_536):
            total += len(chunk)
            if total > _MAX_CONFIG_BYTES:
                raise AgentExecutionError("generated MCP config is too large")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _assert_config_unchanged(handle: _ClaudeHandle) -> None:
    """Reject a generated configuration changed after initial admission."""
    if isinstance(handle.launch, DecisionAgentLaunch):
        return
    current = hashlib.sha256(
        _read_private_config(handle.launch.client_config_path)
    ).hexdigest()
    if not hmac.compare_digest(current, handle.config_sha256):
        raise AgentExecutionError("generated MCP config changed after verification")


def _valid_server_entry(server: object) -> bool:
    """Return whether an MCP server entry has the required strict shape."""
    return (
        isinstance(server, dict)
        and set(server) == {"command", "args", "env"}
        and isinstance(server["command"], str)
        and Path(server["command"]).is_absolute()
        and isinstance(server["args"], list)
        and all(isinstance(arg, str) for arg in server["args"])
        and isinstance(server["env"], dict)
        and all(
            isinstance(name, str) and isinstance(value, str)
            for name, value in server["env"].items()
        )
    )


def _credential_aliases(servers: dict[str, dict[str, object]]) -> set[str]:
    """Collect credential aliases referenced by selected server environments."""
    aliases: set[str] = set()
    for server in servers.values():
        for value in server["env"].values():
            if value.startswith("${") and value.endswith("}"):
                aliases.add(value[2:-1])
    return aliases


def _server_environment(
    server: dict[str, object], credentials: Mapping[str, str]
) -> dict[str, str]:
    """Resolve one MCP server's environment from its credential lease."""
    environment = {"PATH": _BASE_ENVIRONMENT["PATH"]}
    for name, value in server["env"].items():
        if value.startswith("${") and value.endswith("}"):
            alias = value[2:-1]
            environment[name] = credentials[alias]
        else:
            environment[name] = value
    return environment


def _require_handle(handle: object) -> _ClaudeHandle:
    """Validate and narrow an opaque managed-agent handle."""
    if not isinstance(handle, _ClaudeHandle):
        raise AgentExecutionError("unknown agent handle")
    return handle


def _parse_agent_result(stdout: bytes) -> str:
    """Parse the installed agent's strict JSON result envelope."""
    try:
        payload = json.loads(stdout.decode("utf-8"))
        result = payload["result"]
        if (
            payload.get("type") != "result"
            or payload.get("is_error") is not False
            or not isinstance(result, str)
            or not result
        ):
            raise ValueError
        return result
    except (KeyError, ValueError) as exc:
        raise AgentExecutionError("agent returned an invalid result") from exc
