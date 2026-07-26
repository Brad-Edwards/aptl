"""Bounded installed-agent and real MCP inventory adapter."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Protocol

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aptl.utils.placeholders import contains_placeholder
from aptl.workbench.runtime import ProfileLaunch

_BASE_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
    "NO_COLOR": "1",
}
_MODEL_CREDENTIAL = "ANTHROPIC_API_KEY"
_MCP_INVENTORY_TIMEOUT_SECONDS = 10
_MAX_CONFIG_BYTES = 1_000_000


class AgentExecutionError(RuntimeError):
    """The installed agent or one of its selected MCP servers failed safely."""


@dataclass(frozen=True)
class ProcessResult:
    """Bounded child result returned by the process runner."""

    returncode: int
    stdout: bytes
    stderr: bytes


class ProcessRunner(Protocol):
    """Execute one fixed agent request without a shell."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        env: dict[str, str],
        cwd: Path,
        stdin: bytes,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ProcessResult: ...


InventoryProbe = Callable[[str, str, list[str], dict[str, str]], tuple[str, ...]]


@dataclass
class _ClaudeHandle:
    launch: ProfileLaunch
    servers: dict[str, dict[str, object]]
    environment: dict[str, str]
    config_sha256: str
    inventory: dict[str, tuple[str, ...]] = field(default_factory=dict)
    closed: bool = False


class BoundedProcessRunner:
    """Run a child process with bounded combined output and group teardown."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        env: dict[str, str],
        cwd: Path,
        stdin: bytes,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ProcessResult:
        if timeout_seconds <= 0 or max_output_bytes <= 0:
            raise AgentExecutionError("agent process limits are invalid")
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout = bytearray()
        stderr = bytearray()
        overflow = threading.Event()
        budget = _OutputBudget(max_output_bytes)
        readers = [
            threading.Thread(
                target=_drain_bounded,
                args=(process.stdout, stdout, budget, overflow),
                daemon=True,
            ),
            threading.Thread(
                target=_drain_bounded,
                args=(process.stderr, stderr, budget, overflow),
                daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()
        _write_stdin(process, stdin)
        reason = _wait_for_process(process, timeout_seconds, overflow)
        if reason is not None:
            _terminate_process_group(process)
        for reader in readers:
            reader.join(timeout=1)
        if reason is not None:
            raise AgentExecutionError(reason)
        return ProcessResult(process.returncode, bytes(stdout), bytes(stderr))


class _OutputBudget:
    """Serialize a strict combined stdout/stderr byte budget."""

    def __init__(self, limit: int) -> None:
        self._remaining = limit
        self._lock = threading.Lock()

    def admit(self, chunk: bytes) -> tuple[bytes, bool]:
        with self._lock:
            admitted = chunk[: self._remaining]
            self._remaining -= len(admitted)
            return admitted, len(admitted) != len(chunk)


def _drain_bounded(
    pipe: object,
    target: bytearray,
    budget: _OutputBudget,
    overflow: threading.Event,
) -> None:
    if pipe is None:
        return
    while chunk := pipe.read(8192):
        admitted, exceeded = budget.admit(chunk)
        target.extend(admitted)
        if exceeded:
            overflow.set()
            return


def _write_stdin(process: subprocess.Popen[bytes], data: bytes) -> None:
    if process.stdin is None:
        return
    try:
        process.stdin.write(data)
        process.stdin.close()
    except BrokenPipeError:
        pass


def _wait_for_process(
    process: subprocess.Popen[bytes],
    timeout_seconds: float,
    overflow: threading.Event,
) -> str | None:
    deadline = time.monotonic() + timeout_seconds
    while process.poll() is None:
        if overflow.wait(0.02):
            return "agent output exceeded the configured limit"
        if time.monotonic() >= deadline:
            return "agent request exceeded the configured timeout"
    return None


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=1)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


async def _probe(
    command: str, args: list[str], environment: dict[str, str]
) -> tuple[str, ...]:
    parameters = StdioServerParameters(command=command, args=args, env=environment)
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(
                seconds=_MCP_INVENTORY_TIMEOUT_SECONDS
            ),
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
        if (
            timeout_seconds <= 0
            or max_output_bytes <= 0
            or max_prompt_chars <= 0
        ):
            raise AgentExecutionError("agent limits are invalid")
        self._executable = _admitted_executable(claude_executable)
        self._work_dir = _prepare_work_dir(work_dir)
        self._runner = runner or BoundedProcessRunner()
        self._inventory_probe = inventory_probe
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes
        self._max_prompt_chars = max_prompt_chars

    def launch(
        self, launch: ProfileLaunch, credentials: Mapping[str, str]
    ) -> object:
        """Admit a generated strict config and create a minimal secret lease."""
        servers, config_sha256 = _load_server_config(launch.client_config_path)
        required_aliases = _credential_aliases(servers)
        admitted = (_MODEL_CREDENTIAL, *sorted(required_aliases))
        environment = dict(_BASE_ENVIRONMENT)
        for name in admitted:
            value = credentials.get(name)
            if not value or contains_placeholder(value):
                raise AgentExecutionError("agent credential lease is incomplete")
            environment[name] = value
        return _ClaudeHandle(launch, servers, environment, config_sha256)

    def list_tools(self, handle: object) -> Mapping[str, tuple[str, ...]]:
        """Probe every selected stdio server instead of trusting the descriptor."""
        active = _require_handle(handle)
        if active.closed:
            raise AgentExecutionError("agent profile is closed")
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
        return inventory

    def respond(self, handle: object, message: str) -> str:
        """Run one bounded non-persistent agent request with prompt on stdin."""
        active = _require_handle(handle)
        if active.closed or not active.inventory:
            raise AgentExecutionError("agent profile is not ready")
        _assert_config_unchanged(active)
        if not message or len(message) > self._max_prompt_chars:
            raise AgentExecutionError("participant message exceeds the configured limit")
        result = self._runner.run(
            self._argv(active),
            env=dict(active.environment),
            cwd=self._work_dir,
            stdin=message.encode(),
            timeout_seconds=self._timeout_seconds,
            max_output_bytes=self._max_output_bytes,
        )
        if result.returncode != 0:
            raise AgentExecutionError("agent request failed")
        return _parse_agent_result(result.stdout)

    def close(self, handle: object) -> None:
        """Invalidate the selected environment after one-shot children exit."""
        active = _require_handle(handle)
        active.environment.clear()
        active.inventory.clear()
        active.closed = True

    def _argv(self, handle: _ClaudeHandle) -> tuple[str, ...]:
        allowed = ",".join(
            f"mcp__{server_id}__{tool}"
            for server_id, tools in handle.inventory.items()
            for tool in tools
        )
        return (
            str(self._executable),
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
            "--allowedTools",
            allowed,
            "--mcp-config",
            str(handle.launch.client_config_path),
            "--strict-mcp-config",
        )


def _admitted_executable(path: Path) -> Path:
    if not path.is_absolute():
        raise AgentExecutionError("agent executable must be absolute")
    resolved = path.resolve(strict=True)
    stat = resolved.stat()
    if (
        not resolved.is_file()
        or not os.access(resolved, os.X_OK)
        or stat.st_uid not in {0, os.getuid()}
        or stat.st_mode & 0o022
    ):
        raise AgentExecutionError("agent executable is not admissible")
    return resolved


def _prepare_work_dir(path: Path) -> Path:
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
    raw = _read_private_config(path)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentExecutionError("generated MCP config is unreadable") from exc
    if set(document) != {"mcpServers"} or not isinstance(
        document["mcpServers"], dict
    ):
        raise AgentExecutionError("generated MCP config has an invalid shape")
    servers = document["mcpServers"]
    if not servers:
        raise AgentExecutionError("generated MCP config has no servers")
    for server in servers.values():
        if not _valid_server_entry(server):
            raise AgentExecutionError("generated MCP server config is invalid")
    return servers, hashlib.sha256(raw).hexdigest()


def _read_private_config(path: Path) -> bytes:
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
    current = hashlib.sha256(
        _read_private_config(handle.launch.client_config_path)
    ).hexdigest()
    if not hmac.compare_digest(current, handle.config_sha256):
        raise AgentExecutionError("generated MCP config changed after verification")


def _valid_server_entry(server: object) -> bool:
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
    aliases: set[str] = set()
    for server in servers.values():
        for value in server["env"].values():
            if value.startswith("${") and value.endswith("}"):
                aliases.add(value[2:-1])
    return aliases


def _server_environment(
    server: dict[str, object], credentials: Mapping[str, str]
) -> dict[str, str]:
    environment = {"PATH": _BASE_ENVIRONMENT["PATH"]}
    for name, value in server["env"].items():
        if value.startswith("${") and value.endswith("}"):
            alias = value[2:-1]
            environment[name] = credentials[alias]
        else:
            environment[name] = value
    return environment


def _require_handle(handle: object) -> _ClaudeHandle:
    if not isinstance(handle, _ClaudeHandle):
        raise AgentExecutionError("unknown agent handle")
    return handle


def _parse_agent_result(stdout: bytes) -> str:
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
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError) as exc:
        raise AgentExecutionError("agent returned an invalid result") from exc
