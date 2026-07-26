"""Bounded MCP stdio protocol exchange for live semantic qualification."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from functools import partial
from pathlib import Path
from typing import TextIO


class McpProtocolError(RuntimeError):
    """A bounded MCP protocol exchange failed without exposing child output."""


def _read_response(
    stdout: TextIO,
    *,
    deadline: float,
) -> dict[str, object] | None:
    """Read and decode one response before the shared exchange deadline."""

    remaining = deadline - time.monotonic()
    response: dict[str, object] | None = None
    if remaining > 0:
        selector = selectors.DefaultSelector()
        try:
            selector.register(stdout, selectors.EVENT_READ)
            readable = bool(selector.select(timeout=remaining))
        finally:
            selector.close()
        if readable:
            line = stdout.readline()
            if line:
                try:
                    decoded = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise McpProtocolError(
                        "MCP server returned an invalid response"
                    ) from exc
                if not isinstance(decoded, dict):
                    raise McpProtocolError("MCP server returned an invalid response")
                response = decoded
    return response


def _start_server(
    command: list[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None,
) -> subprocess.Popen[str]:
    """Start one released MCP server with no child-output evidence channel."""

    try:
        return subprocess.Popen(
            command,
            cwd=cwd,
            env=dict(os.environ if env is None else env),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, ValueError) as exc:
        raise McpProtocolError("MCP server could not start") from exc


def _exchange_messages(
    process: subprocess.Popen[str],
    messages: Sequence[Mapping[str, object]],
    deadline: float,
    response_validator: (
        Callable[[Mapping[str, object], Mapping[str, object]], None] | None
    ),
) -> tuple[list[dict[str, object]], bool]:
    """Write the requests and collect their bounded responses."""

    if process.stdin is None or process.stdout is None:
        raise McpProtocolError("MCP server pipes are unavailable")
    responses: list[dict[str, object]] = []
    complete = True
    for message in messages:
        if time.monotonic() >= deadline:
            complete = False
            break
        try:
            process.stdin.write(json.dumps(dict(message), separators=(",", ":")) + "\n")
            process.stdin.flush()
        except (OSError, TypeError, ValueError):
            complete = False
            break
        if "id" not in message:
            continue
        response = _read_response(process.stdout, deadline=deadline)
        if response is None:
            complete = False
            break
        if response_validator is not None:
            response_validator(message, response)
        responses.append(response)
    return responses, complete


def _stop_server(process: subprocess.Popen[str], deadline: float) -> None:
    """Close stdin and terminate a server that outlives the exchange."""

    if process.stdin is not None:
        try:
            process.stdin.close()
        except OSError:
            pass
    remaining = max(0.0, deadline - time.monotonic())
    try:
        process.wait(timeout=min(1.0, remaining))
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def exchange_jsonrpc(
    argv: Sequence[str],
    messages: Sequence[Mapping[str, object]],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    timeout_seconds: float = 30,
    response_validator: (
        Callable[[Mapping[str, object], Mapping[str, object]], None] | None
    ) = None,
) -> list[dict[str, object]]:
    """Exchange bounded line-delimited JSON-RPC messages with one MCP server.

    ``argv`` comes from a validated released MCP registration, never from the
    participant-profile manifest. Child stderr is discarded at this boundary:
    MCP errors may contain credentials or backend response bodies and are not a
    qualification evidence surface.
    """

    command = list(argv)
    if not command:
        raise McpProtocolError("MCP command is empty")
    if timeout_seconds <= 0:
        raise McpProtocolError("MCP timeout must be positive")
    process = _start_server(command, cwd=cwd, env=env)
    deadline = time.monotonic() + timeout_seconds
    try:
        responses, complete = _exchange_messages(
            process,
            messages,
            deadline,
            response_validator,
        )
    finally:
        _stop_server(process, deadline)

    expected_responses = sum("id" in message for message in messages)
    if not complete or len(responses) != expected_responses:
        raise McpProtocolError("MCP server did not return a complete response")
    return responses


def _listed_tool_names(response: Mapping[str, object]) -> set[str]:
    """Extract the exact string tool names from a successful list response."""

    listed_result = response.get("result")
    tools = listed_result.get("tools") if isinstance(listed_result, dict) else None
    if not isinstance(tools, list):
        return set()
    return {
        item.get("name")
        for item in tools
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }


def _validate_inventory(
    expected_tool_names: Collection[str] | None,
    requested_tool_name: str,
    request: Mapping[str, object],
    response: Mapping[str, object],
) -> None:
    """Fail closed when the released server exposes an unexpected inventory."""

    if request.get("id") != 2:
        return
    if "error" in response:
        raise McpProtocolError("MCP tool list failed")
    listed_names = _listed_tool_names(response)
    if expected_tool_names is not None and listed_names != set(expected_tool_names):
        raise McpProtocolError("MCP tool inventory does not match the profile")
    if requested_tool_name not in listed_names:
        raise McpProtocolError("MCP tool is not registered")


def call_mcp_tool(
    argv: Sequence[str],
    tool_name: str,
    arguments: Mapping[str, object],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    timeout_seconds: float = 60,
    expected_tool_names: Collection[str] | None = None,
) -> dict[str, object]:
    """Initialize a real MCP server and return one ``tools/call`` result."""

    responses = exchange_jsonrpc(
        argv,
        (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "aptl-participant-qualification",
                        "version": "1.0.0",
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": dict(arguments),
                },
            },
        ),
        cwd=cwd,
        env=env,
        timeout_seconds=timeout_seconds,
        response_validator=partial(
            _validate_inventory,
            expected_tool_names,
            tool_name,
        ),
    )

    response = next(
        (item for item in responses if item.get("id") == 3),
        None,
    )
    if response is None or "error" in response:
        raise McpProtocolError("MCP tool call failed")
    result = response.get("result")
    if not isinstance(result, dict):
        raise McpProtocolError("MCP tool call returned an invalid result")
    return result
