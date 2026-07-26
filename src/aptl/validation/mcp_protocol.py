"""Bounded MCP stdio protocol exchange for live semantic qualification."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from pathlib import Path
from typing import Any


class McpProtocolError(RuntimeError):
    """A bounded MCP protocol exchange failed without exposing child output."""


def _read_response(
    stdout: Any,
    *,
    deadline: float,
) -> dict[str, Any] | None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    selector = selectors.DefaultSelector()
    try:
        selector.register(stdout, selectors.EVENT_READ)
        if not selector.select(timeout=remaining):
            return None
    finally:
        selector.close()
    line = stdout.readline()
    if not line:
        return None
    try:
        response = json.loads(line)
    except json.JSONDecodeError as exc:
        raise McpProtocolError("MCP server returned an invalid response") from exc
    if not isinstance(response, dict):
        raise McpProtocolError("MCP server returned an invalid response")
    return response


def exchange_jsonrpc(
    argv: Sequence[str],
    messages: Sequence[Mapping[str, object]],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    timeout_seconds: float = 30,
    response_validator: (
        Callable[[Mapping[str, object], Mapping[str, Any]], None] | None
    ) = None,
) -> list[dict[str, Any]]:
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
    child_env = dict(os.environ if env is None else env)
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=child_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, ValueError) as exc:
        raise McpProtocolError("MCP server could not start") from exc

    assert process.stdin is not None
    assert process.stdout is not None
    deadline = time.monotonic() + timeout_seconds
    responses: list[dict[str, Any]] = []
    complete = True
    try:
        for message in messages:
            if time.monotonic() >= deadline:
                complete = False
                break
            try:
                process.stdin.write(
                    json.dumps(dict(message), separators=(",", ":")) + "\n"
                )
                process.stdin.flush()
            except (BrokenPipeError, OSError, TypeError, ValueError):
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
    finally:
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

    expected_responses = sum("id" in message for message in messages)
    if not complete or len(responses) != expected_responses:
        raise McpProtocolError("MCP server did not return a complete response")
    return responses


def call_mcp_tool(
    argv: Sequence[str],
    tool_name: str,
    arguments: Mapping[str, object],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    timeout_seconds: float = 60,
    expected_tool_names: Collection[str] | None = None,
) -> dict[str, Any]:
    """Initialize a real MCP server and return one ``tools/call`` result."""

    def validate_inventory(
        request: Mapping[str, object],
        response: Mapping[str, Any],
    ) -> None:
        if request.get("id") != 2:
            return
        if "error" in response:
            raise McpProtocolError("MCP tool list failed")
        listed_result = response.get("result")
        tools = listed_result.get("tools") if isinstance(listed_result, dict) else None
        listed_names = (
            {
                item.get("name")
                for item in tools
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            }
            if isinstance(tools, list)
            else set()
        )
        if expected_tool_names is not None and listed_names != set(
            expected_tool_names
        ):
            raise McpProtocolError("MCP tool inventory does not match the profile")
        if tool_name not in listed_names:
            raise McpProtocolError("MCP tool is not registered")

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
        response_validator=validate_inventory,
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
