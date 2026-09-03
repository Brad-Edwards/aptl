"""Tests for the shared bounded MCP stdio protocol driver."""

from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest

from aptl.validation.mcp_protocol import (
    McpProtocolError,
    call_mcp_tool,
    exchange_jsonrpc,
)


_SERVER = r"""
import json
import sys

for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    if message["method"] == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {}}
    elif message["method"] == "tools/list":
        result = {"tools": [{"name": "kali_run_command"}]}
    elif message["method"] == "tools/call":
        result = {"content": [{"type": "text", "text": "uid=1000(kali)"}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
"""

_SIDE_EFFECT_SERVER = r"""
import json
import os
import sys

for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    if message["method"] == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {}}
    elif message["method"] == "tools/list":
        result = {"tools": [{"name": "kali_run_command"}]}
    else:
        with open(os.environ["SIDE_EFFECT"], "w", encoding="utf-8") as output:
            output.write("called")
        result = {"content": [{"type": "text", "text": "called"}]}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
"""


def test_call_mcp_tool_performs_real_initialize_and_tool_exchange(
    tmp_path: Path,
) -> None:
    result = call_mcp_tool(
        [sys.executable, "-c", _SERVER],
        "kali_run_command",
        {"command": "id"},
        cwd=tmp_path,
        timeout_seconds=5,
    )

    assert result["content"] == [{"type": "text", "text": "uid=1000(kali)"}]


def test_call_mcp_tool_requires_the_tool_to_be_registered(tmp_path: Path) -> None:
    with pytest.raises(McpProtocolError, match="not registered"):
        call_mcp_tool(
            [sys.executable, "-c", _SERVER],
            "wazuh_query_alerts",
            {},
            cwd=tmp_path,
            timeout_seconds=5,
        )


def test_call_mcp_tool_can_require_the_exact_profile_inventory(
    tmp_path: Path,
) -> None:
    side_effect = tmp_path / "side-effect"
    command = [sys.executable, "-c", _SIDE_EFFECT_SERVER]
    environment = {**os.environ, "SIDE_EFFECT": str(side_effect)}
    with pytest.raises(McpProtocolError, match="inventory does not match"):
        call_mcp_tool(
            command,
            "kali_run_command",
            {"command": "id"},
            cwd=tmp_path,
            env=environment,
            timeout_seconds=5,
            expected_tool_names=("kali_run_command", "kali_info"),
        )
    assert not side_effect.exists()


def test_exchange_rejects_timeout_without_leaking_child_stderr(
    tmp_path: Path,
) -> None:
    secret = "qualification-secret-value"
    server = (
        "import os,sys,time;"
        "sys.stderr.write(os.environ['QUALIFICATION_SECRET']);"
        "sys.stderr.flush();time.sleep(5)"
    )

    with pytest.raises(McpProtocolError) as error:
        exchange_jsonrpc(
            [sys.executable, "-c", server],
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {},
                }
            ],
            cwd=tmp_path,
            env={**os.environ, "QUALIFICATION_SECRET": secret},
            timeout_seconds=0.1,
        )

    assert secret not in str(error.value)
    assert str(error.value) == "MCP server did not return a complete response"


def test_exchange_rejects_empty_argv(tmp_path: Path) -> None:
    with pytest.raises(McpProtocolError, match="MCP command is empty"):
        exchange_jsonrpc([], [], cwd=tmp_path)
