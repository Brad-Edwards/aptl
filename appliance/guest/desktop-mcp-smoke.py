#!/usr/bin/python3
"""Prove the desktop identity can use live red and blue scenario tools."""

from __future__ import annotations

import json
import os
from pathlib import Path

from aptl.validation.mcp_protocol import call_mcp_tool
from aptl_techvault.participant_smoke import _kali_user, _successful_json


def _registration(role: str, server: str) -> tuple[list[str], dict[str, str]]:
    document = json.loads((Path.home() / f"{role}.mcp.json").read_text())
    spec = document["mcpServers"][server]
    return [spec["command"], *spec["args"]], {
        **os.environ, **spec["env"],
    }


def main() -> None:
    project = Path("/opt/aptl/project")
    checks = (
        ("red", "aptl-red", "kali_run_command", {"command": "id"}, _kali_user),
        (
            "blue", "aptl-wazuh", "wazuh_query_alerts",
            {"body": {"size": 1, "query": {"match_all": {}}}},
            _successful_json,
        ),
    )
    for role, server, tool, arguments, validates in checks:
        argv, env = _registration(role, server)
        result = call_mcp_tool(
            argv, tool, arguments, cwd=project, env=env,
            timeout_seconds=90,
        )
        if not validates(result):
            raise RuntimeError(f"{role} desktop MCP call failed")


if __name__ == "__main__":
    main()
