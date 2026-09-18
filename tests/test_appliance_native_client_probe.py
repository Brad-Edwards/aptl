"""Native Claude/Codex qualification must prove a real client tool event."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts/appliance/probe-native-client.py"
)
SPEC = importlib.util.spec_from_file_location("aptl_native_probe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
_write_bytecode = sys.dont_write_bytecode
try:
    sys.dont_write_bytecode = True
    SPEC.loader.exec_module(probe)
finally:
    sys.dont_write_bytecode = _write_bytecode


def test_native_event_parsers_require_successful_mcp_tool_results() -> None:
    claude = "\n".join(
        (
            json.dumps(
                {
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "call-1",
                                "name": "mcp__seat-red__kali_info",
                            }
                        ]
                    }
                }
            ),
            json.dumps(
                {
                    "message": {
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "call-1",
                                "content": {"target_name": "Kali Linux"},
                            }
                        ]
                    }
                }
            ),
        )
    )
    codex = json.dumps(
        {
            "type": "item.completed",
            "item": {
                "type": "mcp_tool_call",
                "server": "seat-red",
                "tool": "kali_info",
                "status": "completed",
                "result": {"target_name": "Kali Linux"},
            },
        }
    )

    assert probe._parse_client_events(
        claude, client="claude", server_name="seat-red", tool_name="kali_info"
    ) == {"target_name": "Kali Linux"}
    assert probe._parse_client_events(
        codex, client="codex", server_name="seat-red", tool_name="kali_info"
    ) == {"target_name": "Kali Linux"}
    assert (
        probe._parse_client_events(
            '{"message":"kali_info succeeded"}',
            client="codex",
            server_name="seat-red",
            tool_name="kali_info",
        )
        is None
    )


def test_native_probe_executes_the_selected_client_binary(
    tmp_path, monkeypatch
) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(
        json.dumps(
            {"mcpServers": {"seat-red": {"command": "ssh", "args": ["example"]}}}
        )
    )
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if command[1:] == ["--version"]:
            return subprocess.CompletedProcess(command, 0, "2.1.276\n", "")
        output = "\n".join(
            (
                json.dumps(
                    {
                        "message": {
                            "content": [
                                {
                                    "type": "tool_use",
                                    "id": "call-1",
                                    "name": "mcp__seat-red__kali_info",
                                }
                            ]
                        }
                    }
                ),
                json.dumps(
                    {
                        "message": {
                            "content": [
                                {
                                    "type": "tool_result",
                                    "tool_use_id": "call-1",
                                    "content": {"ok": True},
                                }
                            ]
                        }
                    }
                ),
            )
        )
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(probe.shutil, "which", lambda _client: "/usr/bin/claude")
    monkeypatch.setattr(probe.subprocess, "run", run)

    name, version, result = probe._native_call(config, "claude", require_success=True)

    assert (name, version, result) == ("seat-red", "2.1.276", {"ok": True})
    assert "--strict-mcp-config" in calls[1][0]
    assert "mcp__seat-red__kali_info" in calls[1][0]
