"""Semantic MCP smoke tests for the guided participant profile."""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from aptl.validation.participant_mcp_smoke import (
    McpRegistration,
    ParticipantMcpSmokeError,
    run_participant_mcp_smoke,
)
from aptl.validation.participant_profile import load_participant_profile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = (
    PROJECT_ROOT / "participant-profiles" / "guided-purple-v1" / "profile.json"
)

_SERVER = r"""
import json
import sys

TOOLS = __TOOLS__
FAIL_RED = __FAIL_RED__
FAIL_ATTACK = __FAIL_ATTACK__
EMPTY_ALERTS = __EMPTY_ALERTS__

for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    if message["method"] == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {}}
    elif message["method"] == "tools/list":
        result = {"tools": [{"name": name} for name in TOOLS]}
    else:
        tool = message["params"]["name"]
        arguments = message["params"]["arguments"]
        if tool == "kali_run_command" and arguments["command"] == "id":
            text = (
                "uid=0(root) gid=0(root)"
                if FAIL_RED
                else "uid=1000(kali) gid=1000(kali)"
            )
        elif tool == "kali_run_command":
            text = json.dumps({
                "success": True,
                "output": {
                    "stdout": "attack incomplete\n" if FAIL_ATTACK else "done\n",
                    "code": 0
                }
            })
        else:
            rows = [] if EMPTY_ALERTS else [{"_id": "alert-1"}]
            text = json.dumps({"data": {"hits": {"hits": rows}}})
        result = {"content": [{"type": "text", "text": text}]}
    print(
        json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}),
        flush=True,
    )
"""


def _profile():
    return load_participant_profile(PROJECT_ROOT, PROFILE_PATH)


def _server_for(
    server_id: str,
    *,
    fail_red: bool = False,
    fail_attack: bool = False,
    empty_alerts: bool = False,
) -> str:
    profile = _profile()
    tools = next(
        server.tool_names
        for workbench in profile.workbench_profiles
        for server in workbench.servers
        if server.server_id == server_id
    )
    return (
        _SERVER.replace("__TOOLS__", repr(tools))
        .replace("__FAIL_RED__", repr(fail_red and server_id == "aptl-red"))
        .replace("__FAIL_ATTACK__", repr(fail_attack and server_id == "aptl-red"))
        .replace(
            "__EMPTY_ALERTS__",
            repr(empty_alerts and server_id in {"aptl-indexer", "aptl-wazuh"}),
        )
    )


def _registrations(
    tmp_path: Path,
    *,
    fail_red: bool = False,
    fail_attack: bool = False,
    empty_alerts: bool = False,
):
    return {
        server_id: McpRegistration(
            argv=(
                sys.executable,
                "-c",
                _server_for(
                    server_id,
                    fail_red=fail_red,
                    fail_attack=fail_attack,
                    empty_alerts=empty_alerts,
                ),
            ),
            cwd=tmp_path,
            env={},
        )
        for server_id in _profile().mcp_server_ids
    }


def test_profile_smoke_calls_every_allowed_real_backend_operation(
    tmp_path: Path,
) -> None:
    evidence = run_participant_mcp_smoke(
        _profile(),
        _registrations(tmp_path),
    )

    assert {item.check_id for item in evidence} == {
        "mcp.red.kali-command",
        "mcp.red.ssh-authentication-attack",
        "mcp.blue.indexer-investigation",
        "mcp.blue.wazuh-investigation",
    }
    assert {item.status for item in evidence} == {"passed"}


def test_profile_smoke_rejects_missing_or_extra_registration(
    tmp_path: Path,
) -> None:
    registrations = _registrations(tmp_path)
    registrations.pop("aptl-wazuh")
    registrations["aptl-casemgmt"] = next(iter(registrations.values()))

    with pytest.raises(
        ParticipantMcpSmokeError,
        match="registration surface does not match",
    ):
        run_participant_mcp_smoke(_profile(), registrations)


def test_profile_smoke_records_semantic_failure_without_child_output(
    tmp_path: Path,
) -> None:
    evidence = run_participant_mcp_smoke(
        _profile(),
        _registrations(tmp_path, fail_red=True),
    )

    red = next(item for item in evidence if item.check_id == "mcp.red.kali-command")
    assert red.status == "failed"
    assert red.summary == "semantic backend operation failed"
    assert "uid=0" not in red.summary


def test_profile_smoke_rejects_incomplete_attack_semantics(
    tmp_path: Path,
) -> None:
    evidence = run_participant_mcp_smoke(
        _profile(),
        _registrations(tmp_path, fail_attack=True),
    )

    attack = next(
        item
        for item in evidence
        if item.check_id == "mcp.red.ssh-authentication-attack"
    )
    assert attack.status == "failed"


def test_profile_smoke_rejects_empty_alert_results(tmp_path: Path) -> None:
    evidence = run_participant_mcp_smoke(
        _profile(),
        _registrations(tmp_path, empty_alerts=True),
    )

    assert {
        item.check_id
        for item in evidence
        if item.status == "failed"
    } == {
        "mcp.blue.indexer-investigation",
        "mcp.blue.wazuh-investigation",
    }
