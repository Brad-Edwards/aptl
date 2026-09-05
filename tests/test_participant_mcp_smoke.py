"""Semantic MCP smoke tests for the guided participant profile."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
import sys
import importlib

import pytest

from aptl.validation import participant_mcp_smoke as smoke
from aptl.validation.participant_mcp_smoke import (
    McpRegistration,
    McpSmokeOperation,
    ParticipantMcpSmokeError,
    run_participant_mcp_smoke,
)
from aptl.validation.participant_profile import load_participant_profile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(
    0,
    str(PROJECT_ROOT / "plugins" / "aptl-techvault-verifier" / "src"),
)
techvault_verifier = importlib.import_module("aptl_techvault_verifier")
participant_smoke = importlib.import_module("aptl_techvault_verifier.participant_smoke")
SMOKE_OPERATIONS = participant_smoke.PARTICIPANT_SMOKE_OPERATIONS
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


class _EntryPoint:
    name = "guided-purple.techvault-attacker-target"

    def __init__(self, loaded):
        self.loaded = loaded
        self.load_calls = 0

    def load(self):
        self.load_calls += 1
        if isinstance(self.loaded, BaseException):
            raise self.loaded
        return self.loaded


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
        SMOKE_OPERATIONS,
    )

    assert {item.check_id for item in evidence} == {
        "mcp.red.kali-command",
        "mcp.red.ssh-authentication-attack",
        "mcp.blue.indexer-investigation",
        "mcp.blue.wazuh-investigation",
    }
    assert {item.status for item in evidence} == {"passed"}


def test_profile_smoke_resolves_the_installed_plan_for_production_callers(
    monkeypatch, tmp_path: Path
) -> None:
    entry_point = _EntryPoint(SMOKE_OPERATIONS)
    monkeypatch.setattr(smoke, "_installed_plan_entry_points", lambda: [entry_point])

    evidence = run_participant_mcp_smoke(
        _profile(),
        _registrations(tmp_path),
    )

    assert entry_point.load_calls == 1
    assert {item.status for item in evidence} == {"passed"}


@pytest.mark.parametrize("count", [0, 2])
def test_profile_smoke_requires_exactly_one_installed_plan(monkeypatch, count) -> None:
    monkeypatch.setattr(
        smoke,
        "_installed_plan_entry_points",
        lambda: [_EntryPoint(SMOKE_OPERATIONS) for _ in range(count)],
    )
    profile = _profile()

    with pytest.raises(ParticipantMcpSmokeError, match="exactly one compatible"):
        smoke.resolve_participant_mcp_smoke_operations(profile)


def test_profile_smoke_rejects_a_plan_that_fails_to_load(monkeypatch) -> None:
    monkeypatch.setattr(
        smoke,
        "_installed_plan_entry_points",
        lambda: [_EntryPoint(RuntimeError("must not escape"))],
    )
    profile = _profile()

    with pytest.raises(ParticipantMcpSmokeError, match="could not be loaded"):
        smoke.resolve_participant_mcp_smoke_operations(profile)


@pytest.mark.parametrize(
    "loaded",
    [
        [],
        (),
        (SMOKE_OPERATIONS[0],) * 65,
        (replace(SMOKE_OPERATIONS[0], check_id="bad id"),),
        (replace(SMOKE_OPERATIONS[0], server_id="bad id"),),
        (replace(SMOKE_OPERATIONS[0], tool_name="bad tool"),),
        (replace(SMOKE_OPERATIONS[0], arguments=[]),),
        (replace(SMOKE_OPERATIONS[0], validates=None),),
        (object(),),
    ],
)
def test_profile_smoke_rejects_malformed_installed_plans(monkeypatch, loaded) -> None:
    monkeypatch.setattr(
        smoke,
        "_installed_plan_entry_points",
        lambda: [_EntryPoint(loaded)],
    )
    profile = _profile()

    with pytest.raises(ParticipantMcpSmokeError, match="plan is malformed"):
        smoke.resolve_participant_mcp_smoke_operations(profile)


def test_profile_smoke_rejects_missing_or_extra_registration(
    tmp_path: Path,
) -> None:
    registrations = _registrations(tmp_path)
    registrations.pop("aptl-wazuh")
    registrations["aptl-casemgmt"] = next(iter(registrations.values()))
    profile = _profile()

    with pytest.raises(
        ParticipantMcpSmokeError,
        match="registration surface does not match",
    ):
        run_participant_mcp_smoke(profile, registrations, SMOKE_OPERATIONS)


def test_profile_smoke_records_semantic_failure_without_child_output(
    tmp_path: Path,
) -> None:
    evidence = run_participant_mcp_smoke(
        _profile(),
        _registrations(tmp_path, fail_red=True),
        SMOKE_OPERATIONS,
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
        SMOKE_OPERATIONS,
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
        SMOKE_OPERATIONS,
    )

    assert {item.check_id for item in evidence if item.status == "failed"} == {
        "mcp.blue.indexer-investigation",
        "mcp.blue.wazuh-investigation",
    }
