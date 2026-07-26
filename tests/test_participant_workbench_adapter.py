"""Production-adapter coverage for the participant workbench."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aptl.workbench.agent import (
    AgentExecutionError,
    BoundedProcessRunner,
    ClaudeCodeManagedAgentAdapter,
    ProcessResult,
    probe_mcp_server,
)
from aptl.workbench.credentials import (
    EphemeralCredentialBroker,
    WorkbenchCredentialError,
)
from aptl.workbench.profiles import ProfileId, profile_for, render_profile_config
from aptl.workbench.runtime import ProfileLaunch


def test_ephemeral_broker_returns_only_the_selected_profile_lease() -> None:
    broker = EphemeralCredentialBroker(
        {
            "ANTHROPIC_API_KEY": "model-secret",
            "INDEXER_USERNAME": "indexer-user",
            "INDEXER_PASSWORD": "indexer-secret",
            "API_USERNAME": "api-user",
            "API_PASSWORD": "api-secret",
            "MISP_API_KEY": "misp-secret",
        }
    )

    lease = broker.prepare(
        ProfileId.BLUE,
        "a" * 32,
        ("INDEXER_USERNAME", "INDEXER_PASSWORD"),
    )

    assert lease == {
        "ANTHROPIC_API_KEY": "model-secret",
        "INDEXER_USERNAME": "indexer-user",
        "INDEXER_PASSWORD": "indexer-secret",
    }
    assert "MISP_API_KEY" not in lease
    broker.destroy(ProfileId.BLUE, "a" * 32)
    with pytest.raises(WorkbenchCredentialError, match="no active credential lease"):
        broker.lease(ProfileId.BLUE, "a" * 32)


@pytest.mark.parametrize("value", ["", "CHANGE_ME", "please-replace_me-now"])
def test_ephemeral_broker_rejects_missing_or_placeholder_credentials(
    value: str,
) -> None:
    broker = EphemeralCredentialBroker(
        {"ANTHROPIC_API_KEY": "model-secret", "INDEXER_PASSWORD": value}
    )

    with pytest.raises(WorkbenchCredentialError, match="INDEXER_PASSWORD"):
        broker.prepare(ProfileId.BLUE, "a" * 32, ("INDEXER_PASSWORD",))


def test_renderer_emits_a_standard_strict_mcp_config_with_trace_handoff(
    tmp_path: Path,
) -> None:
    payload_root = _payload_with_profile(tmp_path / "payload", ProfileId.BLUE)
    state_dir = (tmp_path / "state").resolve()

    config_path = render_profile_config(
        profile=ProfileId.BLUE,
        payload_root=payload_root,
        output_dir=tmp_path / "generated",
        state_dir=state_dir,
        node_executable=Path("/usr/bin/node"),
        run_id="a" * 32,
        credential_aliases=profile_for(ProfileId.BLUE).credential_aliases,
    )

    document = json.loads(config_path.read_text(encoding="utf-8"))
    assert set(document) == {"mcpServers"}
    for server_id, server in document["mcpServers"].items():
        assert server["command"] == "/usr/bin/node"
        assert Path(server["args"][0]).is_absolute()
        assert Path(server["args"][0]).is_relative_to(payload_root.resolve())
        assert server["env"]["APTL_STATE_DIR"] == str(state_dir)
        assert server["env"]["APTL_MCP_DISABLE_DOTENV"] == "1"
        expected_aliases = next(
            entry.credential_aliases
            for entry in profile_for(ProfileId.BLUE).servers
            if entry.server_id == server_id
        )
        for alias in expected_aliases:
            assert server["env"][alias] == f"${{{alias}}}"


def test_blue_profile_uses_the_existing_mcp_credential_contracts() -> None:
    aliases = {
        server.server_id: server.credential_aliases
        for server in profile_for(ProfileId.BLUE).servers
    }

    assert aliases["aptl-indexer"] == (
        "INDEXER_USERNAME",
        "INDEXER_PASSWORD",
        "API_USERNAME",
        "API_PASSWORD",
    )
    assert aliases["aptl-wazuh"] == aliases["aptl-indexer"]
    assert aliases["aptl-network"] == ("INDEXER_USERNAME", "INDEXER_PASSWORD")


def test_real_stdio_probe_performs_initialize_and_tools_list(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "workbench_mcp_server.py"

    tools = probe_mcp_server(
        "fixture",
        sys.executable,
        [str(fixture)],
        {"PATH": "/usr/local/bin:/usr/bin:/bin"},
    )

    assert tools == ("fixture_read", "fixture_write")


def test_claude_adapter_uses_fixed_argv_minimal_env_and_stdin(
    tmp_path: Path,
) -> None:
    executable = _executable(tmp_path / "claude")
    runner = _RecordingRunner(
        ProcessResult(
            returncode=0,
            stdout=b'{"type":"result","subtype":"success","is_error":false,'
            b'"result":"Use the indexed alert."}',
            stderr=b"",
        )
    )
    adapter = ClaudeCodeManagedAgentAdapter(
        claude_executable=executable,
        work_dir=tmp_path / "work",
        runner=runner,
        inventory_probe=lambda *_args: ("kali_info",),
    )
    config_path = _single_server_config(tmp_path)
    launch = ProfileLaunch(
        profile=ProfileId.RED,
        run_id="a" * 32,
        client_config_path=config_path,
        policy_version="participant-workbench-profile/v1",
    )
    handle = adapter.launch(
        launch,
        {
            "ANTHROPIC_API_KEY": "model-secret",
            "UNSELECTED_BLUE_SECRET": "must-not-pass",
        },
    )
    assert adapter.list_tools(handle) == {"aptl-red": ("kali_info",)}

    response = adapter.respond(handle, "Inspect the target.")

    assert response == "Use the indexed alert."
    invocation = runner.invocations[0]
    assert invocation.stdin == b"Inspect the target."
    assert "Inspect the target." not in invocation.argv
    assert invocation.env["ANTHROPIC_API_KEY"] == "model-secret"
    assert "UNSELECTED_BLUE_SECRET" not in invocation.env
    assert invocation.env["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1"
    assert "--bare" in invocation.argv
    assert "--strict-mcp-config" in invocation.argv
    assert "--no-session-persistence" in invocation.argv
    assert _option_value(invocation.argv, "--max-budget-usd") == "1.00"
    assert _option_value(invocation.argv, "--tools") == ""
    assert _option_value(invocation.argv, "--permission-mode") == "dontAsk"
    assert _option_value(invocation.argv, "--mcp-config") == str(config_path)
    assert _option_value(invocation.argv, "--allowedTools") == (
        "mcp__aptl-red__kali_info"
    )


def test_claude_adapter_rejects_oversized_prompts_and_failed_results(
    tmp_path: Path,
) -> None:
    executable = _executable(tmp_path / "claude")
    runner = _RecordingRunner(
        ProcessResult(returncode=1, stdout=b"", stderr=b"provider leaked detail")
    )
    adapter = ClaudeCodeManagedAgentAdapter(
        claude_executable=executable,
        work_dir=tmp_path / "work",
        runner=runner,
        inventory_probe=lambda *_args: ("kali_info",),
        max_prompt_chars=8,
    )
    handle = adapter.launch(
        ProfileLaunch(
            profile=ProfileId.RED,
            run_id="a" * 32,
            client_config_path=_single_server_config(tmp_path),
            policy_version="participant-workbench-profile/v1",
        ),
        {"ANTHROPIC_API_KEY": "model-secret"},
    )
    adapter.list_tools(handle)

    with pytest.raises(AgentExecutionError, match="message exceeds"):
        adapter.respond(handle, "x" * 9)
    with pytest.raises(AgentExecutionError, match="agent request failed") as error:
        adapter.respond(handle, "short")
    assert "provider leaked detail" not in str(error.value)


def test_claude_adapter_rejects_config_tampering_after_inventory(
    tmp_path: Path,
) -> None:
    runner = _RecordingRunner(
        ProcessResult(
            returncode=0,
            stdout=b'{"type":"result","is_error":false,"result":"ok"}',
            stderr=b"",
        )
    )
    config_path = _single_server_config(tmp_path)
    adapter = ClaudeCodeManagedAgentAdapter(
        claude_executable=_executable(tmp_path / "claude"),
        work_dir=tmp_path / "work",
        runner=runner,
        inventory_probe=lambda *_args: ("kali_info",),
    )
    handle = adapter.launch(
        ProfileLaunch(
            profile=ProfileId.RED,
            run_id="a" * 32,
            client_config_path=config_path,
            policy_version="participant-workbench-profile/v1",
        ),
        {"ANTHROPIC_API_KEY": "model-secret"},
    )
    adapter.list_tools(handle)
    config_path.write_text('{"mcpServers":{}}', encoding="utf-8")

    with pytest.raises(AgentExecutionError, match="config changed"):
        adapter.respond(handle, "inspect")
    assert runner.invocations == []


def test_bounded_runner_terminates_output_overflow_and_timeout(
    tmp_path: Path,
) -> None:
    runner = BoundedProcessRunner()
    environment = {"PATH": "/usr/local/bin:/usr/bin:/bin"}

    with pytest.raises(AgentExecutionError, match="output exceeded"):
        runner.run(
            (sys.executable, "-c", "print('x' * 10000)"),
            env=environment,
            cwd=tmp_path,
            stdin=b"",
            timeout_seconds=2,
            max_output_bytes=32,
        )
    with pytest.raises(AgentExecutionError, match="timeout"):
        runner.run(
            (sys.executable, "-c", "import time; time.sleep(10)"),
            env=environment,
            cwd=tmp_path,
            stdin=b"",
            timeout_seconds=0.05,
            max_output_bytes=32,
        )


def test_appliance_factory_wires_the_production_workbench_without_operator_routes(
    tmp_path: Path,
) -> None:
    from aptl.workbench.bootstrap import (
        ApplianceWorkbenchSettings,
        create_appliance_workbench_app,
    )

    app = create_appliance_workbench_app(
        ApplianceWorkbenchSettings(
            payload_root=tmp_path / "payload",
            state_dir=tmp_path / "state",
            claude_executable=_executable(tmp_path / "claude"),
            node_executable=Path("/usr/bin/node"),
        ),
        secret_source={"ANTHROPIC_API_KEY": "model-secret"},
        authorizer=lambda request: request.headers.get("X-Seat") == "seat",
    )
    client = TestClient(app)

    assert client.get("/").status_code == 401
    assert client.get("/", headers={"X-Seat": "seat"}).status_code == 200
    assert client.get("/api/lab/status", headers={"X-Seat": "seat"}).status_code == 404


class _Invocation:
    def __init__(
        self,
        argv: tuple[str, ...],
        env: dict[str, str],
        stdin: bytes,
    ) -> None:
        self.argv = argv
        self.env = env
        self.stdin = stdin


class _RecordingRunner:
    def __init__(self, result: ProcessResult) -> None:
        self._result = result
        self.invocations: list[_Invocation] = []

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
        del cwd, timeout_seconds, max_output_bytes
        self.invocations.append(_Invocation(argv, env, stdin))
        return self._result


def _single_server_config(tmp_path: Path) -> Path:
    artifact = tmp_path / "payload" / "mcp" / "mcp-red" / "build" / "index.js"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.touch()
    config = tmp_path / "red.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "aptl-red": {
                        "command": "/usr/bin/node",
                        "args": [str(artifact)],
                        "env": {
                            "APTL_MCP_DISABLE_DOTENV": "1",
                            "APTL_STATE_DIR": str(tmp_path / "state"),
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    config.chmod(0o600)
    return config


def _payload_with_profile(payload_root: Path, profile: ProfileId) -> Path:
    for server in profile_for(profile).servers:
        artifact = payload_root / server.artifact_ref
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.touch()
    return payload_root


def _executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def _option_value(argv: tuple[str, ...], option: str) -> str:
    return argv[argv.index(option) + 1]
