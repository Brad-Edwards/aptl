"""Behavioural coverage for the in-appliance participant workbench boundary."""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aptl.core.session import ScenarioSession
from aptl.core.runstore import LocalRunStore


def test_profiles_expose_exactly_the_allowed_mcp_servers() -> None:
    from aptl.workbench import ProfileId, profile_for

    assert profile_for(ProfileId.RED).server_ids == ("aptl-red",)
    assert profile_for(ProfileId.GUIDED_BLUE).server_ids == (
        "aptl-indexer",
        "aptl-wazuh",
    )
    assert profile_for(ProfileId.BLUE).server_ids == (
        "aptl-casemgmt",
        "aptl-indexer",
        "aptl-network",
        "aptl-soar",
        "aptl-threatintel",
        "aptl-wazuh",
    )
    assert profile_for(ProfileId.RED).servers[0].tool_names == (
        "kali_info",
        "kali_run_command",
        "kali_interactive_session",
        "kali_background_session",
        "kali_session_command",
        "kali_list_sessions",
        "kali_close_session",
        "kali_get_session_output",
        "kali_close_all_sessions",
    )
    assert {
        server.server_id: server.tool_names
        for server in profile_for(ProfileId.BLUE).servers
    } == {
        "aptl-casemgmt": (
            "cases_list_cases",
            "cases_create_case",
            "cases_add_observable",
            "cases_update_case",
            "cases_create_alert",
        ),
        "aptl-indexer": (
            "indexer_query",
            "indexer_create_rule",
            "indexer_restart_manager",
            "indexer_get_rule_file",
        ),
        "aptl-network": (
            "network_query_ids_alerts",
            "network_query_dns_events",
            "network_query_network_flows",
            "network_query_web_attacks",
        ),
        "aptl-soar": (
            "soar_list_workflows",
            "soar_get_workflow",
            "soar_execute_workflow",
            "soar_list_executions",
            "soar_search_workflows",
        ),
        "aptl-threatintel": (
            "threatintel_search_iocs",
            "threatintel_get_events",
            "threatintel_add_indicator",
            "threatintel_correlate_observable",
        ),
        "aptl-wazuh": (
            "wazuh_query_alerts",
            "wazuh_query_logs",
            "wazuh_create_detection_rule",
        ),
    }
    assert {
        server.server_id: server.tool_names
        for server in profile_for(ProfileId.GUIDED_BLUE).servers
    } == {
        server.server_id: server.tool_names
        for server in profile_for(ProfileId.BLUE).servers
        if server.server_id in {"aptl-indexer", "aptl-wazuh"}
    }
    assert profile_for(ProfileId.GUIDED_BLUE).bookmark_refs == (
        "aptl-guide",
        "soc-wazuh",
    )
    assert profile_for(ProfileId.GUIDED_BLUE).credential_aliases == (
        "API_PASSWORD",
        "API_USERNAME",
        "INDEXER_PASSWORD",
        "INDEXER_USERNAME",
    )


def test_profile_renderer_keeps_credentials_out_of_client_config(
    tmp_path: Path,
) -> None:
    from aptl.workbench import ProfileId, render_profile_config

    payload_root = tmp_path / "payload"
    for entrypoint in (
        "mcp/mcp-indexer/build/index.js",
        "mcp/mcp-wazuh/build/index.js",
        "mcp/mcp-network/build/index.js",
        "mcp/mcp-threatintel/build/index.js",
        "mcp/mcp-casemgmt/build/index.js",
        "mcp/mcp-soar/build/index.js",
    ):
        target = payload_root / entrypoint
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()

    config_path = render_profile_config(
        profile=ProfileId.BLUE,
        payload_root=payload_root,
        output_dir=tmp_path / "generated",
        state_dir=tmp_path / "state",
        node_executable=Path(sys.executable),
        run_id="a" * 32,
        credential_aliases={
            "INDEXER_USERNAME",
            "INDEXER_PASSWORD",
            "API_USERNAME",
            "API_PASSWORD",
            "MISP_API_KEY",
            "THEHIVE_API_KEY",
            "SHUFFLE_API_KEY",
        },
    )

    rendered = config_path.read_text(encoding="utf-8")
    parsed = json.loads(rendered)
    assert set(parsed["mcpServers"]) == {
        "aptl-casemgmt",
        "aptl-indexer",
        "aptl-network",
        "aptl-soar",
        "aptl-threatintel",
        "aptl-wazuh",
    }
    assert set(parsed) == {"mcpServers"}
    assert all(
        server["env"]["APTL_MCP_DISABLE_DOTENV"] == "1"
        for server in parsed["mcpServers"].values()
    )
    assert "model-secret" not in rendered
    assert config_path.stat().st_mode & 0o777 == 0o600


def test_profile_renderer_rejects_missing_required_credential_alias(
    tmp_path: Path,
) -> None:
    from aptl.workbench import (
        ProfileId,
        WorkbenchConfigurationError,
        render_profile_config,
    )

    with pytest.raises(WorkbenchConfigurationError, match="MISP_API_KEY"):
        render_profile_config(
            profile=ProfileId.BLUE,
            payload_root=tmp_path,
            output_dir=tmp_path / "generated",
            state_dir=tmp_path / "state",
            node_executable=Path(sys.executable),
            run_id="a" * 32,
            credential_aliases={
                "INDEXER_USERNAME",
                "INDEXER_PASSWORD",
                "API_USERNAME",
                "API_PASSWORD",
                "THEHIVE_API_KEY",
                "SHUFFLE_API_KEY",
            },
        )


def test_profile_renderer_rejects_an_existing_or_symlinked_output(
    tmp_path: Path,
) -> None:
    from aptl.workbench import (
        ProfileId,
        WorkbenchConfigurationError,
        render_profile_config,
    )

    output_dir = tmp_path / "generated"
    outside = tmp_path / "outside"
    outside.mkdir()
    output_dir.symlink_to(outside, target_is_directory=True)
    artifact = tmp_path / "mcp" / "mcp-red" / "build" / "index.js"
    artifact.parent.mkdir(parents=True)
    artifact.touch()

    with pytest.raises(WorkbenchConfigurationError):
        render_profile_config(
            profile=ProfileId.RED,
            payload_root=tmp_path,
            output_dir=output_dir,
            state_dir=tmp_path / "state",
            node_executable=Path(sys.executable),
            run_id="a" * 32,
            credential_aliases=set(),
        )


def test_profile_switch_closes_the_previous_runtime_and_records_the_active_trace(
    tmp_path: Path,
) -> None:
    from aptl.workbench import ProfileId, WorkbenchRuntime

    session_manager = ScenarioSession(tmp_path / "state")
    active_session = session_manager.start("techvault")
    adapter = _FakeAdapter()
    credentials = _FakeCredentials()
    payload_root = _payload_with_all_artifacts(tmp_path / "payload")
    runtime = WorkbenchRuntime(
        session_manager,
        adapter,
        LocalRunStore(tmp_path / "runs"),
        payload_root=payload_root,
        generated_config_dir=tmp_path / "generated",
        credential_broker=credentials,
        node_executable=Path(sys.executable),
    )

    red = runtime.start(ProfileId.RED)
    blue = runtime.switch(ProfileId.GUIDED_BLUE)

    assert red.run_id == active_session.trace_id
    assert blue.run_id == active_session.trace_id
    assert adapter.closed_profiles == [ProfileId.RED]
    assert [launch.profile for launch in adapter.launches] == [
        ProfileId.RED,
        ProfileId.GUIDED_BLUE,
    ]
    assert credentials.prepared_profiles == [ProfileId.RED, ProfileId.GUIDED_BLUE]
    assert credentials.destroyed_profiles == [ProfileId.RED]
    records = (
        tmp_path / "runs" / active_session.trace_id / "workbench" / "events.jsonl"
    ).read_text(encoding="utf-8")
    assert active_session.trace_id in records
    assert "_unbound" not in records
    assert not red.client_config_path.exists()


def test_profile_runtime_fails_closed_without_an_active_scenario(
    tmp_path: Path,
) -> None:
    from aptl.workbench import ProfileId, WorkbenchStateError, WorkbenchRuntime

    runtime = WorkbenchRuntime(
        ScenarioSession(tmp_path / "state"),
        _FakeAdapter(),
        LocalRunStore(tmp_path / "runs"),
        payload_root=_payload_with_all_artifacts(tmp_path / "payload"),
        generated_config_dir=tmp_path / "generated",
        credential_broker=_FakeCredentials(),
        node_executable=Path(sys.executable),
    )

    with pytest.raises(WorkbenchStateError, match="active scenario"):
        runtime.start(ProfileId.RED)


def test_runtime_creates_its_managed_config_parent_on_fresh_state(
    tmp_path: Path,
) -> None:
    from aptl.workbench import ProfileId, WorkbenchRuntime

    session_manager = ScenarioSession(tmp_path / "state")
    session_manager.start("techvault")
    generated = tmp_path / "state" / "workbench" / "mcp-config"
    runtime = WorkbenchRuntime(
        session_manager,
        _FakeAdapter(),
        LocalRunStore(tmp_path / "state" / "runs"),
        payload_root=_payload_with_all_artifacts(tmp_path / "payload"),
        generated_config_dir=generated,
        credential_broker=_FakeCredentials(),
        node_executable=Path(sys.executable),
    )

    launch = runtime.start(ProfileId.RED)

    assert launch.client_config_path.parent == generated
    assert generated.parent.stat().st_mode & 0o777 == 0o700


def test_failed_agent_start_revokes_credentials_and_removes_generated_config(
    tmp_path: Path,
) -> None:
    from aptl.workbench import ProfileId, WorkbenchRuntime

    session_manager = ScenarioSession(tmp_path / "state")
    session_manager.start("techvault")
    credentials = _FakeCredentials()
    runtime = WorkbenchRuntime(
        session_manager,
        _FailingAdapter(),
        LocalRunStore(tmp_path / "runs"),
        payload_root=_payload_with_all_artifacts(tmp_path / "payload"),
        generated_config_dir=tmp_path / "generated",
        credential_broker=credentials,
        node_executable=Path(sys.executable),
    )

    with pytest.raises(RuntimeError, match="agent launch failed"):
        runtime.start(ProfileId.RED)

    assert credentials.destroyed_profiles == [ProfileId.RED]
    assert not list((tmp_path / "generated").glob("*.json"))


def test_runtime_rejects_a_profile_with_an_unexpected_mcp_tool_inventory(
    tmp_path: Path,
) -> None:
    from aptl.workbench import ProfileId, WorkbenchRuntime, WorkbenchStateError

    session_manager = ScenarioSession(tmp_path / "state")
    session_manager.start("techvault")
    adapter = _UnexpectedInventoryAdapter()
    credentials = _FakeCredentials()
    runtime = WorkbenchRuntime(
        session_manager,
        adapter,
        LocalRunStore(tmp_path / "runs"),
        payload_root=_payload_with_all_artifacts(tmp_path / "payload"),
        generated_config_dir=tmp_path / "generated",
        credential_broker=credentials,
        node_executable=Path(sys.executable),
    )

    with pytest.raises(WorkbenchStateError, match="MCP tool inventory"):
        runtime.start(ProfileId.RED)

    assert adapter.closed_profiles == [ProfileId.RED]
    assert credentials.destroyed_profiles == [ProfileId.RED]
    assert not list((tmp_path / "generated").glob("*.json"))


def test_runtime_keeps_a_rejected_agent_until_failed_cleanup_is_retried(
    tmp_path: Path,
) -> None:
    from aptl.workbench import ProfileId, WorkbenchRuntime, WorkbenchStateError

    session_manager = ScenarioSession(tmp_path / "state")
    session_manager.start("techvault")
    adapter = _InventoryFailureWithFailedCloseAdapter()
    credentials = _FakeCredentials()
    runtime = WorkbenchRuntime(
        session_manager,
        adapter,
        LocalRunStore(tmp_path / "runs"),
        payload_root=_payload_with_all_artifacts(tmp_path / "payload"),
        generated_config_dir=tmp_path / "generated",
        credential_broker=credentials,
        node_executable=Path(sys.executable),
    )

    with pytest.raises(WorkbenchStateError, match="cleanup remains incomplete"):
        runtime.start(ProfileId.RED)

    assert runtime.current_launch is not None
    assert runtime.current_launch.profile is ProfileId.RED
    assert credentials.destroyed_profiles == [ProfileId.RED]
    assert not list((tmp_path / "generated").glob("*.json"))
    with pytest.raises(WorkbenchStateError, match="already running"):
        runtime.start(ProfileId.BLUE)

    runtime.close()

    assert adapter.close_attempts == 2
    assert adapter.closed_profiles == [ProfileId.RED]
    assert runtime.current_launch is None
    runtime.start(ProfileId.BLUE)


def test_runtime_validates_a_switch_target_before_closing_the_active_profile(
    tmp_path: Path,
) -> None:
    from aptl.workbench import (
        ProfileId,
        WorkbenchConfigurationError,
        WorkbenchRuntime,
    )

    session_manager = ScenarioSession(tmp_path / "state")
    session_manager.start("techvault")
    adapter = _FakeAdapter()
    credentials = _FakeCredentials()
    runtime = WorkbenchRuntime(
        session_manager,
        adapter,
        LocalRunStore(tmp_path / "runs"),
        payload_root=_payload_with_all_artifacts(tmp_path / "payload"),
        generated_config_dir=tmp_path / "generated",
        credential_broker=credentials,
        node_executable=Path(sys.executable),
    )
    red = runtime.start(ProfileId.RED)

    with pytest.raises(
        WorkbenchConfigurationError, match="unknown participant profile"
    ):
        runtime.switch("unknown")

    assert runtime.current_launch == red
    assert adapter.closed_profiles == []
    assert credentials.destroyed_profiles == []
    assert red.client_config_path.exists()


def test_profile_switch_waits_for_an_active_agent_turn(tmp_path: Path) -> None:
    from aptl.workbench import ProfileId, WorkbenchRuntime

    session_manager = ScenarioSession(tmp_path / "state")
    session_manager.start("techvault")
    adapter = _BlockingAdapter()
    runtime = WorkbenchRuntime(
        session_manager,
        adapter,
        LocalRunStore(tmp_path / "runs"),
        payload_root=_payload_with_all_artifacts(tmp_path / "payload"),
        generated_config_dir=tmp_path / "generated",
        credential_broker=_FakeCredentials(),
        node_executable=Path(sys.executable),
    )
    runtime.start(ProfileId.RED)
    turn = threading.Thread(target=runtime.respond, args=("inspect",))
    switch_done = threading.Event()

    def switch_profile() -> None:
        runtime.switch(ProfileId.BLUE)
        switch_done.set()

    turn.start()
    assert adapter.turn_started.wait(timeout=1)
    switch = threading.Thread(target=switch_profile)
    switch.start()

    assert not switch_done.wait(timeout=0.1)
    assert adapter.closed_profiles == []

    adapter.release_turn.set()
    turn.join(timeout=1)
    switch.join(timeout=1)
    assert switch_done.is_set()
    assert adapter.closed_profiles == [ProfileId.RED]
    assert runtime.current_launch is not None
    assert runtime.current_launch.profile is ProfileId.BLUE


def test_browser_workbench_is_a_separate_authenticated_profile_surface(
    tmp_path: Path,
) -> None:
    from aptl.workbench.app import create_participant_workbench_app
    from aptl.workbench import WorkbenchRuntime

    session_manager = ScenarioSession(tmp_path / "state")
    session_manager.start("techvault")
    runtime = WorkbenchRuntime(
        session_manager,
        _FakeAdapter(),
        LocalRunStore(tmp_path / "runs"),
        payload_root=_payload_with_all_artifacts(tmp_path / "payload"),
        generated_config_dir=tmp_path / "generated",
        credential_broker=_FakeCredentials(),
        node_executable=Path(sys.executable),
    )
    app = create_participant_workbench_app(
        runtime,
        lambda request: request.headers.get("X-APTL-Participant-Session") == "seat",
    )
    client = TestClient(app)
    participant_headers = {"X-APTL-Participant-Session": "seat"}

    assert client.get("/workbench").status_code == 401
    assert (
        client.get(
            "/api/lab/start", headers={"X-APTL-Participant-Session": "seat"}
        ).status_code
        == 404
    )
    assert client.post("/workbench/profiles/red").status_code == 401
    assert client.post("/workbench/messages", json={"message": "help"}).status_code == 401
    assert client.delete("/workbench/profile").status_code == 401
    assert client.get("/openapi.json").status_code == 404

    response = client.post(
        "/workbench/profiles/red", headers=participant_headers
    )
    assert response.status_code == 200
    assert response.json() == {
        "profile": "red",
        "run_id": session_manager.get_active().trace_id,
    }

    view = client.get("/workbench", headers=participant_headers)
    assert view.status_code == 200
    assert view.json()["mcp_servers"] == ["aptl-red"]
    assert view.json()["bookmarks"] == [
        {"label": "APTL guide", "href": "/guide/"},
        {"label": "Kali desktop", "href": "/desktop/kali/"},
    ]
    assert "docker" not in view.json()

    invalid = client.post(
        "/workbench/messages",
        headers=participant_headers,
        json={"message": "", "command": "id"},
    )
    assert invalid.status_code == 422
    answer = client.post(
        "/workbench/messages",
        headers=participant_headers,
        json={"message": "inspect the target"},
    )
    assert answer.status_code == 200
    assert answer.json() == {"response": "response to inspect the target"}

    page = client.get("/", headers=participant_headers)
    assert page.status_code == 200
    assert 'id="message"' in page.text
    assert "/workbench/messages" in page.text
    assert "/api/lab/start" not in page.text
    assert page.headers["content-security-policy"].startswith("default-src 'self'")

    records = (
        tmp_path
        / "runs"
        / session_manager.get_active().trace_id
        / "workbench"
        / "events.jsonl"
    ).read_text(encoding="utf-8")
    parsed_records = [json.loads(line) for line in records.splitlines()]
    assert any(record["event"] == "agent_turn" for record in parsed_records)
    assert "inspect the target" not in records
    assert "response to inspect the target" not in records

    response = client.post(
        "/workbench/profiles/guided-blue",
        headers=participant_headers,
    )
    assert response.status_code == 200
    view = client.get("/workbench", headers=participant_headers)
    assert view.json()["profile"] == "guided-blue"
    assert view.json()["mcp_servers"] == ["aptl-indexer", "aptl-wazuh"]
    assert view.json()["bookmarks"] == [
        {"label": "APTL guide", "href": "/guide/"},
        {"label": "Wazuh", "href": "/soc/wazuh/"},
    ]

    closed = client.delete("/workbench/profile", headers=participant_headers)
    assert closed.status_code == 200
    assert closed.json() == {"status": "closed"}
    assert client.get("/workbench", headers=participant_headers).json()["profile"] is None


class _FakeAdapter:
    def __init__(self) -> None:
        self.launches: list[object] = []
        self.closed_profiles: list[object] = []

    def launch(self, launch: object, credentials: object) -> object:
        del credentials
        self.launches.append(launch)
        return launch

    def close(self, handle: object) -> None:
        self.closed_profiles.append(handle.profile)

    def list_tools(self, handle: object) -> dict[str, list[str]]:
        from aptl.workbench.profiles import profile_for

        profile = profile_for(handle.profile)
        return {server.server_id: list(server.tool_names) for server in profile.servers}

    def respond(self, handle: object, message: str) -> str:
        del handle
        return f"response to {message}"


class _FakeCredentials:
    def __init__(self) -> None:
        self.prepared_profiles: list[object] = []
        self.destroyed_profiles: list[object] = []

    def prepare(
        self, profile: object, run_id: str, aliases: tuple[str, ...]
    ) -> dict[str, str]:
        del run_id, aliases
        self.prepared_profiles.append(profile)
        return {}

    def destroy(self, profile: object, run_id: str) -> None:
        del run_id
        self.destroyed_profiles.append(profile)


class _BlockingAdapter(_FakeAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.turn_started = threading.Event()
        self.release_turn = threading.Event()

    def respond(self, handle: object, message: str) -> str:
        del handle, message
        self.turn_started.set()
        assert self.release_turn.wait(timeout=1)
        return "complete"


class _FailingAdapter:
    def launch(self, launch: object, credentials: object) -> object:
        del launch, credentials
        raise RuntimeError("agent launch failed")

    def close(self, handle: object) -> None:
        del handle


class _UnexpectedInventoryAdapter(_FakeAdapter):
    def list_tools(self, handle: object) -> dict[str, list[str]]:
        del handle
        return {"aptl-red": ["unexpected_tool"]}


class _InventoryFailureWithFailedCloseAdapter(_UnexpectedInventoryAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.close_attempts = 0

    def close(self, handle: object) -> None:
        self.close_attempts += 1
        if self.close_attempts == 1:
            raise RuntimeError("agent close failed")
        super().close(handle)

    def list_tools(self, handle: object) -> dict[str, list[str]]:
        if self.close_attempts < 2:
            return super().list_tools(handle)
        return _FakeAdapter.list_tools(self, handle)


def _payload_with_all_artifacts(payload_root: Path) -> Path:
    for profile in (
        "red",
        "indexer",
        "wazuh",
        "network",
        "threatintel",
        "casemgmt",
        "soar",
    ):
        artifact = payload_root / "mcp" / f"mcp-{profile}" / "build" / "index.js"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.touch()
    return payload_root
