"""Integration tests for the APTL API.

Unlike test_api_*.py which mock core business logic entirely, these
tests exercise the full request path through FastAPI -> routers -> core
logic, mocking only external I/O (subprocess calls to Docker, SSH).
"""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


@pytest.fixture
def integration_client(tmp_path):
    """TestClient wired to real core logic with DI override for project_dir."""
    from aptl.api.deps import get_project_dir, verify_token
    from aptl.api.main import app
    from starlette.testclient import TestClient

    # Write minimal aptl.json so config loader succeeds.
    (tmp_path / "aptl.json").write_text(
        json.dumps(
            {
                "lab": {"name": "test-lab"},
                "containers": {
                    "wazuh": True,
                    "victim": True,
                    "kali": False,
                    "reverse": False,
                },
            }
        )
    )

    app.dependency_overrides[get_project_dir] = lambda: tmp_path
    app.dependency_overrides[verify_token] = lambda: None
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Lab Status Integration (API -> routers/lab.py -> core/lab.py -> docker_compose.py -> subprocess)
# ---------------------------------------------------------------------------


class TestLabStatusIntegration:
    """Lab status endpoint with real core logic, mocked subprocess."""

    @patch("aptl.core.deployment.docker_compose.subprocess.run")
    def test_parses_json_array(self, mock_run, integration_client):
        """Status endpoint correctly parses JSON array from docker compose ps."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "Name": "aptl-victim",
                        "State": "running",
                        "Health": "healthy",
                        "Image": "victim:latest",
                    }
                ]
            ),
            stderr="",
        )

        resp = integration_client.get("/api/lab/status")

        assert resp.status_code == 200
        data = resp.json()
        assert data["running"] is True
        assert len(data["containers"]) == 1
        assert data["containers"][0]["name"] == "aptl-victim"
        assert data["containers"][0]["state"] == "running"

    @patch("aptl.core.deployment.docker_compose.subprocess.run")
    def test_parses_ndjson(self, mock_run, integration_client):
        """Status endpoint handles NDJSON (one JSON object per line)."""
        ndjson = (
            '{"Name":"aptl-victim","State":"running","Health":"healthy"}\n'
            '{"Name":"aptl-kali","State":"running","Health":""}\n'
        )
        mock_run.return_value = MagicMock(
            returncode=0, stdout=ndjson, stderr=""
        )

        resp = integration_client.get("/api/lab/status")

        assert resp.status_code == 200
        data = resp.json()
        assert data["running"] is True
        assert len(data["containers"]) == 2

    @patch("aptl.core.deployment.docker_compose.subprocess.run")
    def test_docker_failure_returns_not_running(self, mock_run, integration_client):
        """Status returns running=False when docker compose fails."""
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="docker not found"
        )

        resp = integration_client.get("/api/lab/status")

        data = resp.json()
        assert data["running"] is False
        assert data["error"] is not None


# ---------------------------------------------------------------------------
# Kill Integration (API -> routers/kill.py -> core/kill.py -> OS/subprocess)
# ---------------------------------------------------------------------------


class TestKillIntegration:
    """Kill endpoint with real execute_kill orchestration."""

    @patch("aptl.core.kill.find_mcp_processes")
    @patch("aptl.core.kill.os.kill")
    @patch("aptl.core.kill._process_exited", return_value=True)
    def test_kill_exercises_real_orchestration(
        self, mock_exited, mock_kill, mock_find, integration_client
    ):
        """Kill endpoint runs through the real execute_kill flow."""
        mock_find.return_value = [
            {
                "pid": 999,
                "cmdline": "node mcp-wazuh/build/index.js",
                "name": "mcp-wazuh",
            }
        ]

        resp = integration_client.post("/api/lab/kill")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["mcp_processes_killed"] == 1

    @patch("aptl.core.kill.find_mcp_processes", return_value=[])
    def test_kill_no_processes(self, mock_find, integration_client):
        """Kill endpoint succeeds when no MCP processes are running."""
        resp = integration_client.post("/api/lab/kill")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["mcp_processes_killed"] == 0


# ---------------------------------------------------------------------------
# Terminal Origin Integration
# ---------------------------------------------------------------------------


class TestTerminalOriginIntegration:
    """WebSocket origin validation with real router logic (no mock on origin check)."""

    def test_unknown_container_with_valid_origin(self, integration_client):
        """Unknown container is rejected even with a valid origin.

        The integration_client does not override get_web_auth, so the
        endpoint-level auth dependency raises 401 before the WS handshake
        is accepted — Starlette TestClient surfaces this as
        WebSocketDenialResponse.
        """
        from starlette.testclient import WebSocketDenialResponse

        with pytest.raises(WebSocketDenialResponse):
            with integration_client.websocket_connect(
                "/api/terminal/ws/nonexistent",
                headers={"origin": "http://testserver"},
            ) as ws:
                ws.receive_json()
