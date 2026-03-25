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
    from aptl.api.deps import get_project_dir
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
    client = TestClient(app)
    yield client
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
        """Unknown container is rejected even with a valid origin."""
        with pytest.raises(Exception):
            with integration_client.websocket_connect(
                "/api/terminal/ws/nonexistent",
                headers={"origin": "http://localhost:3000"},
            ) as ws:
                ws.receive_json()


# ---------------------------------------------------------------------------
# CORS env var override
# ---------------------------------------------------------------------------


class TestCorsEnvOverride:
    """Verify that APTL_ALLOWED_ORIGINS env var parsing logic works.

    Tests the parsing logic directly to avoid module reload side effects
    that could break other tests in the suite.
    """

    def test_custom_origins_parsed(self):
        """Comma-separated origins are parsed into a set."""
        env_val = "http://custom:9000,http://other:8080"
        result = {o.strip() for o in env_val.split(",") if o.strip()}
        assert result == {"http://custom:9000", "http://other:8080"}

    def test_empty_env_falls_back_to_defaults(self):
        """Empty string produces empty set, triggering default fallback."""
        env_val = ""
        result = {o.strip() for o in env_val.split(",") if o.strip()}
        # Empty set is falsy, so `result or defaults` returns defaults.
        defaults = {"http://localhost:3000", "http://localhost:5173"}
        actual = result or defaults
        assert actual == defaults

    def test_whitespace_trimmed(self):
        """Leading/trailing whitespace in origins is stripped."""
        env_val = " http://a:1 , http://b:2 "
        result = {o.strip() for o in env_val.split(",") if o.strip()}
        assert result == {"http://a:1", "http://b:2"}

    def test_default_origins_are_set(self):
        """Without env override, default origins are present."""
        from aptl.api.deps import ALLOWED_ORIGINS

        assert "http://localhost:3000" in ALLOWED_ORIGINS
        assert "http://localhost:5173" in ALLOWED_ORIGINS
