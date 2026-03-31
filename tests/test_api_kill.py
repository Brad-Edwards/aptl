"""Tests for the kill switch API endpoint."""

from unittest.mock import patch

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


@pytest.fixture
def api_client(tmp_path):
    """Create a FastAPI test client with DI override for project_dir."""
    from aptl.api.deps import get_project_dir
    from aptl.api.main import app
    from starlette.testclient import TestClient

    app.dependency_overrides[get_project_dir] = lambda: tmp_path
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


class TestKillEndpoint:
    """Tests for POST /api/lab/kill."""

    @patch("aptl.api.routers.kill.execute_kill")
    def test_kill_success(self, mock_execute, api_client):
        from aptl.core.kill import KillResult

        mock_execute.return_value = KillResult(
            success=True,
            mcp_processes_killed=2,
            session_cleared=True,
        )

        response = api_client.post("/api/lab/kill")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["mcp_processes_killed"] == 2
        assert data["session_cleared"] is True

    @patch("aptl.api.routers.kill.execute_kill")
    def test_kill_with_containers(self, mock_execute, api_client):
        from aptl.core.kill import KillResult

        mock_execute.return_value = KillResult(
            success=True,
            mcp_processes_killed=1,
            containers_stopped=True,
        )

        response = api_client.post("/api/lab/kill?containers=true")

        assert response.status_code == 200
        data = response.json()
        assert data["containers_stopped"] is True
        mock_execute.assert_called_once()
        assert mock_execute.call_args.kwargs["containers"] is True

    @patch("aptl.api.routers.kill.execute_kill")
    def test_kill_failure(self, mock_execute, api_client):
        from aptl.core.kill import KillResult

        mock_execute.return_value = KillResult(
            success=False,
            errors=["Permission denied", "Docker not running"],
        )

        response = api_client.post("/api/lab/kill")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert len(data["errors"]) == 2

    @patch("aptl.api.routers.kill.execute_kill")
    def test_kill_returns_process_count(self, mock_execute, api_client):
        from aptl.core.kill import KillResult

        mock_execute.return_value = KillResult(
            success=True,
            mcp_processes_killed=5,
        )

        response = api_client.post("/api/lab/kill")

        assert response.status_code == 200
        assert response.json()["mcp_processes_killed"] == 5

    @patch("aptl.api.routers.kill.execute_kill")
    def test_kill_default_no_containers(self, mock_execute, api_client):
        from aptl.core.kill import KillResult

        mock_execute.return_value = KillResult(success=True)

        response = api_client.post("/api/lab/kill")

        assert response.status_code == 200
        assert mock_execute.call_args.kwargs["containers"] is False
