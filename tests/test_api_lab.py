"""Tests for lab API endpoints."""

import json
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def api_client():
    """Create a FastAPI test client."""
    from aptl.api.main import app

    # Import here to avoid issues if httpx/fastapi not installed
    from starlette.testclient import TestClient

    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, api_client):
        response = api_client.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestLabStatus:
    @patch("aptl.api.routers.lab.core_lab_status")
    @patch("aptl.api.routers.lab.get_project_dir")
    def test_returns_running_status(self, mock_dir, mock_status, api_client, tmp_path):
        from aptl.core.lab import LabStatus

        mock_dir.return_value = tmp_path
        mock_status.return_value = LabStatus(
            running=True,
            containers=[
                {"Name": "aptl-victim", "State": "running", "Health": "healthy", "Image": "victim:latest"}
            ],
        )

        response = api_client.get("/api/lab/status")

        assert response.status_code == 200
        data = response.json()
        assert data["running"] is True
        assert len(data["containers"]) == 1
        assert data["containers"][0]["name"] == "aptl-victim"

    @patch("aptl.api.routers.lab.core_lab_status")
    @patch("aptl.api.routers.lab.get_project_dir")
    def test_returns_stopped_status(self, mock_dir, mock_status, api_client, tmp_path):
        from aptl.core.lab import LabStatus

        mock_dir.return_value = tmp_path
        mock_status.return_value = LabStatus(running=False, containers=[])

        response = api_client.get("/api/lab/status")

        assert response.status_code == 200
        data = response.json()
        assert data["running"] is False
        assert data["containers"] == []

    @patch("aptl.api.routers.lab.core_lab_status")
    @patch("aptl.api.routers.lab.get_project_dir")
    def test_returns_error(self, mock_dir, mock_status, api_client, tmp_path):
        from aptl.core.lab import LabStatus

        mock_dir.return_value = tmp_path
        mock_status.return_value = LabStatus(
            running=False, error="docker not found"
        )

        response = api_client.get("/api/lab/status")

        assert response.status_code == 200
        data = response.json()
        assert data["error"] == "docker not found"


class TestLabStart:
    @patch("aptl.api.routers.lab.orchestrate_lab_start")
    @patch("aptl.api.routers.lab.get_project_dir")
    def test_start_success(self, mock_dir, mock_start, api_client, tmp_path):
        from aptl.core.lab import LabResult

        mock_dir.return_value = tmp_path
        mock_start.return_value = LabResult(success=True, message="Lab started")

        response = api_client.post("/api/lab/start")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Lab started"

    @patch("aptl.api.routers.lab.orchestrate_lab_start")
    @patch("aptl.api.routers.lab.get_project_dir")
    def test_start_failure(self, mock_dir, mock_start, api_client, tmp_path):
        from aptl.core.lab import LabResult

        mock_dir.return_value = tmp_path
        mock_start.return_value = LabResult(
            success=False, error="Missing .env"
        )

        response = api_client.post("/api/lab/start")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "Missing .env" in data["error"]


class TestLabStop:
    @patch("aptl.api.routers.lab.core_stop_lab")
    @patch("aptl.api.routers.lab.get_project_dir")
    def test_stop_success(self, mock_dir, mock_stop, api_client, tmp_path):
        from aptl.core.lab import LabResult

        mock_dir.return_value = tmp_path
        mock_stop.return_value = LabResult(success=True, message="Lab stopped")

        response = api_client.post("/api/lab/stop")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    @patch("aptl.api.routers.lab.core_stop_lab")
    @patch("aptl.api.routers.lab.get_project_dir")
    def test_stop_failure(self, mock_dir, mock_stop, api_client, tmp_path):
        from aptl.core.lab import LabResult

        mock_dir.return_value = tmp_path
        mock_stop.return_value = LabResult(
            success=False, error="compose down failed"
        )

        response = api_client.post("/api/lab/stop")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
