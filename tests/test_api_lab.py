"""Tests for lab API endpoints."""

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


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


async def _noop_sleep(_seconds):
    """Instant replacement for asyncio.sleep in tests."""


class TestLabEventGenerator:
    """Test the SSE generator directly (avoids HTTP streaming hangs)."""

    @patch("aptl.api.routers.lab.asyncio.sleep", _noop_sleep)
    @patch("aptl.api.routers.lab._build_status_response")
    def test_emits_initial_status(self, mock_build):
        from aptl.api.routers.lab import _lab_event_generator
        from aptl.api.schemas import LabStatusResponse

        mock_build.return_value = LabStatusResponse(running=False, containers=[])

        async def run():
            gen = _lab_event_generator()
            event = await gen.__anext__()
            await gen.aclose()
            return event

        event = asyncio.run(run())
        assert event["event"] == "lab_status"
        data = json.loads(event["data"])
        assert data["running"] is False

    @patch("aptl.api.routers.lab.asyncio.sleep", _noop_sleep)
    @patch("aptl.api.routers.lab._build_status_response")
    def test_emits_on_state_change(self, mock_build):
        from aptl.api.routers.lab import _lab_event_generator
        from aptl.api.schemas import ContainerInfo, LabStatusResponse

        call_count = 0

        def changing_status():
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                return LabStatusResponse(running=False, containers=[])
            return LabStatusResponse(
                running=True,
                containers=[ContainerInfo(name="aptl-victim", state="running")],
            )

        mock_build.side_effect = changing_status

        async def run():
            gen = _lab_event_generator()
            first = await gen.__anext__()
            second = await gen.__anext__()
            await gen.aclose()
            return first, second

        first, second = asyncio.run(run())
        assert json.loads(first["data"])["running"] is False
        assert json.loads(second["data"])["running"] is True
        assert json.loads(second["data"])["containers"][0]["name"] == "aptl-victim"

    @patch("aptl.api.routers.lab.asyncio.sleep", _noop_sleep)
    @patch("aptl.api.routers.lab._build_status_response")
    def test_emits_error_event(self, mock_build):
        from aptl.api.routers.lab import _lab_event_generator

        mock_build.side_effect = RuntimeError("docker daemon not running")

        async def run():
            gen = _lab_event_generator()
            event = await gen.__anext__()
            await gen.aclose()
            return event

        event = asyncio.run(run())
        assert event["event"] == "error"
        assert "docker daemon not running" in event["data"]

    @patch("aptl.api.routers.lab.asyncio.sleep", _noop_sleep)
    @patch("aptl.api.routers.lab._build_status_response")
    def test_skips_duplicate_status(self, mock_build):
        from aptl.api.routers.lab import _lab_event_generator
        from aptl.api.schemas import LabStatusResponse

        # Same status every time — only first poll should emit
        mock_build.return_value = LabStatusResponse(running=False, containers=[])

        async def run():
            gen = _lab_event_generator()
            event1 = await gen.__anext__()
            # Second __anext__ should NOT yield because state didn't change.
            # It will loop and sleep forever, so we time it out.
            got_second = False
            try:
                await asyncio.wait_for(gen.__anext__(), timeout=0.05)
                got_second = True
            except asyncio.TimeoutError:
                pass
            await gen.aclose()
            return got_second

        got_second = asyncio.run(run())
        assert got_second is False

    def test_lab_events_endpoint_returns_sse(self):
        """Verify the endpoint function returns an EventSourceResponse."""
        from aptl.api.routers.lab import lab_events
        from sse_starlette.sse import EventSourceResponse

        result = asyncio.run(lab_events())
        assert isinstance(result, EventSourceResponse)


class TestContainerInfoPortParsing:
    def test_string_ports(self):
        from aptl.api.schemas import ContainerInfo

        info = ContainerInfo.from_compose_dict({
            "Name": "web",
            "Ports": "0.0.0.0:443->443/tcp, 0.0.0.0:80->80/tcp",
        })
        assert info.ports == ["0.0.0.0:443->443/tcp", "0.0.0.0:80->80/tcp"]

    def test_publisher_dict_ports(self):
        from aptl.api.schemas import ContainerInfo

        info = ContainerInfo.from_compose_dict({
            "Name": "web",
            "Publishers": [
                {"URL": "0.0.0.0", "TargetPort": 443, "PublishedPort": 8443, "Protocol": "tcp"},
                {"URL": "", "TargetPort": 80, "PublishedPort": 0, "Protocol": "tcp"},
            ],
        })
        assert "0.0.0.0:8443->443/tcp" in info.ports
        # PublishedPort=0 means not published
        assert len(info.ports) == 1

    def test_list_of_string_ports(self):
        from aptl.api.schemas import ContainerInfo

        info = ContainerInfo.from_compose_dict({
            "Name": "web",
            "Ports": ["443/tcp", "80/tcp"],
        })
        assert info.ports == ["443/tcp", "80/tcp"]

    def test_non_list_non_string_ports(self):
        from aptl.api.schemas import ContainerInfo

        info = ContainerInfo.from_compose_dict({
            "Name": "web",
            "Ports": 12345,
        })
        assert info.ports == []
