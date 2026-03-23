"""Tests for lab API endpoints."""

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


@pytest.fixture
def api_client(tmp_path):
    """Create a FastAPI test client with DI override for project_dir."""
    from aptl.api.deps import get_project_dir
    from aptl.api.main import app
    from starlette.testclient import TestClient

    app.dependency_overrides[get_project_dir] = lambda: tmp_path
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


class TestHealthEndpoint:
    def test_health_returns_ok(self, api_client):
        response = api_client.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestLabStatus:
    @patch("aptl.api.routers.lab.core_lab_status")
    def test_returns_running_status(self, mock_status, api_client):
        from aptl.core.lab import LabStatus

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
    def test_returns_stopped_status(self, mock_status, api_client):
        from aptl.core.lab import LabStatus

        mock_status.return_value = LabStatus(running=False, containers=[])

        response = api_client.get("/api/lab/status")

        assert response.status_code == 200
        data = response.json()
        assert data["running"] is False
        assert data["containers"] == []

    @patch("aptl.api.routers.lab.core_lab_status")
    def test_returns_error(self, mock_status, api_client):
        from aptl.core.lab import LabStatus

        mock_status.return_value = LabStatus(
            running=False, error="docker not found"
        )

        response = api_client.get("/api/lab/status")

        assert response.status_code == 200
        data = response.json()
        assert data["error"] == "docker not found"

    @patch("aptl.api.routers.lab.core_lab_status")
    def test_error_field_is_null_when_no_error(self, mock_status, api_client):
        from aptl.core.lab import LabStatus

        mock_status.return_value = LabStatus(running=True, containers=[])

        response = api_client.get("/api/lab/status")

        data = response.json()
        assert data["error"] is None


class TestLabStart:
    @patch("aptl.api.routers.lab.orchestrate_lab_start")
    def test_start_success(self, mock_start, api_client):
        from aptl.core.lab import LabResult

        mock_start.return_value = LabResult(success=True, message="Lab started")

        response = api_client.post("/api/lab/start")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Lab started"

    @patch("aptl.api.routers.lab.orchestrate_lab_start")
    def test_start_failure(self, mock_start, api_client):
        from aptl.core.lab import LabResult

        mock_start.return_value = LabResult(
            success=False, error="Missing .env"
        )

        response = api_client.post("/api/lab/start")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "Missing .env" in data["error"]

    @patch("aptl.api.routers.lab.orchestrate_lab_start")
    def test_start_timeout(self, mock_start, api_client):
        """Lab start returns error when orchestration exceeds timeout."""
        from aptl.core.lab import LabResult

        # Simulate a function that takes forever
        import time
        def slow_start(project_dir):
            time.sleep(10)
            return LabResult(success=True, message="done")

        mock_start.side_effect = slow_start

        # Patch the timeout to something small for the test
        with patch("aptl.api.routers.lab.asyncio.wait_for", side_effect=asyncio.TimeoutError):
            response = api_client.post("/api/lab/start")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "timed out" in data["error"]


class TestLabStop:
    @patch("aptl.api.routers.lab.core_stop_lab")
    def test_stop_success(self, mock_stop, api_client):
        from aptl.core.lab import LabResult

        mock_stop.return_value = LabResult(success=True, message="Lab stopped")

        response = api_client.post("/api/lab/stop")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    @patch("aptl.api.routers.lab.core_stop_lab")
    def test_stop_failure(self, mock_stop, api_client):
        from aptl.core.lab import LabResult

        mock_stop.return_value = LabResult(
            success=False, error="compose down failed"
        )

        response = api_client.post("/api/lab/stop")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False


class TestProjectDirValidation:
    def test_nonexistent_project_dir_returns_503(self):
        """When APTL_PROJECT_DIR points to nonexistent dir, API returns 503."""
        from aptl.api.deps import get_project_dir
        from aptl.api.main import app
        from starlette.testclient import TestClient
        from pathlib import Path

        app.dependency_overrides[get_project_dir] = lambda: (_ for _ in ()).throw(
            __import__("fastapi").HTTPException(
                status_code=503,
                detail="Project directory not found or not configured",
            )
        )
        try:
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/lab/status")
            assert response.status_code == 503
        finally:
            app.dependency_overrides.clear()

    def test_nonexistent_project_dir_via_env(self):
        """get_project_dir raises 503 for nonexistent env path."""
        from aptl.api.deps import get_project_dir
        from unittest.mock import patch as _patch
        import os

        with _patch.dict(os.environ, {"APTL_PROJECT_DIR": "/no/such/path"}):
            with pytest.raises(Exception) as exc_info:
                get_project_dir()
            assert "503" in str(exc_info.value.status_code)


async def _noop_sleep(_seconds):
    """Instant replacement for asyncio.sleep in tests."""


class TestLabEventGenerator:
    """Test the SSE generator directly (avoids HTTP streaming hangs)."""

    @patch("aptl.api.routers.lab.asyncio.sleep", _noop_sleep)
    @patch("aptl.api.routers.lab._build_status_response")
    def test_emits_initial_status(self, mock_build, tmp_path):
        from aptl.api.routers.lab import _lab_event_generator
        from aptl.api.schemas import LabStatusResponse

        mock_build.return_value = LabStatusResponse(running=False, containers=[])

        async def run():
            gen = _lab_event_generator(tmp_path)
            event = await gen.__anext__()
            await gen.aclose()
            return event

        event = asyncio.run(run())
        assert event["event"] == "lab_status"
        data = json.loads(event["data"])
        assert data["running"] is False

    @patch("aptl.api.routers.lab.asyncio.sleep", _noop_sleep)
    @patch("aptl.api.routers.lab._build_status_response")
    def test_emits_on_state_change(self, mock_build, tmp_path):
        from aptl.api.routers.lab import _lab_event_generator
        from aptl.api.schemas import ContainerInfo, LabStatusResponse

        call_count = 0

        def changing_status(project_dir):
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
            gen = _lab_event_generator(tmp_path)
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
    def test_emits_error_event(self, mock_build, tmp_path):
        from aptl.api.routers.lab import _lab_event_generator

        mock_build.side_effect = RuntimeError("docker daemon not running")

        async def run():
            gen = _lab_event_generator(tmp_path)
            event = await gen.__anext__()
            await gen.aclose()
            return event

        event = asyncio.run(run())
        assert event["event"] == "error"
        assert "Internal error" in event["data"]

    @patch("aptl.api.routers.lab.asyncio.sleep", _noop_sleep)
    @patch("aptl.api.routers.lab._build_status_response")
    def test_skips_duplicate_status(self, mock_build, tmp_path):
        from aptl.api.routers.lab import _lab_event_generator
        from aptl.api.schemas import LabStatusResponse

        # Same status every time — only first poll should emit
        mock_build.return_value = LabStatusResponse(running=False, containers=[])

        async def run():
            gen = _lab_event_generator(tmp_path)
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

    @patch("aptl.api.routers.lab.asyncio.sleep", _noop_sleep)
    @patch("aptl.api.routers.lab._build_status_response")
    def test_circuit_breaker_terminates_after_max_errors(self, mock_build, tmp_path):
        """SSE generator terminates after MAX_CONSECUTIVE_ERRORS."""
        from aptl.api.routers.lab import _lab_event_generator, MAX_CONSECUTIVE_ERRORS

        mock_build.side_effect = RuntimeError("persistent failure")

        async def run():
            gen = _lab_event_generator(tmp_path)
            events = []
            async for event in gen:
                events.append(event)
            return events

        events = asyncio.run(run())
        assert len(events) == MAX_CONSECUTIVE_ERRORS
        assert all(e["event"] == "error" for e in events)

    def test_lab_events_endpoint_returns_sse(self, tmp_path):
        """Verify the endpoint function returns an EventSourceResponse."""
        from aptl.api.routers.lab import lab_events
        from aptl.api.deps import get_project_dir
        from sse_starlette.sse import EventSourceResponse

        # Call with project_dir directly (simulating Depends injection)
        result = asyncio.run(lab_events(project_dir=tmp_path))
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
