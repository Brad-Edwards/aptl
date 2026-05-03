"""Tests for terminal WebSocket API endpoint."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")
pytest.importorskip("asyncssh", reason="asyncssh not installed")


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


def _make_lab_status(running: bool):
    """Create a mock LabStatus."""
    from aptl.core.lab import LabStatus
    return LabStatus(running=running, containers=[])


def _make_mock_process():
    """Create a mock asyncssh process with stdout/stdin."""
    process = MagicMock()

    # stdout is an async iterator that yields data then EOF
    stdout = AsyncMock()
    stdout.read = AsyncMock(side_effect=["hello from container", ""])
    process.stdout = stdout

    # stdin
    stdin = MagicMock()
    stdin.write = MagicMock()
    process.stdin = stdin

    # resize
    process.change_terminal_size = MagicMock()

    return process


def _make_mock_conn(process):
    """Create a mock asyncssh connection."""
    conn = AsyncMock()
    conn.create_process = AsyncMock(return_value=process)
    conn.close = MagicMock()
    return conn


_VALID_ORIGIN = {"origin": "http://localhost:3000"}


class TestTerminalWebSocket:
    def test_cross_origin_rejected(self, api_client):
        """Cross-origin WebSocket connections are rejected before accept."""
        with pytest.raises(Exception):
            with api_client.websocket_connect(
                "/api/terminal/ws/victim",
                headers={"origin": "http://evil.com"},
            ) as ws:
                ws.receive_json()

    @patch("aptl.api.routers.terminal.lab_status")
    def test_allowed_origin_accepted(self, mock_status, api_client):
        """Connections from allowed origins proceed normally."""
        mock_status.return_value = _make_lab_status(running=False)

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            headers={"origin": "http://localhost:3000"},
        ) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "error"
            assert "not running" in msg["message"]

    def test_no_origin_header_rejected(self, api_client):
        """Connections without an Origin header are rejected."""
        with pytest.raises(Exception):
            with api_client.websocket_connect("/api/terminal/ws/victim") as ws:
                ws.receive_json()

    @patch("aptl.api.routers.terminal.lab_status")
    def test_invalid_container_rejected(self, mock_status, api_client):
        """Unknown container name closes WebSocket with 1008."""
        mock_status.return_value = _make_lab_status(running=True)

        with pytest.raises(Exception):
            with api_client.websocket_connect(
                "/api/terminal/ws/nonexistent", headers=_VALID_ORIGIN
            ) as ws:
                # Should be closed by server
                ws.receive_json()

    @patch("aptl.api.routers.terminal.lab_status")
    def test_lab_not_running_rejected(self, mock_status, api_client):
        """Lab not running sends error and closes WebSocket."""
        mock_status.return_value = _make_lab_status(running=False)

        with api_client.websocket_connect(
            "/api/terminal/ws/victim", headers=_VALID_ORIGIN
        ) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "error"
            assert "not running" in msg["message"]

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_stdin_forwarded_to_ssh(self, mock_status, mock_asyncssh, api_client):
        """stdin messages are forwarded to SSH process."""
        mock_status.return_value = _make_lab_status(running=True)

        process = _make_mock_process()
        conn = _make_mock_conn(process)
        mock_asyncssh.connect = AsyncMock(return_value=conn)
        mock_asyncssh.Error = Exception

        # stdout.read returns empty immediately to end the ssh->ws relay
        process.stdout.read = AsyncMock(return_value="")

        with api_client.websocket_connect(
            "/api/terminal/ws/victim", headers=_VALID_ORIGIN
        ) as ws:
            ws.send_text(json.dumps({"type": "stdin", "data": "ls\n"}))

        # ws context exit closes the WebSocket, which unblocks the relay
        # tasks and allows them to process queued messages before shutdown
        process.stdin.write.assert_called_with("ls\n")

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_stdout_forwarded_to_ws(self, mock_status, mock_asyncssh, api_client):
        """SSH stdout is forwarded to WebSocket as stdout messages."""
        mock_status.return_value = _make_lab_status(running=True)

        process = _make_mock_process()
        conn = _make_mock_conn(process)
        mock_asyncssh.connect = AsyncMock(return_value=conn)
        mock_asyncssh.Error = Exception

        # stdout returns data then empty
        process.stdout.read = AsyncMock(side_effect=["$ prompt\n", ""])

        with api_client.websocket_connect(
            "/api/terminal/ws/victim", headers=_VALID_ORIGIN
        ) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "stdout"
            assert "prompt" in msg["data"]

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_resize_calls_change_terminal_size(self, mock_status, mock_asyncssh, api_client):
        """resize messages call change_terminal_size on the SSH process."""
        mock_status.return_value = _make_lab_status(running=True)

        process = _make_mock_process()
        conn = _make_mock_conn(process)
        mock_asyncssh.connect = AsyncMock(return_value=conn)
        mock_asyncssh.Error = Exception

        # stdout returns empty immediately
        process.stdout.read = AsyncMock(return_value="")

        with api_client.websocket_connect(
            "/api/terminal/ws/victim", headers=_VALID_ORIGIN
        ) as ws:
            ws.send_text(json.dumps({"type": "resize", "cols": 120, "rows": 40}))

        process.change_terminal_size.assert_called_with(120, 40)

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_disconnect_closes_ssh(self, mock_status, mock_asyncssh, api_client):
        """WebSocket disconnect triggers SSH connection cleanup."""
        mock_status.return_value = _make_lab_status(running=True)

        process = _make_mock_process()
        conn = _make_mock_conn(process)
        mock_asyncssh.connect = AsyncMock(return_value=conn)
        mock_asyncssh.Error = Exception

        # stdout returns empty immediately to allow clean close
        process.stdout.read = AsyncMock(return_value="")

        with api_client.websocket_connect(
            "/api/terminal/ws/victim", headers=_VALID_ORIGIN
        ) as ws:
            pass  # disconnect on exit

        conn.close.assert_called_once()

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_ssh_error_sends_error_message(self, mock_status, mock_asyncssh, api_client):
        """SSH connection failure sends error message to WebSocket."""
        mock_status.return_value = _make_lab_status(running=True)

        mock_asyncssh.connect = AsyncMock(side_effect=Exception("Connection refused"))
        mock_asyncssh.Error = Exception

        with api_client.websocket_connect(
            "/api/terminal/ws/victim", headers=_VALID_ORIGIN
        ) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "error"
            assert msg["message"] == "SSH connection failed"

    @patch("aptl.api.routers.terminal.lab_status")
    def test_valid_containers_accepted(self, mock_status, api_client):
        """All valid container names are accepted (not rejected with 1008)."""
        mock_status.return_value = _make_lab_status(running=False)

        for name in ["victim", "kali", "reverse", "workstation"]:
            with api_client.websocket_connect(
                f"/api/terminal/ws/{name}", headers=_VALID_ORIGIN
            ) as ws:
                msg = ws.receive_json()
                # Should get "lab not running" error, not unknown container
                assert msg["type"] == "error"
                assert "not running" in msg["message"]
