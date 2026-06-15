"""Tests for terminal WebSocket API endpoint."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")
pytest.importorskip("asyncssh", reason="asyncssh not installed")

from fastapi import WebSocketDisconnect  # noqa: E402

from aptl.core.snapshot import SSHEndpoint  # noqa: E402


_TEST_WS_TOKEN = "ws-test-token-abc"
_VALID_WS_SUBPROTOCOLS = [f"aptl-token.{_TEST_WS_TOKEN}"]


@pytest.fixture
def api_client(tmp_path):
    """Create a FastAPI test client with auth and project_dir overridden."""
    from aptl.api.deps import (
        WebAuthSettings,
        get_project_dir,
        get_web_auth,
        verify_token,
    )
    from aptl.api.main import app
    from starlette.testclient import TestClient

    _test_auth = WebAuthSettings(api_token=_TEST_WS_TOKEN)
    app.dependency_overrides[get_project_dir] = lambda: tmp_path
    app.dependency_overrides[verify_token] = lambda: None
    app.dependency_overrides[get_web_auth] = lambda: _test_auth
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

# A terminal endpoint as resolved from runtime inventory: container IP +
# port 22 (issue #293 / ADR-040), NOT a hardcoded localhost:<port> map.
_VICTIM_ENDPOINT = SSHEndpoint(
    name="Victim",
    host="172.20.2.20",
    port=22,
    user="labadmin",
    key_path="~/.ssh/aptl_lab_key",
    command="ssh -i ~/.ssh/aptl_lab_key labadmin@172.20.2.20",
)


def _pin_known_hosts(tmp_path):
    """Write a plausible lab-start-pinned known_hosts file under .aptl/."""
    kh = tmp_path / ".aptl" / "known_hosts"
    kh.parent.mkdir(parents=True, exist_ok=True)
    kh.write_text(
        "172.20.2.20 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIMTUqAKGaTTU6ZQIX0CtZty7aChRO5ArrLlzkucPQrBh\n"
    )
    return kh


class TestTerminalWebSocket:
    def test_cross_origin_rejected(self, api_client):
        """Cross-origin WebSocket connections are rejected before accept.

        No subprotocol is passed, so the token check fires first. The handler
        sends a close frame before accept(), which Starlette surfaces as
        WebSocketDisconnect (not WebSocketDenialResponse, which is reserved for
        dependency-level HTTPException rejections).
        """
        with pytest.raises(WebSocketDisconnect):
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
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers={"origin": "http://localhost:3000"},
        ) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "error"
            assert "not running" in msg["message"]

    def test_no_origin_header_rejected(self, api_client):
        """Connections without an Origin header are rejected.

        No subprotocol is passed, so the token check fires first. The handler
        sends a close frame before accept(), surfaced as WebSocketDisconnect.
        """
        with pytest.raises(WebSocketDisconnect):
            with api_client.websocket_connect("/api/terminal/ws/victim") as ws:
                ws.receive_json()

    def test_valid_token_but_cross_origin_rejected(self, api_client):
        """Valid token + disallowed origin hits the origin gate.

        The token check passes first, then the origin is rejected, so the
        handler calls close() before accept() — surfaced as WebSocketDisconnect.
        """
        with pytest.raises(WebSocketDisconnect):
            with api_client.websocket_connect(
                "/api/terminal/ws/victim",
                subprotocols=_VALID_WS_SUBPROTOCOLS,
                headers={"origin": "http://evil.com"},
            ) as ws:
                ws.receive_json()

    @patch("aptl.api.routers.terminal.lab_status")
    def test_invalid_container_rejected(self, mock_status, api_client):
        """Unknown container name closes WebSocket with 1008.

        Auth and origin pass, so the container-allowlist gate rejects with a
        close(1008), surfaced as WebSocketDisconnect.
        """
        mock_status.return_value = _make_lab_status(running=True)

        with pytest.raises(WebSocketDisconnect):
            with api_client.websocket_connect(
                "/api/terminal/ws/nonexistent",
                subprotocols=_VALID_WS_SUBPROTOCOLS,
                headers=_VALID_ORIGIN,
            ) as ws:
                ws.receive_json()

    @patch("aptl.api.routers.terminal.lab_status")
    def test_lab_not_running_rejected(self, mock_status, api_client):
        """Lab not running sends error and closes WebSocket."""
        mock_status.return_value = _make_lab_status(running=False)

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers=_VALID_ORIGIN,
        ) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "error"
            assert "not running" in msg["message"]

    @patch("aptl.api.routers.terminal.lab_terminal_ssh_endpoints")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_container_not_in_inventory_rejected(
        self, mock_status, mock_endpoints, api_client, tmp_path
    ):
        """A known container that is not in runtime inventory fails closed."""
        mock_status.return_value = _make_lab_status(running=True)
        mock_endpoints.return_value = {}  # victim not currently running
        _pin_known_hosts(tmp_path)

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers=_VALID_ORIGIN,
        ) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "error"
            assert "not available" in msg["message"].lower()

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_terminal_ssh_endpoints")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_known_hosts_path_passed_to_connect(
        self, mock_status, mock_endpoints, mock_asyncssh, api_client, tmp_path
    ):
        """The relay verifies host keys: known_hosts is the pinned file, not None."""
        mock_status.return_value = _make_lab_status(running=True)
        mock_endpoints.return_value = {"victim": _VICTIM_ENDPOINT}
        kh = _pin_known_hosts(tmp_path)

        process = _make_mock_process()
        conn = _make_mock_conn(process)
        mock_asyncssh.connect = AsyncMock(return_value=conn)
        mock_asyncssh.Error = Exception
        process.stdout.read = AsyncMock(side_effect=["__ready__", ""])

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers=_VALID_ORIGIN,
        ) as ws:
            # Receive one relayed message to deterministically synchronize:
            # by the time it arrives the handler has dialed asyncssh.connect
            # (avoids a close-before-connect race under slow CI timing).
            ws.receive_json()

        mock_asyncssh.connect.assert_awaited_once()
        kwargs = mock_asyncssh.connect.call_args.kwargs
        assert kwargs["known_hosts"] is not None
        assert kwargs["known_hosts"] == str(kh)
        # Endpoint identity comes from runtime inventory, not localhost.
        assert kwargs["host"] == "172.20.2.20"
        assert kwargs["port"] == 22
        assert kwargs["username"] == "labadmin"

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_terminal_ssh_endpoints")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_missing_pin_fails_closed(
        self, mock_status, mock_endpoints, mock_asyncssh, api_client, tmp_path
    ):
        """No pinned known_hosts file → reject without dialing SSH."""
        mock_status.return_value = _make_lab_status(running=True)
        mock_endpoints.return_value = {"victim": _VICTIM_ENDPOINT}
        # Deliberately do NOT create .aptl/known_hosts.
        mock_asyncssh.connect = AsyncMock()
        mock_asyncssh.Error = Exception

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers=_VALID_ORIGIN,
        ) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "error"
            assert "host key" in msg["message"].lower()

        mock_asyncssh.connect.assert_not_called()

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_terminal_ssh_endpoints")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_stdin_forwarded_to_ssh(
        self, mock_status, mock_endpoints, mock_asyncssh, api_client, tmp_path
    ):
        """stdin messages are forwarded to SSH process."""
        mock_status.return_value = _make_lab_status(running=True)
        mock_endpoints.return_value = {"victim": _VICTIM_ENDPOINT}
        _pin_known_hosts(tmp_path)

        process = _make_mock_process()
        conn = _make_mock_conn(process)
        mock_asyncssh.connect = AsyncMock(return_value=conn)
        mock_asyncssh.Error = Exception
        process.stdout.read = AsyncMock(side_effect=["__ready__", ""])

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers=_VALID_ORIGIN,
        ) as ws:
            # Sync on the first relayed message so both relay tasks are live
            # before sending stdin (avoids a close-before-connect race).
            ws.receive_json()
            ws.send_text(json.dumps({"type": "stdin", "data": "ls\n"}))

        # ws context exit closes the WebSocket, which unblocks the relay
        # tasks and allows them to process queued messages before shutdown
        process.stdin.write.assert_called_with("ls\n")

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_terminal_ssh_endpoints")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_stdout_forwarded_to_ws(
        self, mock_status, mock_endpoints, mock_asyncssh, api_client, tmp_path
    ):
        """SSH stdout is forwarded to WebSocket as stdout messages."""
        mock_status.return_value = _make_lab_status(running=True)
        mock_endpoints.return_value = {"victim": _VICTIM_ENDPOINT}
        _pin_known_hosts(tmp_path)

        process = _make_mock_process()
        conn = _make_mock_conn(process)
        mock_asyncssh.connect = AsyncMock(return_value=conn)
        mock_asyncssh.Error = Exception
        process.stdout.read = AsyncMock(side_effect=["$ prompt\n", ""])

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers=_VALID_ORIGIN,
        ) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "stdout"
            assert "prompt" in msg["data"]

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_terminal_ssh_endpoints")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_resize_calls_change_terminal_size(
        self, mock_status, mock_endpoints, mock_asyncssh, api_client, tmp_path
    ):
        """resize messages call change_terminal_size on the SSH process."""
        mock_status.return_value = _make_lab_status(running=True)
        mock_endpoints.return_value = {"victim": _VICTIM_ENDPOINT}
        _pin_known_hosts(tmp_path)

        process = _make_mock_process()
        conn = _make_mock_conn(process)
        mock_asyncssh.connect = AsyncMock(return_value=conn)
        mock_asyncssh.Error = Exception
        process.stdout.read = AsyncMock(side_effect=["__ready__", ""])

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers=_VALID_ORIGIN,
        ) as ws:
            # Sync on the first relayed message before sending resize.
            ws.receive_json()
            ws.send_text(json.dumps({"type": "resize", "cols": 120, "rows": 40}))

        process.change_terminal_size.assert_called_with(120, 40)

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_terminal_ssh_endpoints")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_disconnect_closes_ssh(
        self, mock_status, mock_endpoints, mock_asyncssh, api_client, tmp_path
    ):
        """WebSocket disconnect triggers SSH connection cleanup."""
        mock_status.return_value = _make_lab_status(running=True)
        mock_endpoints.return_value = {"victim": _VICTIM_ENDPOINT}
        _pin_known_hosts(tmp_path)

        process = _make_mock_process()
        conn = _make_mock_conn(process)
        mock_asyncssh.connect = AsyncMock(return_value=conn)
        mock_asyncssh.Error = Exception
        process.stdout.read = AsyncMock(side_effect=["__ready__", ""])

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers=_VALID_ORIGIN,
        ) as ws:
            # Sync on the first relayed message so the SSH connection has been
            # established before the client disconnects (then cleanup runs).
            ws.receive_json()

        conn.close.assert_called_once()

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_terminal_ssh_endpoints")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_ssh_error_sends_error_message(
        self, mock_status, mock_endpoints, mock_asyncssh, api_client, tmp_path
    ):
        """SSH failure (incl. host-key mismatch) sends generic error message."""
        mock_status.return_value = _make_lab_status(running=True)
        mock_endpoints.return_value = {"victim": _VICTIM_ENDPOINT}
        _pin_known_hosts(tmp_path)

        mock_asyncssh.connect = AsyncMock(side_effect=Exception("host key mismatch"))
        mock_asyncssh.Error = Exception

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers=_VALID_ORIGIN,
        ) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "error"
            assert msg["message"] == "SSH connection failed"

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_terminal_ssh_endpoints")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_malformed_json_message_is_ignored(
        self, mock_status, mock_endpoints, mock_asyncssh, api_client, tmp_path
    ):
        """Malformed JSON from the WebSocket is swallowed at the JSONDecodeError handler."""
        mock_status.return_value = _make_lab_status(running=True)
        mock_endpoints.return_value = {"victim": _VICTIM_ENDPOINT}
        _pin_known_hosts(tmp_path)

        process = _make_mock_process()
        conn = _make_mock_conn(process)
        mock_asyncssh.connect = AsyncMock(return_value=conn)
        mock_asyncssh.Error = Exception
        process.stdout.read = AsyncMock(side_effect=["__ready__", ""])

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers=_VALID_ORIGIN,
        ) as ws:
            # Sync on the first relayed message before sending malformed input.
            ws.receive_json()
            ws.send_text("not-valid-json")

        # No exception: JSONDecodeError is caught and ignored.

    @patch("aptl.api.routers.terminal.asyncssh")
    @patch("aptl.api.routers.terminal.lab_terminal_ssh_endpoints")
    @patch("aptl.api.routers.terminal.lab_status")
    def test_ws_disconnect_during_ssh_read_exits_cleanly(
        self, mock_status, mock_endpoints, mock_asyncssh, api_client, tmp_path
    ):
        """WebSocketDisconnect raised mid-SSH-read is swallowed by the relay."""
        mock_status.return_value = _make_lab_status(running=True)
        mock_endpoints.return_value = {"victim": _VICTIM_ENDPOINT}
        _pin_known_hosts(tmp_path)

        process = _make_mock_process()
        conn = _make_mock_conn(process)
        mock_asyncssh.connect = AsyncMock(return_value=conn)
        mock_asyncssh.Error = Exception

        # First read returns data; second read simulates disconnection during relay
        process.stdout.read = AsyncMock(
            side_effect=["ssh output", WebSocketDisconnect()]
        )

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers=_VALID_ORIGIN,
        ) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "stdout"
            assert msg["data"] == "ssh output"

        conn.close.assert_called_once()

    @patch("aptl.api.routers.terminal.lab_status")
    def test_valid_containers_accepted(self, mock_status, api_client):
        """All valid container names are accepted (not rejected with 1008)."""
        mock_status.return_value = _make_lab_status(running=False)

        for name in ["victim", "kali", "reverse", "workstation"]:
            with api_client.websocket_connect(
                f"/api/terminal/ws/{name}",
                subprotocols=_VALID_WS_SUBPROTOCOLS,
                headers=_VALID_ORIGIN,
            ) as ws:
                msg = ws.receive_json()
                # Should get "lab not running" error, not unknown container
                assert msg["type"] == "error"
                assert "not running" in msg["message"]
