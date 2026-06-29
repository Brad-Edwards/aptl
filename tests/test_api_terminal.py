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


# Same-origin as the TestClient's default Host ("testserver"). The WS origin gate
# is strict same-origin (UI-008a): Origin host must equal the request Host.
_VALID_ORIGIN = {"origin": "http://testserver"}

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
        """Connections from a same-origin browser proceed normally."""
        mock_status.return_value = _make_lab_status(running=False)

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers={**_VALID_ORIGIN},
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
                headers={**_VALID_ORIGIN},
            ) as ws:
                ws.receive_json()

    @patch("aptl.api.routers.terminal.lab_status")
    def test_lab_not_running_rejected(self, mock_status, api_client):
        """Lab not running sends error and closes WebSocket."""
        mock_status.return_value = _make_lab_status(running=False)

        with api_client.websocket_connect(
            "/api/terminal/ws/victim",
            subprotocols=_VALID_WS_SUBPROTOCOLS,
            headers={**_VALID_ORIGIN},
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
            headers={**_VALID_ORIGIN},
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
            headers={**_VALID_ORIGIN},
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
            headers={**_VALID_ORIGIN},
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
            headers={**_VALID_ORIGIN},
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
            headers={**_VALID_ORIGIN},
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
            headers={**_VALID_ORIGIN},
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
            headers={**_VALID_ORIGIN},
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
            headers={**_VALID_ORIGIN},
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
            headers={**_VALID_ORIGIN},
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
            headers={**_VALID_ORIGIN},
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
                headers={**_VALID_ORIGIN},
            ) as ws:
                msg = ws.receive_json()
                # Should get "lab not running" error, not unknown container
                assert msg["type"] == "error"
                assert "not running" in msg["message"]


# ---------------------------------------------------------------------------
# Terminal ticket store and endpoint
# ---------------------------------------------------------------------------


class TestTerminalTicketStore:
    """Unit tests for the module-level ticket store functions."""

    def setup_method(self):
        """Reset the ticket store before each test."""
        from aptl.api.routers.terminal import _ticket_store
        _ticket_store._tickets.clear()

    def test_issue_returns_opaque_string(self):
        from aptl.api.routers.terminal import issue_ticket
        t = issue_ticket()
        assert isinstance(t, str)
        assert len(t) > 20  # token_urlsafe(32) → 43 chars

    def test_consume_returns_true_first_call(self):
        from aptl.api.routers.terminal import consume_ticket, issue_ticket
        t = issue_ticket()
        assert consume_ticket(t) is True

    def test_consume_returns_false_second_call(self):
        from aptl.api.routers.terminal import consume_ticket, issue_ticket
        t = issue_ticket()
        consume_ticket(t)
        assert consume_ticket(t) is False

    def test_consume_unknown_ticket_returns_false(self):
        from aptl.api.routers.terminal import consume_ticket
        assert consume_ticket("not-a-real-ticket") is False

    def test_expired_ticket_returns_false(self):
        """Tickets past their TTL are treated as non-existent.

        The clock is injected as an explicit value sequence rather than patched
        on the module: issue() reads it twice (prune + expiry stamp) at ``base``,
        then consume()'s prune reads it once at ``base + 61`` — past the 30 s TTL.
        Using a finite iterator means any extra clock call in the implementation
        raises StopIteration and fails the test loudly, instead of silently
        feeding the wrong value (the call-count-branching fake's blind spot).
        """
        from aptl.api.routers.terminal import _TicketStore

        base = 1000.0
        store = _TicketStore(
            ttl=30.0,
            time_source=iter([base, base, base + 61.0]).__next__,
        )

        ticket = store.issue()
        assert store.consume(ticket) is False


class TestVerifyWsTicket:
    """Unit tests for verify_ws_ticket."""

    def setup_method(self):
        from aptl.api.routers.terminal import _ticket_store
        _ticket_store._tickets.clear()

    def test_valid_ticket_subprotocol_accepted(self):
        from aptl.api.routers.terminal import issue_ticket, verify_ws_ticket
        t = issue_ticket()
        assert verify_ws_ticket(f"aptl-token.{t}") is True

    def test_consumed_ticket_rejected_on_second_use(self):
        from aptl.api.routers.terminal import issue_ticket, verify_ws_ticket
        t = issue_ticket()
        verify_ws_ticket(f"aptl-token.{t}")  # first use
        assert verify_ws_ticket(f"aptl-token.{t}") is False

    def test_unknown_ticket_rejected(self):
        from aptl.api.routers.terminal import verify_ws_ticket
        assert verify_ws_ticket("aptl-token.not-a-ticket") is False

    def test_missing_prefix_rejected(self):
        from aptl.api.routers.terminal import issue_ticket, verify_ws_ticket
        t = issue_ticket()
        assert verify_ws_ticket(t) is False  # no prefix

    def test_empty_string_rejected(self):
        from aptl.api.routers.terminal import verify_ws_ticket
        assert verify_ws_ticket("") is False


class TestTerminalTicketEndpoint:
    """HTTP tests for GET /api/terminal/ticket."""

    def test_ticket_endpoint_requires_auth(self, api_client):
        """Without token override, endpoint should be reachable (deps overridden)."""
        # api_client overrides verify_token → lambda: None (always passes)
        resp = api_client.get("/api/terminal/ticket")
        assert resp.status_code == 200
        body = resp.json()
        assert "ticket" in body
        assert body["expires_in"] == 30

    def test_ticket_endpoint_returns_unique_tickets(self, api_client):
        """Two consecutive calls return different tickets."""
        r1 = api_client.get("/api/terminal/ticket")
        r2 = api_client.get("/api/terminal/ticket")
        assert r1.json()["ticket"] != r2.json()["ticket"]

    def test_ticket_endpoint_401_without_token(self, tmp_path, monkeypatch):
        """Without overridden auth, the endpoint requires a bearer token."""
        monkeypatch.setenv("APTL_API_TOKEN", _TEST_WS_TOKEN)
        import aptl.api.deps as _deps
        monkeypatch.setattr(_deps, "_WEB_AUTH", None)

        from aptl.api.main import create_app
        from aptl.api.deps import get_project_dir
        from starlette.testclient import TestClient

        real_app = create_app()
        real_app.dependency_overrides[get_project_dir] = lambda: tmp_path
        with TestClient(real_app) as c:
            resp = c.get("/api/terminal/ticket")
            assert resp.status_code == 401


class TestWsAcceptsTicketSubprotocol:
    """Integration-style: WS handshake with a ticket subprotocol.

    Starlette 1.0.0's TestClient (anyio-backed) leaves a pending WS close
    event in the event loop when successive connections are made within the
    same TestClient session.  To avoid stale-subprotocol contamination across
    tests, each test uses a FRESH TestClient (fresh anyio portal).

    Single-use semantics are verified at the unit level in TestVerifyWsTicket
    and TestTerminalTicketStore; the WS integration tests here verify only the
    happy path and the straight-reject of an unknown ticket.
    """

    def setup_method(self) -> None:
        from aptl.api.routers.terminal import _ticket_store
        _ticket_store._tickets.clear()

    def _make_fresh_client(self, tmp_path, monkeypatch):
        """Create a fresh isolated TestClient (one per call = one per test)."""
        monkeypatch.setenv("APTL_API_TOKEN", _TEST_WS_TOKEN)
        import aptl.api.deps as _deps
        monkeypatch.setattr(_deps, "_WEB_AUTH", None)

        from aptl.api.deps import (
            WebAuthSettings,
            get_project_dir,
            get_web_auth,
            verify_token,
        )
        from aptl.api.main import create_app
        from starlette.testclient import TestClient

        fresh_app = create_app()
        _test_auth = WebAuthSettings(api_token=_TEST_WS_TOKEN)
        fresh_app.dependency_overrides[get_project_dir] = lambda: tmp_path
        fresh_app.dependency_overrides[verify_token] = lambda: None
        fresh_app.dependency_overrides[get_web_auth] = lambda: _test_auth
        return TestClient(fresh_app)

    @patch("aptl.api.routers.terminal.lab_status")
    def test_ws_accepts_valid_ticket(self, mock_status, tmp_path, monkeypatch):
        """A freshly issued ticket is accepted as WS auth."""
        from aptl.api.routers.terminal import issue_ticket
        mock_status.return_value = _make_lab_status(running=False)
        t = issue_ticket()

        with self._make_fresh_client(tmp_path, monkeypatch) as client:
            with client.websocket_connect(
                "/api/terminal/ws/victim",
                subprotocols=[f"aptl-token.{t}"],
                headers={**_VALID_ORIGIN},
            ) as ws:
                msg = ws.receive_json()
                # Token check passes; reaches "lab not running" gate
                assert msg["type"] == "error"
                assert "not running" in msg["message"]

    def test_ws_rejects_unknown_ticket(self, tmp_path, monkeypatch):
        """An unknown ticket is rejected before the WS is accepted."""
        with self._make_fresh_client(tmp_path, monkeypatch) as client:
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect(
                    "/api/terminal/ws/victim",
                    subprotocols=["aptl-token.bogus-ticket-value"],
                    headers={**_VALID_ORIGIN},
                ) as ws:
                    ws.receive_json()

    def test_ticket_is_single_use_for_ws(self, tmp_path, monkeypatch):
        """A spent ticket is rejected at the WS auth gate.

        Starlette TestClient's anyio portal leaves in-flight close frames in the
        event queue when a WS connection exits.  A subsequent ``websocket_connect``
        in a new portal can replay those stale frames, making it appear that the
        NEW connection's subprotocol is the OLD connection's ticket — causing a
        false positive when the old ticket has already been consumed.

        To avoid this, the "first use" is simulated by calling ``consume_ticket``
        directly (which exercises exactly the code path ``verify_ws_ticket`` calls).
        The WS integration then verifies that the auth gate rejects the now-spent
        ticket.  The full accept path (fresh ticket → WS accepted) is covered by
        ``test_ws_accepts_valid_ticket``; unit coverage of single-use is in
        ``TestTerminalTicketStore`` and ``TestVerifyWsTicket``.
        """
        from aptl.api.routers.terminal import consume_ticket, issue_ticket

        t = issue_ticket()

        # Simulate first WS connection consuming the ticket (mirrors what
        # _resolve_terminal_target does via verify_ws_ticket → consume_ticket).
        assert consume_ticket(t) is True, "ticket must be in store after issue"

        # A second WS connection with the same (now-consumed) ticket must be
        # rejected before the WebSocket is accepted.
        with self._make_fresh_client(tmp_path, monkeypatch) as client:
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect(
                    "/api/terminal/ws/victim",
                    subprotocols=[f"aptl-token.{t}"],
                    headers={**_VALID_ORIGIN},
                ) as ws:
                    ws.receive_json()


class TestWsOriginAllowed:
    """_ws_origin_allowed enforces STRICT same-origin (Origin host == Host)."""

    @staticmethod
    def _ws(origin=None, host=None):
        headers = {}
        if origin is not None:
            headers["origin"] = origin
        if host is not None:
            headers["host"] = host
        ws = MagicMock()
        ws.headers = headers
        return ws

    def test_non_same_origin_rejected_even_if_loopback_named(self):
        """SECURITY: a non-matching origin is rejected — no allow-list bypass.

        A malicious local process on a trusted dev port must NOT pass the gate;
        only Origin host == Host is accepted (the dev/preview proxy preserves
        Host so the real browser still matches)."""
        from aptl.api.routers.terminal import _ws_origin_allowed

        assert not _ws_origin_allowed(self._ws("http://localhost:3000", "testserver"))

    def test_same_origin_shipped_model(self):
        """Shipped `aptl web serve`: page and API share an origin; same-origin
        (Origin netloc == Host) is trusted."""
        from aptl.api.routers.terminal import _ws_origin_allowed

        assert _ws_origin_allowed(
            self._ws("http://127.0.0.1:8400", "127.0.0.1:8400")
        )

    def test_same_origin_dev_proxy(self):
        """Dev/preview proxy preserves Host, so the browser origin matches."""
        from aptl.api.routers.terminal import _ws_origin_allowed

        assert _ws_origin_allowed(
            self._ws("http://localhost:3000", "localhost:3000")
        )

    def test_missing_origin_rejected(self):
        from aptl.api.routers.terminal import _ws_origin_allowed

        assert not _ws_origin_allowed(self._ws(origin=None, host="127.0.0.1:8400"))

    def test_foreign_origin_rejected(self):
        from aptl.api.routers.terminal import _ws_origin_allowed

        assert not _ws_origin_allowed(self._ws("http://evil.com", "127.0.0.1:8400"))

    def test_origin_host_mismatch_rejected(self):
        from aptl.api.routers.terminal import _ws_origin_allowed

        # Origin not in allow-set and not matching Host → rejected.
        assert not _ws_origin_allowed(
            self._ws("http://127.0.0.1:8400", "evil.example:9999")
        )
