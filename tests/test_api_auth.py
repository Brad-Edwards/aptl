"""Tests for the web API bearer-token authentication layer (ADR-039)."""

import hmac
import os

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")


_TEST_TOKEN = "test-token-abc123def456"


@pytest.fixture
def auth_env(monkeypatch):
    """Set APTL_API_TOKEN in the environment before app initialisation."""
    monkeypatch.setenv("APTL_API_TOKEN", _TEST_TOKEN)


@pytest.fixture
def authed_client(tmp_path, auth_env, monkeypatch):
    """TestClient with a valid token configured and project dir overridden.

    Resets the ``_WEB_AUTH`` global before and after the test so that different
    fixtures don't bleed auth state into each other.
    """
    import aptl.api.deps as _deps

    monkeypatch.setattr(_deps, "_WEB_AUTH", None)

    from aptl.api.deps import get_project_dir
    from aptl.api.main import create_app
    from starlette.testclient import TestClient

    app = create_app()  # load_web_auth() reads APTL_API_TOKEN from env
    app.dependency_overrides[get_project_dir] = lambda: tmp_path
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client


@pytest.fixture
def bearer(authed_client):
    """Return the Authorization header value for the test token."""
    return f"Bearer {_TEST_TOKEN}"


# ---------------------------------------------------------------------------
# Health endpoint — every request requires auth (ADR-039)
# ---------------------------------------------------------------------------


class TestHealthAuth:
    def test_health_returns_401_without_token(self, authed_client):
        resp = authed_client.get("/api/health")
        assert resp.status_code == 401

    def test_health_returns_401_with_wrong_token(self, authed_client):
        resp = authed_client.get(
            "/api/health", headers={"Authorization": "Bearer wrong-token"}
        )
        assert resp.status_code == 401

    def test_health_returns_200_with_correct_token(self, authed_client, bearer):
        resp = authed_client.get("/api/health", headers={"Authorization": bearer})
        assert resp.status_code == 200

    def test_health_401_does_not_leak_token_state(self, authed_client):
        """401 detail must be a generic message — no 'wrong', 'missing', or 'invalid'."""
        resp = authed_client.get("/api/health")
        assert resp.status_code == 401
        body = resp.text.lower()
        assert "missing" not in body
        assert "invalid" not in body
        assert _TEST_TOKEN not in body

    def test_health_401_includes_www_authenticate_bearer(self, authed_client):
        resp = authed_client.get("/api/health")
        assert resp.headers.get("www-authenticate") == "Bearer"


# ---------------------------------------------------------------------------
# Other HTTP endpoints also require auth
# ---------------------------------------------------------------------------


class TestEndpointAuth:
    def test_kill_returns_401_without_token(self, authed_client):
        resp = authed_client.post("/api/lab/kill")
        assert resp.status_code == 401

    def test_config_returns_401_without_token(self, authed_client):
        resp = authed_client.get("/api/config")
        assert resp.status_code == 401

    def test_lab_status_returns_401_without_token(self, authed_client):
        resp = authed_client.get("/api/lab/status")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# WebAuthSettings validation
# ---------------------------------------------------------------------------


class TestWebAuthSettings:
    def test_missing_token_raises(self, monkeypatch):
        monkeypatch.delenv("APTL_API_TOKEN", raising=False)
        from aptl.api import deps as d

        with pytest.raises((ValueError, RuntimeError)):
            d.WebAuthSettings.from_env()

    def test_empty_token_raises(self, monkeypatch):
        monkeypatch.setenv("APTL_API_TOKEN", "")
        from aptl.api import deps as d

        with pytest.raises((ValueError, RuntimeError)):
            d.WebAuthSettings.from_env()

    def test_placeholder_token_raises(self, monkeypatch):
        monkeypatch.setenv("APTL_API_TOKEN", "CHANGE_ME")
        from aptl.api import deps as d

        with pytest.raises((ValueError, RuntimeError)):
            d.WebAuthSettings.from_env()

    def test_valid_token_loads(self, monkeypatch):
        monkeypatch.setenv("APTL_API_TOKEN", _TEST_TOKEN)
        from aptl.api import deps as d

        settings = d.WebAuthSettings.from_env()
        assert settings.api_token == _TEST_TOKEN


# ---------------------------------------------------------------------------
# verify_ws_token helper
# ---------------------------------------------------------------------------


class TestWebSocketAuth:
    """WebSocket endpoint rejects connections with missing or invalid token."""

    @pytest.fixture
    def ws_client(self, tmp_path, auth_env, monkeypatch):
        import aptl.api.deps as _deps

        monkeypatch.setattr(_deps, "_WEB_AUTH", None)

        from aptl.api.deps import WebAuthSettings, get_project_dir, get_web_auth
        from aptl.api.main import create_app
        from starlette.testclient import TestClient

        app = create_app()
        app.dependency_overrides[get_project_dir] = lambda: tmp_path
        with TestClient(app, raise_server_exceptions=True) as client:
            yield client, _TEST_TOKEN

    def test_ws_rejected_without_token(self, ws_client):
        from starlette.testclient import WebSocketDenialResponse

        client, _ = ws_client
        with pytest.raises(WebSocketDenialResponse):
            with client.websocket_connect(
                "/api/terminal/ws/victim",
                headers={"origin": "http://localhost:3000"},
            ) as ws:
                ws.receive_json()

    def test_ws_rejected_with_wrong_token(self, ws_client):
        from starlette.testclient import WebSocketDenialResponse

        client, _ = ws_client
        with pytest.raises(WebSocketDenialResponse):
            with client.websocket_connect(
                "/api/terminal/ws/victim",
                subprotocols=["aptl-token.wrong-token"],
                headers={"origin": "http://localhost:3000"},
            ) as ws:
                ws.receive_json()


class TestVerifyWsToken:
    def setup_method(self):
        os.environ["APTL_API_TOKEN"] = _TEST_TOKEN

    def teardown_method(self):
        os.environ.pop("APTL_API_TOKEN", None)

    def test_valid_subprotocol_returns_true(self, auth_env):
        from aptl.api.deps import WebAuthSettings, verify_ws_token

        settings = WebAuthSettings.from_env()
        assert verify_ws_token(f"aptl-token.{_TEST_TOKEN}", settings) is True

    def test_wrong_token_returns_false(self, auth_env):
        from aptl.api.deps import WebAuthSettings, verify_ws_token

        settings = WebAuthSettings.from_env()
        assert verify_ws_token("aptl-token.wrong-token", settings) is False

    def test_missing_prefix_returns_false(self, auth_env):
        from aptl.api.deps import WebAuthSettings, verify_ws_token

        settings = WebAuthSettings.from_env()
        assert verify_ws_token(_TEST_TOKEN, settings) is False

    def test_empty_string_returns_false(self, auth_env):
        from aptl.api.deps import WebAuthSettings, verify_ws_token

        settings = WebAuthSettings.from_env()
        assert verify_ws_token("", settings) is False
