"""Tests for BFF middleware, asset serving, and static-file SPA fallback.

ADR-039 / UI-008a: the FastAPI app is its own BFF. Browser API calls are
authenticated by a server-issued **two-factor session credential** (an HttpOnly
cookie PLUS a port-scoped ``X-APTL-Session`` header token, both minted by the
launch handshake), not by forgeable Fetch-Metadata/Origin headers; those headers
drive only the CSRF gate. Requiring both factors closes the cross-port cookie
leak (cookies are host-scoped, not port-scoped). Cross-site mutating requests are
rejected at 403, disallowed Hosts at 403 (DNS-rebinding defence), and built web
assets are served as a SPA from the same origin so there is no cross-origin
boundary in production.
"""

import os
from pathlib import Path
from typing import Optional

import pytest

pytest.importorskip("fastapi", reason="Web dependencies not installed")

_TEST_TOKEN = "bff-test-token-abc123"
_LAUNCH_TOKEN = "launch-token-test-value"
_SESSION_VALUE = "session-secret-test-value"

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def _set_token(monkeypatch):
    """Reset _WEB_AUTH and set APTL_API_TOKEN + the per-process session secrets.

    Pinning APTL_WEB_LAUNCH_TOKEN / APTL_WEB_SESSION_SECRET to known values lets
    tests present a valid session cookie and a valid launch token deterministically.
    """
    monkeypatch.setenv("APTL_API_TOKEN", _TEST_TOKEN)
    monkeypatch.setenv("APTL_WEB_LAUNCH_TOKEN", _LAUNCH_TOKEN)
    monkeypatch.setenv("APTL_WEB_SESSION_SECRET", _SESSION_VALUE)
    import aptl.api.deps as _deps
    monkeypatch.setattr(_deps, "_WEB_AUTH", None)
    # The one-time launch-token consumed flag is module-global; reset it so each
    # test starts with an unredeemed launch token.
    from aptl.api import session as _session
    _session.reset_launch_token_for_test()


@pytest.fixture()
def echo_app(_set_token):
    """Minimal FastAPI app with BFF middleware and auth-gated /api/echo route."""
    from fastapi import Depends, FastAPI, Request
    from aptl.api.deps import load_web_auth, verify_token
    from aptl.api.middleware.bff import BFFMiddleware

    load_web_auth()

    app = FastAPI()
    app.add_middleware(BFFMiddleware)

    @app.api_route("/api/echo", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def echo(request: Request, _: None = Depends(verify_token)):
        """Reflect the Authorization header back so tests can inspect injection."""
        return {
            "method": request.method,
            "auth": request.headers.get("authorization"),
        }

    return app


@pytest.fixture()
def echo_client(echo_app):
    """Echo client WITHOUT a session cookie (an unauthenticated/direct caller)."""
    from starlette.testclient import TestClient
    with TestClient(echo_app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture()
def browser_client(echo_app):
    """Echo client with BOTH valid session factors (a bootstrapped browser).

    The two-factor session credential (UI-008a / ADR-039) is a derived cookie
    tag PLUS a derived header tag — the cookie is no longer the raw secret. Both
    are required for bearer injection; this client presents both.
    """
    from starlette.testclient import TestClient
    from aptl.api.session import session_cookie_value, session_header_value
    with TestClient(echo_app, raise_server_exceptions=True) as c:
        c.cookies.set("aptl_session", session_cookie_value())
        c.headers["X-APTL-Session"] = session_header_value()
        yield c


@pytest.fixture()
def no_token_echo_app(monkeypatch):
    """BFF echo app with no API token configured (simulates unconfigured state)."""
    monkeypatch.delenv("APTL_API_TOKEN", raising=False)
    monkeypatch.setenv("APTL_WEB_SESSION_SECRET", _SESSION_VALUE)
    import aptl.api.deps as _deps
    monkeypatch.setattr(_deps, "_WEB_AUTH", None)
    # do NOT call load_web_auth — leaves _WEB_AUTH = None

    from fastapi import Depends, FastAPI, Request
    from aptl.api.deps import verify_token
    from aptl.api.middleware.bff import BFFMiddleware

    app = FastAPI()
    app.add_middleware(BFFMiddleware)

    @app.api_route("/api/echo", methods=["GET", "POST"])
    async def echo(request: Request, _: None = Depends(verify_token)):
        return {"auth": request.headers.get("authorization")}

    return app


@pytest.fixture()
def no_token_echo_client(no_token_echo_app):
    from starlette.testclient import TestClient
    from aptl.api.session import session_cookie_value, session_header_value
    with TestClient(no_token_echo_app, raise_server_exceptions=True) as c:
        c.cookies.set("aptl_session", session_cookie_value())
        c.headers["X-APTL-Session"] = session_header_value()
        yield c


# ---------------------------------------------------------------------------
# 1. CSRF / origin gate (mutating requests only)
# ---------------------------------------------------------------------------


class TestCsrfGate:
    def test_sec_fetch_site_cross_site_post_rejected(self, browser_client):
        """`Sec-Fetch-Site: cross-site` on a mutating request → 403."""
        resp = browser_client.post(
            "/api/echo", headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Cross-origin API request rejected"}

    def test_foreign_origin_post_rejected(self, browser_client):
        """Foreign `Origin` header on POST → 403, even with a valid session."""
        resp = browser_client.post(
            "/api/echo", headers={"Origin": "http://evil.com"}
        )
        assert resp.status_code == 403
        assert "Cross-origin" in resp.json()["detail"]

    def test_foreign_origin_put_rejected(self, browser_client):
        """PUT with foreign Origin → 403 (all MUTATING_METHODS covered)."""
        resp = browser_client.put(
            "/api/echo", headers={"Origin": "http://evil.com"}
        )
        assert resp.status_code == 403

    def test_foreign_origin_delete_rejected(self, browser_client):
        """DELETE with foreign Origin → 403."""
        resp = browser_client.delete(
            "/api/echo", headers={"Origin": "http://evil.com"}
        )
        assert resp.status_code == 403

    def test_same_origin_post_passes_csrf_gate(self, browser_client):
        """Same-origin POST with a valid session reaches the route → 200."""
        resp = browser_client.post(
            "/api/echo", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert resp.status_code == 200

    def test_sec_fetch_site_none_post_passes_csrf_gate(self, browser_client):
        """`Sec-Fetch-Site: none` is not cross-site → CSRF gate passes → 200."""
        resp = browser_client.post(
            "/api/echo", headers={"Sec-Fetch-Site": "none"}
        )
        assert resp.status_code == 200

    def test_same_origin_explicit_origin_passes(self, browser_client):
        """An explicit Origin equal to the request's own origin passes → 200."""
        resp = browser_client.post(
            "/api/echo", headers={"Origin": "http://testserver"}
        )
        assert resp.status_code == 200

    def test_dev_origin_mutating_rejected(self, browser_client):
        """SECURITY (codex #3 cycle 2): a non-own Origin — even a trusted-looking
        dev origin — is cross-site on a mutating request → 403. No allow-list
        bypass: a cookie is a host credential SameSite sends across ports, so a
        malicious local process on localhost:3000 must not drive mutating routes.
        """
        resp = browser_client.post(
            "/api/echo", headers={"Origin": "http://localhost:3000"}
        )
        assert resp.status_code == 403

    def test_foreign_origin_get_not_rejected_by_csrf(self, browser_client):
        """GET with a foreign Origin is NOT rejected by the CSRF gate (non-mutating)."""
        resp = browser_client.get(
            "/api/echo", headers={"Origin": "http://evil.com"}
        )
        # CSRF gate is mutating-only; the valid session still authenticates.
        assert resp.status_code != 403
        assert resp.status_code == 200

    def test_non_api_path_exempt(self, echo_app, _set_token):
        """Non-/api/* paths are not processed by the BFF middleware at all."""
        from starlette.testclient import TestClient

        # Add a route outside /api/ that accepts POST
        @echo_app.api_route("/public", methods=["GET", "POST"])
        async def public():
            return {"ok": True}

        with TestClient(echo_app) as c:
            resp = c.post("/public", headers={"Origin": "http://evil.com"})
            # No 403 — CSRF gate only fires for /api/* paths
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 2. Session-cookie bearer injection (auth)
# ---------------------------------------------------------------------------


class TestSessionInjection:
    def test_valid_session_cookie_gets_bearer(self, browser_client):
        """A valid session cookie → bearer injected → 200, token reflected."""
        resp = browser_client.get("/api/echo")
        assert resp.status_code == 200
        assert resp.json()["auth"] == f"Bearer {_TEST_TOKEN}"

    def test_forged_headers_without_cookie_rejected(self, echo_client):
        """SECURITY (codex #3): forgeable first-party headers without a session
        cookie get NO injection → 401. A local process cannot authenticate by
        setting Sec-Fetch-Site / Origin alone."""
        for headers in (
            {"Sec-Fetch-Site": "same-origin"},
            {"Sec-Fetch-Site": "none"},
            {"Origin": "http://localhost:3000"},
            {"Origin": "http://127.0.0.1:8400"},
        ):
            resp = echo_client.get("/api/echo", headers=headers)
            assert resp.status_code == 401, headers

    def test_invalid_session_cookie_rejected(self, echo_client):
        """A wrong session cookie value → no injection → 401."""
        echo_client.cookies.set("aptl_session", "not-the-real-secret")
        resp = echo_client.get(
            "/api/echo", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert resp.status_code == 401

    def test_explicit_wrong_auth_not_overwritten(self, browser_client):
        """Explicit (wrong) Authorization is NOT overwritten, even with a session → 401."""
        resp = browser_client.get(
            "/api/echo",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401

    def test_explicit_correct_auth_passes_through(self, echo_client):
        """Correct explicit Authorization passes without a cookie → 200."""
        resp = echo_client.get(
            "/api/echo",
            headers={"Authorization": f"Bearer {_TEST_TOKEN}"},
        )
        assert resp.status_code == 200

    def test_no_token_configured_no_injection(self, no_token_echo_client):
        """Valid session but no API token configured → nothing to inject → 401."""
        resp = no_token_echo_client.get("/api/echo")
        assert resp.status_code == 401

    def test_no_cookie_no_auth_rejected(self, echo_client):
        """No cookie and no Authorization → direct API client → 401."""
        resp = echo_client.get("/api/echo")
        assert resp.status_code == 401

    def test_cookie_without_header_rejected(self, echo_client):
        """SECURITY (F3): a valid cookie WITHOUT the header token → no injection
        → 401. Models a cross-port attacker who stole the host-scoped cookie but
        cannot read the port-scoped sessionStorage header token."""
        from aptl.api.session import session_cookie_value

        echo_client.cookies.set("aptl_session", session_cookie_value())
        resp = echo_client.get("/api/echo")
        assert resp.status_code == 401

    def test_header_without_cookie_rejected(self, echo_client):
        """SECURITY (F3): a valid header token WITHOUT the cookie → 401. Models an
        XSS payload that exfiltrated the sessionStorage token but cannot read the
        HttpOnly cookie."""
        from aptl.api.session import session_header_value

        resp = echo_client.get(
            "/api/echo", headers={"X-APTL-Session": session_header_value()}
        )
        assert resp.status_code == 401

    def test_leaked_cookie_value_as_header_rejected(self, echo_client):
        """SECURITY (F3): presenting the cookie value ALSO as the header (what a
        cross-port attacker who only has the cookie could try) → 401. Proves the
        two tags are domain-separated: the cookie tag is not a valid header tag."""
        from aptl.api.session import session_cookie_value

        cookie_value = session_cookie_value()
        echo_client.cookies.set("aptl_session", cookie_value)
        resp = echo_client.get(
            "/api/echo", headers={"X-APTL-Session": cookie_value}
        )
        assert resp.status_code == 401

    def test_both_factors_inject_bearer(self, echo_client):
        """Both valid factors together → bearer injected → 200."""
        from aptl.api.session import session_cookie_value, session_header_value

        echo_client.cookies.set("aptl_session", session_cookie_value())
        resp = echo_client.get(
            "/api/echo", headers={"X-APTL-Session": session_header_value()}
        )
        assert resp.status_code == 200
        assert resp.json()["auth"] == f"Bearer {_TEST_TOKEN}"


# ---------------------------------------------------------------------------
# 3. Host gate (DNS-rebinding defence)
# ---------------------------------------------------------------------------


class TestHostGate:
    def test_disallowed_host_rejected(self, browser_client):
        """A non-loopback Host (rebinding attacker) → 403 even with a session."""
        resp = browser_client.get("/api/echo", headers={"Host": "evil.com"})
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Host not allowed"}

    def test_loopback_host_allowed(self, browser_client):
        """An explicit loopback Host passes the gate → 200."""
        resp = browser_client.get("/api/echo", headers={"Host": "127.0.0.1:8400"})
        assert resp.status_code == 200

    def test_disallowed_host_rejected_before_auth(self, echo_client):
        """Host gate fires before auth — disallowed host → 403, not 401."""
        resp = echo_client.get(
            "/api/echo",
            headers={"Host": "attacker.example", "Authorization": f"Bearer {_TEST_TOKEN}"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 4. Launch handshake (/api/auth/login)
# ---------------------------------------------------------------------------


class TestLoginHandshake:
    @pytest.fixture()
    def login_client(self, tmp_path, _set_token):
        from aptl.api.deps import get_project_dir
        from aptl.api.main import create_app
        from starlette.testclient import TestClient

        app = create_app()
        app.dependency_overrides[get_project_dir] = lambda: tmp_path
        # Default http base_url models the 98% case: `aptl web serve` on the
        # loopback origin. The cookie's Secure flag follows the request scheme,
        # so over http it is NOT Secure and the generic HTTP client stores and
        # resends it (just as a browser does on loopback). The https path is
        # covered separately by test_login_cookie_secure_flag_follows_scheme.
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c

    def test_valid_launch_token_sets_cookie_and_redirects(self, login_client):
        """A valid launch token → 303 redirect + HttpOnly cookie + header token.

        The redirect target carries the port-scoped header token in the URL
        fragment (so the SPA can store it); the cookie is the HttpOnly factor.
        """
        from aptl.api.session import session_header_value

        resp = login_client.get(
            f"/api/auth/login?token={_LAUNCH_TOKEN}", follow_redirects=False
        )
        assert resp.status_code == 303
        # Redirect goes to the SPA root with the header token in the fragment.
        assert resp.headers["location"] == f"/#aptl_session={session_header_value()}"
        set_cookie = resp.headers.get("set-cookie", "")
        assert "aptl_session=" in set_cookie
        assert "httponly" in set_cookie.lower()
        assert "samesite=strict" in set_cookie.lower()
        # Over plain http (loopback serve) the cookie must NOT be Secure, or the
        # browser would withhold it and the two-factor session never completes.
        assert "secure" not in set_cookie.lower()

    def test_login_cookie_secure_flag_follows_scheme(self, tmp_path, _set_token):
        """Over https the session cookie IS issued Secure (TLS-fronted deploys).

        A real browser, or a same-host TLS proxy (Tailscale Serve / Caddy) whose
        X-Forwarded-Proto uvicorn trusts from loopback, reaches the app over
        https; the cookie must then carry Secure. Modelled with an https base_url.
        """
        from aptl.api.deps import get_project_dir
        from aptl.api.main import create_app
        from starlette.testclient import TestClient

        app = create_app()
        app.dependency_overrides[get_project_dir] = lambda: tmp_path
        with TestClient(
            app, base_url="https://testserver", raise_server_exceptions=True
        ) as c:
            resp = c.get(
                f"/api/auth/login?token={_LAUNCH_TOKEN}", follow_redirects=False
            )
        assert resp.status_code == 303
        assert "secure" in resp.headers.get("set-cookie", "").lower()

    def test_cookie_from_handshake_authenticates_api(self, login_client):
        """After the handshake, both issued factors authenticate /api/* calls.

        The client persists the (non-Secure, loopback-http) Set-Cookie
        automatically; a real browser also captures the header token from the
        redirect fragment, which we simulate by sending ``X-APTL-Session``.
        """
        from aptl.api.session import session_header_value

        login_client.get(
            f"/api/auth/login?token={_LAUNCH_TOKEN}", follow_redirects=False
        )
        resp = login_client.get(
            "/api/health", headers={"X-APTL-Session": session_header_value()}
        )
        assert resp.status_code == 200

    def test_cookie_alone_from_handshake_insufficient(self, login_client):
        """SECURITY (F3): the handshake cookie WITHOUT the header token → 401.

        A cross-port attacker who steals only the (host-scoped) cookie cannot
        authenticate without the port-scoped header token.
        """
        login_client.get(
            f"/api/auth/login?token={_LAUNCH_TOKEN}", follow_redirects=False
        )
        resp = login_client.get("/api/health")  # cookie persisted, header absent
        assert resp.status_code == 401

    def test_invalid_launch_token_rejected(self, login_client):
        """A wrong launch token → 401, no cookie set."""
        resp = login_client.get(
            "/api/auth/login?token=wrong", follow_redirects=False
        )
        assert resp.status_code == 401
        assert "set-cookie" not in resp.headers

    def test_missing_launch_token_rejected(self, login_client):
        """No launch token → 401."""
        resp = login_client.get("/api/auth/login", follow_redirects=False)
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 5. Against the real create_app()
# ---------------------------------------------------------------------------


class TestRealApp:
    @pytest.fixture()
    def real_client(self, tmp_path, _set_token, monkeypatch):
        from aptl.api.deps import get_project_dir
        from aptl.api.main import create_app
        from starlette.testclient import TestClient

        app = create_app()
        app.dependency_overrides[get_project_dir] = lambda: tmp_path
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c

    def test_session_cookie_health_injects(self, real_client):
        """Both valid session factors → bearer injected for GET /api/health → 200."""
        from aptl.api.session import session_cookie_value, session_header_value

        real_client.cookies.set("aptl_session", session_cookie_value())
        resp = real_client.get(
            "/api/health", headers={"X-APTL-Session": session_header_value()}
        )
        assert resp.status_code == 200

    def test_same_origin_without_cookie_rejected(self, real_client):
        """SECURITY (codex #3): same-origin headers without a session → 401."""
        resp = real_client.get(
            "/api/health", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert resp.status_code == 401

    def test_cross_site_post_still_rejected(self, real_client, tmp_path):
        """Cross-site POST rejected at middleware before reaching any route."""
        from aptl.api.session import session_cookie_value, session_header_value

        real_client.cookies.set("aptl_session", session_cookie_value())
        resp = real_client.post(
            "/api/lab/kill",
            headers={
                "Sec-Fetch-Site": "cross-site",
                "X-APTL-Session": session_header_value(),
            },
        )
        assert resp.status_code == 403

    def test_no_auth_no_cookie_returns_401(self, real_client):
        """No auth, no cookie → 401 (not injected, not cross-site)."""
        resp = real_client.get("/api/health")
        assert resp.status_code == 401

    def test_explicit_token_still_works(self, real_client):
        """Direct API clients with their own bearer pass through unchanged."""
        resp = real_client.get(
            "/api/health", headers={"Authorization": f"Bearer {_TEST_TOKEN}"}
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 4. Static asset serving + SPA fallback
# ---------------------------------------------------------------------------


def _make_asset_root(tmp_path: Path) -> Path:
    """Create a minimal SPA build directory under tmp_path."""
    root = tmp_path / "web_build"
    root.mkdir()
    (root / "index.html").write_text("<!doctype html><html><body>SPA</body></html>")
    (root / "app.js").write_text("// js bundle")
    return root


class TestStaticAssets:
    @pytest.fixture()
    def spa_app(self, tmp_path, _set_token, monkeypatch):
        """Real create_app() with a valid web asset root set via env.

        ``get_web_asset_root`` reads ``APTL_WEB_ROOT`` at call time, so a
        monkeypatched env var is picked up without any module reload.
        ``create_app()`` calls ``load_web_auth()`` internally, so no explicit
        call is needed here.  Avoiding ``importlib.reload`` is important:
        reload replaces function objects in ``aptl.api.deps``, while
        ``aptl.api.routers.terminal`` (imported once) still holds the original
        references — dependency override keys would no longer match, breaking
        ``api_client`` in all subsequent ``test_api_terminal.py`` tests.
        """
        root = _make_asset_root(tmp_path)
        monkeypatch.setenv("APTL_WEB_ROOT", str(root))

        from aptl.api.deps import get_project_dir
        from aptl.api.main import create_app
        from starlette.testclient import TestClient

        app = create_app()
        app.dependency_overrides[get_project_dir] = lambda: tmp_path

        with TestClient(app, raise_server_exceptions=False) as c:
            yield c

    def test_get_root_returns_index_html(self, spa_app):
        """GET / returns the SPA index.html."""
        resp = spa_app.get("/")
        assert resp.status_code == 200
        assert "SPA" in resp.text

    def test_unknown_client_route_returns_index_html(self, spa_app):
        """GET /terminal/x returns index.html (SPA fallback)."""
        resp = spa_app.get("/terminal/x")
        assert resp.status_code == 200
        assert "SPA" in resp.text

    def test_api_unknown_not_served_as_html(self, spa_app):
        """GET /api/unknown never serves index.html; returns 401 (no auth)."""
        resp = spa_app.get("/api/unknown")
        # Must be 401 (auth gate) or 404 (after valid auth) — never 200 HTML
        assert resp.status_code in (401, 404)
        assert "SPA" not in resp.text

    def test_api_health_works_without_asset_root(self, _set_token, tmp_path, monkeypatch):
        """Without an asset root, app starts and /api/health is functional."""
        monkeypatch.delenv("APTL_WEB_ROOT", raising=False)

        from aptl.api.deps import get_project_dir
        from aptl.api.main import create_app
        from starlette.testclient import TestClient

        app = create_app()
        app.dependency_overrides[get_project_dir] = lambda: tmp_path

        with TestClient(app) as c:
            resp = c.get(
                "/api/health",
                headers={"Authorization": f"Bearer {_TEST_TOKEN}"},
            )
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 5. get_web_asset_root resolver
# ---------------------------------------------------------------------------


class TestGetWebAssetRoot:
    def test_explicit_arg_wins_over_env(self, tmp_path, monkeypatch):
        """Explicit arg takes top precedence over APTL_WEB_ROOT."""
        explicit_root = tmp_path / "explicit"
        explicit_root.mkdir()
        (explicit_root / "index.html").write_text("<html/>")

        env_root = tmp_path / "env_root"
        env_root.mkdir()
        (env_root / "index.html").write_text("<html/> env")
        monkeypatch.setenv("APTL_WEB_ROOT", str(env_root))

        from aptl.api.deps import get_web_asset_root
        assert get_web_asset_root(str(explicit_root)) == explicit_root

    def test_explicit_arg_without_index_skips_to_next_candidate(self, tmp_path, monkeypatch):
        """Explicit arg dir without index.html → falls through to next candidate."""
        root_no_index = tmp_path / "empty"
        root_no_index.mkdir()

        env_root = tmp_path / "env_root"
        env_root.mkdir()
        (env_root / "index.html").write_text("<html/>")
        monkeypatch.setenv("APTL_WEB_ROOT", str(env_root))

        from aptl.api.deps import get_web_asset_root
        # Explicit has no index.html → falls through → env_root wins
        result = get_web_asset_root(str(root_no_index))
        assert result == env_root

    def test_env_fallback(self, tmp_path, monkeypatch):
        """APTL_WEB_ROOT env var is used when no explicit arg given."""
        root = tmp_path / "env_root"
        root.mkdir()
        (root / "index.html").write_text("<html/>")
        monkeypatch.setenv("APTL_WEB_ROOT", str(root))
        from aptl.api.deps import get_web_asset_root
        result = get_web_asset_root()
        assert result == root

    def test_env_wins_over_repo_relative(self, tmp_path, monkeypatch):
        """APTL_WEB_ROOT wins over the repo-relative web/build fallback."""
        env_root = tmp_path / "custom_root"
        env_root.mkdir()
        (env_root / "index.html").write_text("<html/>")
        monkeypatch.setenv("APTL_WEB_ROOT", str(env_root))

        from aptl.api.deps import get_web_asset_root
        result = get_web_asset_root()
        # Should be the env root, not the repo's web/build
        assert result == env_root

    def test_nonexistent_explicit_returns_next_match(self, tmp_path, monkeypatch):
        """When explicit path does not exist at all, falls through to env."""
        monkeypatch.delenv("APTL_WEB_ROOT", raising=False)
        env_root = tmp_path / "env"
        env_root.mkdir()
        (env_root / "index.html").write_text("<html/>")
        monkeypatch.setenv("APTL_WEB_ROOT", str(env_root))

        from aptl.api.deps import get_web_asset_root
        result = get_web_asset_root("/nonexistent/path/that/does/not/exist")
        assert result == env_root

    def test_tmp_dir_with_index_resolves(self, tmp_path):
        """A tmp dir passed explicitly with index.html is returned as-is."""
        (tmp_path / "index.html").write_text("<html/>")
        from aptl.api.deps import get_web_asset_root
        assert get_web_asset_root(str(tmp_path)) == tmp_path


# ---------------------------------------------------------------------------
# SPA file resolution / path-traversal guard
# ---------------------------------------------------------------------------


class TestResolveSpaFile:
    """resolve_spa_file serves only files contained within the asset root."""

    @pytest.fixture()
    def web_root(self, tmp_path):
        (tmp_path / "index.html").write_text("<!doctype html>root")
        assets = tmp_path / "_app"
        assets.mkdir()
        (assets / "app.js").write_text("console.log(1)")
        # A secret living OUTSIDE the asset root, as a traversal target.
        (tmp_path.parent / "secret.txt").write_text("TOP SECRET")
        return tmp_path

    def test_serves_existing_contained_asset(self, web_root):
        from aptl.api.main import resolve_spa_file

        assert resolve_spa_file(web_root, "_app/app.js") == (
            web_root / "_app" / "app.js"
        ).resolve()

    def test_missing_file_falls_back_to_index(self, web_root):
        from aptl.api.main import resolve_spa_file

        # A client-side route with no matching file → index.html.
        assert resolve_spa_file(web_root, "terminal/kali") == (
            web_root / "index.html"
        )

    def test_empty_path_returns_index(self, web_root):
        from aptl.api.main import resolve_spa_file

        assert resolve_spa_file(web_root, "") == web_root / "index.html"

    def test_traversal_escape_returns_index_not_secret(self, web_root):
        from aptl.api.main import resolve_spa_file

        # ../secret.txt exists and is a real file, but escapes the root.
        result = resolve_spa_file(web_root, "../secret.txt")
        assert result == web_root.resolve() / "index.html"
        assert result.read_text() != "TOP SECRET"

    def test_deep_traversal_returns_index(self, web_root):
        from aptl.api.main import resolve_spa_file

        result = resolve_spa_file(web_root, "../../../../../../etc/passwd")
        assert result == web_root.resolve() / "index.html"
