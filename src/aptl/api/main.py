"""FastAPI application factory for the APTL web API."""

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response

from aptl.api.deps import (
    get_web_asset_root,
    load_web_auth,
    verify_token,
)
from aptl.api.middleware.bff import BFFMiddleware
from aptl.api.routers import config, kill, lab, scenarios, terminal
from aptl.api.session import (
    SESSION_COOKIE,
    SESSION_HEADER_PARAM,
    session_cookie_value,
    session_header_value,
    verify_launch_token,
)
from aptl.utils.logging import get_logger, setup_logging

log = get_logger("api")


def resolve_spa_file(web_root: Path, full_path: str) -> Path:
    """Resolve *full_path* to a file under *web_root*, falling back to index.html.

    Guards against path traversal: a ``full_path`` that escapes *web_root*
    (for example ``../../etc/passwd``) resolves outside the root and is treated
    as a client-side route, returning ``index.html`` rather than the escaped
    file. Only an existing regular file genuinely contained within *web_root* is
    served directly.
    """
    root = web_root.resolve()
    candidate = (root / full_path).resolve()
    if candidate.is_relative_to(root) and candidate.is_file():
        return candidate
    return root / "index.html"


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    setup_logging()
    log.info("Creating APTL web API application")

    # logs CRITICAL and returns None when APTL_API_TOKEN is absent
    load_web_auth()

    app = FastAPI(
        title="APTL Web API",
        description="Advanced Purple Team Lab — Web Interface API",
        version="0.1.0",
    )

    # BFF middleware: Host gate + CSRF gate + session-cookie bearer injection for
    # /api/*. Runs before all routers; non-HTTP (WebSocket) scopes pass through.
    app.add_middleware(BFFMiddleware)

    _auth = [Depends(verify_token)]

    app.include_router(lab.router, prefix="/api", dependencies=_auth)
    app.include_router(config.router, prefix="/api", dependencies=_auth)
    app.include_router(terminal.router, prefix="/api", dependencies=_auth)
    app.include_router(kill.router, prefix="/api", dependencies=_auth)
    app.include_router(scenarios.router, prefix="/api", dependencies=_auth)

    @app.get("/api/health", dependencies=_auth)
    async def health() -> dict[str, str]:
        """Return a liveness indicator for the web API."""
        return {"status": "ok"}

    # Launch handshake (UI-008a / ADR-039): the operator opens this URL (printed
    # to their terminal by `aptl web serve`) with the one-time launch token. On a
    # valid token, set the HttpOnly SameSite=Strict session cookie AND hand the
    # SPA the port-scoped header token, then redirect to the app. This is the ONLY
    # unauthenticated /api route — it mints the browser's two-factor session
    # credential, replacing forgeable-header trust. It must be registered before
    # the authenticated /api/{full_path} catch-all.
    #
    # The header token is delivered in the redirect URL *fragment* (`/#...`), not
    # a query string or a second cookie: a fragment is never sent to any server
    # (so it cannot leak to logs, the Referer header, or a sibling loopback port
    # the way a cookie does) and is readable only by same-origin page JS. The SPA
    # moves it into port-scoped sessionStorage and scrubs the fragment.
    @app.get(
        "/api/auth/login",
        include_in_schema=False,
        responses={401: {"description": "Invalid or missing one-time launch token."}},
    )
    async def login(request: Request, token: str = "") -> Response:
        """Exchange a valid launch token for the two-factor session, then redirect."""
        if not verify_launch_token(token):
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        resp = RedirectResponse(
            url=f"/#{SESSION_HEADER_PARAM}={session_header_value()}",
            status_code=303,
        )
        # The Secure flag follows the effective request scheme so the cookie is
        # delivered correctly across every shipping model. Over HTTPS (a TLS
        # front such as Tailscale Serve or the split aptl-web-ui Caddy profile,
        # surfaced here via uvicorn's loopback-trusted X-Forwarded-Proto) it is
        # mandatory. Over plain HTTP it must be OFF, or the browser withholds the
        # cookie and the two-factor session never completes: that covers the
        # default loopback `aptl web serve` (no wire to protect) and an opt-in
        # remote bind whose confidentiality comes from the transport (e.g.
        # Tailscale/WireGuard). request.url.scheme is trustworthy because
        # forwarded headers are honoured only from a loopback proxy.
        resp.set_cookie(
            SESSION_COOKIE,
            session_cookie_value(),
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="strict",
            path="/",
        )
        return resp

    # Authenticated catch-all for unmatched /api/* paths.
    # Without this, unmatched API paths would fall through to the SPA
    # catch-all and receive index.html instead of a 401/404.
    @app.api_route(
        "/api/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        dependencies=_auth,
        include_in_schema=False,
    )
    async def _api_wildcard() -> None:
        """Authenticated catch-all for unrecognised /api/* paths."""
        raise HTTPException(status_code=404, detail="Not found")

    # Conditionally mount built web assets and SPA fallback.
    # Routes are matched in insertion order, so this comes after all /api/*
    # routes, ensuring /api/* is never served as a static asset.
    web_root = get_web_asset_root()
    if web_root is not None:
        log.info("Serving GUI from %s", web_root)
        # close over resolved path
        _captured_root = web_root

        @app.get("/{full_path:path}", include_in_schema=False)
        async def _spa_fallback(full_path: str) -> FileResponse:
            """SPA catch-all: serve a contained static asset, else index.html.

            Added after all /api/* routes so route ordering lets /api/* match
            first; this intercepts every other GET. Path traversal is handled
            by :func:`resolve_spa_file`, which only serves files genuinely
            contained within the asset root.

            ``X-Frame-Options: DENY`` enforces the anti-clickjacking intent of
            the SPA's ``frame-ancestors 'none'`` CSP, which a ``<meta>``-delivered
            CSP cannot carry; ``X-Content-Type-Options: nosniff`` stops MIME
            sniffing.
            """
            return FileResponse(
                str(resolve_spa_file(_captured_root, full_path)),
                headers={
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                },
            )

    else:
        log.info(
            "No web assets found at any candidate location; running in API-only mode"
        )

    return app


app = create_app()
