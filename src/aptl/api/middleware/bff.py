"""BFF middleware: Host gate, CSRF gate, and session-cookie bearer injection.

For requests whose path starts with /api/:

1. Host gate (DNS-rebinding defence): reject with 403 when the ``Host`` header is
   not a configured/loopback host. A rebound attacker page reaches the loopback
   service with an attacker ``Host``; rejecting it fails closed.

2. CSRF/origin gate (mutating methods only): reject with 403 when the request
   appears cross-site — ``Sec-Fetch-Site: cross-site``, OR an ``Origin`` header
   that is not the server's own origin (STRICT same-origin; no allow-list bypass,
   because the session cookie is a host credential that SameSite sends across
   ports). Fetch Metadata / Origin are a CSRF-isolation signal only; they are
   NEVER used to authenticate (they are client-forgeable — see ``aptl.api.session``).

3. Two-factor session bearer injection: when the request carries BOTH a valid
   ``aptl_session`` cookie AND a valid ``X-APTL-Session`` header, and no
   ``Authorization`` header, inject ``Authorization: Bearer <token>`` so the
   browser never holds the API token. Both factors are required because a cookie
   alone is not port-scoped (it leaks to sibling loopback ports, where a hostile
   local process could steal and replay it); the header token lives in the SPA's
   port-scoped ``sessionStorage`` and is never auto-sent on navigation, so a
   cross-port attacker who steals the cookie still cannot forge the header. A
   request lacking either factor falls through to ``verify_token`` → 401.
   Requests that already carry ``Authorization`` pass through unchanged (direct
   API clients validate their own token). See ``aptl.api.session`` for the full
   threat model.

Non-/api/* paths and non-HTTP scopes (WebSocket upgrades, lifespan) pass through
untouched. Implemented as a pure ASGI middleware rather than
``BaseHTTPMiddleware``, which buffers streaming responses and would break the
``/api/lab/events`` SSE stream — this middleware only inspects request headers
and either short-circuits or mutates the request scope's headers.
"""

import os

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from aptl.api.deps import current_api_token
from aptl.api.session import (
    SESSION_COOKIE,
    SESSION_HEADER,
    verify_session_cookie,
    verify_session_header,
)
from aptl.utils.logging import get_logger

log = get_logger("api.middleware.bff")

MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Loopback hosts always permitted; APTL_ALLOWED_HOSTS adds extras (comma-sep,
# e.g. the dev/preview UI origin host). Default is loopback-only per ADR-039.
_DEFAULT_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


def _allowed_hosts() -> set[str]:
    """Return the set of permitted ``Host`` hostnames (read at request time)."""
    extra = {
        h.strip()
        for h in os.environ.get("APTL_ALLOWED_HOSTS", "").split(",")
        if h.strip()
    }
    return set(_DEFAULT_HOSTS) | extra


def effective_allowed_hosts() -> list[str]:
    """Return the effective Host allow-list, sorted, for non-secret projection.

    The single owner of Host allow-list parsing is :func:`_allowed_hosts`; this
    public wrapper exposes its result (loopback defaults plus
    ``APTL_ALLOWED_HOSTS``) so the ``/config`` projection can display it without
    re-implementing the env parsing. Hostnames are non-secret.
    """
    return sorted(_allowed_hosts())


def _hostname(host_header: str) -> str:
    """Extract the hostname (no port) from a ``Host`` header value."""
    if not host_header:
        return ""
    if host_header.startswith("["):
        # bracketed IPv6, e.g. [::1]:8400
        end = host_header.find("]")
        return host_header[1:end] if end != -1 else host_header
    return host_header.split(":", 1)[0]


def _host_allowed(request: Request) -> bool:
    """Return True when the request's ``Host`` hostname is permitted."""
    return _hostname(request.headers.get("host", "")) in _allowed_hosts()


def _own_origin(request: Request) -> str:
    """Return the request's own origin as ``scheme://netloc``."""
    return f"{request.url.scheme}://{request.url.netloc}"


def _is_cross_site(request: Request) -> bool:
    """Return True when the request appears to originate from a different site.

    Checks ``Sec-Fetch-Site`` first (authoritative when present), then falls back
    to a STRICT ``Origin`` comparison: any ``Origin`` that is not the request's
    own origin is cross-site. No allow-list bypass — see ``aptl.api.deps``. This
    is a CSRF-isolation signal only.
    """
    if request.headers.get("sec-fetch-site") == "cross-site":
        return True
    origin = request.headers.get("origin")
    return origin is not None and origin != _own_origin(request)


def _has_valid_session(request: Request) -> bool:
    """Return True only when BOTH session factors are present and valid.

    The HttpOnly cookie (XSS-safe) and the ``sessionStorage`` header token
    (port-scoped, cross-port-safe) are independent; requiring both means neither
    a cross-port-leaked cookie nor an XSS-exfiltrated header token is sufficient
    on its own to trigger bearer injection.
    """
    cookie_ok = verify_session_cookie(request.cookies.get(SESSION_COOKIE))
    header_ok = verify_session_header(request.headers.get(SESSION_HEADER))
    return cookie_ok and header_ok


def _inject_bearer(scope: Scope, token: str) -> None:
    """Inject ``Authorization: Bearer <token>`` into *scope*'s headers in place."""
    raw: list[tuple[bytes, bytes]] = [
        (name, value)
        for name, value in scope["headers"]
        if name != b"authorization"
    ]
    raw.append((b"authorization", f"Bearer {token}".encode()))
    scope["headers"] = raw


class BFFMiddleware:
    """Backend-for-frontend Host gate, CSRF gate, and session bearer injection.

    Runs before all routers for HTTP requests on /api/* paths. Non-API paths and
    non-HTTP scopes are passed through untouched.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Apply the Host gate, CSRF gate, and session injection for /api/*."""
        if scope["type"] != "http" or not scope["path"].startswith("/api/"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        # --- Host gate (DNS-rebinding defence) ---
        if not _host_allowed(request):
            log.warning("BFF: rejected disallowed Host for %s", request.url.path)
            await JSONResponse(
                {"detail": "Host not allowed"}, status_code=403
            )(scope, receive, send)
            return

        # --- CSRF gate (mutating methods only) ---
        if request.method in MUTATING_METHODS and _is_cross_site(request):
            log.warning(
                "BFF: rejected cross-site %s to %s",
                request.method,
                request.url.path,
            )
            await JSONResponse(
                {"detail": "Cross-origin API request rejected"}, status_code=403
            )(scope, receive, send)
            return

        # --- Two-factor session bearer injection ---
        # Only a valid server-issued cookie AND the port-scoped sessionStorage
        # header together trigger injection; forgeable Fetch-Metadata/Origin
        # headers never do. Missing either factor (or an Authorization header
        # already present) falls through to verify_token → 401.
        if "authorization" not in request.headers and _has_valid_session(request):
            token = current_api_token()
            if token:
                _inject_bearer(scope, token)

        await self.app(scope, receive, send)
