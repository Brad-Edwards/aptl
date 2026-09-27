"""Role-checked virtual-host ingress for real guest browser services."""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, field_validator
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocket
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import WebSocketException

from aptl.workbench.app import BrowserPrincipal, ParticipantAuthorizer
from aptl.workbench.profiles import profile_for

_ACCESS_DENIED = "Participant service access denied"

_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


class BrowserRoute(BaseModel):
    """A trusted service destination; participants supply neither URLs nor ports."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    bookmark_ref: str
    hostname: str
    upstream: str

    @field_validator("bookmark_ref")
    @classmethod
    def known_surface(cls, value: str) -> str:
        """Require a browser surface published by the participant profiles."""
        allowed = {
            ref for role in ("red", "blue") for ref in profile_for(role).bookmark_refs
        } - {"aptl-guide"}
        if value not in allowed:
            raise ValueError("unknown participant browser service")
        return value

    @field_validator("hostname")
    @classmethod
    def local_name(cls, value: str) -> str:
        """Require a dedicated localhost virtual-host name."""
        import re

        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,180}\.localhost", value):
            raise ValueError("browser service requires a dedicated localhost name")
        return value

    @field_validator("upstream")
    @classmethod
    def loopback_service(cls, value: str) -> str:
        """Restrict upstreams to fixed loopback HTTP services."""
        url = urlsplit(value)
        if (
            url.scheme not in {"http", "https"}
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.path not in {"", "/"}
            or url.port is None
            or not ipaddress.ip_address(url.hostname).is_loopback
        ):
            raise ValueError("browser upstream must be a fixed loopback service")
        return value.rstrip("/")


class _ProxyDenied(Exception):
    """A bounded proxy operation stopped before returning upstream data."""

    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


class BrowserGateway:
    """Keep upstream root paths, cookies and websockets on separate virtual hosts."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        routes: tuple[BrowserRoute, ...],
        authorizer: ParticipantAuthorizer,
        tls_context: ssl.SSLContext | bool = True,
    ) -> None:
        self.app = app
        self.routes = {route.hostname: route for route in routes}
        if len(self.routes) != len(routes):
            raise ValueError("browser virtual hosts must be unique")
        self.authorizer = authorizer
        self.tls = tls_context
        self.slots = asyncio.Semaphore(16)

    def _admit(self, request: Request, route: BrowserRoute) -> int:
        """Map participant role authorization to a denial status or zero."""
        principal = self.authorizer(request)
        if not isinstance(principal, BrowserPrincipal):
            return 401
        allowed = {
            ref
            for role in principal.profiles
            for ref in profile_for(role).bookmark_refs
        }
        return 0 if route.bookmark_ref in allowed else 403

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Dispatch admitted browser requests to their fixed local upstream."""
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        request = Request({**scope, "type": "http"}, receive)
        route = self.routes.get(request.url.hostname)
        if route is None:
            await self.app(scope, receive, send)
            return
        denied = await asyncio.to_thread(self._admit, request, route)
        if denied:
            await self._deny(scope, receive, send, denied)
        else:
            async with self.slots:
                await self._proxy(scope, receive, send, request, route)

    @staticmethod
    async def _deny(scope: Scope, receive: Receive, send: Send, status: int) -> None:
        """Reject an unauthorized HTTP request or websocket handshake."""
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            await Response(_ACCESS_DENIED, status_code=status)(scope, receive, send)

    async def _proxy(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        request: Request,
        route: BrowserRoute,
    ) -> None:
        """Apply the connection budget to one admitted upstream request."""
        if scope["type"] == "websocket":
            await self._websocket(scope, receive, send, request, route)
        else:
            try:
                response = await asyncio.wait_for(
                    self._http(request, route), timeout=60
                )
            except asyncio.TimeoutError:
                response = Response("Guest browser service timed out", status_code=504)
            await response(scope, receive, send)

    @staticmethod
    def _headers(request: Request) -> list[tuple[str, str]]:
        """Remove hop-by-hop headers and the workbench session cookie."""
        headers = []
        for name, value in request.headers.items():
            if name.lower() in _HOP or name.lower().startswith(
                ("x-aptl-", "x-forwarded-")
            ):
                continue
            if name.lower() == "cookie":
                value = "; ".join(
                    part.strip()
                    for part in value.split(";")
                    if not part.strip().startswith("aptl_participant=")
                )
            headers.append((name, value))
        return headers

    async def _http(self, request: Request, route: BrowserRoute) -> Response:
        """Proxy bounded HTTP traffic with authorization checks during streaming."""
        try:
            body = await self._request_body(request, route)
            path = request.scope.get("raw_path", request.url.path.encode()).decode(
                "ascii"
            )
            target = (
                route.upstream
                + path
                + ("?" + request.url.query if request.url.query else "")
            )
            async with httpx.AsyncClient(
                verify=self.tls, trust_env=False, follow_redirects=False, timeout=30
            ) as client:
                async with client.stream(
                    request.method, target, headers=self._headers(request), content=body
                ) as upstream:
                    return await self._http_response(upstream, request, route)
        except _ProxyDenied as exc:
            return Response(str(exc), status_code=exc.status)
        except (OSError, httpx.HTTPError):
            return Response("Guest browser service unavailable", status_code=502)

    async def _request_body(self, request: Request, route: BrowserRoute) -> bytes:
        """Reject cross-origin writes and oversized or newly unauthorized bodies."""
        origin = request.headers.get("origin")
        if (
            request.method not in {"GET", "HEAD", "OPTIONS"}
            and origin is not None
            and urlsplit(origin).netloc != request.headers.get("host")
        ):
            raise _ProxyDenied("Cross-origin request denied", 403)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16 * 1024**2:
                raise _ProxyDenied("Request limit exceeded", 413)
        if await asyncio.to_thread(self._admit, request, route):
            raise _ProxyDenied(_ACCESS_DENIED, 403)
        return bytes(body)

    async def _http_response(
        self, upstream: httpx.Response, request: Request, route: BrowserRoute
    ) -> Response:
        """Read bounded upstream content and rewrite service-local headers."""
        data = bytearray()
        async for chunk in upstream.aiter_raw():
            if await asyncio.to_thread(self._admit, request, route):
                raise _ProxyDenied(_ACCESS_DENIED, 403)
            data.extend(chunk)
            if len(data) > 64 * 1024**2:
                raise _ProxyDenied("Response limit exceeded", 502)
        response = Response(bytes(data), status_code=upstream.status_code)
        response.raw_headers = [
            (name.encode(), self._response_header(name, value, request, route).encode())
            for name, value in upstream.headers.multi_items()
            if name.lower() not in _HOP
        ]
        return response

    @staticmethod
    def _response_header(
        name: str, value: str, request: Request, route: BrowserRoute
    ) -> str:
        """Keep redirects and service cookies on the participant virtual host."""
        if name.lower() == "location" and value.startswith(route.upstream + "/"):
            return str(request.base_url).rstrip("/") + value[len(route.upstream) :]
        if name.lower() == "set-cookie":
            from http.cookies import SimpleCookie

            cookies = SimpleCookie()
            cookies.load(value)
            for cookie in cookies.values():
                cookie["domain"] = ""
            return cookies.output(header="").strip() if cookies else value
        return value

    async def _websocket(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        request: Request,
        route: BrowserRoute,
    ) -> None:
        """Relay bounded websocket traffic while checking grant revocation."""
        socket = WebSocket(scope, receive, send)
        origin = request.headers.get("origin")
        if origin is not None and urlsplit(origin).netloc != request.headers.get(
            "host"
        ):
            return await socket.close(code=1008)
        target = route.upstream.replace("http", "ws", 1) + request.url.path
        if request.url.query:
            target += "?" + request.url.query
        headers = [
            (name, value)
            for name, value in self._headers(request)
            if not name.lower().startswith("sec-websocket-")
            and name.lower() != "origin"
        ]
        options = (
            {"ssl": self.tls}
            if target.startswith("wss:") and isinstance(self.tls, ssl.SSLContext)
            else {}
        )
        try:
            async with connect(
                target,
                additional_headers=headers,
                subprotocols=scope.get("subprotocols") or None,
                proxy=None,
                max_size=1024**2,
                max_queue=8,
                **options,
            ) as upstream:
                await socket.accept(subprotocol=upstream.subprotocol)

                await self._bridge(socket, upstream, request, route)
        except (OSError, RuntimeError, WebSocketException):
            await socket.close(code=1011)

    async def _inbound(
        self,
        socket: WebSocket,
        upstream: ClientConnection,
        request: Request,
        route: BrowserRoute,
    ) -> None:
        """Forward bounded browser frames while rechecking role authorization."""
        while True:
            message = await socket.receive()
            if message["type"] == "websocket.disconnect":
                return
            data = (
                message.get("text")
                if message.get("text") is not None
                else message.get("bytes", b"")
            )
            if len(data) > 1024**2 or await asyncio.to_thread(
                self._admit, request, route
            ):
                return
            await upstream.send(data)

    @staticmethod
    async def _outbound(socket: WebSocket, upstream: ClientConnection) -> None:
        """Forward upstream frames without transforming their payload."""
        async for data in upstream:
            if isinstance(data, str):
                await socket.send_text(data)
            else:
                await socket.send_bytes(data)

    async def _watch(self, request: Request, route: BrowserRoute) -> None:
        """Detect revocation even when neither peer is sending frames."""
        while not await asyncio.to_thread(self._admit, request, route):
            await asyncio.sleep(0.5)

    async def _bridge(
        self,
        socket: WebSocket,
        upstream: ClientConnection,
        request: Request,
        route: BrowserRoute,
    ) -> None:
        """Cancel both directions and reap their tasks when the bridge closes."""
        tasks = [
            asyncio.create_task(coro)
            for coro in (
                self._inbound(socket, upstream, request, route),
                self._outbound(socket, upstream),
                self._watch(request, route),
            )
        ]
        try:
            await asyncio.wait(tasks, timeout=3600, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await socket.close()
