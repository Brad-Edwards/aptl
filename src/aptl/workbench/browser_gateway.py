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
from starlette.websockets import WebSocket
from websockets.asyncio.client import connect

from aptl.workbench.app import BrowserPrincipal
from aptl.workbench.profiles import profile_for

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
    def known_surface(cls, value):
        allowed = {
            ref for role in ("red", "blue") for ref in profile_for(role).bookmark_refs
        } - {"aptl-guide"}
        if value not in allowed:
            raise ValueError("unknown participant browser service")
        return value

    @field_validator("hostname")
    @classmethod
    def local_name(cls, value):
        import re

        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,180}\.localhost", value):
            raise ValueError("browser service requires a dedicated localhost name")
        return value

    @field_validator("upstream")
    @classmethod
    def loopback_service(cls, value):
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


class BrowserGateway:
    """Keep upstream root paths, cookies and websockets on separate virtual hosts."""

    def __init__(
        self, app, *, routes, authorizer, tls_context: ssl.SSLContext | bool = True
    ):
        self.app = app
        self.routes = {route.hostname: route for route in routes}
        if len(self.routes) != len(routes):
            raise ValueError("browser virtual hosts must be unique")
        self.authorizer = authorizer
        self.tls = tls_context
        self.slots = asyncio.Semaphore(16)

    def _admit(self, request, route):
        principal = self.authorizer(request)
        if not isinstance(principal, BrowserPrincipal):
            return 401
        allowed = {
            ref
            for role in principal.profiles
            for ref in profile_for(role).bookmark_refs
        }
        return 0 if route.bookmark_ref in allowed else 403

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            return await self.app(scope, receive, send)
        request = Request({**scope, "type": "http"}, receive)
        route = self.routes.get(request.url.hostname)
        if route is None:
            return await self.app(scope, receive, send)
        denied = await asyncio.to_thread(self._admit, request, route)
        if denied:
            if scope["type"] == "websocket":
                return await send({"type": "websocket.close", "code": 1008})
            return await Response(
                "Participant service access denied", status_code=denied
            )(scope, receive, send)
        async with self.slots:
            if scope["type"] == "websocket":
                return await self._websocket(scope, receive, send, request, route)
            try:
                response = await asyncio.wait_for(
                    self._http(request, route), timeout=60
                )
            except asyncio.TimeoutError:
                response = Response("Guest browser service timed out", status_code=504)
            return await response(scope, receive, send)

    @staticmethod
    def _headers(request):
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

    async def _http(self, request, route):
        origin = request.headers.get("origin")
        if (
            request.method not in {"GET", "HEAD", "OPTIONS"}
            and origin is not None
            and urlsplit(origin).netloc != request.headers.get("host")
        ):
            return Response("Cross-origin request denied", status_code=403)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16 * 1024**2:
                return Response("Request limit exceeded", status_code=413)
        if await asyncio.to_thread(self._admit, request, route):
            return Response("Participant service access denied", status_code=403)
        path = request.scope.get("raw_path", request.url.path.encode()).decode("ascii")
        target = (
            route.upstream
            + path
            + ("?" + request.url.query if request.url.query else "")
        )
        try:
            async with httpx.AsyncClient(
                verify=self.tls, trust_env=False, follow_redirects=False, timeout=30
            ) as client:
                async with client.stream(
                    request.method,
                    target,
                    headers=self._headers(request),
                    content=bytes(body),
                ) as upstream:
                    data = bytearray()
                    async for chunk in upstream.aiter_raw():
                        if await asyncio.to_thread(self._admit, request, route):
                            return Response(
                                "Participant service access denied", status_code=403
                            )
                        data.extend(chunk)
                        if len(data) > 64 * 1024**2:
                            return Response("Response limit exceeded", status_code=502)
                    response = Response(bytes(data), status_code=upstream.status_code)
                    response.raw_headers = [
                        (
                            name.encode(),
                            self._response_header(name, value, request, route).encode(),
                        )
                        for name, value in upstream.headers.multi_items()
                        if name.lower() not in _HOP
                    ]
                    return response
        except (OSError, httpx.HTTPError):
            return Response("Guest browser service unavailable", status_code=502)

    @staticmethod
    def _response_header(name, value, request, route):
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

    async def _websocket(self, scope, receive, send, request, route):
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
                subprotocols=scope.get("subprotocols", []),
                proxy=None,
                max_size=1024**2,
                max_queue=8,
                **options,
            ) as upstream:
                await socket.accept(subprotocol=upstream.subprotocol)

                async def inbound():
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

                async def outbound():
                    async for data in upstream:
                        if isinstance(data, str):
                            await socket.send_text(data)
                        else:
                            await socket.send_bytes(data)

                async def watch():
                    while not await asyncio.to_thread(self._admit, request, route):
                        await asyncio.sleep(0.5)

                tasks = [
                    asyncio.create_task(coro)
                    for coro in (inbound(), outbound(), watch())
                ]
                try:
                    await asyncio.wait(
                        tasks, timeout=3600, return_when=asyncio.FIRST_COMPLETED
                    )
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    await socket.close()
        except (OSError, RuntimeError):
            await socket.close(code=1011)
