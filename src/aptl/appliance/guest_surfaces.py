"""Minimal guest-owned HTTP surfaces for signed seat publications."""

from __future__ import annotations

import ipaddress
import json
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aptl.core.appliance_boundary import ApplianceBoundaryPolicy

_PARTICIPANT_PAGE = b"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>APTL participant seat</title></head>
<body><main><h1>APTL participant seat</h1>
<p>The isolated lab is available through your configured APTL MCP client.</p>
</main></body></html>
"""
_RECOVERY_STATUS = json.dumps(
    {"status": "available"}, separators=(",", ":"), sort_keys=True
).encode()


@dataclass(frozen=True)
class GuestSurfaceBinding:
    """One fixed guest-loopback HTTP publication."""

    audience: str
    address: str
    port: int

    def __post_init__(self) -> None:
        address = ipaddress.ip_address(self.address)
        if (
            self.audience not in {"participant", "recovery"}
            or not address.is_loopback
            or address.version != 4
            or not 0 <= self.port <= 65535
        ):
            raise ValueError("guest seat surface binding is invalid")


def build_guest_surface_bindings(
    policy: ApplianceBoundaryPolicy,
) -> tuple[GuestSurfaceBinding, ...]:
    """Select the exact participant and recovery listeners from signed policy."""

    publications = tuple(
        item
        for item in policy.guest_publications
        if item.audience in {"participant", "recovery"}
    )
    if (
        {item.audience for item in publications} != {"participant", "recovery"}
        or len(publications) != 2
        or any(item.protocol != "tcp" for item in publications)
    ):
        raise ValueError("signed seat surface publications are incomplete")
    return tuple(
        GuestSurfaceBinding(item.audience, item.address, item.port)
        for item in publications
    )


class _GuestSurfaceHandler(BaseHTTPRequestHandler):
    """Serve no management operations and disclose only coarse fixed content."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._respond(include_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._respond(include_body=False)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _respond(self, *, include_body: bool) -> None:
        server = self.server
        if not isinstance(server, _GuestSurfaceServer):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if self.path.split("?", 1)[0] not in {"/", "/healthz"}:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        participant = server.binding.audience == "participant"
        body = _PARTICIPANT_PAGE if participant else _RECOVERY_STATUS
        content_type = "text/html; charset=utf-8" if participant else "application/json"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        """Keep request metadata out of guest logs."""


class _GuestSurfaceServer(ThreadingHTTPServer):
    """Threaded listener carrying one immutable surface identity."""

    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, binding: GuestSurfaceBinding) -> None:
        self.binding = binding
        super().__init__((binding.address, binding.port), _GuestSurfaceHandler)


def serve_guest_surfaces(bindings: tuple[GuestSurfaceBinding, ...]) -> None:
    """Serve all signed guest surfaces until the process is terminated."""

    if {binding.audience for binding in bindings} != {"participant", "recovery"}:
        raise ValueError("guest seat surfaces are incomplete")
    servers = [_GuestSurfaceServer(binding) for binding in bindings]
    threads = [threading.Thread(target=server.serve_forever) for server in servers]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
