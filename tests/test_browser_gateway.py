"""Browser service access checks the caller role before reaching a real backend."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_gateway_preserves_root_paths_and_denies_other_role():
    from aptl.workbench.app import BrowserPrincipal
    from aptl.workbench.browser_gateway import BrowserGateway, BrowserRoute

    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"actual service response")

        def log_message(self, *_):
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    principal = [BrowserPrincipal("alice", ("red",))]
    route = BrowserRoute(
        bookmark_ref="soc-thehive",
        hostname="thehive.seat.localhost",
        upstream=f"http://127.0.0.1:{upstream.server_port}",
    )
    app = BrowserGateway(FastAPI(), routes=(route,), authorizer=lambda _: principal[0])
    try:
        client = TestClient(app)
        assert client.get("http://thehive.seat.localhost/api/cases").status_code == 403
        assert hits == []
        principal[0] = BrowserPrincipal("alice", ("blue",))
        response = client.get("http://thehive.seat.localhost/api/cases")
        assert response.status_code == 200
        assert response.text == "actual service response"
        assert hits == ["/api/cases"]
        principal[0] = None
        assert client.get("http://thehive.seat.localhost/api/cases").status_code == 401
    finally:
        upstream.shutdown()
        thread.join()
        upstream.server_close()


def test_gateway_websocket_relays_both_frame_types_and_closes_revoked_session():
    import pytest
    from starlette.websockets import WebSocketDisconnect
    from websockets.sync.server import serve

    from aptl.workbench.app import BrowserPrincipal
    from aptl.workbench.browser_gateway import BrowserGateway, BrowserRoute

    def echo(socket):
        for message in socket:
            socket.send(message)

    with serve(echo, "127.0.0.1", 0) as upstream:
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        principal = [BrowserPrincipal("alice", ("blue",))]
        port = upstream.socket.getsockname()[1]
        route = BrowserRoute(
            bookmark_ref="soc-thehive",
            hostname="thehive.seat.localhost",
            upstream=f"http://127.0.0.1:{port}",
        )
        gateway = BrowserGateway(
            FastAPI(), routes=(route,), authorizer=lambda _: principal[0]
        )
        try:
            with TestClient(gateway) as client:
                with client.websocket_connect(
                    "ws://thehive.seat.localhost/events?seat=1"
                ) as socket:
                    socket.send_text("text frame")
                    assert socket.receive_text() == "text frame"
                    socket.send_bytes(b"binary frame")
                    assert socket.receive_bytes() == b"binary frame"
                    principal[0] = None
                    with pytest.raises(WebSocketDisconnect):
                        socket.receive_text()
                principal[0] = BrowserPrincipal("alice", ("red",))
                denied = client.websocket_connect("ws://thehive.seat.localhost/events")
                with pytest.raises(WebSocketDisconnect):
                    denied.__enter__()
        finally:
            upstream.shutdown()
            thread.join(timeout=5)


def test_gateway_rewrites_local_redirects_and_strips_workbench_cookie():
    from starlette.requests import Request

    from aptl.workbench.browser_gateway import BrowserGateway, BrowserRoute

    route = BrowserRoute(
        bookmark_ref="soc-thehive",
        hostname="thehive.seat.localhost",
        upstream="http://127.0.0.1:9000",
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "query_string": b"",
            "server": ("thehive.seat.localhost", 8080),
            "headers": [
                (b"host", b"thehive.seat.localhost:8080"),
                (b"cookie", b"aptl_participant=private-session; service=retained"),
                (b"x-aptl-owner", b"untrusted"),
                (b"x-forwarded-host", b"foreign"),
            ],
        }
    )
    assert BrowserGateway._headers(request) == [("cookie", "service=retained")]
    assert (
        BrowserGateway._response_header(
            "Location", route.upstream + "/login", request, route
        )
        == "http://thehive.seat.localhost:8080/login"
    )
    cookie = BrowserGateway._response_header(
        "Set-Cookie", "service=value; Domain=internal.local; HttpOnly", request, route
    )
    assert "Domain" not in cookie
    assert "HttpOnly" in cookie
