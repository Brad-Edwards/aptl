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
