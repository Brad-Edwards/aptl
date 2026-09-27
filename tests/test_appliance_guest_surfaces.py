"""Live protocol coverage for the appliance participant and health listeners."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

from aptl.appliance.guest_surfaces import GuestSurfaceBinding, _GuestSurfaceServer
from aptl.appliance.guest_surfaces import build_guest_surface_bindings
from tests.test_appliance_boundary_inventory import _policy


def _request(server: _GuestSurfaceServer, path: str = "/") -> tuple[int, bytes, dict[str, str]]:
    address, port = server.server_address
    with urllib.request.urlopen(f"http://{address}:{port}{path}", timeout=2) as response:
        return response.status, response.read(), dict(response.headers.items())


def test_participant_surface_is_a_bounded_non_operator_landing_page() -> None:
    server = _GuestSurfaceServer(
        GuestSurfaceBinding("participant", "127.0.0.1", 0)
    )
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        status, body, headers = _request(server)
        assert status == 200
        assert b"APTL participant seat" in body
        assert b"/api/" not in body
        assert headers["Cache-Control"] == "no-store"
        with urllib.request.urlopen(
            urllib.request.Request(
                f"http://{server.server_address[0]}:{server.server_address[1]}/",
                method="HEAD",
            ),
            timeout=2,
        ) as response:
            assert response.status == 200
            assert response.read() == b""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_recovery_surface_exposes_only_coarse_health() -> None:
    server = _GuestSurfaceServer(GuestSurfaceBinding("recovery", "127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        status, body, headers = _request(server, "/healthz")
        assert status == 200
        assert json.loads(body) == {"status": "available"}
        assert headers["Cache-Control"] == "no-store"
        request = urllib.request.Request(
            f"http://{server.server_address[0]}:{server.server_address[1]}/reset",
            data=b"",
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=2)
        except urllib.error.HTTPError as exc:
            assert exc.code == 405
        else:
            raise AssertionError("recovery surface admitted an operation")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_surface_bindings_are_derived_from_signed_publications() -> None:
    bindings = build_guest_surface_bindings(_policy())

    assert [(item.audience, item.address, item.port) for item in bindings] == [
        ("participant", "127.0.0.1", 443),
        ("recovery", "127.0.0.1", 9443),
    ]
