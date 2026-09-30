"""Security boundary checks for the desktop guest's public HTTPS path."""

from __future__ import annotations

import os
import socket
import threading
from pathlib import Path
from unittest.mock import patch

from aptl.appliance.seat.https_egress import (
    _ConnectHandler,
    _ProxyServer,
    _public_address,
    start_proxy,
)


def test_proxy_refuses_host_lan_and_non_https_requests(tmp_path: Path) -> None:
    path = tmp_path / "seat.sock"
    with _ProxyServer(str(path), _ConnectHandler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            requests = (
                (b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n", b"403"),
                (b"CONNECT localhost:443 HTTP/1.1\r\n\r\n", b"403"),
                (b"CONNECT 192.168.1.2:443 HTTP/1.1\r\n\r\n", b"403"),
                (b"CONNECT example.com:80 HTTP/1.1\r\n\r\n", b"403"),
                (b"GET http://example.com/ HTTP/1.1\r\n\r\n", b"403"),
            )
            for request, expected in requests:
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(path))
                    client.sendall(request)
                    assert expected in client.recv(256)
        finally:
            server.shutdown()
            worker.join(timeout=2)


def test_proxy_filters_dns_answers_and_pins_public_target() -> None:
    with patch("socket.getaddrinfo") as lookup:
        lookup.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
        ]
        assert _public_address("api.anthropic.com") == (
            socket.AF_INET, ("1.1.1.1", 443)
        )
        assert _public_address("10.0.0.1") is None
        assert _public_address("host.docker.internal") is None


def test_proxy_process_uses_private_unix_socket(tmp_path: Path) -> None:
    path = tmp_path / "seat.sock"
    process = start_proxy(path, os.getpid())
    try:
        assert path.is_socket()
        assert path.stat().st_mode & 0o777 == 0o600
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(path))
            client.sendall(b"CONNECT localhost:443 HTTP/1.1\r\n\r\n")
            assert b"403" in client.recv(256)
    finally:
        process.terminate()
        process.wait(timeout=5)
