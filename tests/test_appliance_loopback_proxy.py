"""Guest adapter tests for signed loopback publications."""

import socket
import threading

import pytest

from aptl.appliance.loopback_proxy import (
    ProxyBinding,
    _ThreadingProxyServer,
    build_proxy_bindings,
)
from tests.test_appliance_boundary_inventory import _policy


def test_proxy_bindings_preserve_signed_loopback_destinations() -> None:
    bindings = build_proxy_bindings(_policy(), adapter_address="10.0.2.15")

    assert [(item.listen_address, item.listen_port) for item in bindings] == [
        ("10.0.2.15", 443),
        ("10.0.2.15", 9443),
    ]
    assert [(item.target_address, item.target_port) for item in bindings] == [
        ("127.0.0.1", 443),
        ("127.0.0.1", 9443),
    ]


def test_proxy_bindings_reject_non_tcp_publication() -> None:
    policy = _policy().model_copy(
        update={
            "guest_publications": [
                _policy().guest_publications[0].model_copy(update={"protocol": "udp"})
            ]
        }
    )

    with pytest.raises(ValueError, match="TCP"):
        build_proxy_bindings(policy, adapter_address="10.0.2.15")


def test_proxy_relays_bytes_to_the_fixed_loopback_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream_port = upstream.getsockname()[1]
        target_connections: list[socket.socket] = []
        create_connection = socket.create_connection

        def observe_connection(
            address: tuple[str, int], timeout: float | object = socket._GLOBAL_DEFAULT_TIMEOUT
        ) -> socket.socket:
            connection = create_connection(address, timeout=timeout)
            if address == ("127.0.0.1", upstream_port):
                target_connections.append(connection)
            return connection

        monkeypatch.setattr(socket, "create_connection", observe_connection)

        def echo() -> None:
            connection, _ = upstream.accept()
            with connection:
                connection.sendall(connection.recv(1024).upper())

        echo_thread = threading.Thread(target=echo)
        echo_thread.start()
        proxy = _ThreadingProxyServer(
            ProxyBinding(
                listen_address="127.0.0.1",
                listen_port=0,
                target_address="127.0.0.1",
                target_port=upstream_port,
            )
        )
        proxy_thread = threading.Thread(target=proxy.serve_forever)
        proxy_thread.start()
        try:
            with socket.create_connection(proxy.server_address, timeout=2) as client:
                client.sendall(b"candidate")
                client.shutdown(socket.SHUT_WR)
                assert client.recv(1024) == b"CANDIDATE"
        finally:
            proxy.shutdown()
            proxy.server_close()
            proxy_thread.join(timeout=2)
            echo_thread.join(timeout=2)

    assert not proxy_thread.is_alive()
    assert not echo_thread.is_alive()
    assert len(target_connections) == 1
    assert target_connections[0].gettimeout() is None
