"""Guest-side projection of signed loopback publications onto the VM adapter."""

from __future__ import annotations

import ipaddress
import socket
import socketserver
import threading
from dataclasses import dataclass

from aptl.core.appliance_boundary import ApplianceBoundaryPolicy


@dataclass(frozen=True)
class ProxyBinding:
    """One exact TCP listener and signed loopback destination."""

    listen_address: str
    listen_port: int
    target_address: str
    target_port: int


def build_proxy_bindings(
    policy: ApplianceBoundaryPolicy,
    *,
    adapter_address: str,
) -> tuple[ProxyBinding, ...]:
    """Project signed TCP publications onto one private guest adapter address."""

    adapter = ipaddress.ip_address(adapter_address)
    if not adapter.is_private or adapter.is_loopback or adapter.version != 4:
        raise ValueError("proxy adapter address must be private non-loopback IPv4")
    bindings: list[ProxyBinding] = []
    for publication in policy.guest_publications:
        if publication.protocol != "tcp":
            raise ValueError("guest publication proxy supports TCP only")
        bindings.append(
            ProxyBinding(
                listen_address=str(adapter),
                listen_port=publication.port,
                target_address=publication.address,
                target_port=publication.port,
            )
        )
    listeners = {(item.listen_address, item.listen_port) for item in bindings}
    if len(listeners) != len(bindings):
        raise ValueError("guest publication proxy listeners must be unique")
    return tuple(bindings)


def _relay(client: socket.socket, target: socket.socket) -> None:
    """Copy one connection in both directions until either side closes."""

    def copy(source: socket.socket, destination: socket.socket) -> None:
        """Copy one half of the bidirectional stream and close its writer."""

        try:
            while payload := source.recv(64 * 1024):
                destination.sendall(payload)
        except OSError:
            pass
        finally:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    upstream = threading.Thread(target=copy, args=(client, target), daemon=True)
    try:
        upstream.start()
        copy(target, client)
        upstream.join(timeout=5)
    finally:
        client.close()
        target.close()


class _ProxyHandler(socketserver.BaseRequestHandler):
    """Connect one admitted listener to its immutable loopback destination."""

    def handle(self) -> None:
        server = self.server
        if not isinstance(server, _ThreadingProxyServer):
            return
        try:
            target = socket.create_connection(server.target, timeout=10)
        except OSError:
            return
        _relay(self.request, target)


class _ThreadingProxyServer(socketserver.ThreadingTCPServer):
    """Threaded TCP listener with one fixed destination."""

    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, binding: ProxyBinding) -> None:
        self.target = (binding.target_address, binding.target_port)
        super().__init__((binding.listen_address, binding.listen_port), _ProxyHandler)


def serve_proxy_bindings(bindings: tuple[ProxyBinding, ...]) -> None:
    """Serve all bindings until the process receives termination."""

    if not bindings:
        raise ValueError("guest publication proxy requires at least one binding")
    servers = [_ThreadingProxyServer(binding) for binding in bindings]
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
