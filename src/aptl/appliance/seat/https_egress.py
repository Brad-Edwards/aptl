"""Public HTTPS access for a desktop guest without host or LAN networking.

QEMU's restricted user network forwards a single guest proxy address to the
``bridge`` command.  The command relays to this per-seat Unix socket.  The
server runs in the launching user's original network namespace, and only
CONNECT requests to public DNS destinations on port 443 are accepted.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import select
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

GUEST_PROXY_ADDRESS = "10.0.2.100"
GUEST_PROXY_PORT = 3128
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _public_address(hostname: str) -> tuple[int, tuple] | None:
    """Resolve a DNS name once and return an explicitly public socket target."""

    if (
        len(hostname) > 253
        or "." not in hostname
        or hostname.lower().endswith((".internal", ".local", ".localhost"))
        or any(not _HOST_LABEL.fullmatch(label) for label in hostname.split("."))
    ):
        return None
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return None
    try:
        answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    for family, _kind, _proto, _canonical, address in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        ip = ipaddress.ip_address(address[0])
        if ip.is_global and not (
            isinstance(ip, ipaddress.IPv6Address)
            and ip.ipv4_mapped is not None
            and not ip.ipv4_mapped.is_global
        ):
            return family, address
    return None


def _relay(left: socket.socket, right: socket.socket) -> None:
    """Pass opaque TLS bytes without inspecting credentials or content."""

    live = [left, right]
    while live:
        readable, _, _ = select.select(live, [], [], 600)
        if not readable:
            break
        for source in readable:
            chunk = source.recv(65536)
            destination = right if source is left else left
            if not chunk:
                live.remove(source)
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            else:
                destination.sendall(chunk)


class _ConnectHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client: socket.socket = self.request
        client.settimeout(10)
        header = bytearray()
        while b"\r\n\r\n" not in header and len(header) <= 16384:
            chunk = client.recv(4096)
            if not chunk:
                return
            header.extend(chunk)
        if len(header) > 16384 or b"\r\n\r\n" not in header:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        first_line, _separator, _rest = header.partition(b"\r\n")
        try:
            method, authority, version = first_line.decode("ascii").split(" ")
            hostname, port = authority.rsplit(":", 1)
        except (UnicodeDecodeError, ValueError):
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        if method != "CONNECT" or port != "443" or version != "HTTP/1.1":
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        target = _public_address(hostname)
        if target is None:
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        family, address = target
        established = False
        try:
            with socket.socket(family, socket.SOCK_STREAM) as remote:
                remote.settimeout(10)
                remote.connect(address)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                established = True
                client.settimeout(None)
                remote.settimeout(None)
                # HTTP clients send TLS only after CONNECT succeeds. Any bytes
                # read past the header are preserved in case a client pipelines.
                pending = header.split(b"\r\n\r\n", 1)[1]
                if pending:
                    remote.sendall(pending)
                _relay(client, remote)
        except OSError:
            if not established:
                try:
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                except OSError:
                    pass


class _ProxyServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, server_address: str, handler: type[_ConnectHandler]) -> None:
        self._capacity = threading.BoundedSemaphore(64)
        super().__init__(server_address, handler)

    def process_request(self, request: socket.socket, client_address: object) -> None:
        if not self._capacity.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
            except OSError:
                pass
            finally:
                request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._capacity.release()
            raise

    def process_request_thread(
        self, request: socket.socket, client_address: object,
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._capacity.release()


def serve(socket_path: Path, qemu_pid: int) -> None:
    """Serve until the matching QEMU process exits."""

    socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    socket_path.unlink(missing_ok=True)
    with _ProxyServer(str(socket_path), _ConnectHandler) as server:
        socket_path.chmod(0o600)
        identity = Path(f"/proc/{qemu_pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        server.timeout = 1
        while True:
            try:
                current = Path(f"/proc/{qemu_pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
            except OSError:
                break
            if current != identity:
                break
            server.handle_request()
    socket_path.unlink(missing_ok=True)


def bridge() -> None:
    """Attach one QEMU guestfwd connection to the private Unix socket."""

    path = os.environ["APTL_SEAT_HTTPS_SOCKET"]
    with socket.socket(socket.AF_UNIX) as remote:
        remote.connect(path)
        stdin_open = True
        while True:
            inputs = [remote]
            if stdin_open:
                inputs.append(sys.stdin.buffer)
            readable, _, _ = select.select(inputs, [], [], 600)
            if not readable:
                return
            for source in readable:
                if source is remote:
                    chunk = remote.recv(65536)
                    if not chunk:
                        return
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(sys.stdout.fileno(), view):]
                else:
                    chunk = os.read(sys.stdin.fileno(), 65536)
                    if chunk:
                        remote.sendall(chunk)
                    else:
                        stdin_open = False
                        remote.shutdown(socket.SHUT_WR)


def start_proxy(socket_path: Path, qemu_pid: int) -> subprocess.Popen[bytes]:
    """Start a detached per-seat proxy and wait for its private socket."""

    process = subprocess.Popen(
        [sys.executable, "-m", __name__, "serve", str(socket_path), str(qemu_pid)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        if socket_path.is_socket():
            return process
        time.sleep(0.05)
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    raise RuntimeError("desktop HTTPS proxy did not start")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("bridge", "serve"))
    parser.add_argument("socket", nargs="?")
    parser.add_argument("qemu_pid", nargs="?", type=int)
    args = parser.parse_args()
    if args.mode == "bridge":
        bridge()
    else:
        if args.socket is None or args.qemu_pid is None:
            parser.error("serve requires a socket and QEMU PID")
        serve(Path(args.socket), args.qemu_pid)


if __name__ == "__main__":
    main()
