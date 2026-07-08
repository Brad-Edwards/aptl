"""Loopback-published TCP proxy for host-run Kali MCP SSH."""

from __future__ import annotations

import os
import socket
import threading


LISTEN = (
    os.getenv("APTL_PROXY_LISTEN_HOST", "0.0.0.0"),
    int(os.getenv("APTL_PROXY_LISTEN_PORT", "2023")),
)
TARGET = (
    os.getenv("APTL_PROXY_TARGET_HOST", "172.20.4.30"),
    int(os.getenv("APTL_PROXY_TARGET_PORT", "22")),
)


def _close(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    finally:
        _close(src)
        _close(dst)


def _handle(client: socket.socket) -> None:
    try:
        target = socket.create_connection(TARGET, timeout=10)
    except OSError:
        _close(client)
        return

    threading.Thread(target=_pipe, args=(client, target), daemon=True).start()
    threading.Thread(target=_pipe, args=(target, client), daemon=True).start()


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(LISTEN)
        server.listen()
        while True:
            client, _addr = server.accept()
            _handle(client)


if __name__ == "__main__":
    main()
