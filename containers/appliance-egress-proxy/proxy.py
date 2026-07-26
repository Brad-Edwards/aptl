#!/usr/bin/env python3
"""Small exact-authority CONNECT broker for appliance model egress."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import socket
from collections.abc import Iterable, Mapping
from pathlib import Path

_AUTHORITY = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")


class ProxyLimits:
    __slots__ = (
        "max_connections",
        "max_header_bytes",
        "header_timeout_seconds",
        "connect_timeout_seconds",
        "idle_timeout_seconds",
    )

    def __init__(
        self,
        *,
        max_connections: int,
        max_header_bytes: int,
        header_timeout_seconds: int,
        connect_timeout_seconds: int,
        idle_timeout_seconds: int,
    ) -> None:
        self.max_connections = max_connections
        self.max_header_bytes = max_header_bytes
        self.header_timeout_seconds = header_timeout_seconds
        self.connect_timeout_seconds = connect_timeout_seconds
        self.idle_timeout_seconds = idle_timeout_seconds


def parse_connect(
    request: bytes,
    allowed: set[tuple[str, int]],
    *,
    max_header_bytes: int = 4096,
) -> tuple[str, int]:
    """Return an exact admitted CONNECT target or reject the request."""

    if len(request) > max_header_bytes or b"\r\n\r\n" not in request:
        raise ValueError("CONNECT header is incomplete")
    try:
        first_line = request.split(b"\r\n", 1)[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("CONNECT request must be ASCII") from exc
    parts = first_line.split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] != "HTTP/1.1":
        raise ValueError("only HTTP/1.1 CONNECT is supported")
    target = parts[1]
    if target.count(":") != 1:
        raise ValueError("CONNECT target must be DNS-authority:port")
    host, raw_port = target.rsplit(":", 1)
    host = host.rstrip(".").lower()
    if not _AUTHORITY.fullmatch(host):
        raise ValueError("CONNECT target must be an exact DNS authority")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ValueError("CONNECT port is invalid") from exc
    if not 0 < port <= 65535:
        raise ValueError("CONNECT port is invalid")
    if (host, port) not in allowed:
        raise ValueError("CONNECT authority is not admitted")
    return host, port


def is_safe_destination(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Reject every non-global address and private IPv4 embedded in IPv6."""

    if not address.is_global:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        embedded = address.ipv4_mapped
        if embedded is None and address in _NAT64_WELL_KNOWN:
            embedded = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
        if embedded is not None and not embedded.is_global:
            return False
    return True


def validate_resolved_addresses(
    answers: Iterable[tuple[str, int]],
) -> tuple[tuple[str, int], ...]:
    """Require a non-empty DNS result set containing only global addresses."""

    normalized: list[tuple[str, int]] = []
    for raw_address, port in answers:
        address = ipaddress.ip_address(raw_address)
        if not is_safe_destination(address):
            raise ValueError("DNS result contains an unsafe destination")
        normalized.append((str(address), port))
    if not normalized:
        raise ValueError("DNS returned no usable destination")
    return tuple(normalized)


async def _resolve(host: str, port: int) -> tuple[tuple[str, int], ...]:
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    answers = {
        (str(record[4][0]), int(record[4][1]))
        for record in records
        if isinstance(record[4], tuple) and len(record[4]) >= 2
    }
    return validate_resolved_addresses(sorted(answers))


async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    idle_timeout_seconds: int,
) -> None:
    try:
        while data := await asyncio.wait_for(
            reader.read(65536),
            timeout=idle_timeout_seconds,
        ):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def _handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    allowed: set[tuple[str, int]],
    limits: ProxyLimits,
) -> None:
    upstream_writer: asyncio.StreamWriter | None = None
    try:
        request = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"),
            timeout=limits.header_timeout_seconds,
        )
        host, port = parse_connect(
            request,
            allowed,
            max_header_bytes=limits.max_header_bytes,
        )
        answers = await _resolve(host, port)
        last_error: OSError | None = None
        upstream_reader: asyncio.StreamReader | None = None
        for address, resolved_port in answers:
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(address, resolved_port),
                    timeout=limits.connect_timeout_seconds,
                )
                break
            except OSError as exc:
                last_error = exc
        if upstream_reader is None or upstream_writer is None:
            raise OSError("admitted authority was unreachable") from last_error
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(
            _pipe(
                reader,
                upstream_writer,
                idle_timeout_seconds=limits.idle_timeout_seconds,
            ),
            _pipe(
                upstream_reader,
                writer,
                idle_timeout_seconds=limits.idle_timeout_seconds,
            ),
        )
    except (
        asyncio.IncompleteReadError,
        asyncio.LimitOverrunError,
        asyncio.TimeoutError,
        OSError,
        ValueError,
    ):
        if not writer.is_closing():
            writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        if upstream_writer is not None and not upstream_writer.is_closing():
            upstream_writer.close()
            await upstream_writer.wait_closed()


async def _bounded_handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    allowed: set[tuple[str, int]],
    limits: ProxyLimits,
    capacity: asyncio.Semaphore,
) -> None:
    acquired = False
    try:
        await asyncio.wait_for(capacity.acquire(), timeout=0.1)
        acquired = True
        await _handle(reader, writer, allowed, limits)
    except asyncio.TimeoutError:
        writer.write(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    finally:
        if acquired:
            capacity.release()


def _load_policy(path: Path) -> tuple[set[tuple[str, int]], ProxyLimits]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or set(payload) != {
        "authorities",
        "limits",
    }:
        raise ValueError("egress proxy policy is invalid")
    authorities = payload["authorities"]
    if not isinstance(authorities, list):
        raise ValueError("egress proxy authorities must be a list")
    allowed: set[tuple[str, int]] = set()
    for item in authorities:
        if not isinstance(item, Mapping) or set(item) != {"authority", "port"}:
            raise ValueError("egress proxy authority is invalid")
        authority = item["authority"]
        port = item["port"]
        if (
            not isinstance(authority, str)
            or not isinstance(port, int)
            or isinstance(port, bool)
        ):
            raise ValueError("egress proxy authority is invalid")
        parse_connect(
            f"CONNECT {authority}:{port} HTTP/1.1\r\n\r\n".encode(),
            {(authority, port)},
        )
        if (authority, port) in allowed:
            raise ValueError("egress proxy authorities must be unique")
        allowed.add((authority, port))
    if not allowed:
        raise ValueError("egress proxy policy must admit at least one authority")
    return allowed, _parse_limits(payload["limits"])


def _parse_limits(raw: object) -> ProxyLimits:
    fields = {
        "max_connections": (1, 256),
        "max_header_bytes": (1024, 16384),
        "header_timeout_seconds": (1, 30),
        "connect_timeout_seconds": (1, 60),
        "idle_timeout_seconds": (5, 600),
    }
    if not isinstance(raw, Mapping) or set(raw) != set(fields):
        raise ValueError("egress proxy limits are invalid")
    values: dict[str, int] = {}
    for name, (minimum, maximum) in fields.items():
        value = raw[name]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not minimum <= value <= maximum
        ):
            raise ValueError("egress proxy limits are invalid")
        values[name] = value
    return ProxyLimits(**values)


async def _serve(policy_path: Path, host: str, port: int) -> None:
    allowed, limits = _load_policy(policy_path)
    capacity = asyncio.Semaphore(limits.max_connections)
    server = await asyncio.start_server(
        lambda reader, writer: _bounded_handle(
            reader,
            writer,
            allowed,
            limits,
            capacity,
        ),
        host,
        port,
        limit=limits.max_header_bytes,
        backlog=limits.max_connections,
    )
    async with server:
        await server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=3128)
    args = parser.parse_args()
    try:
        asyncio.run(_serve(args.policy, args.listen_host, args.listen_port))
    except (OSError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
