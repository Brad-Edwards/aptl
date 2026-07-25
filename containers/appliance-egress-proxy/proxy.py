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
_MAX_HEADER_BYTES = 4096
_HEADER_TIMEOUT_SECONDS = 5
_CONNECT_TIMEOUT_SECONDS = 10
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")


def parse_connect(
    request: bytes,
    allowed: set[tuple[str, int]],
) -> tuple[str, int]:
    """Return an exact admitted CONNECT target or reject the request."""

    if len(request) > _MAX_HEADER_BYTES or b"\r\n\r\n" not in request:
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
) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def _handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    allowed: set[tuple[str, int]],
) -> None:
    upstream_writer: asyncio.StreamWriter | None = None
    try:
        request = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"),
            timeout=_HEADER_TIMEOUT_SECONDS,
        )
        host, port = parse_connect(request, allowed)
        answers = await _resolve(host, port)
        last_error: OSError | None = None
        upstream_reader: asyncio.StreamReader | None = None
        for address, resolved_port in answers:
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(address, resolved_port),
                    timeout=_CONNECT_TIMEOUT_SECONDS,
                )
                break
            except OSError as exc:
                last_error = exc
        if upstream_reader is None or upstream_writer is None:
            raise OSError("admitted authority was unreachable") from last_error
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(
            _pipe(reader, upstream_writer),
            _pipe(upstream_reader, writer),
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


def _load_policy(path: Path) -> set[tuple[str, int]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or set(payload) != {"authorities"}:
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
    return allowed


async def _serve(policy_path: Path, host: str, port: int) -> None:
    allowed = _load_policy(policy_path)
    server = await asyncio.start_server(
        lambda reader, writer: _handle(reader, writer, allowed),
        host,
        port,
        limit=_MAX_HEADER_BYTES,
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
