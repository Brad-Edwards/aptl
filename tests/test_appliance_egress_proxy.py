"""Exact-authority CONNECT broker used by the controlled egress crossing."""

import asyncio
import importlib.util
import ipaddress
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest


PROXY = Path(__file__).parents[1] / "containers" / "appliance-egress-proxy" / "proxy.py"


@pytest.fixture(scope="module")
def proxy():
    spec = importlib.util.spec_from_file_location("appliance_egress_proxy", PROXY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_connect_parser_requires_exact_authority_and_port(proxy) -> None:
    allowed = {("api.example.test", 443)}

    assert proxy.parse_connect(
        b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n",
        allowed,
    ) == ("api.example.test", 443)

    for request in (
        b"GET https://api.example.test/ HTTP/1.1\r\n\r\n",
        b"CONNECT api.example.test:8443 HTTP/1.1\r\n\r\n",
        b"CONNECT 10.0.0.1:443 HTTP/1.1\r\n\r\n",
        b"CONNECT other.example.test:443 HTTP/1.1\r\n\r\n",
        b"CONNECT api.example.test:0 HTTP/1.1\r\n\r\n",
        b"CONNECT api.example.test:65536 HTTP/1.1\r\n\r\n",
    ):
        with pytest.raises(ValueError):
            proxy.parse_connect(request, allowed)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "fe80::1",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
    ],
)
def test_special_private_metadata_and_nat64_results_are_denied(proxy, address) -> None:
    assert proxy.is_safe_destination(ipaddress.ip_address(address)) is False


def test_global_ipv4_and_ipv6_results_are_allowed(proxy) -> None:
    assert proxy.is_safe_destination(ipaddress.ip_address("93.184.216.34")) is True
    assert (
        proxy.is_safe_destination(
            ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946")
        )
        is True
    )


def test_any_unsafe_dns_answer_fails_the_whole_resolution(proxy) -> None:
    answers = [
        ("93.184.216.34", 443),
        ("169.254.169.254", 443),
    ]

    with pytest.raises(ValueError, match="unsafe"):
        proxy.validate_resolved_addresses(answers)


def test_signed_resource_limits_are_loaded_with_authorities(proxy, tmp_path) -> None:
    path = tmp_path / "egress.json"
    path.write_text(
        json.dumps(
            {
                "authorities": [{"authority": "api.example.test", "port": 443}],
                "limits": {
                    "max_connections": 32,
                    "max_header_bytes": 4096,
                    "header_timeout_seconds": 5,
                    "connect_timeout_seconds": 10,
                    "idle_timeout_seconds": 60,
                },
            }
        ),
        encoding="utf-8",
    )

    allowed, limits = proxy._load_policy(path)

    assert allowed == {("api.example.test", 443)}
    assert limits.max_connections == 32
    assert limits.idle_timeout_seconds == 60


def test_out_of_range_proxy_limit_fails_closed(proxy, tmp_path) -> None:
    path = tmp_path / "egress.json"
    path.write_text(
        json.dumps(
            {
                "authorities": [{"authority": "api.example.test", "port": 443}],
                "limits": {
                    "max_connections": 0,
                    "max_header_bytes": 4096,
                    "header_timeout_seconds": 5,
                    "connect_timeout_seconds": 10,
                    "idle_timeout_seconds": 60,
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="limits"):
        proxy._load_policy(path)


def test_handle_returns_403_for_disallowed_connect(proxy) -> None:
    reader = MagicMock()
    reader.readuntil = AsyncMock(
        return_value=b"CONNECT blocked.example.test:443 HTTP/1.1\r\n\r\n"
    )
    writer = MagicMock()
    writer.is_closing.return_value = False
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    limits = proxy.ProxyLimits(
        max_connections=1,
        max_header_bytes=4096,
        header_timeout_seconds=1,
        connect_timeout_seconds=1,
        idle_timeout_seconds=5,
    )

    asyncio.run(
        proxy._handle(
            reader,
            writer,
            {("api.example.test", 443)},
            limits,
        )
    )

    writer.write.assert_called_once_with(
        b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
    )
    writer.close.assert_called_once_with()
