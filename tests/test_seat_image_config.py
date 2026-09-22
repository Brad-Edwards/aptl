"""What a seat image is allowed to declare about itself."""

from __future__ import annotations

import json

import pytest

from aptl.appliance.seat.image_config import (
    SeatImageConfigError,
    parse_seat_image_config,
)

RESOURCES = {
    "vcpus": 8,
    "memory_bytes": 34359738368,
    "disk_bytes": 268435456000,
}
PARTICIPANT = {
    "audience": "participant",
    "protocol": "tcp",
    "address": "127.0.0.1",
    "port": 3000,
}
HOST_MCP = {
    "audience": "host-mcp",
    "protocol": "tcp",
    "address": "127.0.0.1",
    "port": 2222,
}


def _config(**overrides: object) -> bytes:
    document = {
        "schema_version": "aptl.seat-image/v1",
        "resources": dict(RESOURCES),
        "publications": [dict(PARTICIPANT)],
    }
    document.update(overrides)
    return json.dumps(document).encode()


def test_declares_resources_and_publications() -> None:
    config = parse_seat_image_config(
        _config(publications=[dict(PARTICIPANT), dict(HOST_MCP)])
    )

    assert config.resources.vcpus == 8
    assert config.participant.port == 3000
    assert {item.audience for item in config.publications} == {
        "participant",
        "host-mcp",
    }


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"publications": [dict(HOST_MCP)]}, "no participant endpoint"),
        (
            {"publications": [dict(PARTICIPANT), dict(PARTICIPANT)]},
            "one audience twice",
        ),
        ({"publications": []}, "no publications at all"),
        (
            {"publications": [dict(PARTICIPANT) | {"address": "10.0.0.1"}]},
            "routable address",
        ),
        (
            {"publications": [dict(PARTICIPANT) | {"port": 0}]},
            "port outside range",
        ),
        (
            {"publications": [dict(PARTICIPANT) | {"protocol": "udp"}]},
            "unsupported transport",
        ),
        ({"resources": dict(RESOURCES) | {"vcpus": 9999}}, "absurd vcpu count"),
        ({"resources": dict(RESOURCES) | {"vcpus": 0}}, "no vcpus"),
        ({"resources": dict(RESOURCES) | {"memory_bytes": 1024}}, "unusable memory"),
        ({"schema_version": "aptl.seat-image/v2"}, "unknown schema version"),
        ({"unexpected": True}, "unknown field"),
    ],
)
def test_unlaunchable_declarations_are_refused(overrides, reason: str) -> None:
    with pytest.raises(SeatImageConfigError):
        parse_seat_image_config(_config(**overrides))


@pytest.mark.parametrize("payload", [b"", b"not json", b"[]", b"null", b'"text"'])
def test_non_object_payloads_are_refused(payload: bytes) -> None:
    with pytest.raises(SeatImageConfigError):
        parse_seat_image_config(payload)
