"""What a seat image is allowed to declare about itself."""

from __future__ import annotations

import json

import pytest

from aptl.appliance.policy import full_techvault_boundary_policy
from aptl.appliance.seat.image_config import (
    SeatImageConfigError,
    parse_seat_image_config,
)

RESOURCES = {
    "vcpus": 8,
    "memory_bytes": 34359738368,
    "disk_bytes": 268435456000,
}


def _boundary(**overrides: object) -> dict[str, object]:
    document = full_techvault_boundary_policy().model_dump(mode="json")
    document.update(overrides)
    return document


BINDING = {
    "boundary_helper_image": "aptl-network-boundary-helper@sha256:" + "a" * 64,
    "egress_proxy_image": "aptl-appliance-egress-proxy@sha256:" + "b" * 64,
    "raes_plan_digest": "sha256:" + "c" * 64,
}


def _config(**overrides: object) -> bytes:
    document: dict[str, object] = {
        "schema_version": "aptl.seat-image/v1",
        "resources": dict(RESOURCES),
        "boundary": _boundary(),
        "binding": dict(BINDING),
    }
    document.update(overrides)
    return json.dumps(document).encode()


def test_declares_resources_and_carries_the_boundary_policy() -> None:
    config = parse_seat_image_config(_config())

    assert config.resources.vcpus == 8
    assert config.participant.port == 3000
    assert {item.audience for item in config.publications} == {
        "participant",
        "recovery",
        "host-mcp",
    }
    # The boundary contract stays the existing platform model, enforced by its
    # own rules rather than a parallel one.
    assert config.boundary.host_mcp_contract == "aptl.restricted-ssh-mcp/v1"
    assert config.boundary.docker_authority.require_guest_daemon is True


def test_a_seat_that_publishes_nothing_is_refused() -> None:
    with pytest.raises(SeatImageConfigError):
        parse_seat_image_config(_config(boundary=_boundary(guest_publications=[])))


def test_a_seat_without_a_participant_endpoint_is_refused() -> None:
    reachable = [
        item
        for item in _boundary()["guest_publications"]  # type: ignore[index]
        if item["audience"] != "participant"
    ]

    with pytest.raises(SeatImageConfigError, match="participant"):
        parse_seat_image_config(
            _config(boundary=_boundary(guest_publications=reachable))
        )


def test_a_routable_publication_is_refused_by_the_boundary_model() -> None:
    publications = _boundary()["guest_publications"]  # type: ignore[index]
    publications[0]["address"] = "10.0.0.1"  # type: ignore[index]

    with pytest.raises(SeatImageConfigError):
        parse_seat_image_config(
            _config(boundary=_boundary(guest_publications=publications))
        )


@pytest.mark.parametrize(
    ("resources", "reason"),
    [
        ({"vcpus": 9999}, "absurd vcpu count"),
        ({"vcpus": 0}, "no vcpus"),
        ({"memory_bytes": 1024}, "unusable memory"),
        ({"disk_bytes": 1}, "unusable disk"),
    ],
)
def test_unlaunchable_resource_requests_are_refused(resources, reason: str) -> None:
    with pytest.raises(SeatImageConfigError):
        parse_seat_image_config(_config(resources=dict(RESOURCES) | resources))


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema_version": "aptl.seat-image/v2"},
        {"unexpected": True},
        {"boundary": {"schema_version": "aptl.appliance-boundary/v2"}},
    ],
)
def test_malformed_declarations_are_refused(overrides) -> None:
    with pytest.raises(SeatImageConfigError):
        parse_seat_image_config(_config(**overrides))


@pytest.mark.parametrize("payload", [b"", b"not json", b"[]", b"null", b'"text"'])
def test_non_object_payloads_are_refused(payload: bytes) -> None:
    with pytest.raises(SeatImageConfigError):
        parse_seat_image_config(payload)


@pytest.mark.parametrize(
    ("binding", "reason"),
    [
        ({"boundary_helper_image": "no-digest:latest"}, "unpinned helper image"),
        ({"egress_proxy_image": "also-unpinned"}, "unpinned proxy image"),
        ({"raes_plan_digest": "not-a-digest"}, "malformed plan digest"),
        ({"raes_plan_digest": "sha256:" + "A" * 64}, "uppercase digest"),
    ],
)
def test_unpinned_guest_identities_are_refused(binding, reason: str) -> None:
    # The boundary gate binds a launch to these; an unpinned one would let the
    # guest run something other than what the image declared.
    with pytest.raises(SeatImageConfigError):
        parse_seat_image_config(_config(binding=dict(BINDING) | binding))
