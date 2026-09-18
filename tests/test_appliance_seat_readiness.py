"""Per-start VM readiness channel tests."""

from pathlib import Path

import pytest

from aptl.appliance.seat.readiness import (
    GuestReadinessChallenge,
    _validate_response,
    encode_guest_readiness,
    load_guest_readiness_challenge,
    publish_guest_readiness,
    publish_readiness_challenge,
)
from tests.test_appliance_boundary_inventory import _guest


def _challenge() -> GuestReadinessChallenge:
    return GuestReadinessChallenge(
        schema_version="aptl.guest-readiness-challenge/v1",
        seat_id="seat-01",
        instance_id="a" * 32,
        generation=2,
        launch_descriptor_digest="sha256:" + "b" * 64,
        nonce="c" * 64,
    )


def test_readiness_response_roundtrip_is_bound_to_current_start() -> None:
    challenge = _challenge()
    payload = encode_guest_readiness(challenge, _guest())

    assert _validate_response(payload, challenge) == _guest()


def test_readiness_response_rejects_stale_nonce() -> None:
    payload = encode_guest_readiness(_challenge(), _guest())
    current = _challenge().model_copy(update={"nonce": "d" * 64})

    with pytest.raises(ValueError, match="stale"):
        _validate_response(payload, current)


def test_readiness_challenge_is_replaced_with_fresh_nonce(tmp_path: Path) -> None:
    path = tmp_path / "readiness-challenge.json"
    first = publish_readiness_challenge(
        path,
        seat_id="seat-01",
        instance_id="a" * 32,
        generation=2,
        launch_descriptor_digest="sha256:" + "b" * 64,
    )
    second = publish_readiness_challenge(
        path,
        seat_id="seat-01",
        instance_id="a" * 32,
        generation=2,
        launch_descriptor_digest="sha256:" + "b" * 64,
    )

    assert first.nonce != second.nonce
    assert path.stat().st_mode & 0o777 == 0o400


def test_guest_publishes_current_challenge_to_character_device(tmp_path: Path) -> None:
    challenge_path = tmp_path / "readiness-challenge.json"
    challenge = publish_readiness_challenge(
        challenge_path,
        seat_id="seat-01",
        instance_id="a" * 32,
        generation=2,
        launch_descriptor_digest="sha256:" + "b" * 64,
    )

    assert load_guest_readiness_challenge(challenge_path) == challenge
    publish_guest_readiness(challenge_path, Path("/dev/null"), _guest())


def test_guest_challenge_loader_rejects_leaf_symlink(tmp_path: Path) -> None:
    actual = tmp_path / "actual.json"
    publish_readiness_challenge(
        actual,
        seat_id="seat-01",
        instance_id="a" * 32,
        generation=2,
        launch_descriptor_digest="sha256:" + "b" * 64,
    )
    linked = tmp_path / "linked.json"
    linked.symlink_to(actual)

    with pytest.raises(Exception, match="challenge was invalid"):
        load_guest_readiness_challenge(linked)
