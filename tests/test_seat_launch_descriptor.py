"""Signed guest launch documents reject ambiguous JSON."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aptl.appliance.policy import write_full_techvault_boundary_policy
from aptl.appliance.seat.launch_descriptor import (
    SeatLaunchDescriptor,
    SeatLaunchError,
    canonical_launch_bytes,
    verify_seat_launch,
)


def test_duplicate_launch_key_is_refused(tmp_path: Path) -> None:
    policy_path = tmp_path / "boundary-policy.json"
    write_full_techvault_boundary_policy(policy_path)
    descriptor = SeatLaunchDescriptor(
        schema_version="aptl.appliance-launch/v2",
        image_reference="ghcr.io/owner/seat:latest",
        image_digest="sha256:" + "a" * 64,
        image_config_digest="sha256:" + "b" * 64,
        boundary_policy_digest="sha256:" + hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        boundary_helper_image="example.test/helper@sha256:" + "c" * 64,
        egress_proxy_image="example.test/proxy@sha256:" + "d" * 64,
        participant_routes_digest="sha256:" + "e" * 64,
        host_observation_id="sha256:" + "f" * 64,
    )
    payload = canonical_launch_bytes(descriptor).replace(
        b'"schema_version":', b'"schema_version":"aptl.appliance-launch/v2","schema_version":', 1
    )
    path = tmp_path / "appliance-launch.json"
    path.write_bytes(payload)

    with pytest.raises(SeatLaunchError, match="invalid appliance launch descriptor"):
        verify_seat_launch(path)
