"""Seat identity, discovery freshness, and transport authorization boundaries."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from aptl.workbench.access import (
    CallerGrant,
    SeatAccessRecord,
    authorize_server,
    require_current_access,
)


def access_record(**changes):
    values = dict(
        schema_version="aptl.seat-access/v1",
        owner_id="alice",
        seat_id="seat-1",
        instance_id="instance-1",
        generation=1,
        guest_boot_id="boot-1",
        guest_daemon_id="daemon-1",
        guest_project="aptl-seat-1",
        container_ids={"kali": "a" * 64},
        scenario_pack=dict(
            pack_id="techvault", pack_version="1.0.0", set_digest="b" * 64
        ),
        guest_endpoint=dict(address="127.0.0.1", port=2222),
        outer_endpoint=dict(address="127.0.0.1", port=30222),
        host_key_fingerprint="SHA256:" + "A" * 43,
        observed_at=datetime.now(UTC),
        lifecycle_state="ready",
    )
    values.update(changes)
    return SeatAccessRecord.model_validate(values)


def grant(**changes):
    values = dict(
        schema_version="aptl.mcp-grant/v1",
        grant_id="grant-1",
        owner_id="alice",
        seat_id="seat-1",
        instance_id="instance-1",
        generation=1,
        public_key_fingerprint="SHA256:" + "B" * 43,
        profile="red",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        revoked=False,
    )
    values.update(changes)
    return CallerGrant.model_validate(values)


def test_transport_grant_is_required_and_separate_from_discovery():
    record = access_record()
    admitted = authorize_server(record, grant(), "aptl-red")
    assert admitted.server_id == "aptl-red"
    prepared_input_1 = grant()
    with pytest.raises(ValueError, match="authorized"):
        authorize_server(record, prepared_input_1, "aptl-indexer")
    prepared_input_2 = grant(owner_id="bob")
    with pytest.raises(ValueError, match="authorized"):
        authorize_server(record, prepared_input_2, "aptl-red")


@pytest.mark.parametrize(
    "changes",
    [
        {"generation": 2},
        {"seat_id": "seat-2"},
        {"instance_id": "replacement"},
        {"revoked": True},
        {"expires_at": datetime(2000, 1, 1, tzinfo=UTC)},
    ],
)
def test_stale_wrong_or_revoked_grant_cannot_launch(changes):
    prepared_input_3 = access_record()
    prepared_input_4 = grant(**changes)
    with pytest.raises(ValueError, match="authorized"):
        authorize_server(prepared_input_3, prepared_input_4, "aptl-red")


@pytest.mark.parametrize(
    "changes",
    [
        {"observed_at": datetime(2026, 1, 1, tzinfo=UTC) - timedelta(minutes=10)},
        {"observed_at": datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=1)},
        {"lifecycle_state": "tainted"},
    ],
)
def test_discovery_must_be_fresh_and_ready(changes):
    prepared_input_5 = access_record(
        observed_at=datetime(2026, 1, 1, tzinfo=UTC)
    ).model_copy(update=changes)
    prepared_input_6 = datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="current"):
        require_current_access(
            prepared_input_5,
            owner_id="alice",
            seat_id="seat-1",
            now=prepared_input_6,
        )


def test_discovery_rejects_short_ids_unknown_fields_and_nonlocal_endpoints():
    for changes in (
        {"container_ids": {"kali": "abc123"}},
        {"password": "secret"},
        {"outer_endpoint": {"address": "0.0.0.0", "port": 30222}},
    ):
        with pytest.raises(ValidationError):
            access_record(**changes)
    record = access_record()
    assert record.guest_endpoint.port != record.outer_endpoint.port
