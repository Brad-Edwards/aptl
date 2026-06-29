"""Pure helpers for the APTL ACES participant runtime adapter.

These functions carry no runtime state; they are factored out of
``aces_participant_runtime`` so the adapter module stays focused on the
``ParticipantRuntime`` lifecycle surface.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256

from aces_contracts.participant_binding import ParticipantActionAdmissionRequest
from aces_contracts.participant_episode import (
    ParticipantEpisodeHistoryEventType,
    ParticipantEpisodeTerminalReason,
)
from aces_contracts.runtime_state import RuntimeSnapshot, SnapshotEntry


def utc_now() -> str:
    """Return the current UTC instant as an ISO-8601 ``...Z`` string."""

    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def binding_post_state_digest(request: ParticipantActionAdmissionRequest) -> str:
    """Derive a deterministic post-state digest for an admission request.

    Mirrors the ACES reference contract: when the caller does not supply a
    ``post_state_digest``, derive a stable one from the admission's identity
    fields so the recorded behavior events carry a content-addressable digest.
    """

    digest_input = "|".join(
        (
            request.participant_address,
            request.action_contract_address,
            request.observation_boundary_address,
            request.action_instance_id,
        )
    )
    return "sha256:" + sha256(digest_input.encode("utf-8")).hexdigest()


def terminal_event(
    reason: ParticipantEpisodeTerminalReason,
) -> ParticipantEpisodeHistoryEventType:
    """Map a terminal reason to the participant episode history event type."""

    return {
        ParticipantEpisodeTerminalReason.COMPLETED: (
            ParticipantEpisodeHistoryEventType.EPISODE_COMPLETED
        ),
        ParticipantEpisodeTerminalReason.TIMED_OUT: (
            ParticipantEpisodeHistoryEventType.EPISODE_TIMED_OUT
        ),
        ParticipantEpisodeTerminalReason.TRUNCATED: (
            ParticipantEpisodeHistoryEventType.EPISODE_TRUNCATED
        ),
        ParticipantEpisodeTerminalReason.INTERRUPTED: (
            ParticipantEpisodeHistoryEventType.EPISODE_INTERRUPTED
        ),
    }[reason]


def build_snapshot(
    baseline: RuntimeSnapshot,
    entries: Mapping[str, SnapshotEntry],
    results: Mapping[str, dict[str, object]],
    history: Mapping[str, list[dict[str, object]]],
    behavior_history: Mapping[str, list[dict[str, object]]],
    shared_state_records: Mapping[str, dict[str, object]] | None = None,
    shared_state_history: Mapping[str, list[dict[str, object]]] | None = None,
) -> RuntimeSnapshot:
    """Return a snapshot with participant state dictionaries replaced."""

    updates: dict[str, object] = {
        "participant_episode_results": {
            address: dict(result) for address, result in results.items()
        },
        "participant_episode_history": {
            address: [dict(event) for event in events]
            for address, events in history.items()
        },
        "participant_behavior_history": {
            address: [dict(event) for event in events]
            for address, events in behavior_history.items()
        },
    }
    if shared_state_records is not None and hasattr(baseline, "shared_state_records"):
        updates["shared_state_records"] = {
            address: dict(record) for address, record in shared_state_records.items()
        }
    if shared_state_history is not None and hasattr(baseline, "shared_state_history"):
        updates["shared_state_history"] = {
            address: [dict(record) for record in records]
            for address, records in shared_state_history.items()
        }
    return baseline.with_entries(dict(entries), **updates)
