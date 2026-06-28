"""APTL ACES participant runtime adapter.

APTL's participant runtime is intentionally narrow: it exposes the ACES
participant episode lifecycle through the published DTOs and records a bounded
behavior-history event when a configured participant action is driven against a
realized container. The destructive live proof uses that action surface to drive
Kali against the monitored victim container; generic conformance probes exercise
the lifecycle without requiring a live lab.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import TYPE_CHECKING
from uuid import uuid4

from aces_contracts.participant_binding import (
    ParticipantActionAdmissionRequest,
    participant_action_binding_events,
    participant_behavior_event_payload,
)
from aces_contracts.participant_episode import (
    ParticipantEpisodeControlAction,
    ParticipantEpisodeExecutionState,
    ParticipantEpisodeHistoryEvent,
    ParticipantEpisodeHistoryEventType,
    ParticipantEpisodeInitializeRequest,
    ParticipantEpisodeResetRequest,
    ParticipantEpisodeRestartRequest,
    ParticipantEpisodeStatus,
    ParticipantEpisodeTerminalReason,
    ParticipantEpisodeTerminateRequest,
)
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry

from aptl.backends.aces_participant_actions import (
    DEFAULT_PARTICIPANT_ACTIONS,
    PARTICIPANT_ACTION_ADDRESS as _PARTICIPANT_ACTION_ADDRESS,
    ParticipantActionSpec,
    drive_participant_action,
    participant_action_diagnostic,
)

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

PARTICIPANT_ACTION_ADDRESS = _PARTICIPANT_ACTION_ADDRESS


def _utc_now() -> str:
    """Return the current UTC instant as an ISO-8601 ``...Z`` string."""

    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _binding_post_state_digest(request: ParticipantActionAdmissionRequest) -> str:
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


def _terminal_event(
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


def _snapshot(
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


@dataclass
class AptlParticipantRuntime:
    """ACES ``ParticipantRuntime`` backed by APTL's deployment boundary."""

    deployment_backend: "DeploymentBackend"
    action_specs: Mapping[str, ParticipantActionSpec] = field(
        default_factory=lambda: dict(DEFAULT_PARTICIPANT_ACTIONS)
    )
    _results: dict[str, dict[str, object]] = field(default_factory=dict, init=False)
    _history: dict[str, list[dict[str, object]]] = field(
        default_factory=dict, init=False
    )
    _behavior_history: dict[str, list[dict[str, object]]] = field(
        default_factory=dict, init=False
    )
    _shared_state_records: dict[str, dict[str, object]] = field(
        default_factory=dict, init=False
    )
    _shared_state_history: dict[str, list[dict[str, object]]] = field(
        default_factory=dict, init=False
    )

    def initialize(
        self,
        request: ParticipantEpisodeInitializeRequest,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        """Create a running episode and drive any configured proof action."""

        participant_address = request.participant_address
        now = _utc_now()
        episode_id = request.episode_id or uuid4().hex
        state = ParticipantEpisodeExecutionState(
            participant_address=participant_address,
            episode_id=episode_id,
            sequence_number=0,
            status=ParticipantEpisodeStatus.RUNNING,
            initialized_at=now,
            updated_at=now,
            last_control_action=ParticipantEpisodeControlAction.INITIALIZE,
        )
        events = [
            self._episode_event(
                ParticipantEpisodeHistoryEventType.EPISODE_INITIALIZED,
                now,
                state,
                ParticipantEpisodeControlAction.INITIALIZE,
            ),
            self._episode_event(
                ParticipantEpisodeHistoryEventType.EPISODE_RUNNING,
                now,
                state,
                None,
            ),
        ]
        next_snapshot, changed = self._store_episode(snapshot, state, events)
        action_result = drive_participant_action(
            self.deployment_backend,
            self.action_specs,
            participant_address,
            state,
            timestamp_factory=_utc_now,
        )
        if action_result is not None:
            self._behavior_history.setdefault(participant_address, []).extend(
                action_result.behavior_events
            )
            self._shared_state_records.update(action_result.shared_state_records)
            self._shared_state_history.update(
                {
                    address: [dict(record)]
                    for address, record in action_result.shared_state_records.items()
                }
            )
            next_snapshot = _snapshot(
                next_snapshot,
                {**next_snapshot.entries, **action_result.snapshot_entries},
                self._results,
                self._history,
                self._behavior_history,
                self._shared_state_records,
                self._shared_state_history,
            )
            changed.append(
                f"runtime.snapshot.participant-behavior-history.{participant_address}"
            )
            changed.extend(action_result.snapshot_entries)
            if hasattr(next_snapshot, "shared_state_records"):
                changed.extend(
                    f"runtime.snapshot.shared-state-records.{address}"
                    for address in action_result.shared_state_records
                )
            return ApplyResult(
                success=action_result.success,
                snapshot=next_snapshot,
                diagnostics=action_result.diagnostics,
                changed_addresses=changed,
            )
        return ApplyResult(
            success=True, snapshot=next_snapshot, changed_addresses=changed
        )

    def reset(
        self,
        request: ParticipantEpisodeResetRequest,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        """Start a replacement episode from a non-terminal predecessor."""

        current = self._current_state(request.participant_address, snapshot)
        if current is None:
            return self.initialize(
                ParticipantEpisodeInitializeRequest(
                    participant_address=request.participant_address,
                    episode_id=request.episode_id,
                ),
                snapshot,
            )
        if current.status == ParticipantEpisodeStatus.TERMINATED:
            return self._failed(
                snapshot,
                request.participant_address,
                "reset requires a non-terminal episode",
            )
        return self._advance_episode(
            snapshot,
            current,
            request.episode_id or uuid4().hex,
            current.sequence_number + 1,
            ParticipantEpisodeControlAction.RESET,
            ParticipantEpisodeHistoryEventType.EPISODE_RESET,
        )

    def restart(
        self,
        request: ParticipantEpisodeRestartRequest,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        """Start a replacement episode from a terminated predecessor."""

        current = self._current_state(request.participant_address, snapshot)
        if current is None:
            return self.initialize(
                ParticipantEpisodeInitializeRequest(
                    participant_address=request.participant_address,
                    episode_id=request.episode_id,
                ),
                snapshot,
            )
        if current.status != ParticipantEpisodeStatus.TERMINATED:
            return self._failed(
                snapshot,
                request.participant_address,
                "restart requires a terminated episode",
            )
        return self._advance_episode(
            snapshot,
            current,
            request.episode_id or uuid4().hex,
            current.sequence_number + 1,
            ParticipantEpisodeControlAction.RESTART,
            ParticipantEpisodeHistoryEventType.EPISODE_RESTARTED,
        )

    def terminate(
        self,
        request: ParticipantEpisodeTerminateRequest,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        """Terminate the current episode with the requested terminal reason."""

        current = self._current_state(request.participant_address, snapshot)
        if current is None:
            return self._failed(
                snapshot,
                request.participant_address,
                "terminate requires an initialized episode",
            )
        now = _utc_now()
        state = ParticipantEpisodeExecutionState(
            participant_address=current.participant_address,
            episode_id=current.episode_id,
            sequence_number=current.sequence_number,
            status=ParticipantEpisodeStatus.TERMINATED,
            terminal_reason=request.terminal_reason,
            initialized_at=current.initialized_at,
            updated_at=now,
            terminated_at=now,
            last_control_action=current.last_control_action,
            previous_episode_id=current.previous_episode_id,
        )
        event = self._episode_event(
            _terminal_event(request.terminal_reason),
            now,
            state,
            None,
            terminal_reason=request.terminal_reason,
            details={"detail": request.detail},
        )
        next_snapshot, changed = self._store_episode(snapshot, state, [event])
        return ApplyResult(
            success=True, snapshot=next_snapshot, changed_addresses=changed
        )

    def admit_action(
        self,
        request: ParticipantActionAdmissionRequest,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        """Admit one implementation-bound participant action attempt.

        Records the portable behavior-history events for an admitted action
        (action attempted, state-transition recorded, observation emitted)
        against the participant's live episode, per the ACES participant
        implementation-binding contract. The action itself is compiled and
        executed by the caller; this surface binds its result into the runtime's
        behavior history. Fails closed when there is no live, non-terminal
        episode to bind the action to.
        """

        address = request.participant_address
        current = self._current_state(address, snapshot)
        if current is None:
            return self._failed(
                snapshot,
                address,
                "cannot admit participant action: no initialized episode",
            )
        if current.status == ParticipantEpisodeStatus.TERMINATED:
            return self._failed(
                snapshot,
                address,
                "cannot admit participant action for a terminated participant",
            )
        now = _utc_now()
        post_state_digest = request.post_state_digest or _binding_post_state_digest(
            request
        )
        events = participant_action_binding_events(
            request,
            episode_id=current.episode_id,
            timestamp=now,
            post_state_digest=post_state_digest,
        )
        self._behavior_history.setdefault(address, []).extend(
            participant_behavior_event_payload(event) for event in events
        )
        next_snapshot = _snapshot(
            snapshot,
            snapshot.entries,
            self._results,
            self._history,
            self._behavior_history,
            self._shared_state_records,
            self._shared_state_history,
        )
        return ApplyResult(
            success=True,
            snapshot=next_snapshot,
            changed_addresses=[
                f"runtime.snapshot.participant-behavior-history.{address}"
            ],
        )

    def status(self) -> dict[str, object]:
        """Return current participant runtime status."""

        return {
            "backend": "aptl",
            "participants": sorted(self._results),
            "action_participants": sorted(self.action_specs),
        }

    def results(self) -> dict[str, dict[str, object]]:
        """Return the most recent participant episode state envelopes."""

        return {address: dict(result) for address, result in self._results.items()}

    def history(self) -> dict[str, list[dict[str, object]]]:
        """Return participant episode history event streams."""

        return {
            address: [dict(event) for event in events]
            for address, events in self._history.items()
        }

    def behavior_history(self) -> dict[str, list[dict[str, object]]]:
        """Return participant behavior history event streams."""

        return {
            address: [dict(event) for event in events]
            for address, events in self._behavior_history.items()
        }

    def _advance_episode(
        self,
        snapshot: RuntimeSnapshot,
        current: ParticipantEpisodeExecutionState,
        episode_id: str,
        sequence_number: int,
        action: ParticipantEpisodeControlAction,
        event_type: ParticipantEpisodeHistoryEventType,
    ) -> ApplyResult:
        """Advance an initialized episode to a replacement running episode."""

        now = _utc_now()
        state = ParticipantEpisodeExecutionState(
            participant_address=current.participant_address,
            episode_id=episode_id,
            sequence_number=sequence_number,
            status=ParticipantEpisodeStatus.RUNNING,
            initialized_at=now,
            updated_at=now,
            last_control_action=action,
            previous_episode_id=current.episode_id,
        )
        events = [
            self._episode_event(event_type, now, state, action),
            self._episode_event(
                ParticipantEpisodeHistoryEventType.EPISODE_RUNNING,
                now,
                state,
                None,
            ),
        ]
        next_snapshot, changed = self._store_episode(snapshot, state, events)
        return ApplyResult(
            success=True, snapshot=next_snapshot, changed_addresses=changed
        )

    def _store_episode(
        self,
        snapshot: RuntimeSnapshot,
        state: ParticipantEpisodeExecutionState,
        events: list[dict[str, object]],
    ) -> tuple[RuntimeSnapshot, list[str]]:
        """Persist participant episode state and history in a new snapshot."""

        participant_address = state.participant_address
        self._results[participant_address] = state.to_payload()
        self._history.setdefault(participant_address, []).extend(events)
        next_snapshot = _snapshot(
            snapshot,
            snapshot.entries,
            self._results,
            self._history,
            self._behavior_history,
            self._shared_state_records,
            self._shared_state_history,
        )
        return next_snapshot, [
            f"runtime.snapshot.participant-episode-results.{participant_address}",
            f"runtime.snapshot.participant-episode-history.{participant_address}",
        ]

    def _current_state(
        self,
        participant_address: str,
        snapshot: RuntimeSnapshot,
    ) -> ParticipantEpisodeExecutionState | None:
        """Return the in-memory or snapshot-backed participant episode state."""

        payload = self._results.get(
            participant_address
        ) or snapshot.participant_episode_results.get(participant_address)
        if not payload:
            return None
        return ParticipantEpisodeExecutionState.from_payload(payload)

    @staticmethod
    def _episode_event(
        event_type: ParticipantEpisodeHistoryEventType,
        timestamp: str,
        state: ParticipantEpisodeExecutionState,
        control_action: ParticipantEpisodeControlAction | None,
        *,
        terminal_reason: ParticipantEpisodeTerminalReason | None = None,
        details: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Build a participant episode history event payload."""

        return ParticipantEpisodeHistoryEvent(
            event_type=event_type,
            timestamp=timestamp,
            participant_address=state.participant_address,
            episode_id=state.episode_id,
            sequence_number=state.sequence_number,
            terminal_reason=terminal_reason,
            control_action=control_action,
            details=dict(details or {}),
        ).to_payload()

    @staticmethod
    def _failed(
        snapshot: RuntimeSnapshot,
        participant_address: str,
        message: str,
    ) -> ApplyResult:
        """Return a failed participant transition result."""

        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                participant_action_diagnostic(
                    "aptl.participant-runtime.invalid-transition",
                    participant_address,
                    message,
                )
            ],
        )
