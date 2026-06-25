"""APTL ACES participant runtime adapter.

APTL's participant runtime is intentionally narrow: it exposes the ACES
participant episode lifecycle through the published DTOs and records a bounded
behavior-history event when a configured participant action is driven against a
realized container. The destructive live proof uses that action surface to drive
Kali against the monitored victim container; generic conformance probes exercise
the lifecycle without requiring a live lab.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.participant_behavior import (
    ParticipantBehaviorHistoryEventType,
    ParticipantLifecycleOperationState,
    ParticipantObservationStatus,
    ParticipantPhaseRealization,
    ParticipantRuntimeLifecyclePhase,
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
from aces_contracts.planning import RuntimeDomain
from aces_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry

from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

PARTICIPANT_ACTION_ADDRESS = "participant.behavior.techvault.kali-victim-ssh-probe"
PARTICIPANT_ACTION_CONTRACT_ADDRESS = (
    "participant.action-contract.aptl.kali-victim-ssh-probe"
)
PARTICIPANT_OBSERVATION_BOUNDARY_ADDRESS = (
    "participant.observation-boundary.aptl.kali-victim-ssh-probe"
)
PARTICIPANT_BEHAVIOR_ADDRESS = PARTICIPANT_ACTION_ADDRESS


@dataclass(frozen=True)
class ParticipantActionSpec:
    """A bounded participant action that can be driven through the backend."""

    source_container: str
    command: tuple[str, ...]
    success_markers: tuple[str, ...]
    action_contract_address: str
    observation_boundary_address: str
    actor_provenance: str = "codex-cli"
    target_refs: tuple[str, ...] = ()
    timeout_seconds: int = 120


DEFAULT_PARTICIPANT_ACTIONS = {
    PARTICIPANT_ACTION_ADDRESS: ParticipantActionSpec(
        source_container="aptl-kali",
        command=("nmap", "-p", "22", "-Pn", "--open", "172.20.2.20", "-oG", "-"),
        success_markers=("22/open",),
        action_contract_address=PARTICIPANT_ACTION_CONTRACT_ADDRESS,
        observation_boundary_address=PARTICIPANT_OBSERVATION_BOUNDARY_ADDRESS,
        target_refs=(
            "container:aptl-kali",
            "container:aptl-victim",
            "tcp:172.20.2.20:22",
        ),
    )
}


def _utc_now() -> str:
    """Return the current UTC instant as an ISO-8601 ``...Z`` string."""

    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _diagnostic(code: str, address: str, message: str) -> Diagnostic:
    """Build a redacted participant-runtime error diagnostic."""

    return Diagnostic(
        code=code,
        domain=RuntimeDomain.PARTICIPANT.value,
        address=address,
        message=redact(message),
        severity=Severity.ERROR,
    )


def _terminal_event(
    reason: ParticipantEpisodeTerminalReason,
) -> ParticipantEpisodeHistoryEventType:
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
        action_result = self._drive_configured_action(participant_address, state)
        if action_result is not None:
            (
                success,
                action_events,
                diagnostics,
                action_entries,
                shared_state_records,
            ) = action_result
            self._behavior_history.setdefault(participant_address, []).extend(
                action_events
            )
            self._shared_state_records.update(shared_state_records)
            self._shared_state_history.update(
                {
                    address: [dict(record)]
                    for address, record in shared_state_records.items()
                }
            )
            next_snapshot = _snapshot(
                next_snapshot,
                {**next_snapshot.entries, **action_entries},
                self._results,
                self._history,
                self._behavior_history,
                self._shared_state_records,
                self._shared_state_history,
            )
            changed.append(
                f"runtime.snapshot.participant-behavior-history.{participant_address}"
            )
            changed.extend(action_entries)
            if hasattr(next_snapshot, "shared_state_records"):
                changed.extend(
                    f"runtime.snapshot.shared-state-records.{address}"
                    for address in shared_state_records
                )
            return ApplyResult(
                success=success,
                snapshot=next_snapshot,
                diagnostics=diagnostics,
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
        payload = self._results.get(
            participant_address
        ) or snapshot.participant_episode_results.get(participant_address)
        if not payload:
            return None
        return ParticipantEpisodeExecutionState.from_payload(payload)

    def _episode_event(
        self,
        event_type: ParticipantEpisodeHistoryEventType,
        timestamp: str,
        state: ParticipantEpisodeExecutionState,
        control_action: ParticipantEpisodeControlAction | None,
        *,
        terminal_reason: ParticipantEpisodeTerminalReason | None = None,
        details: dict[str, object] | None = None,
    ) -> dict[str, object]:
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

    def _drive_configured_action(
        self,
        participant_address: str,
        state: ParticipantEpisodeExecutionState,
    ) -> (
        tuple[
            bool,
            list[dict[str, object]],
            list[Diagnostic],
            dict[str, SnapshotEntry],
            dict[str, dict[str, object]],
        ]
        | None
    ):
        spec = self.action_specs.get(participant_address)
        if spec is None:
            return None
        action_instance_id = f"{participant_address}.{uuid4().hex}"
        started_at = _utc_now()
        attempted = _action_attempted_event(spec, state, action_instance_id, started_at)
        diagnostics = []
        stdout = ""
        stderr = ""
        returncode = 1
        try:
            result = self.deployment_backend.container_exec(
                spec.source_container,
                list(spec.command),
                timeout=spec.timeout_seconds,
            )
            stdout = redact(str(getattr(result, "stdout", "")))
            stderr = redact(str(getattr(result, "stderr", "")))
            returncode = int(getattr(result, "returncode", 1))
        except Exception as exc:  # noqa: BLE001 - backend boundary failure -> Diagnostic.
            stderr = redact(f"{type(exc).__name__}: {exc}")
            diagnostics.append(
                _diagnostic(
                    "aptl.participant-runtime.action-backend-failed",
                    participant_address,
                    "Participant action backend call failed: " + stderr,
                )
            )
        finished_at = _utc_now()
        combined = f"{stdout}\n{stderr}"
        marker_ok = all(marker in combined for marker in spec.success_markers)
        success = returncode == 0 and marker_ok
        observed = _observation_event(
            spec,
            state,
            action_instance_id,
            finished_at,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            success=success,
        )
        if not success:
            diagnostics.append(
                _diagnostic(
                    "aptl.participant-runtime.action-failed",
                    participant_address,
                    (
                        "Participant action did not observe the expected lab result "
                        f"(returncode={returncode}, markers={spec.success_markers})."
                    ),
                )
            )
        return (
            success,
            [attempted, observed],
            diagnostics,
            _action_snapshot_entries(spec, action_instance_id, success),
            _shared_state_records(spec, action_instance_id, success),
        )

    def _failed(
        self,
        snapshot: RuntimeSnapshot,
        participant_address: str,
        message: str,
    ) -> ApplyResult:
        return ApplyResult(
            success=False,
            snapshot=snapshot,
            diagnostics=[
                _diagnostic(
                    "aptl.participant-runtime.invalid-transition",
                    participant_address,
                    message,
                )
            ],
        )


def _action_attempted_event(
    spec: ParticipantActionSpec,
    state: ParticipantEpisodeExecutionState,
    action_instance_id: str,
    timestamp: str,
) -> dict[str, object]:
    return {
        "event_type": ParticipantBehaviorHistoryEventType.ACTION_ATTEMPTED.value,
        "timestamp": timestamp,
        "participant_address": state.participant_address,
        "episode_id": state.episode_id,
        "action_instance_id": action_instance_id,
        "action_contract_address": spec.action_contract_address,
        "observation_boundary_address": None,
        "observation_status": None,
        "actor_provenance": spec.actor_provenance,
        "lifecycle_phase": ParticipantRuntimeLifecyclePhase.EXECUTION_ATTEMPT.value,
        "phase_realization": ParticipantPhaseRealization.RUNTIME_MEDIATED.value,
        "admission_disposition": None,
        "operation_ref": f"container_exec:{spec.source_container}",
        "operation_state": ParticipantLifecycleOperationState.RUNNING.value,
        "state_transition_kind": None,
        "post_state_digest": None,
        "joint_action_set_id": None,
        "realized_order": None,
        "interaction_ref": None,
        "interaction_class": "shared_state_change",
        "shared_state_refs": list(spec.target_refs),
        "details": {
            "source_container": spec.source_container,
            "command": list(spec.command),
            "target_refs": list(spec.target_refs),
        },
    }


def _observation_event(
    spec: ParticipantActionSpec,
    state: ParticipantEpisodeExecutionState,
    action_instance_id: str,
    timestamp: str,
    *,
    returncode: int,
    stdout: str,
    stderr: str,
    success: bool,
) -> dict[str, object]:
    digest = hashlib.sha256(f"{stdout}\n{stderr}".encode("utf-8")).hexdigest()
    return {
        "event_type": ParticipantBehaviorHistoryEventType.OBSERVATION_EMITTED.value,
        "timestamp": timestamp,
        "participant_address": state.participant_address,
        "episode_id": state.episode_id,
        "action_instance_id": action_instance_id,
        "action_contract_address": spec.action_contract_address,
        "observation_boundary_address": spec.observation_boundary_address,
        "observation_status": ParticipantObservationStatus.TERMINAL.value,
        "actor_provenance": spec.actor_provenance,
        "lifecycle_phase": ParticipantRuntimeLifecyclePhase.OBSERVATION_EMISSION.value,
        "phase_realization": ParticipantPhaseRealization.OBSERVED.value,
        "admission_disposition": None,
        "operation_ref": None,
        "operation_state": None,
        "state_transition_kind": None,
        "post_state_digest": f"sha256:{digest}",
        "joint_action_set_id": None,
        "realized_order": None,
        "interaction_ref": None,
        "interaction_class": "shared_state_change",
        "shared_state_refs": list(spec.target_refs),
        "details": {
            "returncode": returncode,
            "success": success,
            "stdout_excerpt": stdout[:2000],
            "stderr_excerpt": stderr[:2000],
            "success_markers": list(spec.success_markers),
        },
    }


def _action_snapshot_entries(
    spec: ParticipantActionSpec,
    action_instance_id: str,
    success: bool,
) -> dict[str, SnapshotEntry]:
    return {
        PARTICIPANT_BEHAVIOR_ADDRESS: SnapshotEntry(
            address=PARTICIPANT_BEHAVIOR_ADDRESS,
            domain=RuntimeDomain.PARTICIPANT,
            resource_type="participant-behavior",
            payload={
                "action_contract_addresses": [spec.action_contract_address],
                "observation_boundary_addresses": [
                    spec.observation_boundary_address
                ],
                "shared_state_refs": list(spec.target_refs),
            },
        ),
        spec.action_contract_address: SnapshotEntry(
            address=spec.action_contract_address,
            domain=RuntimeDomain.PARTICIPANT,
            resource_type="participant-action-contract",
            payload={
                "name": "APTL Kali victim SSH probe",
                "action_name": "kali-victim-ssh-probe",
                "semantic_version": "1.0.0",
                "lifecycle_state": "active",
                "behavioral_granularity": "single-command",
                "interaction_classes": ["shared_state_change"],
                "shared_state_refs": list(spec.target_refs),
                "source_container": spec.source_container,
                "command": list(spec.command),
                "success_markers": list(spec.success_markers),
                "target_refs": list(spec.target_refs),
            },
        ),
        spec.observation_boundary_address: SnapshotEntry(
            address=spec.observation_boundary_address,
            domain=RuntimeDomain.PARTICIPANT,
            resource_type="participant-observation-boundary",
            payload={
                "name": "APTL Kali victim SSH observation boundary",
                "boundary_name": "kali-victim-ssh-probe-output",
                "projection_basis": "nmap grepable output excerpt",
                "observable_refs": list(spec.target_refs),
                "evidence_refs": [action_instance_id],
                "disclosed_refs": list(spec.target_refs),
                "realized_view_disclosure": "terminal-observation",
                "source_container": spec.source_container,
                "target_refs": list(spec.target_refs),
            },
        ),
        action_instance_id: SnapshotEntry(
            address=action_instance_id,
            domain=RuntimeDomain.PARTICIPANT,
            resource_type="participant-action-instance",
            payload={
                "action_contract_address": spec.action_contract_address,
                "observation_boundary_address": spec.observation_boundary_address,
                "actor_provenance": spec.actor_provenance,
                "success": success,
            },
            ordering_dependencies=(spec.action_contract_address,),
            refresh_dependencies=(spec.observation_boundary_address,),
            status="ready" if success else "failed",
        ),
    }


def _shared_state_records(
    spec: ParticipantActionSpec,
    action_instance_id: str,
    success: bool,
) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for ref in spec.target_refs:
        state_kind = "network-service" if ref.startswith("tcp:") else "container"
        digest = hashlib.sha256(
            f"{ref}:{action_instance_id}:{success}".encode("utf-8")
        ).hexdigest()
        records[ref] = {
            "state_address": ref,
            "state_scope": "aptl-techvault-live-range",
            "state_kind": state_kind,
            "ordering_basis": "participant-action-observation",
            "conflict_policy": "single-writer-observation",
            "provenance": spec.actor_provenance,
            "digest": f"sha256:{digest}",
            "accesses": [
                {
                    "state_address": ref,
                    "access_kind": "read",
                    "read_digest": f"sha256:{digest}",
                    "operation_ref": f"container_exec:{spec.source_container}",
                }
            ],
            "evidence_refs": [action_instance_id],
        }
    return records
