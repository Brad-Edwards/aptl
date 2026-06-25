"""Live proof that an ACES participant action works through APTL."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aces_contracts.participant_behavior import (
    iter_participant_behavior_snapshot_violations,
)
from aces_contracts.participant_episode import (
    iter_participant_episode_snapshot_violations,
)
from aces_contracts.runtime_state import OperationState, RuntimeSnapshot
from aces_runtime.control_plane import RuntimeControlPlane
from aces_runtime.registry import RuntimeTarget

try:
    from aces_contracts.participant_concurrency import (
        iter_participant_concurrency_snapshot_violations,
    )
except ImportError:
    # Older ACES locks predate the participant concurrency snapshot contract.
    iter_participant_concurrency_snapshot_violations = None

try:
    from aces_contracts.participant_shared_state import (
        iter_participant_shared_state_snapshot_violations,
    )
except ImportError:
    # Older ACES locks predate the participant shared-state snapshot contract.
    iter_participant_shared_state_snapshot_violations = None

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_participant_actions import PARTICIPANT_ACTION_ADDRESS
from aptl.core.config import AptlConfig
from aptl.core.deployment import get_backend
from aptl.core.snapshot import capture_snapshot
from aptl.utils.redaction import redact
from aptl.validation.range_snapshot_summary import summarize_snapshot

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

BackendFactory = Callable[[AptlConfig, Path], "DeploymentBackend"]
SnapshotCapture = Callable[..., Any]
SnapshotViolation = tuple[str, str]


@dataclass(frozen=True)
class ParticipantSnapshotExtensions:
    """Optional participant snapshot extensions emitted by current ACES."""

    shared_state_records: dict[str, dict[str, object]]
    shared_state_history: dict[str, list[dict[str, object]]]
    joint_action_records: dict[str, dict[str, object]]
    time_management_contexts: dict[str, dict[str, object]]


@dataclass(frozen=True)
class ParticipantSnapshotValidation:
    """Validation results for participant episode and behavior surfaces."""

    episode_violations: list[SnapshotViolation]
    behavior_violations: list[SnapshotViolation]
    shared_state_violations: list[SnapshotViolation]
    concurrency_violations: list[SnapshotViolation]

    def passed(self) -> bool:
        """Return whether all participant snapshot validators passed."""

        return not (
            self.episode_violations
            or self.behavior_violations
            or self.shared_state_violations
            or self.concurrency_violations
        )

    def to_payload(self, capture_diagnostics: Sequence[str]) -> dict[str, object]:
        """Return the validation result as committed proof evidence."""

        return {
            "episode_violations": _violation_payload(self.episode_violations),
            "behavior_violations": _violation_payload(self.behavior_violations),
            "shared_state_violations": _violation_payload(self.shared_state_violations),
            "concurrency_violations": _violation_payload(self.concurrency_violations),
            "capture_diagnostics": list(capture_diagnostics),
        }


@dataclass(frozen=True)
class ParticipantProofContext:
    """Everything needed to render the participant action proof artifact."""

    participant_address: str
    receipt: object
    status: object | None
    target: RuntimeTarget
    snapshot: RuntimeSnapshot
    extensions: ParticipantSnapshotExtensions
    validation: ParticipantSnapshotValidation
    range_snapshot_summary: dict[str, object] | None
    capture_diagnostics: list[str]


def run_participant_action_proof(
    project_dir: Path,
    config: AptlConfig,
    participant_address: str = PARTICIPANT_ACTION_ADDRESS,
    *,
    backend_factory: BackendFactory = get_backend,
    snapshot_capture: SnapshotCapture = capture_snapshot,
) -> dict[str, object]:
    """Drive a participant action through the ACES control plane.

    The lab must already be realized by the public start path. This proof uses
    the configured deployment backend, calls
    ``RuntimeControlPlane.initialize_participant_episode()``, validates the
    participant episode/behavior snapshot surfaces, captures a post-action range
    snapshot, and returns a JSON-serializable evidence object.
    """

    control_plane, target, backend = _participant_control_plane(project_dir, config, backend_factory)
    receipt = control_plane.initialize_participant_episode(participant_address)
    status = control_plane.get_operation(receipt.operation_id)
    snapshot = control_plane.snapshot
    extensions = _snapshot_extensions(snapshot)
    validation = _validate_participant_snapshot(snapshot, extensions)
    range_summary, capture_diagnostics = _capture_post_action_range(
        project_dir, backend, snapshot_capture
    )
    context = ParticipantProofContext(
        participant_address=participant_address,
        receipt=receipt,
        status=status,
        target=target,
        snapshot=snapshot,
        extensions=extensions,
        validation=validation,
        range_snapshot_summary=range_summary,
        capture_diagnostics=capture_diagnostics,
    )
    proof = _participant_proof_payload(context)
    return _redact_volatile_proof_identifiers(proof, participant_address)


def _participant_control_plane(
    project_dir: Path,
    config: AptlConfig,
    backend_factory: BackendFactory,
) -> tuple[RuntimeControlPlane, RuntimeTarget, "DeploymentBackend"]:
    """Create the ACES control plane backed by the configured APTL backend."""

    backend = backend_factory(config, project_dir)
    target = create_aptl_runtime_target(project_dir=project_dir, config=config, backend=backend)
    return RuntimeControlPlane(target), target, backend


def _snapshot_extensions(snapshot: RuntimeSnapshot) -> ParticipantSnapshotExtensions:
    """Read optional participant snapshot extensions defensively."""

    return ParticipantSnapshotExtensions(
        shared_state_records=dict(getattr(snapshot, "shared_state_records", {})),
        shared_state_history={
            address: list(records)
            for address, records in getattr(snapshot, "shared_state_history", {}).items()
        },
        joint_action_records=dict(getattr(snapshot, "joint_action_records", {})),
        time_management_contexts=dict(getattr(snapshot, "time_management_contexts", {})),
    )


def _validate_participant_snapshot(
    snapshot: RuntimeSnapshot,
    extensions: ParticipantSnapshotExtensions,
) -> ParticipantSnapshotValidation:
    """Run every available ACES participant snapshot validator."""

    return ParticipantSnapshotValidation(
        episode_violations=list(
            iter_participant_episode_snapshot_violations(
                snapshot.participant_episode_results,
                snapshot.participant_episode_history,
            )
        ),
        behavior_violations=list(
            iter_participant_behavior_snapshot_violations(
                snapshot.participant_behavior_history,
                participant_episode_results=snapshot.participant_episode_results,
                participant_episode_history=snapshot.participant_episode_history,
                metadata=snapshot.metadata,
            )
        ),
        shared_state_violations=_shared_state_violations(snapshot, extensions),
        concurrency_violations=_concurrency_violations(snapshot, extensions),
    )


def _shared_state_violations(
    snapshot: RuntimeSnapshot,
    extensions: ParticipantSnapshotExtensions,
) -> list[SnapshotViolation]:
    """Return shared-state violations when the current ACES contract exists."""

    if iter_participant_shared_state_snapshot_violations is None:
        return []
    return list(
        iter_participant_shared_state_snapshot_violations(
            extensions.shared_state_records,
            extensions.shared_state_history,
            participant_behavior_history=snapshot.participant_behavior_history,
            metadata=snapshot.metadata,
        )
    )


def _concurrency_violations(
    snapshot: RuntimeSnapshot,
    extensions: ParticipantSnapshotExtensions,
) -> list[SnapshotViolation]:
    """Return concurrency violations when the current ACES contract exists."""

    if iter_participant_concurrency_snapshot_violations is None:
        return []
    return list(
        iter_participant_concurrency_snapshot_violations(
            extensions.joint_action_records,
            extensions.time_management_contexts,
            participant_behavior_history=snapshot.participant_behavior_history,
            shared_state_records=extensions.shared_state_records,
            shared_state_history=extensions.shared_state_history,
        )
    )


def _capture_post_action_range(
    project_dir: Path,
    backend: "DeploymentBackend",
    snapshot_capture: SnapshotCapture,
) -> tuple[dict[str, object] | None, list[str]]:
    """Capture a post-action range snapshot for proof evidence."""

    diagnostics: list[str] = []
    range_snapshot_summary: dict[str, object] | None = None
    try:
        range_snapshot_summary = summarize_snapshot(
            snapshot_capture(config_dir=project_dir, backend=backend).to_dict()
        )
    except Exception as exc:
        diagnostics.append(redact(f"post-action range snapshot capture failed: {exc}"))
    return range_snapshot_summary, diagnostics


def _participant_proof_payload(
    context: ParticipantProofContext,
) -> dict[str, object]:
    """Render the participant proof as a JSON-serializable payload."""

    snapshot = context.snapshot
    extensions = context.extensions
    return {
        "schema": "aptl.participant-action-proof/v1",
        "participant_address": context.participant_address,
        "operation_receipt_contract": "operation-receipt-v1",
        "operation_status_contract": "operation-status-v1",
        "runtime_snapshot_contract": "runtime-snapshot-v1",
        "operation_receipt": _receipt_payload(context.receipt),
        "operation_status": _status_payload(context.status),
        "participant_runtime_status": _participant_runtime_status(context.target),
        "participant_episode_results": dict(snapshot.participant_episode_results),
        "participant_episode_history": {
            address: list(events)
            for address, events in snapshot.participant_episode_history.items()
        },
        "participant_behavior_history": {
            address: list(events)
            for address, events in snapshot.participant_behavior_history.items()
        },
        "participant_shared_state_records": extensions.shared_state_records,
        "participant_shared_state_history": extensions.shared_state_history,
        "participant_joint_action_records": extensions.joint_action_records,
        "participant_time_management_contexts": extensions.time_management_contexts,
        "participant_snapshot_entries": _participant_snapshot_entries(snapshot),
        "post_action_range_snapshot": context.range_snapshot_summary,
        "validation": context.validation.to_payload(context.capture_diagnostics),
        "verdict": "PASS" if _proof_passed(context) else "FAIL",
    }


def _proof_passed(context: ParticipantProofContext) -> bool:
    """Return whether the participant proof satisfied every required surface."""

    snapshot = context.snapshot
    participant_address = context.participant_address
    return (
        _operation_succeeded(context.status)
        and participant_address in snapshot.participant_episode_results
        and bool(snapshot.participant_episode_history.get(participant_address))
        and bool(snapshot.participant_behavior_history.get(participant_address))
        and context.validation.passed()
        and not context.capture_diagnostics
    )


def _operation_succeeded(status: object | None) -> bool:
    """Return whether an ACES operation status succeeded."""

    return status is not None and getattr(status, "state", None) == OperationState.SUCCEEDED


def _receipt_payload(receipt: object) -> dict[str, object]:
    """Return the operation receipt proof payload."""

    domain = getattr(receipt, "domain")
    return {
        "operation_id": getattr(receipt, "operation_id"),
        "domain": domain.value,
        "accepted": getattr(receipt, "accepted"),
        "submitted_at": getattr(receipt, "submitted_at"),
        "diagnostics": _diagnostics_to_dicts(getattr(receipt, "diagnostics")),
    }


def _status_payload(status: object | None) -> dict[str, object] | None:
    """Return the operation status proof payload."""

    if status is None:
        return None
    domain = getattr(status, "domain")
    state = getattr(status, "state")
    return {
        "operation_id": getattr(status, "operation_id"),
        "domain": domain.value,
        "state": state.value,
        "submitted_at": getattr(status, "submitted_at"),
        "updated_at": getattr(status, "updated_at"),
        "diagnostics": _diagnostics_to_dicts(getattr(status, "diagnostics")),
        "changed_addresses": list(getattr(status, "changed_addresses")),
    }


def _participant_runtime_status(target: RuntimeTarget) -> dict[str, object] | None:
    """Return the participant runtime status when the target exposes one."""

    participant_runtime = target.participant_runtime
    if participant_runtime is None:
        return None
    return participant_runtime.status()


def _participant_snapshot_entries(
    snapshot: RuntimeSnapshot,
) -> dict[str, dict[str, object]]:
    """Return participant-domain snapshot entries as JSON-serializable payloads."""

    return {
        address: {
            "domain": entry.domain.value,
            "resource_type": entry.resource_type,
            "status": entry.status,
            "payload": dict(entry.payload),
        }
        for address, entry in snapshot.entries.items()
        if entry.domain.value == "participant"
    }


def _diagnostics_to_dicts(diagnostics: Sequence[object]) -> list[dict[str, object]]:
    """Return ACES diagnostics as JSON-serializable redacted dictionaries."""

    result: list[dict[str, object]] = []
    for diagnostic in diagnostics:
        severity = getattr(diagnostic, "severity", "")
        result.append(
            {
                "code": getattr(diagnostic, "code", ""),
                "domain": getattr(diagnostic, "domain", ""),
                "address": getattr(diagnostic, "address", ""),
                "severity": getattr(severity, "value", severity),
                "message": redact(str(getattr(diagnostic, "message", ""))),
            }
        )
    return result


def _violation_payload(
    violations: Sequence[SnapshotViolation],
) -> list[dict[str, str]]:
    """Return snapshot validator violations as proof dictionaries."""

    return [{"path": path, "message": message} for path, message in violations]


def _redact_volatile_proof_identifiers(
    proof: dict[str, object],
    participant_address: str,
) -> dict[str, object]:
    """Normalize per-run IDs before evidence is committed."""

    replacements = {}
    replacements.update(_operation_id_replacements(proof))
    replacements.update(_episode_id_replacements(proof))
    replacements.update(_action_instance_replacements(proof, participant_address))
    return _replace_proof_strings(proof, replacements)


def _operation_id_replacements(proof: Mapping[str, object]) -> dict[str, str]:
    """Return replacements for per-run operation ids."""

    receipt = proof.get("operation_receipt")
    replacements: dict[str, str] = {}
    if isinstance(receipt, Mapping):
        operation_id = receipt.get("operation_id")
        if isinstance(operation_id, str) and operation_id:
            replacements[operation_id] = "operation-id-redacted"
    return replacements


def _episode_id_replacements(proof: Mapping[str, object]) -> dict[str, str]:
    """Return replacements for per-run participant episode ids."""

    results = proof.get("participant_episode_results")
    replacements: dict[str, str] = {}
    if isinstance(results, Mapping):
        for result in results.values():
            if isinstance(result, Mapping):
                episode_id = result.get("episode_id")
                if isinstance(episode_id, str) and episode_id:
                    replacements[episode_id] = "episode-id-redacted"
    return replacements


def _action_instance_replacements(
    proof: Mapping[str, object],
    participant_address: str,
) -> dict[str, str]:
    """Return replacements for per-run participant action-instance ids."""

    replacements: dict[str, str] = {}
    redacted = f"{participant_address}.action-instance-redacted"
    for event in _iter_behavior_events(proof):
        action_instance_id = event.get("action_instance_id")
        if isinstance(action_instance_id, str) and action_instance_id:
            replacements[action_instance_id] = redacted
    return replacements


def _iter_behavior_events(
    proof: Mapping[str, object],
) -> Iterable[Mapping[str, object]]:
    """Yield behavior-history event mappings from the proof payload."""

    behavior_history = proof.get("participant_behavior_history")
    if not isinstance(behavior_history, Mapping):
        return
    for events in behavior_history.values():
        if not isinstance(events, list):
            continue
        for event in events:
            if isinstance(event, Mapping):
                yield event


def _replace_proof_strings(value: object, replacements: Mapping[str, str]) -> object:
    """Apply redactions recursively across a proof payload."""

    result = value
    if isinstance(value, str):
        result = _replace_string(value, replacements)
    elif isinstance(value, list):
        result = [_replace_proof_strings(item, replacements) for item in value]
    elif isinstance(value, dict):
        result = {
            str(_replace_proof_strings(key, replacements)): _replace_proof_strings(
                item, replacements
            )
            for key, item in value.items()
        }
    return result


def _replace_string(value: str, replacements: Mapping[str, str]) -> str:
    """Apply digest and identifier redactions to one string value."""

    result = value
    if value.startswith("sha256:") and len(value) > len("sha256:") + 16:
        result = "sha256:redacted-proof-digest"
    else:
        for old, new in replacements.items():
            result = result.replace(old, new)
    return result
