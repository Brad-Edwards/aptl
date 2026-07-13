"""Participant action helpers for the APTL ACES runtime."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from aces_contracts.diagnostics import Diagnostic, Severity
from aces_contracts.participant_behavior import (
    ParticipantBehaviorHistoryEventType,
    ParticipantLifecycleOperationState,
    ParticipantObservationStatus,
    ParticipantPhaseRealization,
    ParticipantRuntimeLifecyclePhase,
)
from aces_contracts.participant_episode import ParticipantEpisodeExecutionState
from aces_contracts.planning import ProvisioningPlan, RuntimeDomain
from aces_contracts.runtime_state import SnapshotEntry
from aces_processor.compiler import compile_runtime_model

from aptl.backends.aces_participant_bindings import (
    participant_action_specs_from_runtime_model as _binding_action_specs,
)
from aptl.core.config import AptlConfig
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
TECHVAULT_VICTIM_SSH_ADDRESS = ".".join(("172", "20", "2", "20"))
TECHVAULT_VICTIM_SSH_REF = f"tcp:{TECHVAULT_VICTIM_SSH_ADDRESS}:22"

# Target refs with this prefix name a negative reachability boundary — an
# internal endpoint (e.g. the DB or Wazuh API) the participant path must NOT
# reach. They are evaluator-only negative-boundary evidence, never a
# participant-visible resource, so they must be kept out of the observation
# boundary's observable/disclosed projection (ADR-046 Paper Scenario Evidence
# Modeling Addendum; issue #691).
_BOUNDARY_NEGATIVE_PREFIX = "boundary-negative:"


def _partition_participant_refs(
    target_refs: tuple[str, ...],
) -> tuple[list[str], list[str]]:
    """Split action target refs into participant-visible and evaluator-only.

    Returns ``(visible, negative_boundary)``. ``negative_boundary`` refs carry
    internal endpoint identities and are the participant projection's hidden
    truth; only ``visible`` refs may project into the participant view.
    """

    visible = [
        ref for ref in target_refs if not ref.startswith(_BOUNDARY_NEGATIVE_PREFIX)
    ]
    negative_boundary = [
        ref for ref in target_refs if ref.startswith(_BOUNDARY_NEGATIVE_PREFIX)
    ]
    return visible, negative_boundary


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


@dataclass(frozen=True)
class ParticipantCommandObservation:
    """Captured terminal observation from a participant action command."""

    returncode: int
    stdout: str
    stderr: str
    success: bool


@dataclass(frozen=True)
class ParticipantActionExecution:
    """Participant action result projected into ACES snapshot surfaces."""

    success: bool
    behavior_events: list[dict[str, object]]
    diagnostics: list[Diagnostic]
    snapshot_entries: dict[str, SnapshotEntry]
    shared_state_records: dict[str, dict[str, object]]


DEFAULT_PARTICIPANT_ACTIONS = {
    PARTICIPANT_ACTION_ADDRESS: ParticipantActionSpec(
        source_container="aptl-kali",
        command=(
            "nmap",
            "-p",
            "22",
            "-Pn",
            "--open",
            TECHVAULT_VICTIM_SSH_ADDRESS,
            "-oG",
            "-",
        ),
        success_markers=("22/open",),
        action_contract_address=PARTICIPANT_ACTION_CONTRACT_ADDRESS,
        observation_boundary_address=PARTICIPANT_OBSERVATION_BOUNDARY_ADDRESS,
        target_refs=(
            "container:aptl-kali",
            "container:aptl-victim",
            TECHVAULT_VICTIM_SSH_REF,
        ),
    )
}


def participant_action_specs_from_runtime_model(
    model: object,
    *,
    provisioning_plan: ProvisioningPlan,
    project_dir: Path,
    config: AptlConfig,
) -> dict[str, ParticipantActionSpec]:
    """Return APTL action bindings declared by compiled runtime artifacts."""

    return cast(
        dict[str, ParticipantActionSpec],
        _binding_action_specs(
            model,
            provisioning_plan=provisioning_plan,
            project_dir=project_dir,
            config=config,
            spec_factory=ParticipantActionSpec,
        ),
    )


def participant_action_specs_for_scenario(
    scenario: object,
    *,
    provisioning_plan: ProvisioningPlan,
    project_dir: Path,
    config: AptlConfig,
) -> dict[str, ParticipantActionSpec]:
    """Best-effort participant bindings from compiled runtime artifacts."""

    try:
        model = compile_runtime_model(scenario)
    except Exception:
        return {}
    return participant_action_specs_from_runtime_model(
        model,
        provisioning_plan=provisioning_plan,
        project_dir=project_dir,
        config=config,
    )


def participant_action_diagnostic(
    code: str, address: str, message: str
) -> Diagnostic:
    """Build a redacted participant-runtime error diagnostic."""

    return Diagnostic(
        code=code,
        domain=RuntimeDomain.PARTICIPANT.value,
        address=address,
        message=redact(message),
        severity=Severity.ERROR,
    )


def drive_participant_action(
    deployment_backend: "DeploymentBackend",
    action_specs: Mapping[str, ParticipantActionSpec],
    participant_address: str,
    state: ParticipantEpisodeExecutionState,
    *,
    timestamp_factory: Callable[[], str],
) -> ParticipantActionExecution | None:
    """Drive the configured participant action and emit ACES evidence surfaces."""

    spec = action_specs.get(participant_address)
    if spec is None:
        return None
    action_instance_id = f"{participant_address}.{uuid4().hex}"
    started_at = timestamp_factory()
    attempted = _action_attempted_event(spec, state, action_instance_id, started_at)
    observation, diagnostics = _run_action_command(
        deployment_backend, spec, participant_address
    )
    finished_at = timestamp_factory()
    observed = _observation_event(
        spec, state, action_instance_id, finished_at, observation
    )
    if not observation.success:
        diagnostics.append(
            participant_action_diagnostic(
                "aptl.participant-runtime.action-failed",
                participant_address,
                (
                    "Participant action did not observe the expected lab result "
                    f"(returncode={observation.returncode}, "
                    f"markers={spec.success_markers})."
                ),
            )
        )
    return ParticipantActionExecution(
        success=observation.success,
        behavior_events=[attempted, observed],
        diagnostics=diagnostics,
        snapshot_entries=_action_snapshot_entries(
            participant_address, spec, action_instance_id, observation.success
        ),
        shared_state_records=_shared_state_records(
            participant_address, spec, action_instance_id, observation.success
        ),
    )


def _run_action_command(
    deployment_backend: "DeploymentBackend",
    spec: ParticipantActionSpec,
    participant_address: str,
) -> tuple[ParticipantCommandObservation, list[Diagnostic]]:
    """Execute the participant command and classify the captured output."""

    diagnostics: list[Diagnostic] = []
    stdout = ""
    stderr = ""
    returncode = 1
    try:
        result = deployment_backend.container_exec(
            spec.source_container,
            list(spec.command),
            timeout=spec.timeout_seconds,
        )
        stdout = redact(str(getattr(result, "stdout", "")))
        stderr = redact(str(getattr(result, "stderr", "")))
        returncode = int(getattr(result, "returncode", 1))
    except Exception as exc:
        stderr = redact(f"{type(exc).__name__}: {exc}")
        diagnostics.append(
            participant_action_diagnostic(
                "aptl.participant-runtime.action-backend-failed",
                participant_address,
                "Participant action backend call failed: " + stderr,
            )
        )
    combined = f"{stdout}\n{stderr}"
    marker_ok = all(marker in combined for marker in spec.success_markers)
    observation = ParticipantCommandObservation(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        success=returncode == 0 and marker_ok,
    )
    return observation, diagnostics


def _action_attempted_event(
    spec: ParticipantActionSpec,
    state: ParticipantEpisodeExecutionState,
    action_instance_id: str,
    timestamp: str,
) -> dict[str, object]:
    """Build the behavior-history event for an attempted participant action."""

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
    observation: ParticipantCommandObservation,
) -> dict[str, object]:
    """Build the behavior-history event for the participant observation."""

    digest = hashlib.sha256(
        f"{observation.stdout}\n{observation.stderr}".encode("utf-8")
    ).hexdigest()
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
            "returncode": observation.returncode,
            "success": observation.success,
            "stdout_excerpt": observation.stdout[:2000],
            "stderr_excerpt": observation.stderr[:2000],
            "success_markers": list(spec.success_markers),
        },
    }


def _action_snapshot_entries(
    participant_address: str,
    spec: ParticipantActionSpec,
    action_instance_id: str,
    success: bool,
) -> dict[str, SnapshotEntry]:
    """Build participant snapshot entries for the action contract and result."""

    action_name = _address_leaf(spec.action_contract_address)
    boundary_name = _address_leaf(spec.observation_boundary_address)
    visible_refs, negative_boundary_refs = _partition_participant_refs(
        spec.target_refs
    )
    return {
        participant_address: SnapshotEntry(
            address=participant_address,
            domain=RuntimeDomain.PARTICIPANT,
            resource_type="participant-behavior",
            payload={
                "participant_address": participant_address,
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
                "name": f"APTL participant action {action_name}",
                "action_name": action_name,
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
                "name": f"APTL participant observation boundary {boundary_name}",
                "boundary_name": boundary_name,
                "projection_basis": "terminal command output excerpt",
                # Negative-boundary refs name hidden internal endpoints and
                # must never project into the participant view (ADR-046); they
                # are evaluator-only evidence alongside the action instance.
                "observable_refs": visible_refs,
                "evidence_refs": [action_instance_id, *negative_boundary_refs],
                "disclosed_refs": visible_refs,
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
    participant_address: str,
    spec: ParticipantActionSpec,
    action_instance_id: str,
    success: bool,
) -> dict[str, dict[str, object]]:
    """Build shared-state records touched by the participant action."""

    records: dict[str, dict[str, object]] = {}
    for ref in spec.target_refs:
        state_kind = "network-service" if ref.startswith("tcp:") else "container"
        digest = hashlib.sha256(
            f"{ref}:{action_instance_id}:{success}".encode("utf-8")
        ).hexdigest()
        records[ref] = {
            "state_address": ref,
            "state_scope": participant_address,
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


def _address_leaf(address: str) -> str:
    """Return the terminal address segment for a runtime artifact."""

    return address.rsplit(".", 1)[-1] if address else "runtime-artifact"
