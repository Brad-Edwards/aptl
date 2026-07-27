"""Execution and evidence publication for admitted participant realizations."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from raes_contracts.contracts import ParticipantActionResultModel
from raes_contracts.diagnostics import Diagnostic, Severity
from raes_contracts.participant_binding import (
    ParticipantActionAdmissionRequest,
    ParticipantNativeActionExecution,
)
from raes_contracts.planning import RuntimeDomain
from raes_contracts.runtime_state import ApplyResult, RuntimeSnapshot, SnapshotEntry

from aptl.backends.raes_participant_fixture import (
    VerifiedParticipantOperation,
)
from aptl.backends.raes_participant_execution_support import (
    evidence_token,
    mapping_digest,
    observation_point,
    rejected_native_execution,
)

if TYPE_CHECKING:
    from aptl.backends.raes_participant_driver import ParticipantPlanAuthority
    from aptl.backends.raes_participant_realizations import (
        ParticipantActionRealization,
        ParticipantRealizationExecution,
    )
    from aptl.core.deployment.backend import DeploymentBackend


@dataclass(frozen=True)
class _ExecutionContext:
    """Resolved native execution inputs for one admitted participant action."""

    request: ParticipantActionAdmissionRequest
    snapshot: RuntimeSnapshot
    episode_id: str
    authority: ParticipantPlanAuthority
    deployment_backend: DeploymentBackend
    realization: ParticipantActionRealization
    container_by_node: Mapping[str, str]
    normalized_arguments: Mapping[str, object]


@dataclass(frozen=True)
class _ContextResolution:
    """Exactly one executable context or closed rejection result."""

    context: _ExecutionContext | None = None
    rejection: ParticipantRealizationExecution | None = None


def execute_participant_realization(
    *,
    request: ParticipantActionAdmissionRequest,
    snapshot: RuntimeSnapshot,
    episode_id: str,
    authority: ParticipantPlanAuthority,
    deployment_backend: DeploymentBackend,
) -> ParticipantRealizationExecution:
    """Execute one RAES-admitted action through its closed native handler."""

    resolution = _resolve_execution_context(
        request=request,
        snapshot=snapshot,
        episode_id=episode_id,
        authority=authority,
        deployment_backend=deployment_backend,
    )
    if resolution.context is None:
        if resolution.rejection is None:
            raise RuntimeError("participant realization resolution was incomplete")
        return resolution.rejection
    observation = _execute_observation(resolution.context)
    return _build_realization_execution(resolution.context, observation)


def _resolve_execution_context(
    *,
    request: ParticipantActionAdmissionRequest,
    snapshot: RuntimeSnapshot,
    episode_id: str,
    authority: ParticipantPlanAuthority,
    deployment_backend: DeploymentBackend,
) -> _ContextResolution:
    """Resolve an admitted address to a ready, closed backend realization."""

    from aptl.backends.raes_participant_realizations import (
        BPA_ACTION_REALIZATIONS,
        ParticipantRealizationExecution,
    )

    readiness = authority.readiness
    realization = BPA_ACTION_REALIZATIONS.get(request.action_contract_address)
    failure: tuple[str, str] | None = None
    if readiness is None:
        failure = ("participant realization authority is not ready", "backend_error")
    elif realization is None:
        failure = ("action has no admitted APTL realization", "unsupported_action")
    else:
        container_by_node = dict(readiness.target_containers)
        if any(node not in container_by_node for node in realization.target_nodes):
            failure = ("action target is not realized", "target_unavailable")

    if failure is not None:
        message, failure_class = failure
        return _ContextResolution(
            rejection=ParticipantRealizationExecution(
                native=rejected_native_execution(
                    request,
                    snapshot,
                    episode_id,
                    message,
                    failure_class=failure_class,
                )
            )
        )
    if readiness is None or realization is None:
        raise RuntimeError("participant realization context was not resolved")
    return _ContextResolution(
        context=_ExecutionContext(
            request=request,
            snapshot=snapshot,
            episode_id=episode_id,
            authority=authority,
            deployment_backend=deployment_backend,
            realization=realization,
            container_by_node=dict(readiness.target_containers),
            normalized_arguments=(
                request.validated_selection.argument_map
                if request.validated_selection is not None
                else {}
            ),
        )
    )


def _execute_observation(context: _ExecutionContext) -> VerifiedParticipantOperation:
    """Execute the native operation and enforce its declared mutation class."""

    from aptl.backends.raes_participant_realizations import (
        execute_verified_participant_operation,
    )

    unmet = _unmet_prior_actions(
        context.request,
        context.snapshot,
        context.episode_id,
    )
    if unmet:
        observation = VerifiedParticipantOperation(
            success=False,
            summary="required prior participant observation is unavailable",
            pre_state={},
            post_state={},
            diagnostic="missing prior actions: " + ", ".join(unmet),
            failure_class="precondition_unsatisfied",
        )
    else:
        observation = execute_verified_participant_operation(
            backend=context.deployment_backend,
            container_by_node=context.container_by_node,
            action_contract_address=context.request.action_contract_address,
            arguments=context.normalized_arguments,
            participant_address=context.request.participant_address,
            episode_id=context.episode_id,
            target_nodes=context.realization.target_nodes,
        )
    return _enforce_mutation_claim(context.realization, observation)


def _enforce_mutation_claim(
    realization: ParticipantActionRealization,
    observation: VerifiedParticipantOperation,
) -> VerifiedParticipantOperation:
    """Reject semantic readback that contradicts the action mutation claim."""

    contradiction: tuple[str, str] | None = None
    if (
        observation.success
        and realization.mutates_state
        and not observation.state_changed
        and not realization.allows_idempotent_stutter
    ):
        contradiction = (
            "trusted semantic readback did not observe the declared state change",
            "semantic post-state digest did not change",
        )
    elif (
        observation.success
        and not realization.mutates_state
        and observation.state_changed
    ):
        contradiction = (
            "trusted semantic readback observed an undeclared state change",
            "read-only realization changed semantic state",
        )
    if contradiction is None:
        return observation
    summary, diagnostic = contradiction
    return VerifiedParticipantOperation(
        success=False,
        summary=summary,
        pre_state=observation.pre_state,
        post_state=observation.post_state,
        diagnostic=diagnostic,
        failure_class="backend_error",
    )


def _build_realization_execution(
    context: _ExecutionContext,
    observation: VerifiedParticipantOperation,
) -> ParticipantRealizationExecution:
    """Build native commit data and separately staged evidence projections."""

    from aptl.backends.raes_participant_realizations import (
        ParticipantRealizationExecution,
    )

    record = _action_evidence_record(context, observation)
    action_result = _action_result(context, observation)
    entry_address = (
        "participant.action-instance."
        f"{hashlib.sha256(context.request.action_instance_id.encode()).hexdigest()}"
    )
    entry = SnapshotEntry(
        address=entry_address,
        domain=RuntimeDomain.PARTICIPANT,
        resource_type="participant-action-instance",
        payload=record,
    )
    working = context.snapshot.with_entries(
        {**context.snapshot.entries, entry_address: entry}
    )
    diagnostics = _native_diagnostics(context, observation)
    return ParticipantRealizationExecution(
        native=ParticipantNativeActionExecution(
            apply_result=ApplyResult(
                success=True,
                snapshot=working,
                diagnostics=diagnostics,
                changed_addresses=[entry_address],
            ),
            action_result=action_result,
            post_state_digest=observation.post_state_digest,
        ),
        evaluator_record=record,
        participant_record=_participant_record(record, observation),
    )


def _action_evidence_record(
    context: _ExecutionContext,
    observation: VerifiedParticipantOperation,
) -> dict[str, object]:
    """Build the evaluator-only semantic evidence record."""

    request = context.request
    evidence_ref = (
        f"participant-evidence.{context.authority.run_id or 'unbound'}."
        f"{evidence_token(request.action_instance_id)}"
    )
    return {
        "schema": "aptl.participant-action-evidence/v1",
        "run_id": context.authority.run_id,
        "participant_address": request.participant_address,
        "episode_id": context.episode_id,
        "action_instance_id": request.action_instance_id,
        "action_contract_address": request.action_contract_address,
        "operation": context.realization.operation.value,
        "target_refs": list(context.realization.target_nodes),
        "observer_kind": context.realization.observer_kind,
        "mutates_state": context.realization.mutates_state,
        "allows_idempotent_stutter": (
            context.realization.allows_idempotent_stutter
        ),
        "pre_state_digest": observation.pre_state_digest,
        "post_state_digest": observation.post_state_digest,
        "state_changed": observation.state_changed,
        "established_precondition_ids": list(observation.established_preconditions),
        "established_effect_ids": list(observation.established_effects),
        "status": "succeeded" if observation.success else "failed",
        "failure_class": observation.failure_class,
        "normalized_argument_digest": mapping_digest(context.normalized_arguments),
        "evidence_ref": evidence_ref,
    }


def _action_result(
    context: _ExecutionContext,
    observation: VerifiedParticipantOperation,
) -> ParticipantActionResultModel:
    """Build the participant-visible terminal action result."""

    request = context.request
    contract = context.authority.runtime_model.action_contracts[
        request.action_contract_address
    ]
    declared_evidence = _declared_action_evidence(contract.spec)
    return ParticipantActionResultModel(
        status="succeeded" if observation.success else "failed",
        participant_address=request.participant_address,
        episode_id=context.episode_id,
        action_instance_id=request.action_instance_id,
        action_contract_address=request.action_contract_address,
        observation_point=observation_point(request),
        preconditions=_precondition_results(context, observation, contract.spec),
        effects=_effect_results(context, observation, contract.spec),
        failure_class=None if observation.success else observation.failure_class,
        observations=[observation.summary],
        evidence_refs=[
            ref for ref in request.evidence_refs if ref in declared_evidence
        ],
        diagnostics=[] if observation.diagnostic is None else [observation.diagnostic],
    )


def _precondition_results(
    context: _ExecutionContext,
    observation: VerifiedParticipantOperation,
    spec: Mapping[str, object],
) -> list[dict[str, object]]:
    """Project established preconditions onto the participant result."""

    request = context.request
    established = set(observation.established_preconditions)
    results: list[dict[str, object]] = []
    for item in spec.get("preconditions", ()):
        precondition_id = item["precondition_id"]
        satisfied = precondition_id in established
        results.append(
            {
                "precondition_id": precondition_id,
                "precondition_class": item["precondition_class"],
                "status": "satisfied" if satisfied else "unsatisfied",
                "participant_address": request.participant_address,
                "episode_id": context.episode_id,
                "action_contract_address": request.action_contract_address,
                "observation_point": observation_point(request),
                "support_refs": [
                    ref
                    for ref in item.get("support_refs", ())
                    if ref in request.visible_refs
                ],
                "evidence_refs": [
                    ref
                    for ref in item.get("evidence_refs", ())
                    if ref in request.evidence_refs
                ],
                "diagnostics": (
                    []
                    if satisfied or observation.diagnostic is None
                    else [observation.diagnostic]
                ),
            }
        )
    return results


def _effect_results(
    context: _ExecutionContext,
    observation: VerifiedParticipantOperation,
    spec: Mapping[str, object],
) -> list[dict[str, object]]:
    """Project only participant-evidenced effects established by readback."""

    if not observation.success:
        return []
    effects: list[dict[str, object]] = []
    established = set(observation.established_effects)
    for item in spec.get("effects", ()):
        raw_evidence = tuple(item.get("evidence_refs", ()))
        participant_evidence = [
            ref for ref in raw_evidence if ref in context.request.evidence_refs
        ]
        if item["effect_id"] not in established:
            continue
        if raw_evidence and not participant_evidence:
            continue
        effects.append(
            {
                "effect_id": item["effect_id"],
                "effect_class": item["effect_class"],
                "description": item["description"],
                "target_refs": list(item.get("target_refs", ())),
                "evidence_refs": participant_evidence,
                "diagnostics": [],
            }
        )
    return effects


def _declared_action_evidence(spec: Mapping[str, object]) -> set[str]:
    """Collect evidence references declared anywhere in the action contract."""

    return {
        ref
        for collection_name in (
            "preconditions",
            "effects",
            "observation_expectations",
            "evidence_expectations",
        )
        for item in spec.get(collection_name, ())
        if isinstance(item, Mapping)
        for ref in item.get("evidence_refs", ())
        if isinstance(ref, str)
    }


def _native_diagnostics(
    context: _ExecutionContext,
    observation: VerifiedParticipantOperation,
) -> list[Diagnostic]:
    """Return a warning for an observed terminal action failure."""

    if observation.success:
        return []
    return [
        Diagnostic(
            code="aptl.participant-runtime.native-action-failed",
            domain=RuntimeDomain.PARTICIPANT.value,
            address=context.request.participant_address,
            message=observation.diagnostic or "bounded native action failed",
            severity=Severity.WARNING,
        )
    ]


def _participant_record(
    record: Mapping[str, object],
    observation: VerifiedParticipantOperation,
) -> dict[str, object]:
    """Project the minimal participant-visible observation record."""

    return {
        "schema": "aptl.participant-observation/v1",
        "participant_address": record["participant_address"],
        "episode_id": record["episode_id"],
        "action_instance_id": record["action_instance_id"],
        "action_contract_address": record["action_contract_address"],
        "status": record["status"],
        "observation": observation.summary,
        "evidence_ref": record["evidence_ref"],
    }


def _unmet_prior_actions(
    request: ParticipantActionAdmissionRequest,
    snapshot: RuntimeSnapshot,
    episode_id: str,
) -> tuple[str, ...]:
    """Return required prior actions without successful episode observations."""

    from aptl.backends.raes_participant_realizations import REQUIRED_PRIOR_ACTIONS

    required = REQUIRED_PRIOR_ACTIONS.get(request.action_contract_address, ())
    completed = {
        str(event.get("action_contract_address"))
        for event in snapshot.participant_behavior_history.get(
            request.participant_address, []
        )
        if event.get("episode_id") == episode_id
        and event.get("event_type") == "observation_emitted"
        and isinstance(event.get("action_result"), Mapping)
        and event["action_result"].get("status") == "succeeded"
    }
    return tuple(address for address in required if address not in completed)


def persist_action_evidence(
    authority: ParticipantPlanAuthority,
    *,
    evaluator_record: Mapping[str, object],
    participant_record: Mapping[str, object],
) -> tuple[Diagnostic, ...]:
    """Publish an atomic source record, then recoverable JSONL projections."""

    from aptl.backends.raes_participant_evidence_publication import (
        persist_action_evidence as persist,
    )

    return persist(
        authority,
        evaluator_record=evaluator_record,
        participant_record=participant_record,
    )
