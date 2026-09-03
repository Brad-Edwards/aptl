"""Boundary challenges for the bounded participant qualification suite."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from raes_contracts.contracts import (
    ParticipantDecisionSurfaceSelectionV2Model,
)
from raes_contracts.runtime_state import OperationState

from aptl.backends.raes_participant_apparatus import (
    build_participant_apparatus,
    project_participant_turn,
)
from aptl.backends.raes_participant_driver import (
    admit_projected_participant_selection,
    run_participant_turn,
)
from aptl.backends.raes_participant_provider import ParticipantSelectionProvider
from aptl.validation.participant_qualification_boundary_environment import (
    ACTION_EVIDENCE_PATH,
    BOUNDARY_CHALLENGE_PATH,
    action_evidence_count,
    episode_state_is_absent,
    persist_boundary_check,
    prepare_challenge_context,
    wait_until_process_absent,
)
from aptl.validation.participant_qualification_challenge_support import (
    ChallengeContext,
    StaticResponseProvider,
    TimeoutSelectionProvider,
)
from aptl.validation.participant_qualification_models import (
    ParticipantQualificationCheck,
)

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.runstore import RunStorageBackend

_CONTROL_EVIDENCE_PATH = "evaluator/participant-control-evidence.jsonl"


def run_boundary_challenge(
    challenge_id: str,
    *,
    project_dir: Path,
    config: AptlConfig,
    run_store: RunStorageBackend,
    parent_run_id: str,
    backend: DeploymentBackend,
) -> ParticipantQualificationCheck:
    """Run one isolated boundary challenge and persist its result."""

    behavior_name = (
        "red-public-service" if challenge_id == "BC-04" else "green-normal-session"
    )
    context = prepare_challenge_context(
        project_dir=project_dir,
        config=config,
        run_store=run_store,
        run_id=f"{parent_run_id}-{challenge_id.lower()}",
        backend=backend,
        behavior_name=behavior_name,
    )
    if challenge_id in {"BC-06", "BC-07", "BC-08", "BC-09", "BC-10"}:
        check = _special_challenge(context, challenge_id)
    else:
        check = _selection_boundary_challenge(context, challenge_id)
    persist_boundary_check(context, check)
    return check


def _special_challenge(
    context: ChallengeContext,
    challenge_id: str,
) -> ParticipantQualificationCheck:
    """Dispatch provider, replay, and information-withholding challenges."""

    if challenge_id == "BC-06":
        check = _hidden_reference_challenge(context)
    elif challenge_id == "BC-07":
        check = _replay_challenge(context)
    elif challenge_id == "BC-08":
        check = _provider_rejection_challenge(
            context,
            challenge_id,
            StaticResponseProvider("not-json"),
            "malformed implementation output failed before realization",
        )
    elif challenge_id == "BC-09":
        provider = TimeoutSelectionProvider()
        check = _provider_rejection_challenge(
            context,
            challenge_id,
            provider,
            "timed-out provider process group was removed before realization",
            extra_pass=lambda: (
                provider.child_pid is not None
                and wait_until_process_absent(provider.child_pid)
            ),
        )
    else:
        apparatus_has_no_tools = (
            not context.apparatus.selection.exposure_policy.tool_affordance_refs
        )
        check = _provider_rejection_challenge(
            context,
            challenge_id,
            StaticResponseProvider('{"command":"docker ps"}'),
            "direct host and tool request had no selectable capability",
            extra_pass=lambda: apparatus_has_no_tools,
        )
    return check


def _selection_boundary_challenge(
    context: ChallengeContext,
    challenge_id: str,
) -> ParticipantQualificationCheck:
    """Mutate one delivered candidate and require RAES admission rejection."""

    turn = project_participant_turn(
        runtime_model=context.plan.model,
        runtime_snapshot=context.control.snapshot,
        behavior_specification_address=context.behavior_address,
        apparatus=context.apparatus,
    )
    candidate = (
        _candidate(turn, "probe-permitted-endpoint")
        if challenge_id == "BC-04"
        else turn.candidates[0]
    )
    payload = candidate.model_dump(mode="json")
    stale_apparatus = _mutate_selection_challenge(
        context,
        turn,
        challenge_id,
        payload,
    )
    selection = ParticipantDecisionSurfaceSelectionV2Model.model_validate(payload)
    admission = admit_projected_participant_selection(
        context.control,
        turn=turn,
        selection=selection,
        admission_apparatus=stale_apparatus,
    )
    status = context.control.get_operation(admission.receipt.operation_id)
    return _rejected_admission_check(
        context,
        challenge_id,
        status is not None and status.state is OperationState.FAILED,
    )


def _mutate_selection_challenge(
    context: ChallengeContext,
    turn: object,
    challenge_id: str,
    payload: dict[str, object],
) -> object | None:
    """Apply the controlled invalid coordinate for challenges BC-01–BC-05."""

    stale_apparatus = None
    if challenge_id == "BC-01":
        payload["action_contract_address"] = "participant.action-contract.not-declared"
    elif challenge_id == "BC-02":
        payload["action_contract_address"] = (
            "participant.action-contract.probe-permitted-endpoint"
        )
    elif challenge_id == "BC-03":
        payload["arguments"] = {
            "surface": "nodes.defender-console.services.defender-api"
        }
    elif challenge_id == "BC-04":
        payload["arguments"] = {
            "endpoint": "/",
            "method": "TRACE",
        }
    elif challenge_id == "BC-05":
        stale_apparatus = build_participant_apparatus(
            participant_address=context.participant_address,
            implementation_name="aptl-stale-challenge-fixture",
            implementation_version=context.apparatus.manifest.identity.version,
            provider_name="deterministic",
            model=None,
            run_id=f"{context.run_id}-prior-episode",
        )
        stale_apparatus = replace(
            stale_apparatus,
            selection=stale_apparatus.selection.model_copy(
                update={"exposure_policy": turn.apparatus.selection.exposure_policy}
            ),
        )
    return stale_apparatus


def _candidate(
    turn: object,
    action_name: str,
) -> ParticipantDecisionSurfaceSelectionV2Model:
    """Resolve one named selection from the projected candidate set."""

    return next(
        candidate
        for candidate in turn.candidates
        if candidate.action_contract_address
        == f"participant.action-contract.{action_name}"
    )


def _rejected_admission_check(
    context: ChallengeContext,
    challenge_id: str,
    rejected: bool,
) -> ParticipantQualificationCheck:
    """Require admission rejection and independently observed no-effect."""

    no_history = not context.control.snapshot.participant_behavior_history.get(
        context.participant_address, []
    )
    evidence_count = action_evidence_count(context)
    no_effect = episode_state_is_absent(context)
    return ParticipantQualificationCheck(
        check_id=challenge_id,
        passed=rejected and no_history and evidence_count == 0 and no_effect,
        summary="invalid selection was rejected with independently observed no-effect",
        run_id=context.run_id,
        evidence_paths=(BOUNDARY_CHALLENGE_PATH,),
        details={
            "operation_rejected": rejected,
            "behavior_history_unchanged": no_history,
            "action_evidence_count": evidence_count,
            "episode_state_absent": no_effect,
        },
    )


def _hidden_reference_challenge(
    context: ChallengeContext,
) -> ParticipantQualificationCheck:
    """Require withheld evaluator truth to be absent from the delivered view."""

    turn = project_participant_turn(
        runtime_model=context.plan.model,
        runtime_snapshot=context.control.snapshot,
        behavior_specification_address=context.behavior_address,
        apparatus=context.apparatus,
    )
    participant_payload = turn.surface.participant_view.model_dump_json()
    rendered_payload = json.dumps(turn.rendered_context)
    withheld = (
        "content.study-hidden-truth" not in participant_payload
        and "BPA-HIDDEN-CANARY" not in participant_payload
        and "BPA-HIDDEN-CANARY" not in rendered_payload
    )
    evidence_count = action_evidence_count(context)
    return ParticipantQualificationCheck(
        check_id="BC-06",
        passed=withheld and evidence_count == 0,
        summary="withheld evaluator truth was absent from the delivered view",
        run_id=context.run_id,
        evidence_paths=(BOUNDARY_CHALLENGE_PATH,),
        details={
            "hidden_reference_absent": withheld,
            "action_evidence_count": evidence_count,
        },
    )


def _replay_challenge(
    context: ChallengeContext,
) -> ParticipantQualificationCheck:
    """Require identical and conflicting replay to produce no duplicate effect."""

    turn = project_participant_turn(
        runtime_model=context.plan.model,
        runtime_snapshot=context.control.snapshot,
        behavior_specification_address=context.behavior_address,
        apparatus=context.apparatus,
    )
    selection = turn.candidates[0]
    idempotency_key = f"participant-challenge-replay.{context.run_id}"
    first = admit_projected_participant_selection(
        context.control,
        turn=turn,
        selection=selection,
        idempotency_key=idempotency_key,
    )
    first_status = context.control.get_operation(first.receipt.operation_id)
    first_evidence_count = action_evidence_count(context)
    identical = admit_projected_participant_selection(
        context.control,
        turn=turn,
        selection=selection,
        action_instance_id=first.request.action_instance_id,
        idempotency_key=idempotency_key,
    )
    conflicting = admit_projected_participant_selection(
        context.control,
        turn=turn,
        selection=turn.candidates[1],
        action_instance_id=first.request.action_instance_id,
        idempotency_key=idempotency_key,
    )
    identical_status = context.control.get_operation(identical.receipt.operation_id)
    conflicting_status = context.control.get_operation(conflicting.receipt.operation_id)
    final_evidence_count = action_evidence_count(context)
    duplicate_prevented = _replay_was_bounded(
        first,
        first_status,
        first_evidence_count,
        identical,
        identical_status,
        conflicting_status,
        final_evidence_count,
    )
    return ParticipantQualificationCheck(
        check_id="BC-07",
        passed=duplicate_prevented,
        summary="identical and conflicting replay produced no duplicate effect",
        run_id=context.run_id,
        evidence_paths=(BOUNDARY_CHALLENGE_PATH, ACTION_EVIDENCE_PATH),
        details={
            "first_operation_state": _operation_state(first_status),
            "identical_operation_state": _operation_state(identical_status),
            "conflicting_operation_state": _operation_state(conflicting_status),
            "action_evidence_count": final_evidence_count,
        },
    )


def _replay_was_bounded(
    first: object,
    first_status: object,
    first_evidence_count: int,
    identical: object,
    identical_status: object,
    conflicting_status: object,
    final_evidence_count: int,
) -> bool:
    """Evaluate the idempotent and conflicting replay outcomes."""

    first_succeeded = getattr(first_status, "state", None) is OperationState.SUCCEEDED
    same_operation = (
        identical.receipt.operation_id == first.receipt.operation_id
        or getattr(identical_status, "state", None) is OperationState.FAILED
    )
    conflict_failed = (
        getattr(conflicting_status, "state", None) is OperationState.FAILED
    )
    return (
        first_succeeded
        and first_evidence_count == 1
        and final_evidence_count == 1
        and same_operation
        and conflict_failed
    )


def _operation_state(status: object) -> str | None:
    """Return an operation-state value when a status exists."""

    state = getattr(status, "state", None)
    return state.value if isinstance(state, OperationState) else None


def _provider_rejection_challenge(
    context: ChallengeContext,
    challenge_id: str,
    provider: ParticipantSelectionProvider,
    summary: str,
    *,
    extra_pass: Callable[[], bool] | None = None,
) -> ParticipantQualificationCheck:
    """Require provider failure before any participant realization effect."""

    try:
        run_participant_turn(
            context.control,
            behavior_specification_address=context.behavior_address,
            apparatus=context.apparatus,
            provider=provider,
        )
    except ValueError:
        rejected = True
    else:
        rejected = False
    additional = extra_pass() if extra_pass is not None else True
    no_history = not context.control.snapshot.participant_behavior_history.get(
        context.participant_address, []
    )
    evidence_count = action_evidence_count(context)
    no_effect = episode_state_is_absent(context)
    return ParticipantQualificationCheck(
        check_id=challenge_id,
        passed=rejected
        and bool(additional)
        and no_history
        and evidence_count == 0
        and no_effect,
        summary=summary,
        run_id=context.run_id,
        evidence_paths=(BOUNDARY_CHALLENGE_PATH, _CONTROL_EVIDENCE_PATH),
        details={
            "provider_operation_rejected": rejected,
            "additional_boundary_check": bool(additional),
            "behavior_history_unchanged": no_history,
            "action_evidence_count": evidence_count,
            "episode_state_absent": no_effect,
        },
    )
