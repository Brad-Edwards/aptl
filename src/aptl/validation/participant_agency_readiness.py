"""Pre-capture readiness runner for the bounded participant demonstration."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from raes_contracts.participant_episode import ParticipantEpisodeTerminalReason
from raes_contracts.runtime_state import OperationState

from aptl.backends.raes import admit_raes_scenario
from aptl.backends.raes_participant_apparatus import build_participant_apparatus
from aptl.backends.raes_participant_driver import (
    AptlParticipantControlPlane,
    MAX_ADMITTED_PARTICIPANT_ACTIONS,
    run_participant_turn,
)
from aptl.backends.raes_participant_provider import (
    ParticipantSelectionProvider,
)
from aptl.backends.raes_realization import interpret_provisioning_plan
from aptl.core.scenario_bundle import project_tree_bundle
from aptl.backends.raes_realization_model import AptlRealization
from aptl.core.deployment import get_backend
from aptl.validation.participant_readiness_materialization import (
    verify_live_materialization,
)
from aptl.validation.participant_readiness_models import (
    ParticipantReadinessReport as ParticipantReadinessReport,
    ParticipantReadinessRequest as ParticipantReadinessRequest,
)
from aptl.validation.participant_readiness_outcomes import (
    record_positive_terminal_outcome,
)
from aptl.validation.participant_readiness_provider import (
    build_selection_provider,
    installed_version,
)
from aptl.validation.participant_readiness_reports import (
    configured_readiness_model,
    persist_failed_readiness_report,
)
from aptl.workbench.process import AgentExecutionError
from aptl.workbench.participant_source_binding import (
    CredentialBindingEvidence,
    evidence_from_error,
)

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig
    from aptl.core.deployment.backend import DeploymentBackend

SCENARIO_RELATIVE_PATH = Path("scenarios/bounded-participant-agency-techvault.sdl.yaml")
_PROVIDER_VERSION_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "NO_COLOR": "1",
}
BEHAVIOR_ADDRESSES = {
    "green-normal-session": (
        "participant.behavior-specification.complete-normal-session"
    ),
    "green-profile": ("participant.behavior-specification.update-customer-profile"),
    "green-support": ("participant.behavior-specification.complete-support-request"),
    "red-public-service": ("participant.behavior-specification.assess-public-service"),
    "red-authentication": (
        "participant.behavior-specification.assess-authentication-surface"
    ),
    "red-objective": ("participant.behavior-specification.reach-synthetic-objective"),
    "blue-triage": ("participant.behavior-specification.triage-authentication-event"),
    "blue-investigation": (
        "participant.behavior-specification.investigate-actor-activity"
    ),
    "blue-response": ("participant.behavior-specification.apply-bounded-response"),
}
_INSTALLED_VERSION_UNAVAILABLE = "installed participant provider version is unavailable"


@dataclass(frozen=True)
class _ReadinessContext:
    """Prepared RAES episode and its immutable readiness coordinates."""

    request: ParticipantReadinessRequest
    run_id: str
    authority: object
    behavior_address: str
    participant_address: str
    control: AptlParticipantControlPlane


@dataclass(frozen=True)
class _TrajectoryOutcome:
    """Observed positive-readiness results before episode termination."""

    selected_actions: tuple[str, ...]
    terminal_outcomes: tuple[Mapping[str, object], ...]
    diagnostics: tuple[str, ...]
    credential_binding: Mapping[str, object] | None = None


class _ReadinessFailure(ValueError):
    """Expected fail-closed readiness result before trajectory execution."""

    def __init__(self, message: str, participant_address: str = "") -> None:
        """Retain a stable public diagnostic and optional participant address."""

        super().__init__(message)
        self.participant_address = participant_address


def validate_participant_agency_readiness(
    request: ParticipantReadinessRequest,
) -> ParticipantReadinessReport:
    """Run one real trajectory without starting an official study capture."""

    _validate_readiness_request(request)
    selected_run_id = request.run_id or f"participant-readiness-{uuid4().hex}"
    request.run_store.create_run(selected_run_id)
    try:
        context = _prepare_readiness_context(request, selected_run_id)
    except _ReadinessFailure as exc:
        return persist_failed_readiness_report(
            request,
            selected_run_id,
            exc.participant_address,
            (str(exc),),
        )
    try:
        provider, cleanup, credential_evidence = _resolve_selection_provider(
            request, selected_run_id
        )
    except (OSError, RuntimeError, ValueError) as exc:
        binding_evidence = evidence_from_error(exc)
        diagnostic = type(exc).__name__
        if str(exc).startswith("installed participant model is not configured"):
            diagnostic = "installed participant model is not configured"
        elif binding_evidence is not None:
            diagnostic = str(exc)
        evidence = (
            binding_evidence.to_payload() if binding_evidence is not None else None
        )
        return persist_failed_readiness_report(
            request,
            selected_run_id,
            context.participant_address,
            (f"participant decision provider is unavailable: {diagnostic}",),
            credential_binding=evidence,
        )
    trajectory = _run_readiness_trajectory(
        context,
        provider,
        cleanup,
        credential_evidence,
    )
    return _terminate_and_persist(context, trajectory)


def _validate_readiness_request(request: ParticipantReadinessRequest) -> None:
    """Reject unknown behaviors, providers, and unbounded turn counts."""

    if request.behavior_name not in BEHAVIOR_ADDRESSES:
        raise ValueError(f"unknown participant behavior: {request.behavior_name}")
    if request.provider_override is None and request.provider_name not in {
        "claude",
        "codex",
        "deterministic",
    }:
        raise ValueError(f"unknown participant provider: {request.provider_name}")
    if request.turns < 1 or request.turns > MAX_ADMITTED_PARTICIPANT_ACTIONS:
        raise ValueError(
            "participant readiness turns must be between 1 and "
            f"{MAX_ADMITTED_PARTICIPANT_ACTIONS}"
        )


def _prepare_readiness_context(
    request: ParticipantReadinessRequest,
    selected_run_id: str,
) -> _ReadinessContext:
    """Plan, verify, bind, and initialize one exact participant episode."""

    deployment = request.backend or get_backend(request.config, request.project_dir)
    scenario_path = request.project_dir / SCENARIO_RELATIVE_PATH
    admitted = admit_raes_scenario(
        request.project_dir,
        request.config,
        deployment,
        scenario_path=scenario_path,
    )
    target, execution_plan = admitted.target, admitted.execution_plan
    if any(diagnostic.is_error for diagnostic in execution_plan.diagnostics):
        raise _ReadinessFailure("bounded participant scenario planning failed")
    bundle = project_tree_bundle(request.project_dir, scenario_path)
    realization = interpret_provisioning_plan(
        plan=execution_plan.provisioning,
        config=request.config,
        bundle=bundle,
    )
    if any(diagnostic.is_error for diagnostic in realization.diagnostics):
        raise _ReadinessFailure(
            "bounded participant scenario materialization is not realizable"
        )
    live_diagnostics = _verify_live_materialization(deployment, realization)
    if live_diagnostics:
        raise _ReadinessFailure("; ".join(live_diagnostics))
    authority = target.participant_runtime.plan_authority
    if authority is None:
        raise _ReadinessFailure("participant plan authority is unavailable")
    authority.bind_runtime_context(
        realization.details(),
        run_store=request.run_store,
        run_id=selected_run_id,
    )
    behavior_address = BEHAVIOR_ADDRESSES[request.behavior_name]
    participant_address = execution_plan.model.behavior_specifications[
        behavior_address
    ].participant_addresses[0]
    control = AptlParticipantControlPlane(
        target,
        behavior_specifications=execution_plan.model.behavior_specifications,
    )
    initialization = control.initialize_participant_episode(
        participant_address,
        episode_id=f"{selected_run_id}-{request.behavior_name}",
    )
    initialization_status = control.get_operation(initialization.operation_id)
    if (
        initialization_status is None
        or initialization_status.state is not OperationState.SUCCEEDED
    ):
        raise _ReadinessFailure(
            "participant episode initialization failed",
            participant_address,
        )
    return _ReadinessContext(
        request=request,
        run_id=selected_run_id,
        authority=authority,
        behavior_address=behavior_address,
        participant_address=participant_address,
        control=control,
    )


def _resolve_selection_provider(
    request: ParticipantReadinessRequest,
    run_id: str,
) -> tuple[
    ParticipantSelectionProvider,
    Callable[[], None],
    CredentialBindingEvidence | None,
]:
    """Resolve an override or launch one admitted decision-only provider."""

    if request.provider_override is not None:
        return request.provider_override, _noop, None
    return _selection_provider(
        request.provider_name,
        config=request.config,
        project_dir=request.project_dir,
        run_id=run_id,
    )


def _run_readiness_trajectory(
    context: _ReadinessContext,
    provider: ParticipantSelectionProvider,
    cleanup: Callable[[], None],
    credential_evidence: CredentialBindingEvidence | None,
) -> _TrajectoryOutcome:
    """Execute the bounded number of turns and retain terminal outcomes."""

    selected_actions: list[str] = []
    terminal_outcomes: list[Mapping[str, object]] = []
    diagnostics: list[str] = []
    try:
        apparatus = build_participant_apparatus(
            participant_address=context.participant_address,
            implementation_name=provider.implementation_name,
            implementation_version=provider.implementation_version,
            provider_name=provider.provider_name,
            model=provider.model,
            run_id=context.run_id,
        )
        for _ in range(context.request.turns):
            if not _run_readiness_turn(
                context,
                provider,
                apparatus,
                selected_actions,
                terminal_outcomes,
                diagnostics,
            ):
                break
    except AgentExecutionError as exc:
        diagnostics.append(f"participant provider request failed: {exc}")
    except (OSError, RuntimeError, ValueError) as exc:
        diagnostics.append(
            f"participant readiness trajectory failed: {type(exc).__name__}"
        )
    finally:
        try:
            cleanup()
        except (OSError, RuntimeError, ValueError):
            if credential_evidence is not None:
                credential_evidence.local_cleanup = "failed"
            diagnostics.append("participant provider cleanup failed")
        if (
            credential_evidence is not None
            and credential_evidence.isolation != "controls-enforced"
        ):
            diagnostics.append("participant credential isolation was not verified")
        if (
            credential_evidence is not None
            and credential_evidence.local_cleanup != "succeeded"
            and "participant provider cleanup failed" not in diagnostics
        ):
            diagnostics.append("participant credential cleanup was not verified")
    return _TrajectoryOutcome(
        selected_actions=tuple(selected_actions),
        terminal_outcomes=tuple(terminal_outcomes),
        diagnostics=tuple(diagnostics),
        credential_binding=(
            credential_evidence.to_payload()
            if credential_evidence is not None
            else None
        ),
    )


def _run_readiness_turn(
    context: _ReadinessContext,
    provider: ParticipantSelectionProvider,
    apparatus: object,
    selected_actions: list[str],
    terminal_outcomes: list[Mapping[str, object]],
    diagnostics: list[str],
) -> bool:
    """Execute and validate one admitted readiness turn."""

    outcome = run_participant_turn(
        context.control,
        behavior_specification_address=context.behavior_address,
        apparatus=apparatus,
        provider=provider,
    )
    admission_status = context.control.get_operation(
        outcome.admission_receipt.operation_id
    )
    if (
        admission_status is None
        or admission_status.state is not OperationState.SUCCEEDED
    ):
        admission_diagnostics = (
            tuple(diagnostic.message for diagnostic in admission_status.diagnostics)
            if admission_status is not None
            else ()
        )
        diagnostics.append(
            "RAES v2 action admission failed"
            + (": " + "; ".join(admission_diagnostics) if admission_diagnostics else "")
        )
        return False
    terminal = context.control.snapshot.participant_behavior_history[
        context.participant_address
    ][-1]
    action_result = terminal.get("action_result")
    return record_positive_terminal_outcome(
        selected_action=outcome.selected_action_contract_address,
        action_result=action_result if isinstance(action_result, Mapping) else None,
        terminal_status=(
            action_result.get("status") if isinstance(action_result, Mapping) else None
        ),
        admission_diagnostics=admission_status.diagnostics,
        selected_actions=selected_actions,
        terminal_outcomes=terminal_outcomes,
        diagnostics=diagnostics,
    )


def _terminate_and_persist(
    context: _ReadinessContext,
    trajectory: _TrajectoryOutcome,
) -> ParticipantReadinessReport:
    """Terminate the episode and persist its secret-free readiness report."""

    diagnostics = list(trajectory.diagnostics)
    terminal_reason = (
        ParticipantEpisodeTerminalReason.COMPLETED
        if len(trajectory.selected_actions) == context.request.turns and not diagnostics
        else ParticipantEpisodeTerminalReason.INTERRUPTED
    )
    termination = context.control.terminate_participant_episode(
        context.participant_address,
        terminal_reason=terminal_reason,
        detail="pre-capture participant readiness trajectory ended",
    )
    termination_status = context.control.get_operation(termination.operation_id)
    if (
        termination_status is None
        or termination_status.state is not OperationState.SUCCEEDED
    ):
        diagnostics.append("participant episode termination failed")
    report = ParticipantReadinessReport(
        passed=(
            len(trajectory.selected_actions) == context.request.turns
            and not diagnostics
        ),
        run_id=context.run_id,
        provider=context.request.provider_name,
        model=configured_readiness_model(context.request),
        behavior=context.request.behavior_name,
        participant_address=context.participant_address,
        selected_actions=trajectory.selected_actions,
        completed_turns=len(trajectory.selected_actions),
        diagnostics=tuple(diagnostics),
        terminal_outcomes=trajectory.terminal_outcomes,
        scenario_source_sha256=context.authority.scenario_source_sha256,
        compiled_model_sha256=context.authority.compiled_model_sha256,
        episode_terminal_reason=terminal_reason.value,
        credential_binding=trajectory.credential_binding,
    )
    context.request.run_store.write_json(
        context.run_id,
        "participant/readiness-report.json",
        report.to_payload(),
    )
    return report


def _verify_live_materialization(
    backend: DeploymentBackend,
    realization: AptlRealization,
) -> tuple[str, ...]:
    """Verify the already-running lab carries this exact scenario's inputs."""

    return verify_live_materialization(backend, realization)


def _selection_provider(
    provider_name: str,
    *,
    config: AptlConfig,
    project_dir: Path,
    run_id: str,
) -> tuple[
    ParticipantSelectionProvider,
    Callable[[], None],
    CredentialBindingEvidence | None,
]:
    """Build one deterministic or admitted installed selection provider."""

    return build_selection_provider(
        provider_name,
        config=config,
        project_dir=project_dir,
        run_id=run_id,
    )


def _installed_version(executable: Path) -> str:
    """Resolve a bounded semantic version from an admitted executable."""

    return installed_version(executable)


def _noop() -> None:
    """No-op cleanup for deterministic selection providers."""
