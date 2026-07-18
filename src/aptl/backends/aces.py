"""Compose APTL's full remote-control-plane ACES target and deployment handoff."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aces_contracts.runtime_state import RuntimeSnapshot
from aces_runtime.manager import RuntimeManager
from aces_runtime.registry import RuntimeTarget
from aces_sdl import SDLError, SDLInstantiationError, parse_sdl_file

from aptl.backends.aces_diagnostics import (
    render_aces_diagnostics,
)
from aptl.backends.aces_manifest import APTL_ACES_TARGET_NAME, create_aptl_manifest
from aptl.backends.aces_evaluator import AptlEvaluator
from aptl.backends.aces_orchestrator import AptlOrchestrator
from aptl.backends.aces_participant_actions import (
    DEFAULT_PARTICIPANT_ACTIONS,
    ParticipantActionSpec,
    participant_action_specs_from_runtime_model,
)
from aptl.backends.aces_participant_runtime import AptlParticipantRuntime
from aptl.backends.aces_provisioner import AptlProvisioner
from aptl.backends.aces_realization import (
    interpret_provisioning_plan,
)
from aptl.backends.aces_profiles import (
    select_backend_profiles,
)
from aptl.backends.aces_start_model import (
    DEFAULT_ACES_SCENARIO,
    AcesRunTarget,
    AcesStartOutcome,
)
from aptl.core.config import AptlConfig
from aptl.core.lab_types import LabResult
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from aces_processor.models import ExecutionPlan

    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.runstore import RunStorageBackend

log = get_logger("aces-backend")

_INSTANTIATION_FAILURE_MESSAGE = (
    "ACES runtime variable binding failed before deployment. Provide every "
    "required variable using its declared type and allowed values."
)
_RETRYABLE_APPLY_DIAGNOSTIC_CODES = frozenset(
    {"aptl.provisioner.backend-start-failed"}
)


def create_aptl_runtime_target(
    *,
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    participant_action_specs: Mapping[str, ParticipantActionSpec] | None = None,
) -> RuntimeTarget:
    """Build APTL's canonical ``full-remote-control-plane`` runtime target."""

    provisioner = AptlProvisioner(
        project_dir=project_dir,
        config=config,
        deployment_backend=backend,
    )
    orchestrator = AptlOrchestrator()
    action_specs = dict(DEFAULT_PARTICIPANT_ACTIONS)
    if participant_action_specs:
        action_specs.update(participant_action_specs)
    participant_runtime = AptlParticipantRuntime(
        deployment_backend=backend,
        action_specs=action_specs,
    )
    return RuntimeTarget(
        name=APTL_ACES_TARGET_NAME,
        manifest=create_aptl_manifest(),
        provisioner=provisioner,  # type: ignore[arg-type]
        orchestrator=orchestrator,  # type: ignore[arg-type]
        evaluator=AptlEvaluator(),  # type: ignore[arg-type]
        participant_runtime=participant_runtime,  # type: ignore[arg-type]
    )


def start_aces_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
    *,
    run_target: AcesRunTarget | None = None,
    parameters: Mapping[str, object] | None = None,
    before_backend_retry: Callable[[], None] | None = None,
) -> AcesStartOutcome:
    """Start an APTL lab by compiling and applying an ACES SDL scenario.

    ``run_target`` (resolved once for the whole lab-start run, REP-001 / GAP 4)
    is threaded into orchestration so workflow result and history artifacts
    persist under the same run directory the reproducibility record is written
    to. ``parameters`` is the explicit per-run ACES binding mapping; only the
    planner sees it, and APTL neither logs nor persists it.
    """

    resolved_scenario = _resolve_scenario_path(project_dir, scenario_path)
    try:
        target, execution_plan = _plan_scenario(
            project_dir,
            config,
            backend,
            resolved_scenario,
            parameters,
        )
        return _apply_with_backend_retry(
            target,
            execution_plan,
            resolved_scenario,
            run_target,
            before_backend_retry,
        )
    except SDLInstantiationError:
        return AcesStartOutcome(
            lab_result=LabResult(
                success=False,
                error=_INSTANTIATION_FAILURE_MESSAGE,
            ),
            final_snapshot=RuntimeSnapshot(),
            realization_details={},
            selected_profiles=[],
            scenario_path=resolved_scenario,
            retryable=False,
        )
    except (FileNotFoundError, SDLError, TypeError, ValueError) as exc:
        return AcesStartOutcome(
            lab_result=LabResult(
                success=False,
                error=redact(f"ACES runtime handoff failed: {exc}"),
            ),
            final_snapshot=RuntimeSnapshot(),
            realization_details={},
            selected_profiles=[],
            scenario_path=resolved_scenario,
        )


def _resolve_scenario_path(project_dir: Path, scenario_path: Path | None) -> Path:
    """Resolve the authored scenario beneath the project when it is relative."""

    resolved = scenario_path or DEFAULT_ACES_SCENARIO
    return resolved if resolved.is_absolute() else project_dir / resolved


def _plan_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path,
    parameters: Mapping[str, object] | None,
) -> tuple[RuntimeTarget, "ExecutionPlan"]:
    """Build one ACES plan and the target that consumes its concrete model."""

    scenario = parse_sdl_file(scenario_path)
    target = create_aptl_runtime_target(
        project_dir=project_dir,
        config=config,
        backend=backend,
    )
    manager = RuntimeManager(target)
    execution_plan = (
        manager.plan(scenario, parameters=dict(parameters))
        if parameters is not None
        else manager.plan(scenario)
    )
    participant_action_specs = participant_action_specs_from_runtime_model(
        execution_plan.model,
        provisioning_plan=execution_plan.provisioning,
        project_dir=project_dir,
        config=config,
    )
    if participant_action_specs:
        target = create_aptl_runtime_target(
            project_dir=project_dir,
            config=config,
            backend=backend,
            participant_action_specs=participant_action_specs,
        )
    return target, execution_plan


def _apply_with_backend_retry(
    target: RuntimeTarget,
    execution_plan: "ExecutionPlan",
    scenario_path: Path,
    run_target: AcesRunTarget | None,
    before_backend_retry: Callable[[], None] | None,
) -> AcesStartOutcome:
    """Apply one admitted plan, retrying only its SOC backend-start failure."""

    run_store = run_target.run_store if run_target is not None else None
    run_id = run_target.run_id if run_target is not None else None
    outcome = _run_execution_plan(
        target,
        execution_plan,
        scenario_path,
        run_store=run_store,
        run_id=run_id,
    )
    if (
        outcome.retryable
        and "soc" in outcome.selected_profiles
        and before_backend_retry is not None
    ):
        before_backend_retry()
        return _run_execution_plan(
            target,
            execution_plan,
            scenario_path,
            run_store=run_store,
            run_id=run_id,
        )
    return outcome


def selected_profiles_for_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
) -> list[str]:
    """Return the Compose profiles selected by a scenario without side effects."""
    resolved_scenario = scenario_path or DEFAULT_ACES_SCENARIO
    if not resolved_scenario.is_absolute():
        resolved_scenario = project_dir / resolved_scenario
    scenario = parse_sdl_file(resolved_scenario)
    target = create_aptl_runtime_target(
        project_dir=project_dir, config=config, backend=backend
    )
    execution_plan = RuntimeManager(target).plan(scenario)
    realization = interpret_provisioning_plan(
        plan=execution_plan.provisioning, project_dir=project_dir, config=config
    )
    return select_backend_profiles(config, realization.profiles)


def admitted_stateful_artifact_ownership(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
) -> frozenset[tuple[str, str, str, str]]:
    """Return exact addressed artifact consumers from the admitted graph."""

    resolved_scenario = scenario_path or DEFAULT_ACES_SCENARIO
    if not resolved_scenario.is_absolute():
        resolved_scenario = project_dir / resolved_scenario
    scenario = parse_sdl_file(resolved_scenario)
    target = create_aptl_runtime_target(
        project_dir=project_dir, config=config, backend=backend
    )
    execution_plan = RuntimeManager(target).plan(scenario)
    blocking = [diagnostic for diagnostic in execution_plan.diagnostics if diagnostic.is_error]
    if blocking:
        raise ValueError(render_aces_diagnostics(blocking))
    realization = interpret_provisioning_plan(
        plan=execution_plan.provisioning,
        project_dir=project_dir,
        config=config,
    )
    blocking = [diagnostic for diagnostic in realization.diagnostics if diagnostic.is_error]
    if blocking:
        raise ValueError(render_aces_diagnostics(blocking))
    return frozenset(
        (
            artifact.address,
            artifact.generator,
            consumer.service_name,
            consumer.mount_destination,
        )
        for artifact in realization.generated_artifacts
        for consumer in artifact.consumers
    )


def _run_execution_plan(
    target: RuntimeTarget,
    execution_plan: "ExecutionPlan",
    scenario_path: Path | None = None,
    *,
    run_store: RunStorageBackend | None = None,
    run_id: str | None = None,
) -> AcesStartOutcome:
    """Apply a planned ACES scenario through ACES's own runtime manager.

    Fail closed on every planner error. Scenario start routes provisioning,
    orchestration (when the scenario carries workflows), and evaluation (when
    the scenario carries observable evaluation resources) through the ACES
    runtime manager, so APTL's published backend adapters record portable
    contract state and ACES runs its own SEM-218 realization gate over the
    result.
    """
    blocking = [diag for diag in execution_plan.diagnostics if diag.is_error]
    if blocking:
        return AcesStartOutcome(
            lab_result=LabResult(
                success=False, error=render_aces_diagnostics(blocking)
            ),
            final_snapshot=RuntimeSnapshot(),
            realization_details={},
            selected_profiles=[],
            scenario_path=scenario_path,
        )
    realization_details, selected_profiles = _interpret_realization(
        target, execution_plan
    )
    failure, snapshot, retryable = _apply_execution_plan(
        target,
        execution_plan,
        run_store=run_store,
        run_id=run_id,
    )
    if failure is not None:
        return AcesStartOutcome(
            lab_result=failure,
            final_snapshot=snapshot,
            realization_details=realization_details,
            selected_profiles=selected_profiles,
            scenario_path=scenario_path,
            retryable=retryable,
        )
    return AcesStartOutcome(
        lab_result=LabResult(
            success=True,
            message=f"Lab started through ACES runtime target '{APTL_ACES_TARGET_NAME}'",
        ),
        final_snapshot=snapshot,
        realization_details=realization_details,
        selected_profiles=selected_profiles,
        scenario_path=scenario_path,
    )


def _apply_execution_plan(
    target: RuntimeTarget,
    execution_plan: "ExecutionPlan",
    *,
    run_store: RunStorageBackend | None = None,
    run_id: str | None = None,
) -> tuple[LabResult | None, RuntimeSnapshot, bool]:
    """Apply the plan through ACES's own runtime manager, then drive workflows.

    ``RuntimeManager.apply`` is the only path that threads the compiled
    ``realization_requirements`` and the provisioning plan into the backend call
    boundary, so it is the only path on which ACES runs the SEM-218
    non-approximation gate and attaches the realization-provenance ledger to the
    returned snapshot. APTL used to submit each phase through
    ``RuntimeControlPlane`` — which never passes those — and then hand-rolled a
    second, parallel disclosure pass plus a snapshot write-back to compensate.
    Going through the manager deletes that parallel path outright: the gate and
    the provenance ledger are ACES's, not APTL's (issue #578, ADR-046).

    Returns ``(failure | None, snapshot, retryable)``. Only the existing
    deployment-backend start diagnostic is retryable; deterministic admission,
    planning, provider-policy, and workflow failures are not.
    """

    manager = RuntimeManager(target, initial_snapshot=execution_plan.base_snapshot)
    apply_result = manager.apply(execution_plan)
    snapshot = apply_result.snapshot
    if not apply_result.success:
        return (
            LabResult(
                success=False,
                error=render_aces_diagnostics(list(apply_result.diagnostics)),
            ),
            snapshot,
            any(
                diagnostic.code in _RETRYABLE_APPLY_DIAGNOSTIC_CODES
                for diagnostic in apply_result.diagnostics
            ),
        )
    evaluation_results = _evaluation_results(target, execution_plan)
    failure = _drive_orchestrator_workflows(
        target.orchestrator,
        evaluation_results,
        run_store=run_store,
        run_id=run_id,
    )
    return failure, snapshot, False


def _evaluation_results(
    target: RuntimeTarget,
    execution_plan: "ExecutionPlan",
) -> dict[str, dict[str, object]]:
    """Return evaluator results only when evaluation actions ran."""

    results: dict[str, dict[str, object]] = {}
    if execution_plan.evaluation.actionable_operations and target.evaluator is not None:
        results = target.evaluator.results()
    return results


def _drive_orchestrator_workflows(
    orchestrator: object,
    evaluation_results: dict[str, dict[str, object]],
    *,
    run_store: RunStorageBackend | None = None,
    run_id: str | None = None,
) -> LabResult | None:
    """Drive registered workflows and convert diagnostics to a lab failure."""

    drive_diagnostics = []
    if isinstance(orchestrator, AptlOrchestrator) and orchestrator.results():
        drive_diagnostics = orchestrator.drive_workflows(
            evaluation_results=evaluation_results,
            run_store=run_store,
            run_id=run_id,
        )
    failure = None
    if drive_diagnostics:
        failure = LabResult(
            success=False,
            error=render_aces_diagnostics(drive_diagnostics),
        )
    return failure


def _interpret_realization(
    target: RuntimeTarget,
    execution_plan: "ExecutionPlan",
) -> tuple[dict[str, Any], list[str]]:
    """Interpret the provisioning plan into realization details + profiles.

    Reuses the ``AptlProvisioner``'s ``project_dir``/``config`` (REP-001 /
    GAP 1) so the realization is computed exactly once with the real backend
    context. Returns empty placeholders when the provisioner is unavailable.
    """
    provisioner = target.provisioner
    if not isinstance(provisioner, AptlProvisioner):
        return {}, []
    realization = interpret_provisioning_plan(
        plan=execution_plan.provisioning,
        project_dir=provisioner.project_dir,
        config=provisioner.config,
    )
    return realization.details(), select_backend_profiles(
        provisioner.config, realization.profiles
    )
