"""APTL ACES runtime target and deployment handoff."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aces_contracts.runtime_state import OperationState, RuntimeSnapshot
from aces_processor.semantics.realization import realization_disclosure
from aces_runtime.control_plane import RuntimeControlPlane
from aces_runtime.manager import RuntimeManager
from aces_runtime.registry import RuntimeTarget
from aces_sdl import SDLError, parse_sdl_file

from aptl.backends.aces_diagnostics import (
    render_aces_diagnostics,
)
from aptl.backends.aces_manifest import APTL_ACES_TARGET_NAME, create_aptl_manifest
from aptl.backends.aces_evaluator import AptlEvaluator
from aptl.backends.aces_orchestrator import AptlOrchestrator
from aptl.backends.aces_participant_actions import (
    DEFAULT_PARTICIPANT_ACTIONS,
    ParticipantActionSpec,
    participant_action_specs_for_scenario,
)
from aptl.backends.aces_participant_runtime import AptlParticipantRuntime
from aptl.backends.aces_provisioner import AptlProvisioner
from aptl.backends.aces_realization import (
    interpret_provisioning_plan,
)
from aptl.backends.aces_profiles import (
    select_backend_profiles,
)
from aptl.backends.aces_start_model import DEFAULT_ACES_SCENARIO, AcesStartOutcome
from aptl.core.config import AptlConfig
from aptl.core.lab_types import LabResult
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from aces_processor.models import ExecutionPlan

    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.runstore import RunStorageBackend

log = get_logger("aces-backend")


def create_aptl_runtime_target(
    *,
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    participant_action_specs: Mapping[str, ParticipantActionSpec] | None = None,
) -> RuntimeTarget:
    """Build the ACES runtime target for APTL."""

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
    run_store: RunStorageBackend | None = None,
    run_id: str | None = None,
) -> AcesStartOutcome:
    """Start an APTL lab by compiling and applying an ACES SDL scenario.

    ``run_store`` and ``run_id`` (resolved once for the whole lab-start run,
    REP-001 / GAP 4) are threaded into orchestration so workflow result and
    history artifacts persist under the same run directory the reproducibility
    record is written to.
    """

    resolved_scenario = scenario_path or DEFAULT_ACES_SCENARIO
    if not resolved_scenario.is_absolute():
        resolved_scenario = project_dir / resolved_scenario
    try:
        scenario = parse_sdl_file(resolved_scenario)
        target = create_aptl_runtime_target(
            project_dir=project_dir,
            config=config,
            backend=backend,
        )
        execution_plan = RuntimeManager(target).plan(scenario)
        participant_action_specs = participant_action_specs_for_scenario(
            scenario,
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
        return _run_execution_plan(
            target,
            execution_plan,
            resolved_scenario,
            run_store=run_store,
            run_id=run_id,
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


def _run_execution_plan(
    target: RuntimeTarget,
    execution_plan: "ExecutionPlan",
    scenario_path: Path | None = None,
    *,
    run_store: RunStorageBackend | None = None,
    run_id: str | None = None,
) -> AcesStartOutcome:
    """Apply a planned ACES scenario through the runtime control plane.

    Fail closed on every planner error. Scenario start routes provisioning,
    orchestration (when the scenario carries workflows), and evaluation (when
    the scenario carries observable evaluation resources) through the ACES
    runtime control plane so APTL's published backend adapters record portable
    contract state.
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
    control_plane = RuntimeControlPlane(
        target, initial_snapshot=execution_plan.base_snapshot
    )
    failure, realization_details, selected_profiles = _apply_provisioning_and_orchestration(
        control_plane,
        execution_plan,
        target,
        run_store=run_store,
        run_id=run_id,
    )
    if failure is not None:
        return AcesStartOutcome(
            lab_result=failure,
            final_snapshot=_current_runtime_snapshot(control_plane),
            realization_details=realization_details,
            selected_profiles=selected_profiles,
            scenario_path=scenario_path,
        )
    return AcesStartOutcome(
        lab_result=LabResult(
            success=True,
            message=f"Lab started through ACES runtime target '{APTL_ACES_TARGET_NAME}'",
        ),
        final_snapshot=_current_runtime_snapshot(control_plane),
        realization_details=realization_details,
        selected_profiles=selected_profiles,
        scenario_path=scenario_path,
    )


def _apply_provisioning_and_orchestration(
    control_plane: RuntimeControlPlane,
    execution_plan: "ExecutionPlan",
    target: RuntimeTarget,
    *,
    run_store: RunStorageBackend | None = None,
    run_id: str | None = None,
) -> tuple[LabResult | None, dict[str, Any], list[str]]:
    """Submit provisioning, orchestration, and evaluation control-plane phases.

    Returns a triple of (failure | None, realization_details, selected_profiles).
    Failure is a failed LabResult for the first phase that fails, else None.

    ``realization_details`` and ``selected_profiles`` are populated (REP-001 /
    GAP 1) by interpreting the provisioning plan through the same public path
    the provisioner uses, so the reproducibility record carries real
    realization evidence rather than empty placeholders.
    """
    realization_details, selected_profiles = _interpret_realization(
        target, execution_plan
    )
    failure = _run_control_plane_phases(control_plane, execution_plan)
    if failure is None:
        evaluation_results = _evaluation_results(target, execution_plan)
        failure = _drive_orchestrator_workflows(
            target.orchestrator,
            evaluation_results,
            run_store=run_store,
            run_id=run_id,
        )
    return failure, realization_details, selected_profiles


def _run_control_plane_phases(
    control_plane: RuntimeControlPlane,
    execution_plan: "ExecutionPlan",
) -> LabResult | None:
    """Apply provisioning, disclosure, orchestration, and evaluation phases."""

    failure = _apply_phase(
        control_plane,
        lambda: control_plane.submit_provisioning(execution_plan.provisioning),
    )
    if failure is None:
        failure = _apply_realization_disclosure(control_plane, execution_plan)
    if failure is None:
        failure = _apply_optional_control_plane_phases(control_plane, execution_plan)
    return failure


def _apply_optional_control_plane_phases(
    control_plane: RuntimeControlPlane,
    execution_plan: "ExecutionPlan",
) -> LabResult | None:
    """Submit orchestration/evaluation phases only when the plan has work."""

    failure = None
    for submit in _optional_phase_submissions(control_plane, execution_plan):
        failure = _apply_phase(control_plane, submit)
        if failure is not None:
            break
    return failure


def _optional_phase_submissions(
    control_plane: RuntimeControlPlane,
    execution_plan: "ExecutionPlan",
) -> list[Callable[[], object]]:
    """Build deferred submissions for optional ACES phases."""

    phases: list[Callable[[], object]] = []
    if execution_plan.orchestration.actionable_operations:
        phases.append(
            lambda: control_plane.submit_orchestration(execution_plan.orchestration),
        )
    if execution_plan.evaluation.actionable_operations:
        phases.append(
            lambda: control_plane.submit_evaluation(execution_plan.evaluation),
        )
    return phases


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


def _current_runtime_snapshot(control_plane: object) -> RuntimeSnapshot:
    """Return the current control-plane snapshot across ACES API shapes."""

    snapshot = getattr(control_plane, "snapshot", None)
    if not isinstance(snapshot, RuntimeSnapshot):
        snapshot = _snapshot_from_getter(control_plane)
    if not isinstance(snapshot, RuntimeSnapshot):
        snapshot = RuntimeSnapshot()
    return snapshot


def _snapshot_from_getter(control_plane: object) -> RuntimeSnapshot | None:
    """Read a runtime snapshot from legacy/getter ACES control-plane APIs."""

    snapshot = None
    get_snapshot = getattr(control_plane, "get_snapshot", None)
    if callable(get_snapshot):
        returned = get_snapshot()
        if isinstance(returned, RuntimeSnapshot):
            snapshot = returned
        else:
            snapshot = getattr(returned, "snapshot", None)
    if not isinstance(snapshot, RuntimeSnapshot):
        snapshot = None
    return snapshot


def _store_runtime_snapshot(control_plane: object, snapshot: RuntimeSnapshot) -> None:
    """Persist a replacement snapshot when the control-plane object supports it."""

    public_snapshot = getattr(control_plane, "snapshot", None)
    if isinstance(public_snapshot, RuntimeSnapshot):
        try:
            setattr(control_plane, "snapshot", snapshot)
        except AttributeError:
            pass
    if hasattr(control_plane, "_snapshot"):
        setattr(control_plane, "_snapshot", snapshot)
    store = getattr(control_plane, "_store", None)
    save_snapshot = getattr(store, "save_snapshot", None)
    if callable(save_snapshot):
        save_snapshot(snapshot)


def _realization_requirements(execution_plan: object) -> tuple[object, ...]:
    """Return compiled SEM-218 realization requirements when present."""

    model = getattr(execution_plan, "model", None)
    requirements = getattr(model, "realization_requirements", ())
    try:
        return tuple(requirements or ())
    except TypeError:
        return ()


def _apply_realization_disclosure(
    control_plane: object,
    execution_plan: object,
) -> LabResult | None:
    """Run ACES non-approximation disclosure after provisioning applies."""

    requirements = _realization_requirements(execution_plan)
    if not requirements:
        return None
    snapshot = _current_runtime_snapshot(control_plane)
    diagnostics, provenance = realization_disclosure(
        requirements,
        execution_plan.provisioning,
        snapshot,
    )
    if diagnostics:
        return LabResult(
            success=False,
            error=render_aces_diagnostics(list(diagnostics)),
        )
    if provenance:
        next_snapshot = snapshot.with_entries(
            dict(snapshot.entries),
            realization_provenance=(
                *snapshot.realization_provenance,
                *provenance,
            ),
        )
        _store_runtime_snapshot(control_plane, next_snapshot)
    return None


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


def _apply_phase(
    control_plane: RuntimeControlPlane,
    submit: Callable[[], object],
) -> LabResult | None:
    """Submit one control-plane phase; return a failed ``LabResult`` or ``None``.

    Returns ``None`` when the submitted operation succeeded, otherwise a redacted
    failure ``LabResult`` built from the operation's (or receipt's) diagnostics.
    """
    receipt = submit()
    status = control_plane.get_operation(receipt.operation_id)
    if status is not None and status.state == OperationState.SUCCEEDED:
        return None
    diagnostics = (
        list(status.diagnostics) if status is not None else list(receipt.diagnostics)
    )
    return LabResult(success=False, error=render_aces_diagnostics(diagnostics))
