"""Compose APTL's full remote-control-plane RAES target and deployment handoff."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from raes_contracts.runtime_state import RuntimeSnapshot
from raes_runtime.registry import ReferenceTimeRuntime, RuntimeTarget
from raes import SDLError, SDLInstantiationError, parse_sdl_file
from aptl.backends.raes_operator_access import (
    OperatorAccessDecision,
    operator_access_decision,
)
from aptl.backends.raes_observability_scope import (
    ObservabilityScopeDecision,
    observability_scope_decision,
)
from aptl.core.experiment.errors import AdmissionRejection
from aptl.core.experiment.capture_plan import empty_capture_plan

from aptl.backends._raes_apply_helpers import (
    _drive_orchestrator_workflows,
    _with_backend_failure_diagnostics,
)
from aptl.backends._raes_scenario_resolution import (
    _resolve_scenario_path,
    resolve_scenario_bundle,
)
from aptl.backends._raes_runtime_materialization_admission import (
    qualify_admitted_runtime,
)
from aptl.backends._raes_admission_helpers import (
    prepare_admission_scenario,
    resolve_admission_adapters,
)
from aptl.backends._raes_runtime_target_options import RuntimeTargetOptions
from aptl.backends._raes_start_failure import (
    INSTANTIATION_FAILURE_MESSAGE as INSTANTIATION_FAILURE_MESSAGE,
    start_failure_outcome as _start_failure_outcome,
)
from aptl.backends.raes_diagnostics import render_raes_diagnostics
from aptl.backends.raes_execution_helpers import (
    evaluation_results as collect_evaluation_results,
    interpret_realization,
)
from aptl.backends.raes_artifact_availability import artifact_availability_for_scenario
from aptl.backends.raes_runtime_orchestration import (
    prepare_runtime_orchestration_for_scenario,
)
from aptl.backends.raes_manifest import APTL_RAES_TARGET_NAME, create_aptl_manifest
from aptl.backends.raes_planning_compat import (
    AptlPlanningOptions,
    AptlRuntimeManager,
    plan_aptl_scenario,
    resolve_target_planning_compatibility,
)
from aptl.backends.raes_evaluator import AptlEvaluator
from aptl.backends.raes_orchestrator import AptlOrchestrator
from aptl.backends.raes_participant_actions import (
    DEFAULT_PARTICIPANT_ACTIONS,
    participant_action_specs_from_runtime_model,
)
from aptl.backends.raes_participant_driver import ParticipantPlanAuthority
from aptl.backends import raes_participant_delivery as participant_delivery
from aptl.backends.raes_participant_runtime import AptlParticipantRuntime
from aptl.backends.raes_provisioner import AptlProvisioner
from aptl.backends.raes_start_model import (
    AcesRunTarget,
    AcesStartOutcome,
    AdmittedScenarioStart,
)
from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import (
    EnvPackError,
    ScenarioBundle,
)
from aptl.core.lab_types import LabResult
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from raes_processor.models import ExecutionPlan

    from aptl.backends.scenario_startup import ScenarioStartupSelection
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.runstore import RunStorageBackend

log = get_logger("raes-backend")

# Keep the long-standing module seam used by runtime handoff tests and callers,
# while routing real planning through the narrow compatibility subclass.
RuntimeManager = AptlRuntimeManager

_RETRYABLE_APPLY_DIAGNOSTIC_CODES = frozenset({"aptl.provisioner.backend-start-failed"})


def create_aptl_runtime_target(
    *,
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    bundle: ScenarioBundle,
    options: RuntimeTargetOptions | None = None,
) -> RuntimeTarget:
    """Build APTL's canonical ``full-remote-control-plane`` runtime target.

    ``bundle`` is required: the target realizes exactly one scenario, and every
    scenario-declared input resolves against ``bundle.root``. Callers resolve it
    once at ingress with ``project_tree_bundle`` (issue #874).

    ``artifact_availability`` carries the trusted availability facts to the
    provisioner so realization starts each dynamic-composition node from the
    substrate config id availability verified, never a second tag resolution
    (issue #876 cycle-6 review).
    """

    selected = options or RuntimeTargetOptions()
    provisioner = AptlProvisioner(
        project_dir=project_dir,
        config=config,
        deployment_backend=backend,
        bundle=bundle,
        artifact_availability=selected.artifact_availability,
        capture_plan=selected.capture_plan or empty_capture_plan(),
        observability_scope=selected.observability_scope
        or ObservabilityScopeDecision(),
        operator_access=selected.operator_access or OperatorAccessDecision(),
        startup_selection=selected.startup_selection,
        planning_compatibility=resolve_target_planning_compatibility(bundle, config),
    )
    orchestrator = AptlOrchestrator()
    action_specs = dict(DEFAULT_PARTICIPANT_ACTIONS)
    if selected.participant_action_specs:
        action_specs.update(selected.participant_action_specs)
    participant_runtime = AptlParticipantRuntime(
        deployment_backend=backend,
        action_specs=action_specs,
        plan_authority=selected.participant_plan_authority,
    )
    capture_registry = (
        selected.capture_selection.registry
        if selected.capture_selection is not None
        else None
    )
    return RuntimeTarget(
        name=APTL_RAES_TARGET_NAME,
        manifest=create_aptl_manifest(
            capture_registry,
            participant_inject_delivery=selected.participant_inject_delivery,
        ),
        provisioner=provisioner,  # type: ignore[arg-type]
        orchestrator=orchestrator,  # type: ignore[arg-type]
        evaluator=AptlEvaluator(
            proposition_interpreter=(
                selected.capture_selection.contribution.proposition_interpreter
                if selected.capture_selection is not None
                else None
            )
        ),  # type: ignore[arg-type]
        participant_runtime=participant_runtime,  # type: ignore[arg-type]
        time_runtime=(
            ReferenceTimeRuntime() if selected.participant_inject_delivery else None
        ),
    )


def start_raes_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
    *,
    run_target: AcesRunTarget | None = None,
    before_backend_retry: Callable[[], None] | None = None,
    admitted: AdmittedScenarioStart | None = None,
) -> AcesStartOutcome:
    """Start an APTL lab by compiling and applying a RAES SDL scenario.

    ``run_target`` (resolved once for the whole lab-start run, REP-001 / GAP 4)
    is threaded into orchestration so workflow result and history artifacts
    persist under the same run directory the reproducibility record is written
    to. Per-run RAES variable bindings are an *admission* input: supply them to
    :func:`admit_raes_scenario` and pass the resulting admission here.

    ``admitted`` is the scenario execution the caller already admitted through
    :func:`admit_raes_scenario`. Lab start admits once, before it mutates
    anything, and hands that same admission back here; re-planning would stage
    the env-pack a second time and let a pre-start decision diverge from the
    deployment it precedes (issue #951). ``None`` admits here, which keeps
    every other caller unchanged.
    """

    resolved_scenario = _resolve_scenario_path(project_dir, scenario_path, config)
    try:
        if admitted is None:
            admitted = admit_raes_scenario(
                project_dir,
                config,
                backend,
                scenario_path=scenario_path,
            )
        resolved_scenario = admitted.bundle.sdl_path
        return _apply_with_backend_retry(
            admitted.target,
            admitted.execution_plan,
            resolved_scenario,
            run_target,
            before_backend_retry,
        )
    except (
        AdmissionRejection,
        EnvPackError,
        SDLInstantiationError,
        FileNotFoundError,
        SDLError,
        TypeError,
        ValueError,
    ) as exc:
        return _start_failure_outcome(exc, resolved_scenario)


def admit_raes_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    *,
    scenario_path: Path | None = None,
    parameters: Mapping[str, object] | None = None,
    bundle: ScenarioBundle | None = None,
    startup_selection: ScenarioStartupSelection | None = None,
) -> AdmittedScenarioStart:
    """Admit one scenario execution: resolve, parse, plan, and interpret it once.

    This is the single admission every caller shares. Pre-mutation questions
    (which profiles the run selects, which generated artifacts own which mounts,
    which bundle root holds the Compose model) are answered from the returned
    admission rather than by planning again, and the same admission is applied
    by :func:`start_raes_scenario`. Nothing here mutates the deployment.
    """

    # Resolve the scenario bundle once, here, where the scenario is resolved: an
    # explicit path (or in-tree config) yields the project tree; the configured
    # env-pack yields a staged, validated pack. Everything downstream anchors to
    # this rather than the engine's checkout, so rehoming changes only the
    # resolver (issue #874 / #875).
    if bundle is None:
        bundle = resolve_scenario_bundle(project_dir, scenario_path, config)
    startup_selection, capture_selection = resolve_admission_adapters(
        bundle, config, startup_selection
    )
    scenario, parameters, capture_plan = prepare_admission_scenario(
        bundle, parameters, capture_selection, parser=parse_sdl_file
    )
    # A runtime authority is joined and bound before any artifact probe, so
    # every image fact and later mutation targets the same exact local daemon.
    prepare_runtime_orchestration_for_scenario(scenario, backend)
    # Artifact availability is a trusted input to planning, gathered at the
    # backend trust boundary before the single admitted plan() call (ADR-051); a
    # no-op for a scenario that authors no artifact_requirement. The scenario's
    # own inputs (including a component build context) anchor to the bundle,
    # which is the project directory only while the scenario still lives in-tree.
    availability = artifact_availability_for_scenario(
        scenario,
        backend,
        scenario_root=bundle.root,
        component_root=project_dir,
        materialize=False,
    )
    target = create_aptl_runtime_target(
        project_dir=project_dir,
        config=config,
        backend=backend,
        bundle=bundle,
        options=RuntimeTargetOptions(
            artifact_availability=availability,
            capture_plan=capture_plan,
            observability_scope=observability_scope_decision(scenario),
            operator_access=operator_access_decision(scenario),
            startup_selection=startup_selection,
            capture_selection=capture_selection,
            participant_inject_delivery=(
                participant_delivery.has_participant_inject_deliveries(scenario)
            ),
        ),
    )
    runtime_manager = RuntimeManager(target)
    execution_plan = plan_aptl_scenario(
        target=target,
        bundle=bundle,
        scenario=scenario,
        options=AptlPlanningOptions(
            parameters=dict(parameters) if parameters is not None else None,
            artifact_availability=availability,
            runtime_manager=runtime_manager,
        ),
    )
    provisioner = target.provisioner
    realization = (
        provisioner.realize_plan(execution_plan.provisioning)
        if isinstance(provisioner, AptlProvisioner)
        else None
    )
    execution_plan, availability, materialization_failure = qualify_admitted_runtime(
        scenario=scenario,
        bundle=bundle,
        project_dir=project_dir,
        provisioner=provisioner,
        realization=realization,
        execution_plan=execution_plan,
        availability=availability,
    )
    participant_action_specs = participant_action_specs_from_runtime_model(
        execution_plan.model,
        provisioning_plan=execution_plan.provisioning,
        bundle=bundle,
        config=config,
        realization=realization,
    )
    participant_runtime = target.participant_runtime
    if isinstance(participant_runtime, AptlParticipantRuntime):
        participant_runtime.action_specs.update(participant_action_specs)
        participant_runtime.plan_authority = ParticipantPlanAuthority(
            execution_plan,
            bundle.sdl_path,
        )
    participant_delivery_plan = participant_delivery.bind_participant_delivery_capture(
        participant_delivery.build_participant_delivery_plan(
            scenario,
            execution_plan.model,
        ),
        capture_plan,
    )
    return AdmittedScenarioStart(
        bundle=bundle,
        target=target,
        execution_plan=execution_plan,
        realization=realization,
        capture_plan=capture_plan,
        runtime_materialization_failure=materialization_failure,
        startup_selection=startup_selection,
        capture_selection=capture_selection,
        scenario=scenario,
        participant_delivery_plan=participant_delivery_plan,
    )


def _apply_with_backend_retry(
    target: RuntimeTarget,
    execution_plan: "ExecutionPlan",
    scenario_path: Path,
    run_target: AcesRunTarget | None,
    before_backend_retry: Callable[[], None] | None,
) -> AcesStartOutcome:
    """Apply one admitted plan and run one admitted preparation hook on retry."""

    run_store = run_target.run_store if run_target is not None else None
    run_id = run_target.run_id if run_target is not None else None
    outcome = _run_execution_plan(
        target,
        execution_plan,
        scenario_path,
        run_store=run_store,
        run_id=run_id,
    )
    if outcome.retryable and before_backend_retry is not None:
        before_backend_retry()
        return _run_execution_plan(
            target,
            execution_plan,
            scenario_path,
            run_store=run_store,
            run_id=run_id,
        )
    return outcome


def _run_execution_plan(
    target: RuntimeTarget,
    execution_plan: "ExecutionPlan",
    scenario_path: Path | None = None,
    *,
    run_store: RunStorageBackend | None = None,
    run_id: str | None = None,
) -> AcesStartOutcome:
    """Apply a planned RAES scenario through RAES's own runtime manager.

    Fail closed on every planner error. Scenario start routes provisioning,
    orchestration (when workflows are present), and evaluation (when observable
    evaluation resources are present) through the RAES runtime manager, so APTL's
    backend adapters record portable contract state and RAES runs its own SEM-218
    realization gate over the result.
    """
    blocking = [diag for diag in execution_plan.diagnostics if diag.is_error]
    if blocking:
        return AcesStartOutcome(
            lab_result=LabResult(
                success=False, error=render_raes_diagnostics(blocking)
            ),
            final_snapshot=RuntimeSnapshot(),
            realization_details={},
            selected_profiles=[],
            scenario_path=scenario_path,
        )
    (
        realization_details,
        selected_profiles,
        pack_interaction_evidence,
    ) = interpret_realization(target, execution_plan)
    participant_runtime = target.participant_runtime
    if isinstance(participant_runtime, AptlParticipantRuntime):
        authority = participant_runtime.plan_authority
        if authority is not None:
            authority.bind_runtime_context(
                realization_details,
                run_store=run_store,
                run_id=run_id,
            )
    failure, snapshot, retryable, runtime_manager = _apply_execution_plan(
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
            pack_interaction_evidence=pack_interaction_evidence,
            retryable=retryable,
            runtime_manager=runtime_manager,
        )
    return AcesStartOutcome(
        lab_result=LabResult(
            success=True,
            message=f"Lab started through RAES runtime target '{APTL_RAES_TARGET_NAME}'",
        ),
        final_snapshot=snapshot,
        realization_details=realization_details,
        selected_profiles=selected_profiles,
        scenario_path=scenario_path,
        pack_interaction_evidence=pack_interaction_evidence,
        runtime_manager=runtime_manager,
    )


def _apply_execution_plan(
    target: RuntimeTarget,
    execution_plan: "ExecutionPlan",
    *,
    run_store: RunStorageBackend | None = None,
    run_id: str | None = None,
) -> tuple[LabResult | None, RuntimeSnapshot, bool, RuntimeManager]:
    """Apply the plan through RAES's own runtime manager, then drive workflows.

    ``RuntimeManager.apply`` is the only path that threads the compiled
    ``realization_requirements`` and the provisioning plan into the backend call
    boundary, so it is the only path on which RAES runs the SEM-218
    non-approximation gate and attaches the realization-provenance ledger -- it
    replaces the parallel disclosure/write-back pass APTL once hand-rolled around
    ``RuntimeControlPlane`` (issue #578, ADR-046).

    Returns ``(failure | None, snapshot, retryable, manager)``. Only the existing
    deployment-backend start diagnostic is retryable; deterministic admission,
    planning, provider-policy, and workflow failures are not.
    """

    if isinstance(target.provisioner, AptlProvisioner):
        target.provisioner.bind_attempt_id(run_id)
    manager = RuntimeManager(target, initial_snapshot=execution_plan.base_snapshot)
    apply_result = manager.apply(execution_plan)
    snapshot = apply_result.snapshot
    if not apply_result.success:
        diagnostics = _with_backend_failure_diagnostics(
            target, list(apply_result.diagnostics)
        )
        return (
            LabResult(
                success=False,
                error=render_raes_diagnostics(diagnostics),
            ),
            snapshot,
            any(
                diagnostic.code in _RETRYABLE_APPLY_DIAGNOSTIC_CODES
                for diagnostic in diagnostics
            ),
            manager,
        )
    evaluation_results = collect_evaluation_results(target, execution_plan)
    failure = _drive_orchestrator_workflows(
        target.orchestrator,
        evaluation_results,
        run_store=run_store,
        run_id=run_id,
    )
    return failure, snapshot, False, manager
