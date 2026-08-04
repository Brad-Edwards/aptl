"""Compose APTL's full remote-control-plane RAES target and deployment handoff."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from raes_contracts.runtime_state import RuntimeSnapshot
from raes_runtime.manager import RuntimeManager
from raes_runtime.registry import RuntimeTarget
from raes import SDLError, SDLInstantiationError, parse_sdl_file

from aptl.backends._raes_apply_helpers import (
    _drive_orchestrator_workflows,
    _with_backend_failure_diagnostics,
)
from aptl.backends._raes_scenario_queries import (
    # Re-exported so the read-only scenario queries keep their historical
    # ``aptl.backends.raes`` names after the split.
    admitted_stateful_artifact_ownership as admitted_stateful_artifact_ownership,
    selected_profiles_for_scenario as selected_profiles_for_scenario,
)
from aptl.backends._raes_scenario_resolution import (
    # Re-exported so the scenario-selection seam keeps its historical
    # ``aptl.backends.raes`` names after the split.
    _PACK_STAGING_RELPATH as _PACK_STAGING_RELPATH,
    _resolve_scenario_path,
    resolve_scenario_bundle,
)
from aptl.backends.raes_diagnostics import (
    render_raes_diagnostics,
)
from aptl.backends.raes_execution_helpers import (
    evaluation_results as collect_evaluation_results,
    interpret_realization,
)
from aptl.backends.raes_artifact_availability import artifact_availability_for_scenario
from aptl.backends.raes_manifest import APTL_RAES_TARGET_NAME, create_aptl_manifest
from aptl.backends.raes_evaluator import AptlEvaluator
from aptl.backends.raes_orchestrator import AptlOrchestrator
from aptl.backends.raes_participant_actions import (
    DEFAULT_PARTICIPANT_ACTIONS,
    ParticipantActionSpec,
    participant_action_specs_from_runtime_model,
)
from aptl.backends.raes_participant_driver import ParticipantPlanAuthority
from aptl.backends.raes_participant_runtime import AptlParticipantRuntime
from aptl.backends.raes_provisioner import AptlProvisioner
from aptl.backends.raes_start_model import (
    # ``DEFAULT_RAES_SCENARIO`` is re-exported: callers read the default
    # scenario selection off this module.
    DEFAULT_RAES_SCENARIO as DEFAULT_RAES_SCENARIO,
    AcesRunTarget,
    AcesStartOutcome,
)
from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import (
    EnvPackError,
    ScenarioBundle,
)
from aptl.core.lab_types import LabResult
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from raes_contracts.contracts import ArtifactAvailabilityContext
    from raes_processor.models import ExecutionPlan

    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.runstore import RunStorageBackend

log = get_logger("raes-backend")

_INSTANTIATION_FAILURE_MESSAGE = (
    "RAES runtime variable binding failed before deployment. Provide every "
    "required variable using its declared type and allowed values."
)
_RETRYABLE_APPLY_DIAGNOSTIC_CODES = frozenset({"aptl.provisioner.backend-start-failed"})


def create_aptl_runtime_target(
    *,
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    participant_action_specs: Mapping[str, ParticipantActionSpec] | None = None,
    participant_plan_authority: ParticipantPlanAuthority | None = None,
    bundle: ScenarioBundle,
    artifact_availability: ArtifactAvailabilityContext | None = None,
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

    provisioner = AptlProvisioner(
        project_dir=project_dir,
        config=config,
        deployment_backend=backend,
        bundle=bundle,
        artifact_availability=artifact_availability,
    )
    orchestrator = AptlOrchestrator()
    action_specs = dict(DEFAULT_PARTICIPANT_ACTIONS)
    if participant_action_specs:
        action_specs.update(participant_action_specs)
    participant_runtime = AptlParticipantRuntime(
        deployment_backend=backend,
        action_specs=action_specs,
        plan_authority=participant_plan_authority,
    )
    return RuntimeTarget(
        name=APTL_RAES_TARGET_NAME,
        manifest=create_aptl_manifest(),
        provisioner=provisioner,  # type: ignore[arg-type]
        orchestrator=orchestrator,  # type: ignore[arg-type]
        evaluator=AptlEvaluator(),  # type: ignore[arg-type]
        participant_runtime=participant_runtime,  # type: ignore[arg-type]
    )


def start_raes_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
    *,
    run_target: AcesRunTarget | None = None,
    parameters: Mapping[str, object] | None = None,
    before_backend_retry: Callable[[], None] | None = None,
) -> AcesStartOutcome:
    """Start an APTL lab by compiling and applying a RAES SDL scenario.

    ``run_target`` (resolved once for the whole lab-start run, REP-001 / GAP 4)
    is threaded into orchestration so workflow result and history artifacts
    persist under the same run directory the reproducibility record is written
    to. ``parameters`` is the explicit per-run RAES binding mapping; only the
    planner sees it, and APTL neither logs nor persists it.
    """

    resolved_scenario = _resolve_scenario_path(project_dir, scenario_path, config)
    try:
        resolved_scenario = resolve_scenario_bundle(
            project_dir, scenario_path, config
        ).sdl_path
        target, execution_plan = _plan_scenario(
            project_dir,
            config,
            backend,
            scenario_path,
            parameters,
        )
        return _apply_with_backend_retry(
            target,
            execution_plan,
            resolved_scenario,
            run_target,
            before_backend_retry,
        )
    except (
        EnvPackError,
        SDLInstantiationError,
        FileNotFoundError,
        SDLError,
        TypeError,
        ValueError,
    ) as exc:
        return _start_failure_outcome(exc, resolved_scenario)


def _start_failure_outcome(
    exc: Exception, resolved_scenario: Path
) -> AcesStartOutcome:
    """Map a scenario-start failure onto its unretryable failure outcome.

    Each cause keeps the disclosure it always had: a pack acquisition failure and
    a runtime handoff failure report the redacted exception, while a variable
    binding failure reports the fixed instantiation message rather than the
    binding it rejected.
    """

    if isinstance(exc, EnvPackError):
        error = redact(f"RAES scenario pack acquisition failed: {exc}")
    elif isinstance(exc, SDLInstantiationError):
        error = _INSTANTIATION_FAILURE_MESSAGE
    else:
        error = redact(f"RAES runtime handoff failed: {exc}")
    return AcesStartOutcome(
        lab_result=LabResult(success=False, error=error),
        final_snapshot=RuntimeSnapshot(),
        realization_details={},
        selected_profiles=[],
        scenario_path=resolved_scenario,
        retryable=False,
    )


def _plan_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None,
    parameters: Mapping[str, object] | None,
) -> tuple[RuntimeTarget, "ExecutionPlan"]:
    """Build one RAES plan and the target that consumes its concrete model."""

    # Resolve the scenario bundle once, here, where the scenario is resolved: an
    # explicit path (or in-tree config) yields the project tree; the configured
    # env-pack yields a staged, validated pack. Everything downstream anchors to
    # this rather than the engine's checkout, so rehoming changes only the
    # resolver (issue #874 / #875).
    bundle = resolve_scenario_bundle(project_dir, scenario_path, config)
    scenario = parse_sdl_file(bundle.sdl_path)
    target = create_aptl_runtime_target(
        project_dir=project_dir,
        config=config,
        backend=backend,
        bundle=bundle,
    )
    manager = RuntimeManager(target)
    # Artifact availability is a trusted input to planning, gathered at the
    # backend trust boundary before the single admitted plan() call (ADR-051); a
    # no-op for a scenario that authors no artifact_requirement. The scenario's
    # own inputs (including a component build context) anchor to the bundle,
    # which is the project directory only while the scenario still lives in-tree.
    availability = artifact_availability_for_scenario(
        scenario, backend, scenario_root=bundle.root, component_root=project_dir
    )
    execution_plan = (
        manager.plan(
            scenario,
            parameters=dict(parameters),
            artifact_availability=availability,
        )
        if parameters is not None
        else manager.plan(scenario, artifact_availability=availability)
    )
    participant_action_specs = participant_action_specs_from_runtime_model(
        execution_plan.model,
        provisioning_plan=execution_plan.provisioning,
        bundle=bundle,
        config=config,
    )
    target = create_aptl_runtime_target(
        project_dir=project_dir,
        config=config,
        backend=backend,
        participant_action_specs=participant_action_specs,
        bundle=bundle,
        artifact_availability=availability,
    )
    participant_runtime = target.participant_runtime
    if isinstance(participant_runtime, AptlParticipantRuntime):
        participant_runtime.plan_authority = ParticipantPlanAuthority(
            execution_plan,
            bundle.sdl_path,
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
    realization_details, selected_profiles = interpret_realization(
        target, execution_plan
    )
    participant_runtime = target.participant_runtime
    if isinstance(participant_runtime, AptlParticipantRuntime):
        authority = participant_runtime.plan_authority
        if authority is not None:
            authority.bind_runtime_context(
                realization_details,
                run_store=run_store,
                run_id=run_id,
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
            message=f"Lab started through RAES runtime target '{APTL_RAES_TARGET_NAME}'",
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
    """Apply the plan through RAES's own runtime manager, then drive workflows.

    ``RuntimeManager.apply`` is the only path that threads the compiled
    ``realization_requirements`` and the provisioning plan into the backend call
    boundary, so it is the only path on which RAES runs the SEM-218
    non-approximation gate and attaches the realization-provenance ledger -- it
    replaces the parallel disclosure/write-back pass APTL once hand-rolled around
    ``RuntimeControlPlane`` (issue #578, ADR-046).

    Returns ``(failure | None, snapshot, retryable)``. Only the existing
    deployment-backend start diagnostic is retryable; deterministic admission,
    planning, provider-policy, and workflow failures are not.
    """

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
        )
    evaluation_results = collect_evaluation_results(target, execution_plan)
    failure = _drive_orchestrator_workflows(
        target.orchestrator,
        evaluation_results,
        run_store=run_store,
        run_id=run_id,
    )
    return failure, snapshot, False
