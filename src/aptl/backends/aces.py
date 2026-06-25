"""APTL ACES runtime target.

This module is the handoff layer between the external ACES SDL/runtime
packages and APTL's existing deployment primitives.  It intentionally keeps
Docker/SSH details behind ``DeploymentBackend``; the ACES provisioner only
translates a provisioning plan into the compose profiles APTL can already
start.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import ChangeAction, ProvisioningPlan
from aces_contracts.runtime_state import ApplyResult, OperationState, RuntimeSnapshot
from aces_runtime.control_plane import RuntimeControlPlane
from aces_runtime.manager import RuntimeManager
from aces_runtime.registry import RuntimeTarget
from aces_sdl import SDLError, parse_sdl_file

from aptl.backends.aces_diagnostics import (
    PROVISIONING_ADDRESS,
    diagnostic,
    has_error,
    render_aces_diagnostics,
    snapshot_after_apply,
)
from aptl.backends.aces_manifest import APTL_ACES_TARGET_NAME, create_aptl_manifest
from aptl.backends.aces_evaluator import AptlEvaluator
from aptl.backends.aces_orchestrator import AptlOrchestrator
from aptl.backends.aces_realization import (
    AptlRealization,
    interpret_provisioning_plan,
)
from aptl.backends.aces_profiles import (
    load_compose_profile_index,
    select_backend_profiles,
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

DEFAULT_ACES_SCENARIO = Path("scenarios") / "techvault-operational.sdl.yaml"


@dataclass
class AcesStartOutcome:
    """Reference-holder for start_aces_scenario outputs (REP-001 / ADR-044).

    Carries the lab result alongside ACES runtime facts captured during
    _run_execution_plan so downstream steps can build a reproducibility
    record without re-running ACES planning or calling Docker.
    """

    lab_result: LabResult
    final_snapshot: RuntimeSnapshot
    realization_details: dict[str, Any]
    selected_profiles: list[str]
    scenario_path: Path | None
    manifest_payload: dict[str, Any] = field(default_factory=dict)


def create_aptl_runtime_target(
    *,
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
) -> RuntimeTarget:
    """Build the ACES runtime target for APTL."""

    provisioner = AptlProvisioner(
        project_dir=project_dir,
        config=config,
        deployment_backend=backend,
    )
    orchestrator = AptlOrchestrator()
    return RuntimeTarget(
        name=APTL_ACES_TARGET_NAME,
        manifest=create_aptl_manifest(),
        provisioner=provisioner,  # type: ignore[arg-type]
        orchestrator=orchestrator,  # type: ignore[arg-type]
        evaluator=AptlEvaluator(),  # type: ignore[arg-type]
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
    """Return the Compose profiles a scenario selects for the backend start.

    Mirrors ``start_aces_scenario``'s selection path (parse -> plan -> interpret
    -> select_backend_profiles) without side effects, so post-start readiness
    checks can scope to the profiles the scenario actually started rather than
    the global ``config.containers`` flags. A bounded curated scenario starts a
    subset of the enabled profiles, so a config-flag gate would wait on services
    the scenario never launched.
    """
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
    control_plane = RuntimeControlPlane(target, initial_snapshot=execution_plan.base_snapshot)
    failure, realization_details, selected_profiles = _apply_provisioning_and_orchestration(
        control_plane, execution_plan, target, run_store=run_store, run_id=run_id
    )
    if failure is not None:
        return AcesStartOutcome(
            lab_result=failure,
            final_snapshot=control_plane.get_snapshot(),
            realization_details=realization_details,
            selected_profiles=selected_profiles,
            scenario_path=scenario_path,
        )
    return AcesStartOutcome(
        lab_result=LabResult(
            success=True,
            message=f"Lab started through ACES runtime target '{APTL_ACES_TARGET_NAME}'",
        ),
        final_snapshot=control_plane.get_snapshot(),
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
    realization_details, selected_profiles = _interpret_realization(target, execution_plan)
    phases: list[Callable[[], object]] = [
        lambda: control_plane.submit_provisioning(execution_plan.provisioning),
    ]
    if execution_plan.orchestration.actionable_operations:
        phases.append(
            lambda: control_plane.submit_orchestration(execution_plan.orchestration),
        )
    if execution_plan.evaluation.actionable_operations:
        phases.append(
            lambda: control_plane.submit_evaluation(execution_plan.evaluation),
        )
    for submit in phases:
        failure = _apply_phase(control_plane, submit)
        if failure is not None:
            return failure, realization_details, selected_profiles
    evaluation_results: dict[str, dict[str, object]] = {}
    if execution_plan.evaluation.actionable_operations and target.evaluator is not None:
        evaluation_results = target.evaluator.results()
    orchestrator = target.orchestrator
    if isinstance(orchestrator, AptlOrchestrator) and orchestrator.results():
        drive_diagnostics = orchestrator.drive_workflows(
            evaluation_results=evaluation_results,
            run_store=run_store,
            run_id=run_id,
        )
        if drive_diagnostics:
            return (
                LabResult(
                    success=False,
                    error=render_aces_diagnostics(drive_diagnostics),
                ),
                realization_details,
                selected_profiles,
            )
    return None, realization_details, selected_profiles


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
    diagnostics = list(status.diagnostics) if status is not None else list(receipt.diagnostics)
    return LabResult(success=False, error=render_aces_diagnostics(diagnostics))


@dataclass
class AptlProvisioner(object):
    """Provisioning-only ACES backend adapter for APTL."""

    project_dir: Path
    config: AptlConfig
    deployment_backend: "DeploymentBackend"

    def validate(self, plan: object) -> list[Diagnostic]:
        """Validate that the ACES provisioning plan is APTL-realizable."""

        if not isinstance(plan, ProvisioningPlan):
            return [
                diagnostic(
                    "aptl.provisioner.invalid-plan",
                    PROVISIONING_ADDRESS,
                    "APTL provisioner expected an ACES ProvisioningPlan.",
                )
            ]

        return list(self._realize_plan(plan).diagnostics)

    def apply(self, plan: object, snapshot: object) -> ApplyResult:
        """Apply an ACES provisioning plan via APTL's deployment backend."""

        working_snapshot = (
            snapshot if isinstance(snapshot, RuntimeSnapshot) else RuntimeSnapshot()
        )
        diagnostics = self._invalid_plan_diagnostics(plan)
        result = ApplyResult(
            success=False,
            snapshot=working_snapshot,
            diagnostics=diagnostics,
        )
        if isinstance(plan, ProvisioningPlan):
            realization = self._realize_plan(plan)
            diagnostics = list(realization.diagnostics)
            if not has_error(diagnostics):
                result = self._apply_valid_plan(
                    plan,
                    working_snapshot,
                    diagnostics,
                    realization,
                )
            else:
                result = ApplyResult(
                    success=False,
                    snapshot=working_snapshot,
                    diagnostics=diagnostics,
                    details={"realization": realization.details()},
                )
        return result

    def _apply_valid_plan(
        self,
        plan: ProvisioningPlan,
        snapshot: RuntimeSnapshot,
        diagnostics: list[Diagnostic],
        realization: AptlRealization,
    ) -> ApplyResult:
        """Apply a validated ACES plan to the deployment backend."""
        selected_profiles = select_backend_profiles(self.config, realization.profiles)
        validity_diagnostics = self._compose_validity_diagnostics(selected_profiles)
        if validity_diagnostics:
            diagnostics.extend(validity_diagnostics)
            return ApplyResult(
                success=False,
                snapshot=snapshot,
                diagnostics=diagnostics,
                details={
                    "profiles": selected_profiles,
                    "realization": realization.details(),
                },
            )
        start_result = self.deployment_backend.start(selected_profiles)
        if not start_result.success:
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.backend-start-failed",
                    PROVISIONING_ADDRESS,
                    start_result.error or "APTL deployment backend failed.",
                )
            )
            return ApplyResult(
                success=False,
                snapshot=snapshot,
                diagnostics=diagnostics,
                details={
                    "profiles": selected_profiles,
                    "realization": realization.details(),
                },
            )
        return ApplyResult(
            success=True,
            snapshot=snapshot_after_apply(plan, snapshot),
            diagnostics=diagnostics,
            changed_addresses=_changed_addresses(plan),
            details={
                "profiles": selected_profiles,
                "realization": realization.details(),
            },
        )

    def _compose_validity_diagnostics(
        self, selected_profiles: list[str]
    ) -> list[Diagnostic]:
        """Refuse to start when the selected profiles form an invalid project.

        ``deployment_backend.start`` boots with ``docker compose --profile
        <selected>``, which activates every service in each selected profile,
        not just the declared ACES nodes. If an activated service depends on a
        service the selection excludes, Compose rejects the project at ``up``
        time. Catch that here so ``aptl lab start`` fails fast with an APTL
        diagnostic instead of a raw Compose "undefined service" error.
        """
        try:
            profile_index = load_compose_profile_index(self.project_dir)
        except (OSError, ValueError) as exc:
            return [
                diagnostic(
                    "aptl.provisioner.compose-profile-index-failed",
                    PROVISIONING_ADDRESS,
                    redact(str(exc)),
                )
            ]
        gaps = profile_index.cross_profile_dependency_gaps(set(selected_profiles))
        return [
            diagnostic(
                "aptl.provisioner.compose-project-invalid",
                PROVISIONING_ADDRESS,
                (
                    "Selected APTL compose profiles form an invalid project: "
                    f"service '{service_name}' depends on "
                    f"{', '.join(dependencies)}, which the profile selection "
                    "excludes. Declare the dependency's node or enable its "
                    "profile."
                ),
            )
            for service_name, dependencies in sorted(gaps.items())
        ]

    def _realize_plan(self, plan: ProvisioningPlan) -> AptlRealization:
        """Interpret an ACES plan against APTL's supported contract."""
        return interpret_provisioning_plan(
            plan=plan,
            project_dir=self.project_dir,
            config=self.config,
        )

    @staticmethod
    def _invalid_plan_diagnostics(plan: object) -> list[Diagnostic]:
        if isinstance(plan, ProvisioningPlan):
            return []
        return [
            diagnostic(
                "aptl.provisioner.invalid-plan",
                PROVISIONING_ADDRESS,
                "APTL provisioner expected an ACES ProvisioningPlan.",
            )
        ]


def _changed_addresses(plan: ProvisioningPlan) -> list[str]:
    """Return addresses whose planned operation changes runtime state."""
    return [op.address for op in plan.operations if op.action != ChangeAction.UNCHANGED]
