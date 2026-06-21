"""APTL ACES runtime target.

This module is the handoff layer between the external ACES SDL/runtime
packages and APTL's existing deployment primitives.  It intentionally keeps
Docker/SSH details behind ``DeploymentBackend``; the ACES provisioner only
translates a provisioning plan into the compose profiles APTL can already
start.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

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
from aptl.backends.aces_orchestrator import AptlOrchestrator
from aptl.backends.aces_realization import (
    AptlRealization,
    interpret_provisioning_plan,
)
from aptl.backends.aces_profiles import (
    select_backend_profiles,
)
from aptl.core.config import AptlConfig
from aptl.core.lab_types import LabResult
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from aces_processor.models import ExecutionPlan

    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("aces-backend")

DEFAULT_ACES_SCENARIO = Path("scenarios") / "techvault-operational.sdl.yaml"


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
    return RuntimeTarget(
        name=APTL_ACES_TARGET_NAME,
        manifest=create_aptl_manifest(),
        provisioner=provisioner,  # type: ignore[arg-type]
        orchestrator=AptlOrchestrator(),  # type: ignore[arg-type]
    )


def start_aces_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
) -> LabResult:
    """Start an APTL lab by compiling and applying an ACES SDL scenario."""

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
        return _run_execution_plan(target, execution_plan)
    except (FileNotFoundError, SDLError, TypeError, ValueError) as exc:
        return LabResult(
            success=False,
            error=redact(f"ACES runtime handoff failed: {exc}"),
        )


def _run_execution_plan(target: RuntimeTarget, execution_plan: "ExecutionPlan") -> LabResult:
    """Apply a planned ACES scenario through the runtime control plane.

    APTL declares no ACES evaluator yet (tracked by #312). A scenario may still
    carry evaluation content — notably the ``conditions`` section, whose entries
    are Docker Compose healthchecks realized during provisioning, not by an ACES
    evaluator. The planner flags such content with the evaluation-domain
    ``evaluator.missing`` ERROR; tolerate exactly that one expected diagnostic
    and stay fail-closed for every other planner error (provisioning ordering
    cycles, unsupported capabilities, orchestration errors, ...). Now that APTL
    is orchestration-capable, scenario start no longer bypasses the orchestration
    path: provisioning is applied, then — when the scenario carries workflows —
    orchestration is started so APTL's orchestrator records workflow
    result/history through the portable ACES contracts.
    """
    blocking = [
        diag
        for diag in execution_plan.diagnostics
        if diag.is_error
        and not (diag.domain == "evaluation" and diag.code == "evaluator.missing")
    ]
    if blocking:
        return LabResult(success=False, error=render_aces_diagnostics(blocking))
    control_plane = RuntimeControlPlane(target, initial_snapshot=execution_plan.base_snapshot)
    failure = _apply_provisioning_and_orchestration(control_plane, execution_plan)
    if failure is not None:
        return failure
    return LabResult(
        success=True,
        message=f"Lab started through ACES runtime target '{APTL_ACES_TARGET_NAME}'",
    )


def _apply_provisioning_and_orchestration(
    control_plane: RuntimeControlPlane,
    execution_plan: "ExecutionPlan",
) -> LabResult | None:
    """Submit provisioning, then orchestration when the plan carries workflows.

    Returns a failed ``LabResult`` for the first phase that fails, else ``None``.
    Evaluation stays unsubmitted until #312 adds the evaluator.
    """
    provisioning_failure = _apply_phase(
        control_plane,
        lambda: control_plane.submit_provisioning(execution_plan.provisioning),
    )
    if provisioning_failure is not None:
        return provisioning_failure
    if execution_plan.orchestration.actionable_operations:
        return _apply_phase(
            control_plane,
            lambda: control_plane.submit_orchestration(execution_plan.orchestration),
        )
    return None


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
