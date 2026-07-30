"""Small execution-plan helpers shared by the APTL RAES backend."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from raes_runtime.registry import RuntimeTarget

from aptl.backends.raes_profiles import select_backend_profiles
from aptl.backends.raes_provisioner import AptlProvisioner
from aptl.backends.raes_realization import interpret_provisioning_plan

if TYPE_CHECKING:
    from raes_processor.models import ExecutionPlan


def evaluation_results(
    target: RuntimeTarget,
    execution_plan: ExecutionPlan,
) -> dict[str, dict[str, object]]:
    """Return evaluator results only when evaluation actions ran."""

    results: dict[str, dict[str, object]] = {}
    if execution_plan.evaluation.actionable_operations and target.evaluator is not None:
        results = target.evaluator.results()
    return results


def interpret_realization(
    target: RuntimeTarget,
    execution_plan: ExecutionPlan,
) -> tuple[dict[str, Any], list[str]]:
    """Interpret one provisioning plan into details and backend profiles."""

    details: dict[str, Any] = {}
    profiles: list[str] = []
    provisioner = target.provisioner
    if isinstance(provisioner, AptlProvisioner):
        realization = interpret_provisioning_plan(
            plan=execution_plan.provisioning,
            config=provisioner.config,
            bundle=provisioner.bundle,
        )
        details = realization.details()
        profiles = select_backend_profiles(
            provisioner.config,
            realization.profiles,
        )
    return details, profiles
