"""Small execution-plan helpers shared by the APTL RAES backend."""

from __future__ import annotations

from raes_processor.models import ExecutionPlan
from raes_runtime.registry import RuntimeTarget

from aptl.backends.raes_provisioner import AptlProvisioner


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
) -> tuple[dict[str, object], list[str], dict[str, object]]:
    """Interpret one provisioning plan into details and backend profiles."""

    details: dict[str, object] = {}
    profiles: list[str] = []
    pack_interaction_evidence: dict[str, object] = {}
    provisioner = target.provisioner
    if isinstance(provisioner, AptlProvisioner):
        realization = provisioner.realize_plan(execution_plan.provisioning)
        details = realization.details()
        profiles = provisioner.selected_profiles(realization)
        pack_interaction_evidence = realization.pack_interaction_evidence(profiles)
    return details, profiles, pack_interaction_evidence
