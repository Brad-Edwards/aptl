"""Planner for compiled SDL runtime models."""

from aptl.core.runtime.capabilities import BackendManifest
from aptl.core.runtime.models import (
    ExecutionPlan,
    RuntimeModel,
    RuntimeSnapshot,
)
from aptl.core.runtime.planner_capabilities import (
    _account_features,
    _error_diagnostic,
    _resource_count_upper_bound,
    _validate_account_features,
    _validate_count_allowed_values,
    _validate_node_os_family,
    _validate_os_allowed_values,
    _variable_default_suffix,
    _variable_ref,
    _warning_diagnostic,
)
from aptl.core.runtime.planner_graph import (
    _RESOURCE_COLLECTIONS,
    _collect_resources,
    _entry_matches_resource,
    _ordering_cycle_diagnostics,
    _ordering_cycles,
    _ordering_graph,
    _planned_resource,
    _topological_order,
)
from aptl.core.runtime.planner_operations import (
    _build_evaluation_plan,
    _build_operations,
    _build_orchestration_plan,
    _build_provisioning_plan,
    _delete_order,
)
from aptl.core.runtime.planner_validation import (
    _validate_evaluation,
    _validate_manifest,
    _validate_orchestration,
)

__all__ = [
    "_RESOURCE_COLLECTIONS",
    "_account_features",
    "_build_evaluation_plan",
    "_build_operations",
    "_build_orchestration_plan",
    "_build_provisioning_plan",
    "_collect_resources",
    "_delete_order",
    "_entry_matches_resource",
    "_error_diagnostic",
    "_ordering_cycle_diagnostics",
    "_ordering_cycles",
    "_ordering_graph",
    "_planned_resource",
    "_resource_count_upper_bound",
    "_topological_order",
    "_validate_account_features",
    "_validate_count_allowed_values",
    "_validate_evaluation",
    "_validate_manifest",
    "_validate_node_os_family",
    "_validate_orchestration",
    "_validate_os_allowed_values",
    "_variable_default_suffix",
    "_variable_ref",
    "_warning_diagnostic",
    "plan",
]


def plan(
    model: RuntimeModel,
    manifest: BackendManifest,
    snapshot: RuntimeSnapshot | None = None,
    *,
    target_name: str | None = None,
) -> ExecutionPlan:
    """Reconcile a compiled runtime model against the current snapshot."""

    snapshot = snapshot or RuntimeSnapshot()
    resources = _collect_resources(model)
    diagnostics = [
        *model.diagnostics,
        *_validate_manifest(model, manifest),
        *_ordering_cycle_diagnostics(resources),
    ]
    actions, deleted_entries = _build_operations(resources, snapshot)

    provisioning = _build_provisioning_plan(resources, actions, deleted_entries)
    orchestration = _build_orchestration_plan(resources, actions, deleted_entries)
    evaluation = _build_evaluation_plan(resources, actions, deleted_entries)

    return ExecutionPlan(
        target_name=target_name,
        manifest=manifest,
        base_snapshot=snapshot,
        scenario_name=model.scenario_name,
        model=model,
        provisioning=provisioning,
        orchestration=orchestration,
        evaluation=evaluation,
        diagnostics=diagnostics,
    )
