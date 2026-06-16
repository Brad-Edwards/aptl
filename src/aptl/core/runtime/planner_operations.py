"""Change-action computation and per-domain plan assembly for the planner."""

from aptl.core.runtime.models import (
    ChangeAction,
    EvaluationOp,
    EvaluationPlan,
    OrchestrationOp,
    OrchestrationPlan,
    PlannedResource,
    ProvisionOp,
    ProvisioningPlan,
    RuntimeDomain,
    RuntimeSnapshot,
    SnapshotEntry,
)
from aptl.core.runtime.planner_graph import (
    _entry_matches_resource,
    _topological_order,
)


def _build_operations(
    resources: dict[str, PlannedResource],
    snapshot: RuntimeSnapshot,
) -> tuple[dict[str, ChangeAction], dict[str, SnapshotEntry]]:
    """Compute the change action for every address and the entries to delete."""
    actions: dict[str, ChangeAction] = {}
    deleted_entries: dict[str, SnapshotEntry] = {}

    for address, resource in resources.items():
        existing = snapshot.get(address)
        if existing is None:
            actions[address] = ChangeAction.CREATE
        elif _entry_matches_resource(existing, resource):
            actions[address] = ChangeAction.UNCHANGED
        else:
            actions[address] = ChangeAction.UPDATE

    for address, entry in snapshot.entries.items():
        if address not in resources:
            deleted_entries[address] = entry
            actions[address] = ChangeAction.DELETE

    for address in _topological_order(resources):
        if actions[address] != ChangeAction.UNCHANGED:
            continue
        if any(
            actions.get(dep) != ChangeAction.UNCHANGED
            for dep in resources[address].refresh_dependencies
        ):
            actions[address] = ChangeAction.UPDATE

    return actions, deleted_entries


def _delete_order(entries: dict[str, SnapshotEntry]) -> list[str]:
    """Return deletion order as the reverse of the entries' topological order."""
    resources = {
        address: PlannedResource(
            address=entry.address,
            domain=entry.domain,
            resource_type=entry.resource_type,
            payload=entry.payload,
            ordering_dependencies=entry.ordering_dependencies,
            refresh_dependencies=entry.refresh_dependencies,
        )
        for address, entry in entries.items()
    }
    return list(reversed(_topological_order(resources)))


def _build_provisioning_plan(
    resources: dict[str, PlannedResource],
    actions: dict[str, ChangeAction],
    deleted_entries: dict[str, SnapshotEntry],
) -> ProvisioningPlan:
    """Assemble the provisioning-domain plan with ordered create/update/delete ops."""
    provisioning_resources = {
        address: resource
        for address, resource in resources.items()
        if resource.domain == RuntimeDomain.PROVISIONING
    }
    ops: list[ProvisionOp] = []
    for address in _topological_order(provisioning_resources):
        resource = provisioning_resources[address]
        ops.append(
            ProvisionOp(
                action=actions[address],
                address=address,
                resource_type=resource.resource_type,
                payload=resource.payload,
                ordering_dependencies=resource.ordering_dependencies,
                refresh_dependencies=resource.refresh_dependencies,
            )
        )
    for address in _delete_order(
        {
            address: entry
            for address, entry in deleted_entries.items()
            if entry.domain == RuntimeDomain.PROVISIONING
        }
    ):
        entry = deleted_entries[address]
        ops.append(
            ProvisionOp(
                action=ChangeAction.DELETE,
                address=address,
                resource_type=entry.resource_type,
                payload=entry.payload,
                ordering_dependencies=entry.ordering_dependencies,
                refresh_dependencies=entry.refresh_dependencies,
            )
        )
    return ProvisioningPlan(resources=provisioning_resources, operations=ops)


def _build_orchestration_plan(
    resources: dict[str, PlannedResource],
    actions: dict[str, ChangeAction],
    deleted_entries: dict[str, SnapshotEntry],
) -> OrchestrationPlan:
    """Assemble the orchestration-domain plan with startup order and ops."""
    orchestration_resources = {
        address: resource
        for address, resource in resources.items()
        if resource.domain == RuntimeDomain.ORCHESTRATION
    }
    startup_order = _topological_order(orchestration_resources)
    ops: list[OrchestrationOp] = []
    for address in startup_order:
        resource = orchestration_resources[address]
        ops.append(
            OrchestrationOp(
                action=actions[address],
                address=address,
                resource_type=resource.resource_type,
                payload=resource.payload,
                ordering_dependencies=resource.ordering_dependencies,
                refresh_dependencies=resource.refresh_dependencies,
            )
        )
    for address in _delete_order(
        {
            address: entry
            for address, entry in deleted_entries.items()
            if entry.domain == RuntimeDomain.ORCHESTRATION
        }
    ):
        entry = deleted_entries[address]
        ops.append(
            OrchestrationOp(
                action=ChangeAction.DELETE,
                address=address,
                resource_type=entry.resource_type,
                payload=entry.payload,
                ordering_dependencies=entry.ordering_dependencies,
                refresh_dependencies=entry.refresh_dependencies,
            )
        )
    return OrchestrationPlan(
        resources=orchestration_resources,
        operations=ops,
        startup_order=startup_order,
    )


def _build_evaluation_plan(
    resources: dict[str, PlannedResource],
    actions: dict[str, ChangeAction],
    deleted_entries: dict[str, SnapshotEntry],
) -> EvaluationPlan:
    """Assemble the evaluation-domain plan with startup order and ops."""
    evaluation_resources = {
        address: resource
        for address, resource in resources.items()
        if resource.domain == RuntimeDomain.EVALUATION
    }
    startup_order = _topological_order(evaluation_resources)
    ops: list[EvaluationOp] = []
    for address in startup_order:
        resource = evaluation_resources[address]
        ops.append(
            EvaluationOp(
                action=actions[address],
                address=address,
                resource_type=resource.resource_type,
                payload=resource.payload,
                ordering_dependencies=resource.ordering_dependencies,
                refresh_dependencies=resource.refresh_dependencies,
            )
        )
    for address in _delete_order(
        {
            address: entry
            for address, entry in deleted_entries.items()
            if entry.domain == RuntimeDomain.EVALUATION
        }
    ):
        entry = deleted_entries[address]
        ops.append(
            EvaluationOp(
                action=ChangeAction.DELETE,
                address=address,
                resource_type=entry.resource_type,
                payload=entry.payload,
                ordering_dependencies=entry.ordering_dependencies,
                refresh_dependencies=entry.refresh_dependencies,
            )
        )
    return EvaluationPlan(
        resources=evaluation_resources,
        operations=ops,
        startup_order=startup_order,
    )
