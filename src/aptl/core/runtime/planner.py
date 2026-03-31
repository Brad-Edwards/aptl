"""Planner for compiled SDL runtime models."""

from collections import deque

from aptl.core.runtime.capabilities import BackendManifest
from aptl.core.runtime.models import (
    ChangeAction,
    Diagnostic,
    EvaluationOp,
    EvaluationPlan,
    ExecutionPlan,
    OrchestrationOp,
    OrchestrationPlan,
    PlannedResource,
    ProvisionOp,
    ProvisioningPlan,
    RuntimeDomain,
    RuntimeModel,
    RuntimeSnapshot,
    Severity,
    SnapshotEntry,
    resource_payload,
)


def _planned_resource(address: str, domain: RuntimeDomain, resource_type: str, resource) -> PlannedResource:
    return PlannedResource(
        address=address,
        domain=domain,
        resource_type=resource_type,
        payload=resource_payload(resource),
        ordering_dependencies=resource.ordering_dependencies,
        refresh_dependencies=resource.refresh_dependencies,
    )


def _collect_resources(model: RuntimeModel) -> dict[str, PlannedResource]:
    resources: dict[str, PlannedResource] = {}

    for address, resource in model.networks.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.PROVISIONING,
            "network",
            resource,
        )
    for address, resource in model.node_deployments.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.PROVISIONING,
            "node",
            resource,
        )
    for address, resource in model.feature_bindings.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.PROVISIONING,
            "feature-binding",
            resource,
        )
    for address, resource in model.content_placements.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.PROVISIONING,
            "content-placement",
            resource,
        )
    for address, resource in model.account_placements.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.PROVISIONING,
            "account-placement",
            resource,
        )
    for address, resource in model.inject_bindings.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.ORCHESTRATION,
            "inject-binding",
            resource,
        )
    for address, resource in model.injects.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.ORCHESTRATION,
            "inject",
            resource,
        )
    for address, resource in model.events.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.ORCHESTRATION,
            "event",
            resource,
        )
    for address, resource in model.scripts.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.ORCHESTRATION,
            "script",
            resource,
        )
    for address, resource in model.stories.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.ORCHESTRATION,
            "story",
            resource,
        )
    for address, resource in model.workflows.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.ORCHESTRATION,
            "workflow",
            resource,
        )
    for address, resource in model.condition_bindings.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.EVALUATION,
            "condition-binding",
            resource,
        )
    for address, resource in model.metrics.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.EVALUATION,
            "metric",
            resource,
        )
    for address, resource in model.evaluations.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.EVALUATION,
            "evaluation",
            resource,
        )
    for address, resource in model.tlos.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.EVALUATION,
            "tlo",
            resource,
        )
    for address, resource in model.goals.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.EVALUATION,
            "goal",
            resource,
        )
    for address, resource in model.objectives.items():
        resources[address] = _planned_resource(
            address,
            RuntimeDomain.EVALUATION,
            "objective",
            resource,
        )

    return resources


def _topological_order(resources: dict[str, PlannedResource]) -> list[str]:
    graph: dict[str, list[str]] = {address: [] for address in resources}
    indegree: dict[str, int] = {address: 0 for address in resources}

    for address, resource in resources.items():
        for dependency in resource.ordering_dependencies:
            if dependency not in resources:
                continue
            graph[dependency].append(address)
            indegree[address] += 1

    queue = deque(sorted(address for address, degree in indegree.items() if degree == 0))
    order: list[str] = []

    while queue:
        current = queue.popleft()
        order.append(current)
        for dependent in sorted(graph[current]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                queue.append(dependent)

    if len(order) != len(resources):
        remaining = [address for address in resources if address not in order]
        order.extend(sorted(remaining))

    return order


def _entry_matches_resource(entry: SnapshotEntry, resource: PlannedResource) -> bool:
    return (
        entry.domain == resource.domain
        and entry.resource_type == resource.resource_type
        and entry.payload == resource.payload
        and entry.ordering_dependencies == resource.ordering_dependencies
        and entry.refresh_dependencies == resource.refresh_dependencies
    )


def _counted_total_nodes(model: RuntimeModel) -> int | None:
    counts: list[int] = []
    for resource in [*model.networks.values(), *model.node_deployments.values()]:
        count = resource.spec.get("infrastructure", {}).get("count", 1)
        if isinstance(count, int):
            counts.append(count)
    if not counts:
        return 0
    return sum(counts)


def _account_features(account_spec: dict[str, object]) -> set[str]:
    features: set[str] = set()
    if account_spec.get("groups"):
        features.add("groups")
    if account_spec.get("mail"):
        features.add("mail")
    if account_spec.get("spn"):
        features.add("spn")
    if account_spec.get("shell"):
        features.add("shell")
    if account_spec.get("home"):
        features.add("home")
    disabled = account_spec.get("disabled")
    if disabled not in (False, None, ""):
        features.add("disabled")
    auth_method = account_spec.get("auth_method")
    if auth_method not in ("", None, "password"):
        features.add("auth_method")
    return features


def _validate_manifest(model: RuntimeModel, manifest: BackendManifest) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    provisioner = manifest.provisioner

    for network in model.networks.values():
        if "switch" not in provisioner.supported_node_types:
            diagnostics.append(
                Diagnostic(
                    code="provisioner.unsupported-node-type",
                    domain="provisioning",
                    address=network.address,
                    message="Provisioner does not support switch/network nodes.",
                )
            )
        if network.spec.get("infrastructure", {}).get("acls") and not provisioner.supports_acls:
            diagnostics.append(
                Diagnostic(
                    code="provisioner.acls-unsupported",
                    domain="provisioning",
                    address=network.address,
                    message="Provisioner does not support ACL declarations.",
                )
            )

    for node in model.node_deployments.values():
        if node.node_type and node.node_type not in provisioner.supported_node_types:
            diagnostics.append(
                Diagnostic(
                    code="provisioner.unsupported-node-type",
                    domain="provisioning",
                    address=node.address,
                    message=f"Provisioner does not support node type '{node.node_type}'.",
                )
            )
        if node.os_family and node.os_family not in provisioner.supported_os_families:
            diagnostics.append(
                Diagnostic(
                    code="provisioner.unsupported-os-family",
                    domain="provisioning",
                    address=node.address,
                    message=f"Provisioner does not support OS family '{node.os_family}'.",
                )
            )

    total_nodes = _counted_total_nodes(model)
    if (
        provisioner.max_total_nodes is not None
        and total_nodes is not None
        and total_nodes > provisioner.max_total_nodes
    ):
        diagnostics.append(
            Diagnostic(
                code="provisioner.max-total-nodes-exceeded",
                domain="provisioning",
                address="provision",
                message=(
                    f"Scenario requires {total_nodes} deployable nodes/networks, "
                    f"but provisioner maximum is {provisioner.max_total_nodes}."
                ),
            )
        )

    for content in model.content_placements.values():
        content_type = str(content.spec.get("type", ""))
        if (
            content_type
            and content_type not in provisioner.supported_content_types
        ):
            diagnostics.append(
                Diagnostic(
                    code="provisioner.unsupported-content-type",
                    domain="provisioning",
                    address=content.address,
                    message=f"Provisioner does not support content type '{content_type}'.",
                )
            )

    if model.account_placements and not provisioner.supports_accounts:
        diagnostics.append(
            Diagnostic(
                code="provisioner.accounts-unsupported",
                domain="provisioning",
                address="provision.accounts",
                message="Provisioner does not support accounts.",
            )
        )
    elif provisioner.supports_accounts:
        for account in model.account_placements.values():
            for feature in sorted(_account_features(account.spec)):
                if feature not in provisioner.supported_account_features:
                    diagnostics.append(
                        Diagnostic(
                            code="provisioner.unsupported-account-feature",
                            domain="provisioning",
                            address=account.address,
                            message=f"Provisioner does not support account feature '{feature}'.",
                        )
                    )

    orchestration_sections = {
        "injects": bool(model.injects or model.inject_bindings),
        "events": bool(model.events),
        "scripts": bool(model.scripts),
        "stories": bool(model.stories),
        "workflows": bool(model.workflows),
    }
    if any(orchestration_sections.values()):
        if manifest.orchestrator is None:
            diagnostics.append(
                Diagnostic(
                    code="orchestrator.missing",
                    domain="orchestration",
                    address="orchestration",
                    message="Scenario requires orchestration support, but no orchestrator is configured.",
                )
            )
        else:
            for section, used in orchestration_sections.items():
                if used and section not in manifest.orchestrator.supported_sections:
                    diagnostics.append(
                        Diagnostic(
                            code="orchestrator.unsupported-section",
                            domain="orchestration",
                            address=f"orchestration.{section}",
                            message=f"Orchestrator does not support '{section}'.",
                        )
                    )
            if model.workflows and not manifest.orchestrator.supports_workflows:
                diagnostics.append(
                    Diagnostic(
                        code="orchestrator.workflows-unsupported",
                        domain="orchestration",
                        address="orchestration.workflows",
                        message="Orchestrator does not support workflows.",
                    )
                )
            orchestration_uses_condition_refs = any(
                event.condition_addresses for event in model.events.values()
            ) or any(
                addresses
                for workflow in model.workflows.values()
                for addresses in workflow.step_condition_addresses.values()
            )
            if (
                orchestration_uses_condition_refs
                and not manifest.orchestrator.supports_condition_refs
            ):
                diagnostics.append(
                    Diagnostic(
                        code="orchestrator.condition-refs-unsupported",
                        domain="orchestration",
                        address="orchestration.condition-refs",
                        message=(
                            "Orchestrator does not support condition-gated events "
                            "or workflow predicates."
                        ),
                    )
                )
            if model.inject_bindings and not manifest.orchestrator.supports_inject_bindings:
                diagnostics.append(
                    Diagnostic(
                        code="orchestrator.inject-bindings-unsupported",
                        domain="orchestration",
                        address="orchestration.injects",
                        message="Orchestrator does not support node-bound injects.",
                    )
                )

    evaluation_sections = {
        "conditions": bool(model.condition_bindings),
        "metrics": bool(model.metrics),
        "evaluations": bool(model.evaluations),
        "tlos": bool(model.tlos),
        "goals": bool(model.goals),
        "objectives": bool(model.objectives),
    }
    if any(evaluation_sections.values()):
        if not manifest.has_evaluator:
            diagnostics.append(
                Diagnostic(
                    code="evaluator.missing",
                    domain="evaluation",
                    address="evaluation",
                    message="Scenario requires evaluation support, but no evaluator is configured.",
                )
            )
        else:
            supported_sections = manifest.evaluator_supported_sections
            for section, used in evaluation_sections.items():
                if used and section not in supported_sections:
                    diagnostics.append(
                        Diagnostic(
                            code="evaluator.unsupported-section",
                            domain="evaluation",
                            address=f"evaluation.{section}",
                            message=f"Evaluator does not support '{section}'.",
                        )
                    )
            scoring_in_use = bool(
                model.condition_bindings
                or model.metrics
                or model.evaluations
                or model.tlos
                or model.goals
            )
            if scoring_in_use and not manifest.supports_scoring:
                diagnostics.append(
                    Diagnostic(
                        code="evaluator.scoring-unsupported",
                        domain="evaluation",
                        address="evaluation.scoring",
                        message="Evaluator does not support scoring resources.",
                    )
                )
            if model.objectives and not manifest.supports_objectives:
                diagnostics.append(
                    Diagnostic(
                        code="evaluator.objectives-unsupported",
                        domain="evaluation",
                        address="evaluation.objectives",
                        message="Evaluator does not support objectives.",
                    )
                )

    return diagnostics


def _build_operations(
    resources: dict[str, PlannedResource],
    snapshot: RuntimeSnapshot,
) -> tuple[dict[str, ChangeAction], dict[str, SnapshotEntry]]:
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


def plan(
    model: RuntimeModel,
    manifest: BackendManifest,
    snapshot: RuntimeSnapshot | None = None,
    *,
    target_name: str | None = None,
) -> ExecutionPlan:
    """Reconcile a compiled runtime model against the current snapshot."""

    snapshot = snapshot or RuntimeSnapshot()
    diagnostics = [*model.diagnostics, *_validate_manifest(model, manifest)]
    resources = _collect_resources(model)
    actions, deleted_entries = _build_operations(resources, snapshot)

    provisioning = _build_provisioning_plan(resources, actions, deleted_entries)
    orchestration = _build_orchestration_plan(resources, actions, deleted_entries)
    evaluation = _build_evaluation_plan(resources, actions, deleted_entries)

    return ExecutionPlan(
        target_name=target_name or manifest.name,
        manifest=manifest,
        base_snapshot=snapshot,
        scenario_name=model.scenario_name,
        model=model,
        provisioning=provisioning,
        orchestration=orchestration,
        evaluation=evaluation,
        diagnostics=diagnostics,
    )
