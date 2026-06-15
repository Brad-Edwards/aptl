"""Resource collection and dependency-graph analysis for the planner."""

from collections import deque

from aptl.core.runtime.models import (
    Diagnostic,
    PlannedResource,
    ResolvedResource,
    RuntimeDomain,
    RuntimeModel,
    SnapshotEntry,
    resource_payload,
)


def _planned_resource(
    address: str,
    domain: RuntimeDomain,
    resource_type: str,
    resource: ResolvedResource,
) -> PlannedResource:
    """Build a planned resource from a compiled resource and its domain metadata."""
    return PlannedResource(
        address=address,
        domain=domain,
        resource_type=resource_type,
        payload=resource_payload(resource),
        ordering_dependencies=resource.ordering_dependencies,
        refresh_dependencies=resource.refresh_dependencies,
    )


# Ordered table of (model attribute, runtime domain, resource type) describing
# every resource collection that contributes to a planned resource set.
_RESOURCE_COLLECTIONS: tuple[tuple[str, RuntimeDomain, str], ...] = (
    ("networks", RuntimeDomain.PROVISIONING, "network"),
    ("node_deployments", RuntimeDomain.PROVISIONING, "node"),
    ("feature_bindings", RuntimeDomain.PROVISIONING, "feature-binding"),
    ("content_placements", RuntimeDomain.PROVISIONING, "content-placement"),
    ("account_placements", RuntimeDomain.PROVISIONING, "account-placement"),
    ("inject_bindings", RuntimeDomain.ORCHESTRATION, "inject-binding"),
    ("injects", RuntimeDomain.ORCHESTRATION, "inject"),
    ("events", RuntimeDomain.ORCHESTRATION, "event"),
    ("scripts", RuntimeDomain.ORCHESTRATION, "script"),
    ("stories", RuntimeDomain.ORCHESTRATION, "story"),
    ("workflows", RuntimeDomain.ORCHESTRATION, "workflow"),
    ("condition_bindings", RuntimeDomain.EVALUATION, "condition-binding"),
    ("metrics", RuntimeDomain.EVALUATION, "metric"),
    ("evaluations", RuntimeDomain.EVALUATION, "evaluation"),
    ("tlos", RuntimeDomain.EVALUATION, "tlo"),
    ("goals", RuntimeDomain.EVALUATION, "goal"),
    ("objectives", RuntimeDomain.EVALUATION, "objective"),
)


def _collect_resources(model: RuntimeModel) -> dict[str, PlannedResource]:
    """Gather every compiled resource into a single address-keyed planned set."""
    resources: dict[str, PlannedResource] = {}

    for model_attr, domain, resource_type in _RESOURCE_COLLECTIONS:
        for address, resource in getattr(model, model_attr).items():
            resources[address] = _planned_resource(
                address,
                domain,
                resource_type,
                resource,
            )

    return resources


def _ordering_graph(
    resources: dict[str, PlannedResource],
) -> dict[str, tuple[str, ...]]:
    """Map each address to the ordering dependencies present in the resource set."""
    return {
        address: tuple(
            dependency
            for dependency in resource.ordering_dependencies
            if dependency in resources
        )
        for address, resource in resources.items()
    }


def _strongconnect(
    address: str,
    graph: dict[str, tuple[str, ...]],
    state: "_TarjanState",
) -> None:
    """Run one Tarjan strongly-connected-component visit, recording any cycle."""
    state.indices[address] = state.index
    state.lowlinks[address] = state.index
    state.index += 1
    state.stack.append(address)
    state.on_stack.add(address)

    for dependency in graph[address]:
        if dependency not in state.indices:
            _strongconnect(dependency, graph, state)
            state.lowlinks[address] = min(
                state.lowlinks[address], state.lowlinks[dependency]
            )
        elif dependency in state.on_stack:
            state.lowlinks[address] = min(
                state.lowlinks[address], state.indices[dependency]
            )

    if state.lowlinks[address] != state.indices[address]:
        return

    component: list[str] = []
    while state.stack:
        member = state.stack.pop()
        state.on_stack.remove(member)
        component.append(member)
        if member == address:
            break

    component = sorted(component)
    if len(component) > 1 or component[0] in graph[component[0]]:
        state.cycles.append(tuple(component))


class _TarjanState:
    """Mutable bookkeeping shared across Tarjan SCC recursion calls."""

    def __init__(self) -> None:
        """Initialise empty indices, low-links, traversal stack, and cycle list."""
        self.index = 0
        self.indices: dict[str, int] = {}
        self.lowlinks: dict[str, int] = {}
        self.stack: list[str] = []
        self.on_stack: set[str] = set()
        self.cycles: list[tuple[str, ...]] = []


def _ordering_cycles(resources: dict[str, PlannedResource]) -> list[tuple[str, ...]]:
    """Return sorted ordering-dependency cycles within the resource set."""
    graph = _ordering_graph(resources)
    if not graph:
        return []

    state = _TarjanState()
    for address in sorted(graph):
        if address not in state.indices:
            _strongconnect(address, graph, state)

    return sorted(state.cycles)


def _ordering_cycle_diagnostics(
    resources: dict[str, PlannedResource],
) -> list[Diagnostic]:
    """Emit an ordering-cycle diagnostic for each cyclic component per domain."""
    diagnostics: list[Diagnostic] = []

    for domain in RuntimeDomain:
        domain_resources = {
            address: resource
            for address, resource in resources.items()
            if resource.domain == domain
        }
        for cycle in _ordering_cycles(domain_resources):
            rendered = ", ".join(cycle)
            diagnostics.append(
                Diagnostic(
                    code=f"{domain.value}.ordering-cycle",
                    domain=domain.value,
                    address=cycle[0],
                    message=(
                        f"{domain.value.capitalize()} ordering dependencies "
                        f"must be acyclic; detected cycle: {rendered}."
                    ),
                )
            )

    return diagnostics


def _topological_order(resources: dict[str, PlannedResource]) -> list[str]:
    """Return resources in a deterministic dependency-respecting topological order."""
    graph: dict[str, list[str]] = {address: [] for address in resources}
    indegree: dict[str, int] = dict.fromkeys(resources, 0)

    for address, dependencies in _ordering_graph(resources).items():
        for dependency in dependencies:
            graph[dependency].append(address)
            indegree[address] += 1

    queue = deque(
        sorted(address for address, degree in indegree.items() if degree == 0)
    )
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
    """Return whether a snapshot entry exactly matches a planned resource."""
    return (
        entry.domain == resource.domain
        and entry.resource_type == resource.resource_type
        and entry.payload == resource.payload
        and entry.ordering_dependencies == resource.ordering_dependencies
        and entry.refresh_dependencies == resource.refresh_dependencies
    )
