"""Pure dependency-graph semantics shared by planner and runtime lifecycle code."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, TypeVar


class DependencyKind(str, Enum):
    """Typed runtime dependency semantics."""

    ORDERING = "ordering"
    REFRESH = "refresh"


class ReconciliationAction(str, Enum):
    """Generic reconciliation outcome before runtime-specific mapping."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    UNCHANGED = "unchanged"


@dataclass(frozen=True)
class DependencyEdge:
    """Normalized dependency edge between canonical resource identities."""

    source: str
    target: str
    kind: DependencyKind


class SupportsDependencySemantics(Protocol):
    """Duck-typed resource shape for semantic dependency analysis."""

    ordering_dependencies: Iterable[str]
    refresh_dependencies: Iterable[str]


def canonical_resource_identity(address: str) -> tuple[str, ...]:
    """Return the canonical identity tuple for a compiled resource address."""

    return tuple(part for part in address.split(".") if part)


def dependency_graph(
    dependencies_by_node: Mapping[str, Iterable[str]],
) -> dict[str, tuple[str, ...]]:
    """Normalize a dependency graph to only include known nodes."""

    known_nodes = set(dependencies_by_node)
    return {
        node: tuple(
            dependency
            for dependency in dependencies
            if dependency in known_nodes
        )
        for node, dependencies in dependencies_by_node.items()
    }


def dependency_graph_from_edges(
    edges: Iterable[DependencyEdge],
    *,
    known_nodes: Iterable[str],
) -> dict[str, tuple[str, ...]]:
    """Build a normalized graph from typed dependency edges."""

    graph: dict[str, list[str]] = {node: [] for node in known_nodes}
    for edge in edges:
        if edge.source in graph:
            graph[edge.source].append(edge.target)
    return dependency_graph(graph)


def dependency_edges(
    resources: Mapping[str, SupportsDependencySemantics],
    *,
    kind: DependencyKind,
) -> tuple[DependencyEdge, ...]:
    """Return normalized typed dependency edges for compiled resources."""

    edges: list[DependencyEdge] = []
    for source in sorted(resources, key=canonical_resource_identity):
        resource = resources[source]
        dependencies = (
            resource.ordering_dependencies
            if kind == DependencyKind.ORDERING
            else resource.refresh_dependencies
        )
        for target in dependencies:
            if target not in resources:
                continue
            edges.append(DependencyEdge(source=source, target=target, kind=kind))
    return tuple(edges)


def dependency_graph_for_resources(
    resources: Mapping[str, SupportsDependencySemantics],
    *,
    kind: DependencyKind,
) -> dict[str, tuple[str, ...]]:
    """Build a normalized dependency graph from compiled resources."""
    return dependency_graph_from_edges(
        dependency_edges(resources, kind=kind),
        known_nodes=resources,
    )


def dependency_cycles(
    dependencies_by_node: Mapping[str, Iterable[str]],
) -> list[tuple[str, ...]]:
    """Return strongly connected components that represent dependency cycles."""

    graph = dependency_graph(dependencies_by_node)
    if not graph:
        return []

    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    cycles: list[tuple[str, ...]] = []

    def strongconnect(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for dependency in graph[node]:
            if dependency not in indices:
                strongconnect(dependency)
                lowlinks[node] = min(lowlinks[node], lowlinks[dependency])
            elif dependency in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[dependency])

        if lowlinks[node] != indices[node]:
            return

        component: list[str] = []
        while stack:
            member = stack.pop()
            on_stack.remove(member)
            component.append(member)
            if member == node:
                break

        component = sorted(component)
        if len(component) > 1 or component[0] in graph[component[0]]:
            cycles.append(tuple(component))

    for node in sorted(graph, key=canonical_resource_identity):
        if node not in indices:
            strongconnect(node)

    return sorted(cycles, key=lambda cycle: tuple(canonical_resource_identity(node) for node in cycle))


def topological_dependency_order(
    dependencies_by_node: Mapping[str, Iterable[str]],
) -> list[str]:
    """Return a stable topological order, appending residual nodes on cycles."""

    graph = dependency_graph(dependencies_by_node)
    dependents: dict[str, list[str]] = {node: [] for node in graph}
    indegree: dict[str, int] = {node: 0 for node in graph}

    for node, dependencies in graph.items():
        for dependency in dependencies:
            dependents[dependency].append(node)
            indegree[node] += 1

    queue = deque(
        sorted(
            (node for node, degree in indegree.items() if degree == 0),
            key=canonical_resource_identity,
        )
    )
    order: list[str] = []

    while queue:
        current = queue.popleft()
        order.append(current)
        for dependent in sorted(dependents[current], key=canonical_resource_identity):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                queue.append(dependent)

    if len(order) != len(graph):
        order.extend(
            sorted(
                (node for node in graph if node not in order),
                key=canonical_resource_identity,
            )
        )

    return order


def reverse_delete_order(
    dependencies_by_node: Mapping[str, Iterable[str]],
) -> list[str]:
    """Return reverse topological order for delete/teardown semantics."""

    return list(reversed(topological_dependency_order(dependencies_by_node)))


def resource_topological_order(
    resources: Mapping[str, SupportsDependencySemantics],
) -> list[str]:
    """Return ordering-based topological order for compiled resources."""

    return topological_dependency_order(
        dependency_graph_for_resources(resources, kind=DependencyKind.ORDERING)
    )


def resource_delete_order(
    resources: Mapping[str, SupportsDependencySemantics],
) -> list[str]:
    """Return ordering-based delete order for compiled resources."""

    return list(reversed(resource_topological_order(resources)))


def resource_dependency_cycles(
    resources: Mapping[str, SupportsDependencySemantics],
) -> list[tuple[str, ...]]:
    """Return ordering-cycle SCCs for compiled resources."""

    return dependency_cycles(
        dependency_graph_for_resources(resources, kind=DependencyKind.ORDERING)
    )


def refresh_impacted_nodes(
    resources: Mapping[str, SupportsDependencySemantics],
    changed_nodes: Iterable[str],
) -> tuple[str, ...]:
    """Return nodes that must refresh because dependencies changed."""

    changed = set(changed_nodes)
    refresh_graph = dependency_graph_for_resources(resources, kind=DependencyKind.REFRESH)
    dependents: dict[str, list[str]] = {address: [] for address in refresh_graph}
    for address, dependencies in refresh_graph.items():
        for dependency in dependencies:
            dependents.setdefault(dependency, []).append(address)

    queue = deque(sorted(changed, key=canonical_resource_identity))
    impacted_set: set[str] = set()
    while queue:
        dependency = queue.popleft()
        for dependent in sorted(dependents.get(dependency, ()), key=canonical_resource_identity):
            if dependent in changed or dependent in impacted_set:
                continue
            impacted_set.add(dependent)
            queue.append(dependent)

    refresh_order = topological_dependency_order(refresh_graph)
    return tuple(address for address in refresh_order if address in impacted_set)


_TResource = TypeVar("_TResource")
_TSnapshot = TypeVar("_TSnapshot")


def reconcile_resource_actions(
    resources: Mapping[str, _TResource],
    snapshot_entries: Mapping[str, _TSnapshot],
    *,
    resource_dependencies: Callable[[_TResource], SupportsDependencySemantics],
    matches: Callable[[_TSnapshot, _TResource], bool],
) -> tuple[dict[str, ReconciliationAction], dict[str, _TSnapshot]]:
    """Compute create/update/delete/unchanged actions from semantic dependencies."""

    actions: dict[str, ReconciliationAction] = {}
    deleted_entries: dict[str, _TSnapshot] = {}

    for address, resource in resources.items():
        existing = snapshot_entries.get(address)
        if existing is None:
            actions[address] = ReconciliationAction.CREATE
        elif matches(existing, resource):
            actions[address] = ReconciliationAction.UNCHANGED
        else:
            actions[address] = ReconciliationAction.UPDATE

    for address, entry in snapshot_entries.items():
        if address not in resources:
            deleted_entries[address] = entry
            actions[address] = ReconciliationAction.DELETE

    changed_nodes = {
        address
        for address, action in actions.items()
        if action in {ReconciliationAction.CREATE, ReconciliationAction.UPDATE}
    }
    impacted_nodes = refresh_impacted_nodes(
        {
            address: resource_dependencies(resource)
            for address, resource in resources.items()
        },
        changed_nodes,
    )
    for address in impacted_nodes:
        if actions[address] == ReconciliationAction.UNCHANGED:
            actions[address] = ReconciliationAction.UPDATE

    return actions, deleted_entries
