"""Shared planner semantic tests."""

from __future__ import annotations

from types import SimpleNamespace

from hypothesis import given
from hypothesis import strategies as st

from aptl.core.semantics.planner import (
    DependencyKind,
    dependency_edges,
    refresh_impacted_nodes,
    resource_delete_order,
    resource_topological_order,
)


def _resource(
    *,
    ordering: tuple[str, ...] = (),
    refresh: tuple[str, ...] = (),
) -> SimpleNamespace:
    return SimpleNamespace(
        ordering_dependencies=ordering,
        refresh_dependencies=refresh,
    )


@st.composite
def _dag_resources(draw):
    size = draw(st.integers(min_value=1, max_value=6))
    nodes = [f"resource.{index}" for index in range(size)]
    resources: dict[str, SimpleNamespace] = {}
    for index, node in enumerate(nodes):
        available = nodes[:index]
        if available:
            ordering = tuple(
                draw(
                    st.lists(
                        st.sampled_from(available),
                        unique=True,
                        max_size=len(available),
                    )
                )
            )
            refresh = tuple(
                draw(
                    st.lists(
                        st.sampled_from(available),
                        unique=True,
                        max_size=len(available),
                    )
                )
            )
        else:
            ordering = ()
            refresh = ()
        resources[node] = _resource(ordering=ordering, refresh=refresh)
    return resources


@st.composite
def _dag_resources_with_change_sets(draw):
    resources = draw(_dag_resources())
    nodes = list(resources)
    subset_a = (
        set(draw(st.lists(st.sampled_from(nodes), unique=True, max_size=len(nodes))))
        if nodes
        else set()
    )
    remaining = [node for node in nodes if node not in subset_a]
    subset_b = subset_a | (
        set(
            draw(
                st.lists(
                    st.sampled_from(remaining),
                    unique=True,
                    max_size=len(remaining),
                )
            )
        )
        if remaining
        else set()
    )
    return resources, subset_a, subset_b


class TestPlannerSemantics:
    def test_dependency_edges_preserve_kinds(self):
        resources = {
            "evaluation.metric.uptime": _resource(
                ordering=("evaluation.condition.vm.health",),
                refresh=("orchestration.workflow.flow",),
            ),
            "evaluation.condition.vm.health": _resource(),
            "orchestration.workflow.flow": _resource(),
        }

        ordering_edges = dependency_edges(resources, kind=DependencyKind.ORDERING)
        refresh_edges = dependency_edges(resources, kind=DependencyKind.REFRESH)

        assert ordering_edges[0].kind == DependencyKind.ORDERING
        assert ordering_edges[0].target == "evaluation.condition.vm.health"
        assert refresh_edges[0].kind == DependencyKind.REFRESH
        assert refresh_edges[0].target == "orchestration.workflow.flow"

    def test_refresh_impacted_nodes_propagate_transitively(self):
        resources = {
            "evaluation.condition.vm.health": _resource(),
            "evaluation.metric.uptime": _resource(refresh=("evaluation.condition.vm.health",)),
            "evaluation.goal.pass": _resource(refresh=("evaluation.metric.uptime",)),
        }

        assert refresh_impacted_nodes(
            resources,
            {"evaluation.condition.vm.health"},
        ) == (
            "evaluation.metric.uptime",
            "evaluation.goal.pass",
        )

    @given(_dag_resources())
    def test_topological_order_respects_dependencies(self, resources):
        order = resource_topological_order(resources)
        positions = {address: index for index, address in enumerate(order)}

        for address, resource in resources.items():
            for dependency in resource.ordering_dependencies:
                assert positions[dependency] < positions[address]

        assert resource_delete_order(resources) == list(reversed(order))

    @given(_dag_resources_with_change_sets())
    def test_refresh_propagation_is_monotonic(self, payload):
        resources, subset_a, subset_b = payload

        impacted_a = subset_a | set(refresh_impacted_nodes(resources, subset_a))
        impacted_b = subset_b | set(refresh_impacted_nodes(resources, subset_b))

        assert impacted_a <= impacted_b
