"""Shared state and helpers for the semantic validator mixins.

``_ValidatorCore`` holds the scenario under validation plus the error and
warning accumulators. Every validation mixin inherits from it so the mixins
can rely on a single, typed source for ``self._s``, ``self._err``, and the
small node-type predicates shared across passes.
"""

from collections import defaultdict, deque

from aptl.core.sdl._base import is_variable_ref
from aptl.core.sdl.entities import flatten_entities
from aptl.core.sdl.nodes import NodeType
from aptl.core.sdl.scenario import Scenario


def _topological_sort(graph: dict[str, list[str]]) -> list[str] | None:
    """Return topological order or None if a cycle exists."""
    in_degree: dict[str, int] = defaultdict(int)
    for node in graph:
        in_degree.setdefault(node, 0)
    for deps in graph.values():
        for dep in deps:
            in_degree[dep] += 1

    queue = deque(n for n, d in in_degree.items() if d == 0)
    order: list[str] = []

    while queue:
        node = queue.popleft()
        order.append(node)
        for dep in graph.get(node, []):
            in_degree[dep] -= 1
            if in_degree[dep] == 0:
                queue.append(dep)

    return order if len(order) == len(in_degree) else None


class _ValidatorCore(object):
    """Base holding validator state and shared predicate helpers."""

    def __init__(self, scenario: Scenario) -> None:
        self._s = scenario
        self._errors: list[str] = []
        self._warnings: list[str] = []

    def _err(self, msg: str) -> None:
        """Record a fatal validation error."""
        self._errors.append(msg)

    def _warn(self, msg: str) -> None:
        """Record a non-fatal advisory."""
        self._warnings.append(msg)

    @staticmethod
    def _is_unresolved_var(value: object) -> bool:
        """Return True when ``value`` is an unresolved variable reference."""
        return is_variable_ref(value)

    def _node_type(self, node_name: str) -> NodeType | None:
        """Return the type of ``node_name`` or None when it is undefined."""
        node = self._s.nodes.get(node_name)
        return node.type if node is not None else None

    def _is_switch_node(self, node_name: str) -> bool:
        """Return True when ``node_name`` is a defined switch node."""
        return self._node_type(node_name) == NodeType.SWITCH

    def _is_vm_node(self, node_name: str) -> bool:
        """Return True when ``node_name`` is a defined VM node."""
        return self._node_type(node_name) == NodeType.VM

    def _all_entity_names(self) -> set[str]:
        """Return the flattened dot-notation names of every entity."""
        return set(flatten_entities(self._s.entities).keys())
