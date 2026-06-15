"""Address builders and value-dump helpers for the SDL-to-runtime compiler."""

from typing import Any

from aptl.core.sdl.nodes import NodeType
from aptl.core.sdl.scenario import Scenario


def _dump(model: object) -> dict[str, Any]:
    """Serialize a model (or dict) into a JSON-compatible aliased dict."""
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json", by_alias=True)
    if isinstance(model, dict):
        return dict(model)
    return {}


def _address(*parts: str) -> str:
    """Join non-empty address parts with a dot separator."""
    return ".".join(part for part in parts if part)


def _dedupe(items: list[str]) -> tuple[str, ...]:
    """Return the items as a tuple with duplicates removed, preserving order."""
    return tuple(dict.fromkeys(items))


def _template_address(kind: str, name: str) -> str:
    """Build the runtime address for a named template of the given kind."""
    return _address("template", kind, name)


def _network_address(name: str) -> str:
    """Build the runtime address for a provisioned network."""
    return _address("provision", "network", name)


def _node_address(name: str) -> str:
    """Build the runtime address for a provisioned node."""
    return _address("provision", "node", name)


def _feature_binding_address(node_name: str, feature_name: str) -> str:
    """Build the runtime address for a feature binding on a node."""
    return _address("provision", "feature", node_name, feature_name)


def _content_address(name: str) -> str:
    """Build the runtime address for a content placement."""
    return _address("provision", "content", name)


def _account_address(name: str) -> str:
    """Build the runtime address for an account placement."""
    return _address("provision", "account", name)


def _condition_binding_address(node_name: str, condition_name: str) -> str:
    """Build the runtime address for a condition binding on a node."""
    return _address("evaluation", "condition", node_name, condition_name)


def _inject_address(name: str) -> str:
    """Build the runtime address for an inject template."""
    return _address("orchestration", "inject", name)


def _inject_binding_address(node_name: str, inject_name: str) -> str:
    """Build the runtime address for an inject binding on a node."""
    return _address("orchestration", "inject-binding", node_name, inject_name)


def _event_address(name: str) -> str:
    """Build the runtime address for an event."""
    return _address("orchestration", "event", name)


def _script_address(name: str) -> str:
    """Build the runtime address for a script."""
    return _address("orchestration", "script", name)


def _story_address(name: str) -> str:
    """Build the runtime address for a story."""
    return _address("orchestration", "story", name)


def _workflow_address(name: str) -> str:
    """Build the runtime address for a workflow."""
    return _address("orchestration", "workflow", name)


def _metric_address(name: str) -> str:
    """Build the runtime address for a metric."""
    return _address("evaluation", "metric", name)


def _evaluation_address(name: str) -> str:
    """Build the runtime address for an evaluation."""
    return _address("evaluation", "evaluation", name)


def _tlo_address(name: str) -> str:
    """Build the runtime address for a TLO."""
    return _address("evaluation", "tlo", name)


def _goal_address(name: str) -> str:
    """Build the runtime address for a goal."""
    return _address("evaluation", "goal", name)


def _objective_address(name: str) -> str:
    """Build the runtime address for an objective."""
    return _address("evaluation", "objective", name)


def _resource_address_for_node(scenario: Scenario, node_name: str) -> str:
    """Return the network or node address for a node based on its type."""
    node = scenario.nodes.get(node_name)
    if node is not None and node.type == NodeType.SWITCH:
        return _network_address(node_name)
    return _node_address(node_name)
