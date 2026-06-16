"""Reference resolvers for the SDL-to-runtime compiler.

Each resolver turns SDL reference names into runtime addresses, emitting
``Diagnostic`` records for references that fail to bind. The behaviour of these
functions is contract-stable: diagnostic codes, messages, and ordering are part
of the compiler's observable output.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from aptl.core.runtime.compiler_addresses import (
    _dedupe,
    _resource_address_for_node,
    _workflow_address,
)
from aptl.core.runtime.models import Diagnostic
from aptl.core.sdl.nodes import NodeType
from aptl.core.sdl.scenario import Scenario


def _resolve_binding_ref(
    bindings: dict[str, Any],
    *,
    ref_name: str,
    owner_address: str,
    domain: str,
    code_prefix: str,
    binding_attr: str,
    binding_label: str,
) -> tuple[tuple[str, ...], list[Diagnostic]]:
    """Resolve a single reference against a binding map, one match required."""
    matches = tuple(
        sorted(
            address
            for address, binding in bindings.items()
            if getattr(binding, binding_attr) == ref_name
        )
    )
    if len(matches) == 1:
        return matches, []

    if not matches:
        return (), [
            Diagnostic(
                code=f"{code_prefix}-unbound",
                domain=domain,
                address=owner_address,
                message=(
                    f"Reference '{ref_name}' does not resolve to a bound "
                    f"{binding_label}."
                ),
            )
        ]

    joined = ", ".join(matches)
    return (), [
        Diagnostic(
            code=f"{code_prefix}-ambiguous",
            domain=domain,
            address=owner_address,
            message=(
                f"Reference '{ref_name}' resolves to multiple bound "
                f"{binding_label}s: {joined}."
            ),
        )
    ]


def _resolve_binding_refs(
    bindings: dict[str, Any],
    *,
    ref_names: list[str],
    owner_address: str,
    domain: str,
    code_prefix: str,
    binding_attr: str,
    binding_label: str,
) -> tuple[tuple[str, ...], list[Diagnostic]]:
    """Resolve a list of references against a binding map, deduping results."""
    resolved: list[str] = []
    diagnostics: list[Diagnostic] = []
    for ref_name in dict.fromkeys(ref_names):
        addresses, ref_diagnostics = _resolve_binding_ref(
            bindings,
            ref_name=ref_name,
            owner_address=owner_address,
            domain=domain,
            code_prefix=code_prefix,
            binding_attr=binding_attr,
            binding_label=binding_label,
        )
        resolved.extend(addresses)
        diagnostics.extend(ref_diagnostics)
    return _dedupe(resolved), diagnostics


def _resolve_resource_refs(
    resources: dict[str, Any],
    *,
    ref_names: list[str],
    owner_address: str,
    domain: str,
    code_prefix: str,
    resource_label: str,
) -> tuple[tuple[str, ...], list[Diagnostic]]:
    """Resolve references by matching resource ``name`` attributes."""
    resolved: list[str] = []
    diagnostics: list[Diagnostic] = []
    for ref_name in dict.fromkeys(ref_names):
        matched_address = next(
            (
                address
                for address, resource in resources.items()
                if resource.name == ref_name
            ),
            None,
        )
        if matched_address is None:
            diagnostics.append(
                Diagnostic(
                    code=f"{code_prefix}-unbound",
                    domain=domain,
                    address=owner_address,
                    message=(
                        f"Reference '{ref_name}' does not resolve to a defined "
                        f"{resource_label}."
                    ),
                )
            )
            continue
        resolved.append(matched_address)
    return _dedupe(resolved), diagnostics


def _resolve_named_refs(
    *,
    ref_names: list[str],
    available_names: set[str],
    address_builder: Callable[[str], str],
    owner_address: str,
    domain: str,
    code_prefix: str,
    resource_label: str,
) -> tuple[tuple[str, ...], list[Diagnostic]]:
    """Resolve references by membership in a set of available names."""
    resolved: list[str] = []
    diagnostics: list[Diagnostic] = []
    for ref_name in dict.fromkeys(ref_names):
        if ref_name not in available_names:
            diagnostics.append(
                Diagnostic(
                    code=f"{code_prefix}-unbound",
                    domain=domain,
                    address=owner_address,
                    message=(
                        f"Reference '{ref_name}' does not resolve to a defined "
                        f"{resource_label}."
                    ),
                )
            )
            continue
        resolved.append(address_builder(ref_name))
    return _dedupe(resolved), diagnostics


@dataclass(frozen=True)
class NodeRefContext(object):
    """Diagnostic context and type requirements for resolving a node reference."""

    owner_address: str
    domain: str
    code_prefix: str
    node_label: str
    require_vm: bool = False
    require_switch: bool = False


def _node_ref_type_error(
    context: NodeRefContext,
    *,
    node_type: NodeType,
    ref_name: str,
) -> Diagnostic | None:
    """Return a type-mismatch diagnostic for a node reference, or ``None``."""
    if context.require_vm and node_type != NodeType.VM:
        return Diagnostic(
            code=f"{context.code_prefix}-invalid-type",
            domain=context.domain,
            address=context.owner_address,
            message=(
                f"Reference '{ref_name}' must resolve to a VM node for "
                f"{context.node_label}."
            ),
        )
    if context.require_switch and node_type != NodeType.SWITCH:
        return Diagnostic(
            code=f"{context.code_prefix}-invalid-type",
            domain=context.domain,
            address=context.owner_address,
            message=(
                f"Reference '{ref_name}' must resolve to a switch/network "
                f"node for {context.node_label}."
            ),
        )
    return None


def _resolve_node_ref(
    scenario: Scenario,
    context: NodeRefContext,
    *,
    ref_name: str,
) -> tuple[str | None, list[Diagnostic]]:
    """Resolve a node reference to its runtime address, enforcing type rules."""
    node = scenario.nodes.get(ref_name)
    if node is None:
        return None, [
            Diagnostic(
                code=f"{context.code_prefix}-unbound",
                domain=context.domain,
                address=context.owner_address,
                message=(
                    f"Reference '{ref_name}' does not resolve to a defined "
                    f"{context.node_label}."
                ),
            )
        ]

    type_error = _node_ref_type_error(
        context,
        node_type=node.type,
        ref_name=ref_name,
    )
    if type_error is not None:
        return None, [type_error]

    return _resource_address_for_node(scenario, ref_name), []


def _resolve_workflow_step_refs(
    scenario: Scenario,
    *,
    step_refs: list[str],
    owner_address: str,
    domain: str,
    code_prefix: str,
) -> tuple[tuple[str, ...], tuple[str, ...], list[Diagnostic]]:
    """Resolve ``<workflow>.<step>`` references to validated workflow addresses."""
    valid_refs: list[str] = []
    workflow_addresses: list[str] = []
    diagnostics: list[Diagnostic] = []

    for step_ref in dict.fromkeys(step_refs):
        if "." not in step_ref:
            diagnostics.append(
                Diagnostic(
                    code=f"{code_prefix}-invalid-format",
                    domain=domain,
                    address=owner_address,
                    message=(
                        f"Reference '{step_ref}' must use '<workflow>.<step>' syntax."
                    ),
                )
            )
            continue

        workflow_name, step_name = step_ref.split(".", 1)
        workflow = scenario.workflows.get(workflow_name)
        if workflow is None:
            diagnostics.append(
                Diagnostic(
                    code=f"{code_prefix}-workflow-unbound",
                    domain=domain,
                    address=owner_address,
                    message=(
                        f"Reference '{step_ref}' does not resolve to a defined workflow."
                    ),
                )
            )
            continue
        if step_name not in workflow.steps:
            diagnostics.append(
                Diagnostic(
                    code=f"{code_prefix}-step-unbound",
                    domain=domain,
                    address=owner_address,
                    message=(
                        f"Reference '{step_ref}' does not resolve to a defined workflow step."
                    ),
                )
            )
            continue

        valid_refs.append(step_ref)
        workflow_addresses.append(_workflow_address(workflow_name))

    return _dedupe(valid_refs), _dedupe(workflow_addresses), diagnostics
