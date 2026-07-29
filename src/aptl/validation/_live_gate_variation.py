"""Realization-variation probes for the RAES live validation gate (SCN-010F).

The parity check proves that two distinct declared nodes realize to two distinct
models rather than collapsing to one. These helpers build the single-node plans
it drives and compare the resulting interpretations. Split out of
:mod:`aptl.validation._live_gate_probes` to keep that leaf within its size
budget; it depends on the leaf (for diagnostic severity) but the leaf never
depends on it, so the import stays one-directional.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from raes_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RuntimeDomain,
)

from aptl.validation._live_gate_probes import _severity

if TYPE_CHECKING:
    from aptl.backends.raes_realization_model import AptlRealization


def _distinct_profile_nodes(
    nodes: Sequence[Mapping[str, Any]],
) -> tuple[str, str] | None:
    """Pick two node names whose realized profiles differ."""
    seen: list[tuple[str, frozenset[str]]] = []
    for node in nodes:
        name = _node_primary_name(node)
        profiles = frozenset(node.get("profiles", ()))
        if not name or not profiles:
            continue
        for other_name, other_profiles in seen:
            if other_profiles != profiles:
                return other_name, name
        seen.append((name, profiles))
    return None


def _node_primary_name(node: Mapping[str, Any]) -> str:
    """Return a usable node name from the realization node record."""
    aliases = node.get("aliases") or ()
    return str(aliases[0]) if aliases else str(node.get("name", ""))


def _variation_diagnostics(
    first: AptlRealization, second: AptlRealization
) -> list[str]:
    """Confirm two interpretations are error-free and distinct."""
    diagnostics: list[str] = []
    for label, realization in (("first", first), ("second", second)):
        errors = [d for d in realization.diagnostics if _severity(d) == "error"]
        if errors:
            diagnostics.append(f"{label} variation node failed to realize")
    if not diagnostics and first.details() == second.details():
        diagnostics.append("distinct declared nodes collapsed to one realization")
    return diagnostics


def _single_node_plan(node_name: str) -> ProvisioningPlan:
    """Build a single-node RAES provisioning plan for ``node_name``."""
    address = f"provision.node.{node_name}"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload={
            "name": node_name,
            "node_name": node_name,
            "node_type": "vm",
            "os_family": "linux",
            "spec": {"node": {"name": node_name}, "infrastructure": {}},
        },
    )
    return ProvisioningPlan(
        resources={address: resource},
        operations=[
            ProvisionOp(
                action=ChangeAction.CREATE,
                address=address,
                resource_type="node",
                payload=resource.payload,
            )
        ],
    )
