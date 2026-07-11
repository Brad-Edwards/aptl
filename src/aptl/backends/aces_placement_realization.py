"""Realize ACES placement resources (content/account/feature-binding) for APTL.

Split out of ``aces_realization.py`` (issue #689 / ADR-046's TechVault
addendum) to keep that module under the file-length gate: this module owns
resolving a placement resource's target node, dispatching to the typed
content/account resolvers, and building the ``PlacementRealization`` value.
``aces_realization.interpret_provisioning_plan`` composes this module's
``realize_placements`` alongside node/network realization.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import PlannedResource

from aptl.backends.aces_account_realization import resolve_account_placement
from aptl.backends.aces_content_realization import resolve_content_placement
from aptl.backends.aces_diagnostics import diagnostic
from aptl.backends.aces_profiles import normalize_identifier
from aptl.backends.aces_realization_model import (
    NodeRealization,
    PlacementRealization,
    _single_or_none,
)
from aptl.backends.aces_realization_values import (
    first_nonempty_string as _first_nonempty_string,
    placement_target_values as _placement_target_values,
    resolve_target_address as _resolve_target_address,
    resource_name as _resource_name,
)
from aptl.core.deployment.realization import (
    DeploymentAccountRealization,
    DeploymentContentRealization,
)

PLACEMENT_RESOURCE_TYPES = frozenset(
    {"feature-binding", "content-placement", "account-placement"}
)


def realize_placements(
    payload_resources: list[PlannedResource],
    node_lookup: dict[str, str],
    node_by_address: dict[str, NodeRealization],
    project_dir: Path,
    diagnostics: list[Diagnostic],
) -> list[PlacementRealization]:
    """Resolve supported placement resources against realized nodes."""

    placements: list[PlacementRealization] = []
    for resource in payload_resources:
        if resource.resource_type in PLACEMENT_RESOURCE_TYPES:
            placement, placement_diagnostics = _realize_placement(
                resource,
                resource.payload,
                node_lookup,
                node_by_address,
                project_dir,
            )
            diagnostics.extend(placement_diagnostics)
            if placement is not None:
                placements.append(placement)
    return placements


def placement_node_lookup(nodes: list[NodeRealization]) -> dict[str, str]:
    """Index node addresses and aliases for placement target resolution."""

    lookup: dict[str, str] = {}
    for node in nodes:
        values = {node.address, node.name, *node.aliases}
        for value in values:
            if not value:
                continue
            lookup[value] = node.address
            normalized = normalize_identifier(value)
            if normalized:
                lookup[normalized] = node.address
    return lookup


def _realize_placement(
    resource: PlannedResource,
    payload: Mapping[str, Any],
    node_lookup: dict[str, str],
    node_by_address: dict[str, NodeRealization],
    project_dir: Path,
) -> tuple[PlacementRealization | None, list[Diagnostic]]:
    """Realize a placement resource or return its diagnostics."""

    target_values = _placement_target_values(resource.resource_type, payload)
    target_address = _resolve_target_address(target_values, node_lookup)
    if target_address is None:
        return (
            None,
            [
                diagnostic(
                    "aptl.provisioner.binding-target-unresolved",
                    resource.address,
                    (
                        "ACES provisioning binding does not target a "
                        "declared APTL-realizable node."
                    ),
                )
            ],
        )

    content, account, resource_diagnostics = _realize_placement_resource(
        resource, payload, target_address, node_by_address, project_dir
    )
    return (
        PlacementRealization(
            address=resource.address,
            resource_type=resource.resource_type,
            name=_resource_name(resource.address, payload),
            target_address=target_address,
            target_node=_first_nonempty_string(target_values),
            content=content,
            account=account,
        ),
        resource_diagnostics,
    )


def _realize_placement_resource(
    resource: PlannedResource,
    payload: Mapping[str, Any],
    target_address: str,
    node_by_address: dict[str, NodeRealization],
    project_dir: Path,
) -> tuple[
    DeploymentContentRealization | None,
    DeploymentAccountRealization | None,
    list[Diagnostic],
]:
    """Lower a resolved content/account placement into typed backend input.

    Feature bindings resolve target-only (no typed backend op today); an
    unsupported content/account placement fails closed with the resolver's
    diagnostic rather than silently dropping to the count-only path.
    """

    target_node = node_by_address.get(target_address)
    target_service = _single_or_none(target_node.backend_services) if target_node else None

    if resource.resource_type == "content-placement":
        content, diagnostics = resolve_content_placement(
            resource=resource,
            payload=payload,
            target_address=target_address,
            target_service=target_service,
            project_dir=project_dir,
        )
        return content, None, diagnostics
    if resource.resource_type == "account-placement":
        account, diagnostics = resolve_account_placement(
            resource=resource,
            payload=payload,
            target_address=target_address,
            target_service=target_service,
        )
        return None, account, diagnostics
    return None, None, []
