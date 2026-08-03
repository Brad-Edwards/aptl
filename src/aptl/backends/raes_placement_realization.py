"""Realize RAES placement resources for APTL.

Covers content, account, feature-binding and domain-controller placements.

Split out of ``raes_realization.py`` (issue #689 / ADR-046's TechVault
addendum) to keep that module under the file-length gate: this module owns
resolving a placement resource's target node, dispatching to the typed
content/account resolvers, and building the ``PlacementRealization`` value.
``raes_realization.interpret_provisioning_plan`` composes this module's
``realize_placements`` alongside node/network realization.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import PlannedResource

from aptl.backends.raes_account_realization import resolve_account_placement
from aptl.backends.raes_content_realization import resolve_content_placement
from aptl.backends.raes_diagnostics import diagnostic
from aptl.backends.raes_image_free_content_realization import (
    resolve_image_free_content_placement,
)
from aptl.backends.raes_profiles import normalize_identifier
from aptl.backends.raes_realization_model import (
    NodeRealization,
    ParticipantDatasetRealization,
    PlacementRealization,
    _single_or_none,
)
from aptl.backends.raes_realization_values import (
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
    {
        "feature-binding",
        "content-placement",
        "account-placement",
        "domain-controller-placement",
    }
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
                        "RAES provisioning binding does not target a "
                        "declared APTL-realizable node."
                    ),
                )
            ],
        )

    content, dataset, account, resource_diagnostics = _realize_placement_resource(
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
            dataset=dataset,
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
    ParticipantDatasetRealization | None,
    DeploymentAccountRealization | None,
    list[Diagnostic],
]:
    """Lower a resolved content/account placement into typed backend input.

    Feature bindings and domain-controller placements resolve target-only (no
    typed backend op today); an unsupported content/account placement fails
    closed with the resolver's diagnostic rather than silently dropping to the
    count-only path.

    ``domain-controller-placement`` is RAES 1.1.0's typed identity-domain
    bootstrap intent (upstream ``Brad-Edwards/aces#845``). Upstream classifies
    it as a ``TOPOLOGY`` realization concern and its own reference backend
    records it as a target-bound placement without a provisioning op, so APTL
    binds it to its declared node and records it. Actually bootstrapping the
    domain stays with the ``ad`` node's image, exactly as before this resource
    type existed - resolving it here neither claims nor performs that bootstrap.
    """

    target_node = node_by_address.get(target_address)
    target_service = (
        _single_or_none(target_node.backend_services) if target_node else None
    )

    content: DeploymentContentRealization | None = None
    dataset: ParticipantDatasetRealization | None = None
    account: DeploymentAccountRealization | None = None
    diagnostics: list[Diagnostic] = []
    if resource.resource_type == "content-placement":
        spec = payload.get("spec")
        is_dataset = isinstance(spec, Mapping) and spec.get("type") == "dataset"
        if (
            not is_dataset
            and target_node is not None
            and target_node.os
            and (target_node.runtime is not None or target_node.image is not None)
        ):
            # Any realized node — an image-free node the materializer places
            # content into, or an image (compose) node whose content is bound in
            # (issue #875) — takes its content at the authored literal
            # destination. Only the legacy named-volume path below still needs a
            # registered backing mount; an image node that declares content but
            # no other runtime must not fall through to it and be rejected.
            resolved_content, diagnostics = resolve_image_free_content_placement(
                resource, payload, target_address
            )
        else:
            resolved_content, diagnostics = resolve_content_placement(
                resource=resource,
                payload=payload,
                target_address=target_address,
                target_service=target_service,
                project_dir=project_dir,
            )
        if isinstance(resolved_content, ParticipantDatasetRealization):
            dataset = resolved_content
        else:
            content = resolved_content
    elif resource.resource_type == "account-placement":
        account, diagnostics = resolve_account_placement(
            resource=resource,
            payload=payload,
            target_address=target_address,
            target_service=target_service,
        )
    return content, dataset, account, diagnostics
