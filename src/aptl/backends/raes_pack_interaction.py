"""Attach validated pack-serving intent to already-lowered RAES nodes."""

from __future__ import annotations

from dataclasses import replace

from raes_contracts.diagnostics import Diagnostic

from aptl.backends.identity import (
    APTL_RAES_TARGET_NAME,
    APTL_RAES_TARGET_PROFILE,
    APTL_RAES_TARGET_VERSION,
    BackendIdentity,
)
from aptl.backends.pack_interaction import (
    PackBackendInteractionContext,
    ResolvedPackBackendInteraction,
)
from aptl.backends.pack_interaction_discovery import (
    PackBackendInteractionError,
    resolve_pack_backend_interaction,
)
from aptl.backends.raes_diagnostics import PROVISIONING_ADDRESS, diagnostic
from aptl.backends.raes_profiles import (
    OPERATOR_GROUP_VOCABULARY,
    public_start_profiles,
)
from aptl.backends.raes_realization_model import NodeRealization
from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import ScenarioBundle


def apply_pack_interaction(
    nodes: list[NodeRealization],
    bundle: ScenarioBundle,
    config: AptlConfig,
    diagnostics: list[Diagnostic],
) -> tuple[list[NodeRealization], ResolvedPackBackendInteraction | None]:
    """Apply one total serving-label mapping to already-lowered nodes.

    This runs only after RAES has admitted one provisioning plan and APTL has
    lowered its fixed node inventory. The provider can therefore label exact
    addresses, but cannot create, suppress, or otherwise realize a resource.
    """

    pack_identity = bundle.pack_identity
    if pack_identity is None:
        return nodes, None
    context = PackBackendInteractionContext(
        pack=pack_identity,
        backend=BackendIdentity(
            target_name=APTL_RAES_TARGET_NAME,
            target_version=APTL_RAES_TARGET_VERSION,
            profile=APTL_RAES_TARGET_PROFILE,
            transport=config.deployment.provider,
        ),
        component_addresses=tuple(sorted(node.address for node in nodes)),
        operator_groups=OPERATOR_GROUP_VOCABULARY,
    )
    try:
        resolved = resolve_pack_backend_interaction(context)
    except PackBackendInteractionError as exc:
        diagnostics.append(
            diagnostic(
                f"aptl.provisioner.pack-interaction-{exc.code}",
                PROVISIONING_ADDRESS,
                "The installed pack/backend serving interaction could not be resolved.",
            )
        )
        return nodes, None

    labelled = [
        replace(node, profiles=resolved.groups_for(node.address)) for node in nodes
    ]
    _append_disabled_group_diagnostics(labelled, config, diagnostics)
    return labelled, resolved


def _append_disabled_group_diagnostics(
    nodes: list[NodeRealization],
    config: AptlConfig,
    diagnostics: list[Diagnostic],
) -> None:
    """Reject components assigned exclusively to disabled operator groups."""

    enabled = set(public_start_profiles(config))
    for node in nodes:
        if node.profiles and enabled.isdisjoint(node.profiles):
            diagnostics.append(
                diagnostic(
                    "aptl.provisioner.pack-interaction-group-disabled",
                    node.address,
                    (
                        "The component is assigned only to disabled operator groups: "
                        f"{', '.join(node.profiles)}."
                    ),
                )
            )


__all__ = ["apply_pack_interaction"]
