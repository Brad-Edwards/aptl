"""Bounded apply details and capture-apparatus snapshot reporting."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from raes_contracts.realization_structure import validate_realization_value
from raes_contracts.runtime_state import RuntimeSnapshot

from aptl.backends.raes_artifact_mechanisms import SOURCE_ARTIFACT_REQUIREMENT_KIND
from aptl.backends.raes_artifact_satisfaction import satisfactions_for_plan
from aptl.backends.raes_content_satisfaction import content_satisfactions_for_plan
from aptl.backends.raes_manifest import create_aptl_manifest

if TYPE_CHECKING:
    from raes_contracts.planning import ProvisioningPlan

    from aptl.backends.raes_realization_model import AptlRealization
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.observation import DeploymentObservationContext
    from aptl.core.deployment.realization import DeploymentRealizationSpec

_MAX_APPLY_DETAILS_BYTES = 65_536


def _compact_realization_details(realization: AptlRealization) -> dict[str, object]:
    """Return identities/counts; complete realized state lives in the snapshot."""

    full = realization.details()
    return {
        "profiles": full["profiles"],
        "resource_counts": full["resource_counts"],
        "nodes": [
            {
                "address": node.address,
                "name": node.name,
                "backend_services": list(node.backend_services),
                "container_name": node.container_name,
                "profiles": list(node.profiles),
            }
            for node in realization.nodes
        ],
        "networks": [network.details() for network in realization.networks],
        "placements": [
            {
                "address": placement.address,
                "resource_type": placement.resource_type,
                "target_address": placement.target_address,
            }
            for placement in realization.placements
        ],
        "generated_artifacts": [
            {"address": artifact.address}
            for artifact in realization.generated_artifacts
        ],
        "persistent_volumes": [
            {"address": volume.address} for volume in realization.persistent_volumes
        ],
    }


def bounded_apply_details(
    details: dict[str, object], realization: AptlRealization
) -> dict[str, object]:
    """Keep RAES ApplyResult details finite without losing observer additions."""

    try:
        serialized_size = len(json.dumps(details, allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError):
        serialized_size = _MAX_APPLY_DETAILS_BYTES + 1
    if (
        serialized_size <= _MAX_APPLY_DETAILS_BYTES
        and validate_realization_value(details).conformant
    ):
        return details
    compact = {**details, "realization": _compact_realization_details(realization)}
    evidence = compact.get("observation_evidence")
    if isinstance(evidence, dict):
        compact["observation_evidence"] = {
            "projection": "runtime-snapshot",
            "record_count": len(evidence),
        }
    return compact


def capture_apparatus_observations(
    backend: DeploymentBackend,
    deployment_spec: DeploymentRealizationSpec,
) -> tuple[dict[str, object], ...] | None:
    """Read back the actual added observer set from the deployment owner."""

    result: tuple[dict[str, object], ...] | None = None
    if not deployment_spec.capture_apparatus:
        result = ()
    else:
        observe = getattr(backend, "observe_capture_apparatus", None)
        observed = observe(deployment_spec) if callable(observe) else None
        if observed is not None and len(observed) == len(
            deployment_spec.capture_apparatus
        ):
            result = tuple(
                {
                    **item,
                    "runtime_address": "apparatus.capture.kali-session-capture",
                }
                for item in observed
            )
    return result


def with_artifact_satisfactions(
    plan: ProvisioningPlan,
    realized: RuntimeSnapshot,
    realization: AptlRealization,
    observation_context: DeploymentObservationContext,
    backend: DeploymentBackend,
    bundle_root: Path,
) -> RuntimeSnapshot:
    """Attach observed artifact satisfaction disclosures to a snapshot."""

    container_names = {
        node.address: node.container_name
        for node in realization.nodes
        if node.container_name
    }
    content_by_address = {
        placement.address: placement.content
        for placement in realization.placements
        if placement.content is not None
    }
    manifest = create_aptl_manifest()
    disclosures = {
        **satisfactions_for_plan(
            plan,
            container_names,
            backend,
            manifest,
            requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
            observation_context=observation_context,
        ),
        **content_satisfactions_for_plan(
            plan,
            content_by_address,
            bundle_root,
            manifest,
            requirement_kind=SOURCE_ARTIFACT_REQUIREMENT_KIND,
        ),
    }
    if not disclosures:
        return realized
    entries = dict(realized.entries)
    for address, disclosure in disclosures.items():
        entry = entries.get(address)
        if entry is not None:
            entries[address] = replace(
                entry,
                payload={**entry.payload, "artifact_satisfaction": disclosure},
            )
    return realized.with_entries(entries)


__all__ = (
    "bounded_apply_details",
    "capture_apparatus_observations",
    "with_artifact_satisfactions",
)
