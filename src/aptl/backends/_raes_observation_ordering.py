"""Release-scoped ordering compatibility for verified TechVault readback.

RAES's mixed-scope projection currently preserves sequence order recursively,
including for runtime inventories whose members have set/identity semantics.
The released TechVault runtime model canonicalizes those inventories before
APTL materializes them, so native readback can contain every exact member while
using a different presentation order.  OpenRAE/rae#1285 tracks replacing this
release-specific bridge with the upstream evidence/comparison contract.

This module never supplies a value or changes one.  It only restores the
authored presentation order when the content-addressed TechVault release is in
use and the declared and observed values are recursively multiset-identical.
Any missing, additional, or changed value is returned untouched and therefore
continues to fail RAES's exact realization gate.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

from raes_contracts.planning import ProvisioningPlan
from raes_processor.semantics.realization import (
    CONCERN_PAYLOAD_PATH,
    project_realization_concern,
)

from aptl.backends._raes_observation_helpers import ObservedResource
from aptl.backends.raes_planning_compat import (
    TECHVAULT_PACK_ID,
    TECHVAULT_PACK_VERSION,
)
from aptl.backends.raes_runtime_attestation import (
    TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST,
)
from aptl.core.scenario_bundle import PackIdentity

_MISSING = object()

# Every sequence in these released concern values is an inventory, identity
# set, or membership set.  Ordered execution surfaces such as container command
# and entrypoint are intentionally absent.
_TECHVAULT_IDENTITY_COLLECTION_CONCERNS = frozenset(
    {
        "forwarding-agents",
        "runtime-applications",
        "runtime-database-services",
        "runtime-dns-services",
        "runtime-file-services",
        "runtime-filesystem-inventory",
        "runtime-identity-authorities",
        "runtime-local-identity",
        "runtime-network-detection-engines",
        "runtime-platform-applications",
        "runtime-security-monitoring-managers",
        "runtime-service-manager-units",
    }
)


def align_techvault_identity_collection_observations(
    *,
    plan: ProvisioningPlan,
    observations: Mapping[str, ObservedResource],
    pack_identity: PackIdentity | None,
) -> dict[str, ObservedResource]:
    """Restore authored ordering only for equivalent verified collections."""

    aligned = dict(observations)
    if not _identified_release(pack_identity):
        return aligned
    declared_operations = {
        operation.address: operation for operation in plan.operations
    }
    for authority in plan.realization_authority:
        if authority.requirement_kind not in _TECHVAULT_IDENTITY_COLLECTION_CONCERNS:
            continue
        observed_resource = aligned.get(authority.address)
        concern_path = CONCERN_PAYLOAD_PATH.get(authority.requirement_kind)
        declared_operation = declared_operations.get(authority.address)
        if (
            observed_resource is None
            or concern_path is None
            or concern_path not in observed_resource.concerns
            or declared_operation is None
        ):
            continue
        # RAES evaluates realization against the submitted operation payload,
        # not the typed resource view.  The latter is exactly where runtime
        # model normalization changed these identity-collection orders.
        declared = _pointer_value(
            declared_operation.payload, authority.payload_pointer
        )
        if declared is _MISSING:
            continue
        recursive = authority.constraint_document is not None
        try:
            declared_projection = project_realization_concern(
                authority.requirement_kind,
                declared,
                recursive=recursive,
            )
            observed_projection = project_realization_concern(
                authority.requirement_kind,
                observed_resource.concerns[concern_path],
                observed=True,
                recursive=recursive,
            )
        except (TypeError, ValueError):
            continue
        reordered = _align_equivalent_value(declared_projection, observed_projection)
        if reordered is _MISSING:
            continue
        concerns = dict(observed_resource.concerns)
        concerns[concern_path] = reordered
        aligned[authority.address] = replace(observed_resource, concerns=concerns)
    return aligned


def _identified_release(identity: PackIdentity | None) -> bool:
    return bool(
        identity is not None
        and identity.pack_id == TECHVAULT_PACK_ID
        and identity.pack_version == TECHVAULT_PACK_VERSION
        and identity.set_digest == TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST
    )


def _pointer_value(document: object, pointer: str) -> object:
    """Resolve one RFC 6901 pointer without accepting malformed traversal."""

    if pointer == "":
        return document
    if not pointer.startswith("/"):
        return _MISSING
    current = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if token not in current:
                return _MISSING
            current = current[token]
        elif isinstance(current, list):
            try:
                index = int(token)
                current = current[index]
            except (ValueError, IndexError):
                return _MISSING
        else:
            return _MISSING
    return current


def _align_equivalent_value(declared: object, observed: object) -> object:
    """Return ``observed`` in declared collection order, or ``_MISSING``."""

    if isinstance(declared, Mapping) and isinstance(observed, Mapping):
        if set(declared) != set(observed):
            return _MISSING
        result: dict[object, object] = {}
        for key, declared_value in declared.items():
            aligned = _align_equivalent_value(declared_value, observed[key])
            if aligned is _MISSING:
                return _MISSING
            result[key] = aligned
        return result
    if isinstance(declared, list) and isinstance(observed, list):
        if len(declared) != len(observed):
            return _MISSING
        unused = list(observed)
        result = []
        for declared_item in declared:
            for index, observed_item in enumerate(unused):
                aligned = _align_equivalent_value(declared_item, observed_item)
                if aligned is not _MISSING:
                    result.append(aligned)
                    unused.pop(index)
                    break
            else:
                return _MISSING
        return result
    if type(declared) is type(observed) and declared == observed:
        return observed
    return _MISSING


__all__ = ("align_techvault_identity_collection_observations",)
