"""Select backend-owned implementations for semantically described nodes.

An env-pack may deliberately leave realization open while still describing the
in-world product and version precisely.  This module maps those portable facts
to an APTL Docker implementation.  It never selects through a closed scope and
never writes a runtime value unless the plan carries OPEN authority for that
exact concern.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from raes.runtime_configuration import RuntimeConfiguration
from raes_contracts.planning import (
    PlannedResource,
    ProvisioningPlan,
    RealizationAuthorityMode,
)

from aptl.backends._raes_backend_implementation_profiles import (
    matching_backend_implementation_profile,
    selected_backend_base,
)
from aptl.backends.raes_diagnostics import diagnostic
from aptl.core.deployment.realization import DeploymentImageRealization

if TYPE_CHECKING:
    from raes_contracts.diagnostics import Diagnostic


@dataclass(frozen=True)
class BackendNodeImplementation:
    """The implementation values APTL selected under open authority."""

    image: DeploymentImageRealization | None
    base_image_ref: str | None
    base_use_image_command: bool
    base_run_capabilities: tuple[str, ...]
    provider_kind: str
    provider_parameters: tuple[tuple[str, str], ...]
    runtime: RuntimeConfiguration
    selected_concerns: tuple[str, ...]


def select_backend_node_implementation(
    *,
    plan: ProvisioningPlan,
    resource: PlannedResource,
    runtime: RuntimeConfiguration | None,
    service_name: str | None,
    diagnostics: list[Diagnostic],
    component_root: Path = Path("."),
) -> BackendNodeImplementation | None:
    """Return an admitted semantic implementation, or no selection.

    A matching profile with insufficient authority is an admission error rather
    than a cue to fall back to the generic base materializer.  That fallback
    would itself choose a substrate outside the closed boundary.
    """

    profile = matching_backend_implementation_profile(runtime)
    base = selected_backend_base(runtime)
    if profile is None and base is None:
        return None
    if service_name is None or not _compute_substrate_is_open(plan, resource.address):
        diagnostics.append(_implementation_not_authorized(resource.address))
        return None

    runtime = runtime or RuntimeConfiguration()
    payload = runtime.model_dump(mode="python", by_alias=True)
    selections = profile.runtime_selections if profile is not None else {}
    additions = {
        concern: value
        for concern, value in selections.items()
        if _selection_is_absent(payload, concern)
    }
    unauthorized = sorted(
        concern
        for concern in additions
        if not _runtime_concern_is_open(plan, resource.address, concern)
    )
    if unauthorized:
        diagnostics.append(_implementation_not_authorized(resource.address))
        return None

    for concern, value in additions.items():
        _set_runtime_selection(payload, concern, value)
    try:
        selected_runtime = RuntimeConfiguration.model_validate(payload)
    except (TypeError, ValueError):
        diagnostics.append(_implementation_invalid(resource.address))
        return None

    return BackendNodeImplementation(
        image=(
            DeploymentImageRealization(
                address=resource.address,
                service_name=service_name,
                source_name=profile.source_name,
                source_version=profile.source_version,
                image_ref=profile.image_ref,
                mode=profile.image_mode,
                policy_rule="backend-open-profile",
                dockerfile_path=(
                    str(component_root / profile.dockerfile_relpath)
                    if profile.dockerfile_relpath
                    else None
                ),
                context_path=(
                    str(component_root / profile.context_relpath)
                    if profile.context_relpath
                    else None
                ),
                provenance={"backend_profile": 1},
            )
            if profile is not None
            else None
        ),
        base_image_ref=base.image_ref if base is not None else None,
        base_use_image_command=base.use_image_command if base is not None else False,
        base_run_capabilities=(base.run_capabilities if base is not None else ()),
        provider_kind=base.provider_kind if base is not None else "",
        provider_parameters=(base.provider_parameters if base is not None else ()),
        runtime=selected_runtime,
        selected_concerns=("compute-substrate", *sorted(additions)),
    )


def _compute_substrate_is_open(plan: ProvisioningPlan, address: str) -> bool:
    return any(
        constraint.address == address
        and constraint.concern == "compute-substrate"
        and constraint.posture == "open"
        for constraint in plan.realization_constraints
    )


def _runtime_concern_is_open(
    plan: ProvisioningPlan, address: str, concern: str
) -> bool:
    return any(
        authority.address == address
        and authority.requirement_kind == concern
        and authority.mode is RealizationAuthorityMode.OPEN
        for authority in plan.realization_authority
    )


def _selection_is_absent(payload: dict[str, object], concern: str) -> bool:
    value = _runtime_selection(payload, concern)
    if concern == "runtime-restart-policy":
        return value in (None, "", "unknown")
    return value in (None, "", [], {})


def _runtime_selection(payload: dict[str, object], concern: str) -> object:
    if concern == "runtime-environment":
        return payload.get("environment")
    if concern == "published-ports":
        return _nested(payload, "network", "published_ports")
    if concern == "linux-capabilities":
        return payload.get("linux_capabilities")
    if concern == "runtime-container-entrypoint":
        return _nested(payload, "container", "entrypoint")
    if concern == "runtime-container-command":
        return _nested(payload, "container", "command")
    if concern == "runtime-restart-policy":
        return _nested(payload, "operational_policy", "restart")
    if concern == "runtime-node-memory-limit":
        return _nested(payload, "operational_policy", "resource_limits", "memory")
    raise ValueError(f"Unsupported backend runtime selection concern: {concern}")


def _nested(payload: dict[str, object], *path: str) -> object:
    current: object = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _set_runtime_selection(
    payload: dict[str, object], concern: str, value: object
) -> None:
    selected = deepcopy(value)
    if concern == "runtime-environment":
        payload["environment"] = selected
    elif concern == "published-ports":
        _set_nested(payload, ("network", "published_ports"), selected)
    elif concern == "linux-capabilities":
        payload["linux_capabilities"] = selected
    elif concern == "runtime-container-entrypoint":
        _set_nested(payload, ("container", "entrypoint"), selected)
    elif concern == "runtime-container-command":
        _set_nested(payload, ("container", "command"), selected)
    elif concern == "runtime-restart-policy":
        _set_nested(payload, ("operational_policy", "restart"), selected)
    elif concern == "runtime-node-memory-limit":
        _set_nested(
            payload,
            ("operational_policy", "resource_limits", "memory"),
            selected,
        )
    else:
        raise ValueError(f"Unsupported backend runtime selection concern: {concern}")


def _set_nested(
    payload: dict[str, object], path: tuple[str, ...], value: object
) -> None:
    current = payload
    for key in path[:-1]:
        child = current.get(key)
        if not isinstance(child, dict):
            child = {}
            current[key] = child
        current = child
    current[path[-1]] = value


def _implementation_not_authorized(address: str) -> Diagnostic:
    return diagnostic(
        "aptl.provisioner.backend-implementation-not-authorized",
        address,
        "The matching backend implementation requires a realization choice that is not open.",
    )


def _implementation_invalid(address: str) -> Diagnostic:
    return diagnostic(
        "aptl.provisioner.backend-implementation-invalid",
        address,
        "The selected backend implementation does not form a valid runtime configuration.",
    )


__all__ = (
    "BackendNodeImplementation",
    "select_backend_node_implementation",
)
