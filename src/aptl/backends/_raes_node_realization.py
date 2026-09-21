"""Lower one planned RAES node into APTL's node realization model."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from raes.runtime_configuration import RuntimeConfiguration
from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import PlannedResource, ProvisioningPlan

from aptl.backends._raes_conformance_probe import (
    _conformance_probe_services,
    _is_raes_conformance_probe_node,
)
from aptl.backends.raes_backend_implementation import (
    BackendNodeImplementation,
    select_backend_node_implementation,
)
from aptl.backends.raes_base_substrate import base_container_spec
from aptl.backends.raes_image_realization import (
    node_source_is_dynamic_composition,
    resolve_node_image,
)
from aptl.backends.raes_profiles import ComposeProfileIndex, node_aliases
from aptl.backends.raes_realization_model import (
    NodeRealization,
    _single_or_none,
)
from aptl.backends.raes_realization_values import (
    mapping as _mapping,
    network_names as _network_names,
    published_ports as _published_ports,
    resource_name as _resource_name,
    service_ports as _service_ports,
    static_address_assignments as _static_address_assignments,
    static_addresses as _static_addresses,
)
from aptl.core.config import AptlConfig
from aptl.core.deployment.realization import DeploymentImageRealization


@dataclass(frozen=True)
class _NodeBinding:
    """Static Compose binding resolved for one planned node."""

    aliases: frozenset[str]
    backend_services: frozenset[str]
    profiles: frozenset[str]
    node_name: str


def _realize_node(
    plan: ProvisioningPlan,
    resource: PlannedResource,
    payload: Mapping[str, Any],
    profile_index: ComposeProfileIndex,
    component_root: Path,
    config: AptlConfig,
    diagnostics: list[Diagnostic],
) -> NodeRealization:
    """Realize one node from portable declarations and admitted backend choices."""

    binding = _node_binding(resource, payload, profile_index, config)
    node_spec, infra_spec = _node_specs(payload)
    node_os = _node_os(node_spec)
    node_os_version = _node_os_version(node_spec)
    node_runtime = _node_runtime(node_spec)
    service_name = _single_or_none(tuple(sorted(binding.backend_services)))
    node_services = _service_ports(node_spec)
    dynamic = node_source_is_dynamic_composition(payload, resource.address)
    authored_image = resolve_node_image(
        resource=resource,
        payload=payload,
        project_dir=component_root,
        service_name=service_name,
        diagnostics=diagnostics,
    )
    implementation = None
    if authored_image is None and not dynamic:
        implementation = select_backend_node_implementation(
            plan=plan,
            resource=resource,
            runtime=node_runtime,
            service_name=service_name,
            services=node_services,
            component_root=component_root,
            diagnostics=diagnostics,
        )
    if implementation is not None:
        node_runtime = implementation.runtime
    return NodeRealization(
        address=resource.address,
        name=_resource_name(resource.address, payload),
        aliases=tuple(sorted(binding.aliases)),
        profiles=tuple(sorted(binding.profiles)),
        backend_services=tuple(sorted(binding.backend_services)),
        container_name=_resolved_container_name(
            resource,
            profile_index,
            binding.backend_services,
            binding.node_name,
            node_os=node_os,
            node_os_version=node_os_version,
            node_runtime=node_runtime,
        ),
        services=node_services,
        networks=tuple(sorted(_network_names(infra_spec))),
        static_addresses=tuple(sorted(_static_addresses(infra_spec))),
        static_address_assignments=_static_address_assignments(infra_spec),
        published_ports=_runtime_published_ports(node_runtime),
        image=_selected_image(authored_image, implementation),
        ordering_dependencies=resource.ordering_dependencies,
        os=node_os,
        os_version=node_os_version,
        runtime=node_runtime,
        dynamic_composition=dynamic,
        **_backend_details(implementation),
    )


def _node_binding(
    resource: PlannedResource,
    payload: Mapping[str, Any],
    profile_index: ComposeProfileIndex,
    config: AptlConfig,
) -> _NodeBinding:
    """Resolve aliases, services, and profiles for one node."""

    aliases = node_aliases(resource.address, payload)
    services = profile_index.service_names_for_aliases(aliases)
    profiles = profile_index.profiles_for_aliases(
        aliases
    ) | profile_index.profiles_for_services(set(services))
    if not profiles and _is_raes_conformance_probe_node(resource, payload):
        services = _conformance_probe_services(profile_index, config)
        profiles = profile_index.profiles_for_services(set(services))
    node_name = resource.address.rsplit(".", 1)[-1]
    return _NodeBinding(
        aliases=frozenset(aliases),
        backend_services=services or frozenset({node_name}),
        profiles=frozenset(profiles),
        node_name=node_name,
    )


def _node_specs(
    payload: Mapping[str, Any],
) -> tuple[Mapping[str, Any] | None, Mapping[str, Any] | None]:
    """Return the node and infrastructure sections of one resource payload."""

    spec = _mapping(payload.get("spec"))
    node_spec = _mapping(spec.get("node")) if spec else None
    infra_spec = _mapping(spec.get("infrastructure")) if spec else None
    return node_spec, infra_spec


def _selected_image(
    authored: DeploymentImageRealization | None,
    implementation: BackendNodeImplementation | None,
) -> DeploymentImageRealization | None:
    """Prefer the authored image, otherwise use the admitted backend image."""

    return authored if authored is not None else getattr(implementation, "image", None)


def _backend_details(
    implementation: BackendNodeImplementation | None,
) -> dict[str, object]:
    """Return backend-added node fields, including all selected concerns."""

    if implementation is None:
        return {
            "backend_selected_concerns": (),
            "backend_base_image_ref": None,
            "backend_base_use_image_command": False,
            "backend_run_capabilities": (),
            "backend_provider_kind": "",
            "backend_provider_parameters": (),
            "backend_generated_artifacts": (),
        }
    return {
        "backend_selected_concerns": implementation.selected_concerns,
        "backend_base_image_ref": implementation.base_image_ref,
        "backend_base_use_image_command": implementation.base_use_image_command,
        "backend_run_capabilities": implementation.base_run_capabilities,
        "backend_provider_kind": implementation.provider_kind,
        "backend_provider_parameters": implementation.provider_parameters,
        "backend_generated_artifacts": implementation.generated_artifacts,
    }


def _runtime_published_ports(
    runtime: RuntimeConfiguration | None,
) -> tuple[object, ...]:
    """Extract published ports after backend-open runtime selection."""

    if runtime is None:
        return ()
    return _published_ports(
        {"runtime": runtime.model_dump(mode="python", by_alias=True)}
    )


def _resolved_container_name(
    resource: PlannedResource,
    profile_index: ComposeProfileIndex,
    backend_services: frozenset[str],
    node_name: str,
    *,
    node_os: str,
    node_os_version: str,
    node_runtime: RuntimeConfiguration | None,
) -> str:
    """Return the static, materialized, or convention-derived container name."""

    container_name = _container_name(profile_index, backend_services)
    if container_name is None and node_runtime is not None and node_os:
        container_name = base_container_spec(
            resource.address,
            os=node_os,
            os_version=node_os_version,
            runtime=node_runtime,
        ).container_name
    if container_name is None:
        container_name = (
            node_name if node_name.startswith("aptl-") else f"aptl-{node_name}"
        )
    return container_name


def _node_os(node_spec: Mapping[str, Any] | None) -> str:
    """Return the node's declared OS family, or empty when undeclared."""

    return str(node_spec.get("os") or "") if node_spec else ""


def _node_os_version(node_spec: Mapping[str, Any] | None) -> str:
    """Return the node's declared OS version, or empty when undeclared."""

    return str(node_spec.get("os_version") or "") if node_spec else ""


def _node_runtime(node_spec: Mapping[str, Any] | None) -> RuntimeConfiguration | None:
    """Reconstruct the typed runtime, failing closed on absent or invalid input."""

    raw = node_spec.get("runtime") if node_spec else None
    if not isinstance(raw, Mapping):
        return None
    try:
        return RuntimeConfiguration.model_validate(dict(raw))
    except (ValueError, TypeError):
        return None


def _container_name(
    profile_index: ComposeProfileIndex,
    service_names: frozenset[str],
) -> str | None:
    """Return the concrete container name for an unambiguous service binding."""

    service = (
        profile_index.services.get(next(iter(service_names)))
        if len(service_names) == 1
        else None
    )
    return service.container_name or service.name if service is not None else None


__all__ = (
    "_container_name",
    "_node_os",
    "_node_os_version",
    "_node_runtime",
    "_realize_node",
)
