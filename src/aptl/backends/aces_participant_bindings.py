"""Runtime-derived participant action binding parser."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import re

import yaml

from aces_contracts.planning import ProvisioningPlan

from aptl.backends.aces_profiles import (
    ComposeProfileIndex,
    ComposeServiceInfo,
    load_compose_profile_index,
    normalize_identifier,
)
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.backends.aces_realization_model import AptlRealization, NodeRealization
from aptl.core.config import AptlConfig

_BINDING_SCHEMA = "aptl-participant-runtime-binding/v1"
_BINDING_TAGS = frozenset({"aptl-participant-runtime-binding"})
_PLACEHOLDER = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


@dataclass(frozen=True)
class _BindingContext:
    realization: AptlRealization
    profile_index: ComposeProfileIndex
    provisioning_plan: ProvisioningPlan

    def node(self, ref: str) -> NodeRealization | None:
        node_name = _node_name(ref)
        if node_name is None:
            return None
        for node in self.realization.nodes:
            if ref in {node.address, node.name} or node_name in {node.name, node.address}:
                return node
        return None

    def service(self, ref: str) -> tuple[NodeRealization, Mapping[str, object]] | None:
        service_ref = _node_service_ref(ref)
        if service_ref is None:
            return None
        node_name, service_name = service_ref
        node = self.node(f"nodes.{node_name}")
        resource = self.provisioning_plan.resources.get(f"provision.node.{node_name}")
        payload = resource.payload if resource is not None else None
        services = _node_services(payload)
        service = services.get(service_name)
        if node is None or service is None:
            return None
        return node, service

    def container_name(self, ref: str) -> str | None:
        node = self.node(ref)
        return node.container_name if node is not None else None

    def service_port(self, ref: str) -> int | None:
        resolved = self.service(ref)
        if resolved is None:
            return None
        raw = resolved[1].get("port")
        return raw if isinstance(raw, int) and raw > 0 else None

    def service_host(self, ref: str, source_ref: str) -> str | None:
        resolved = self.service(ref)
        if resolved is None:
            return None
        target_node, _service_payload = resolved
        service_info = self._compose_service(target_node)
        if service_info is None:
            return None
        source_node = self.node(source_ref)
        return _select_service_address(service_info, source_node, target_node)

    def _compose_service(self, node: NodeRealization) -> ComposeServiceInfo | None:
        for service_name in node.backend_services:
            service = self.profile_index.services.get(service_name)
            if service is not None:
                return service
        return None


def participant_action_specs_from_runtime_model(
    model: object,
    *,
    provisioning_plan: ProvisioningPlan,
    project_dir: Path,
    config: AptlConfig,
    spec_factory: Callable[..., object],
) -> dict[str, object]:
    """Build participant action specs from compiled runtime binding content."""

    context = _BindingContext(
        realization=interpret_provisioning_plan(
            plan=provisioning_plan,
            project_dir=project_dir,
            config=config,
        ),
        profile_index=load_compose_profile_index(project_dir),
        provisioning_plan=provisioning_plan,
    )
    specs: dict[str, object] = {}
    for binding in _runtime_bindings(model):
        try:
            participant_address, spec = _spec_from_binding(
                binding,
                model=model,
                context=context,
                spec_factory=spec_factory,
            )
        except (TypeError, ValueError, yaml.YAMLError):
            continue
        specs[participant_address] = spec
    return specs


def _runtime_bindings(model: object) -> list[Mapping[str, object]]:
    """Return structured participant binding payloads from compiled content."""

    bindings: list[Mapping[str, object]] = []
    for placement in _compiled_artifact_mapping(model, "content_placements").values():
        spec = getattr(placement, "spec", {})
        if not isinstance(spec, Mapping):
            continue
        tags = {str(tag) for tag in spec.get("tags", ())}
        text = spec.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        parsed = yaml.safe_load(text)
        if not isinstance(parsed, Mapping):
            continue
        if parsed.get("schema_version") != _BINDING_SCHEMA and not tags & _BINDING_TAGS:
            continue
        bindings.append(parsed)
    return bindings


def _spec_from_binding(
    binding: Mapping[str, object],
    *,
    model: object,
    context: _BindingContext,
    spec_factory: Callable[..., object],
) -> tuple[str, object]:
    """Build one participant action spec from a validated binding payload."""

    if binding.get("runtime_target") != "aptl":
        raise ValueError("unsupported runtime target")
    participant_address = _participant_address(_required_string(binding, "participant_ref"))
    action_contract_address = _action_contract_address(
        _required_string(binding, "action_contract_ref")
    )
    observation_boundary_address = _observation_boundary_address(
        _required_string(binding, "observation_boundary_ref")
    )
    _assert_compiled_addresses(
        model,
        participant_address,
        action_contract_address,
        observation_boundary_address,
    )
    source_ref = _required_string(binding, "source_container_ref")
    source_container = context.container_name(source_ref)
    if source_container is None:
        raise ValueError("source container ref did not resolve")
    command = _binding_mapping(binding.get("command"))
    argv = tuple(
        _render_template(value, context=context, source_ref=source_ref)
        for value in _string_list(command.get("argv"))
    )
    success_markers = tuple(_string_list(binding.get("success_markers")))
    target_refs = tuple(
        _render_template(value, context=context, source_ref=source_ref)
        for value in _string_list(binding.get("target_refs"))
    )
    if not argv or not success_markers:
        raise ValueError("binding must declare command argv and success markers")
    return participant_address, spec_factory(
        source_container=source_container,
        command=argv,
        success_markers=success_markers,
        action_contract_address=action_contract_address,
        observation_boundary_address=observation_boundary_address,
        actor_provenance=_optional_string(binding, "actor_provenance")
        or "scenario-runtime-binding",
        target_refs=target_refs,
        timeout_seconds=_optional_positive_int(binding, "timeout_seconds") or 120,
    )


def _assert_compiled_addresses(
    model: object,
    participant_address: str,
    action_contract_address: str,
    observation_boundary_address: str,
) -> None:
    behaviors = _compiled_artifact_mapping(model, "participant_behaviors")
    action_contracts = _compiled_artifact_mapping(model, "action_contracts")
    observation_boundaries = _compiled_artifact_mapping(model, "observation_boundaries")
    behavior = behaviors.get(participant_address)
    if (
        behavior is None
        or action_contract_address not in action_contracts
        or observation_boundary_address not in observation_boundaries
    ):
        raise ValueError("binding references uncompiled participant artifacts")
    if action_contract_address not in getattr(behavior, "action_contract_addresses", ()):
        raise ValueError("binding action contract is not assigned to participant")
    if observation_boundary_address not in getattr(
        behavior, "observation_boundary_addresses", ()
    ):
        raise ValueError("binding observation boundary is not assigned to participant")


def _render_template(
    template: str,
    *,
    context: _BindingContext,
    source_ref: str,
) -> str:
    """Render constrained runtime placeholders inside one binding string."""

    def replace(match: re.Match[str]) -> str:
        return _resolve_placeholder(match.group(1), context, source_ref)

    return _PLACEHOLDER.sub(replace, template)


def _resolve_placeholder(
    token: str,
    context: _BindingContext,
    source_ref: str,
) -> str:
    parts = [part.strip() for part in token.split(":", 3)]
    if len(parts) < 2:
        raise ValueError("runtime binding placeholder is missing a ref")
    kind, ref = parts[0], parts[1]
    if kind == "container":
        value = context.container_name(ref)
    elif kind == "service_host":
        value = context.service_host(ref, source_ref)
    elif kind == "service_port":
        port = context.service_port(ref)
        value = str(port) if port is not None else None
    elif kind == "service_url" and len(parts) == 4:
        host = context.service_host(ref, source_ref)
        port = context.service_port(ref)
        value = (
            f"{parts[2]}://{host}:{port}{parts[3]}"
            if host is not None and port is not None
            else None
        )
    else:
        value = None
    if value is None:
        raise ValueError(f"runtime binding placeholder did not resolve: {token}")
    return value


def _select_service_address(
    service: ComposeServiceInfo,
    source_node: NodeRealization | None,
    target_node: NodeRealization,
) -> str | None:
    if source_node is not None:
        shared = set(source_node.networks) & set(target_node.networks)
        value = _address_for_aces_networks(service, shared)
        if value is not None:
            return value
    value = _address_for_aces_networks(service, set(target_node.networks))
    if value is not None:
        return value
    return next(
        (address for _network, address in sorted(service.network_addresses.items())),
        None,
    )


def _address_for_aces_networks(
    service: ComposeServiceInfo,
    aces_networks: set[str],
) -> str | None:
    desired_aliases = set().union(*(_network_aliases(network) for network in aces_networks))
    for network_name, address in sorted(service.network_addresses.items()):
        if desired_aliases & _network_aliases(network_name):
            return address
    return None


def _network_aliases(raw: str) -> set[str]:
    normalized = normalize_identifier(raw)
    aliases = {normalized}
    for value in tuple(aliases):
        if value.startswith("aptl-"):
            aliases.add(value.removeprefix("aptl-"))
        if value.endswith("-net"):
            aliases.add(value.removesuffix("-net"))
    return {alias for alias in aliases if alias}


def _node_services(payload: object) -> dict[str, Mapping[str, object]]:
    if not isinstance(payload, Mapping):
        return {}
    spec = payload.get("spec")
    node = spec.get("node") if isinstance(spec, Mapping) else None
    services = node.get("services") if isinstance(node, Mapping) else None
    if not isinstance(services, list):
        return {}
    return {
        str(service.get("name")): service
        for service in services
        if isinstance(service, Mapping)
        and isinstance(service.get("name"), str)
        and service.get("name")
    }


def _node_service_ref(ref: str) -> tuple[str, str] | None:
    if not ref.startswith("nodes."):
        return None
    node_name, sep, service_name = ref[len("nodes.") :].partition(".services.")
    if not sep or not node_name or not service_name:
        return None
    return node_name, service_name


def _node_name(ref: str) -> str | None:
    if ref.startswith("nodes."):
        return ref[len("nodes.") :].split(".", 1)[0]
    if ref.startswith("provision.node."):
        return ref[len("provision.node.") :].split(".", 1)[0]
    return ref if ref else None


def _participant_address(ref: str) -> str:
    return ref if ref.startswith("participant.behavior.") else f"participant.behavior.{ref}"


def _action_contract_address(ref: str) -> str:
    return (
        ref
        if ref.startswith("participant.action-contract.")
        else f"participant.action-contract.{ref}"
    )


def _observation_boundary_address(ref: str) -> str:
    return (
        ref
        if ref.startswith("participant.observation-boundary.")
        else f"participant.observation-boundary.{ref}"
    )


def _compiled_artifact_mapping(model: object, attribute: str) -> Mapping[str, object]:
    value = getattr(model, attribute, {})
    return value if isinstance(value, Mapping) else {}


def _binding_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("runtime binding field must be a mapping")
    return value


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]


def _required_string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"runtime binding requires {key}")
    return value


def _optional_string(mapping: Mapping[str, object], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) and value.strip() else None


def _optional_positive_int(mapping: Mapping[str, object], key: str) -> int | None:
    value = mapping.get(key)
    return value if isinstance(value, int) and value > 0 else None
