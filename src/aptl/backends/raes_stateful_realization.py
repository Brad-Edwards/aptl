"""Lower RAES stateful resources into typed deployment operations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import PlannedResource

from aptl.backends.raes_diagnostics import diagnostic
from aptl.backends.raes_realization_model import NodeRealization
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactOutput,
    DeploymentGeneratedArtifactRealization,
    DeploymentPersistentVolumeRealization,
    DeploymentStatefulConsumer,
    GeneratedArtifactKind,
    GeneratedArtifactLifecycle,
    GeneratedArtifactOutputDisposition,
    ResourceSensitivity,
    StatefulConsumerAccessMode,
    VolumeAccessMode,
    VolumeLifecycle,
)

_GENERATORS = frozenset({"certificate_bundle", "rendered_config", "ssh_key_bundle"})
_ARTIFACT_LIFECYCLES = frozenset({"regenerate_on_change", "reuse_valid"})
_SENSITIVITIES = frozenset({"public", "restricted", "secret"})
_DISPOSITIONS = frozenset({"consumer_selected", "producer_private"})
_CONSUMER_ACCESS_MODES = frozenset({"read_only", "read_write"})
_VOLUME_LIFECYCLES = frozenset({"retain", "ephemeral"})
_VOLUME_ACCESS_MODES = frozenset(
    {"read_write_once", "read_write_many", "read_only_many"}
)


def realize_stateful_resources(
    resources: list[PlannedResource],
    nodes: list[NodeRealization],
    diagnostics: list[Diagnostic],
) -> tuple[
    list[DeploymentGeneratedArtifactRealization],
    list[DeploymentPersistentVolumeRealization],
]:
    """Return stateful resources whose complete backend binding is valid."""

    node_by_address = {node.address: node for node in nodes}
    artifacts: list[DeploymentGeneratedArtifactRealization] = []
    volumes: list[DeploymentPersistentVolumeRealization] = []
    for resource in resources:
        if resource.resource_type == "generated-artifact":
            artifact = _generated_artifact(resource, node_by_address, diagnostics)
            if artifact is not None:
                artifacts.append(artifact)
        elif resource.resource_type == "persistent-volume":
            volume = _persistent_volume(resource, node_by_address, diagnostics)
            if volume is not None:
                volumes.append(volume)
    _append_destination_conflicts(artifacts, volumes, diagnostics)
    invalid_addresses = {
        item.address
        for item in diagnostics
        if item.code.startswith("aptl.provisioner.stateful-")
    }
    return (
        [item for item in artifacts if item.address not in invalid_addresses],
        [item for item in volumes if item.address not in invalid_addresses],
    )


def _generated_artifact(
    resource: PlannedResource,
    nodes: dict[str, NodeRealization],
    diagnostics: list[Diagnostic],
) -> DeploymentGeneratedArtifactRealization | None:
    """Lower one valid generated-artifact resource into the deployment DTO."""

    spec = _spec(resource, diagnostics)
    if spec is None:
        return None
    generator = _choice(spec, "generator", _GENERATORS)
    lifecycle = _choice(spec, "lifecycle", _ARTIFACT_LIFECYCLES)
    provenance = _text(spec.get("provenance"))
    outputs = _outputs(resource, spec.get("outputs"), diagnostics)
    consumers = _consumers(resource, spec.get("consumers"), nodes, diagnostics)
    incomplete = (
        generator is None
        or lifecycle is None
        or provenance is None
        or not outputs
        or not consumers
    )
    if incomplete:
        _append_invalid(resource, diagnostics)
    # Selection is checked only for a complete declaration: an incomplete one is
    # already rejected, and re-reporting it as a selection failure would
    # double-count the same resource.
    if incomplete or not _selection_valid(resource, outputs, consumers, diagnostics):
        return None
    return DeploymentGeneratedArtifactRealization(
        address=resource.address,
        name=_resource_name(resource),
        generator=cast(GeneratedArtifactKind, generator),
        lifecycle=cast(GeneratedArtifactLifecycle, lifecycle),
        provenance=provenance,
        outputs=tuple(outputs),
        consumers=tuple(consumers),
        ordering_dependencies=resource.ordering_dependencies,
        refresh_dependencies=resource.refresh_dependencies,
    )


def _selection_valid(
    resource: PlannedResource,
    outputs: list[DeploymentGeneratedArtifactOutput],
    consumers: list[DeploymentStatefulConsumer],
    diagnostics: list[Diagnostic],
) -> bool:
    """Reject a consumer that selects an undeclared or producer-private output.

    A ``producer_private`` output must never be mounted into any consumer, and a
    consumer can only select an output the artifact declares. Either violation
    fails closed before any key material is generated.
    """

    by_name = {output.name: output for output in outputs}
    for consumer in consumers:
        for name in consumer.selected_outputs:
            output = by_name.get(name)
            if output is None or output.disposition == "producer_private":
                diagnostics.append(
                    diagnostic(
                        "aptl.provisioner.stateful-output-not-selectable",
                        resource.address,
                        "Consumer selects an undeclared or producer-private "
                        "generated-artifact output.",
                    )
                )
                return False
    return True


def _persistent_volume(
    resource: PlannedResource,
    nodes: dict[str, NodeRealization],
    diagnostics: list[Diagnostic],
) -> DeploymentPersistentVolumeRealization | None:
    """Lower one valid persistent-volume resource into the deployment DTO."""

    spec = _spec(resource, diagnostics)
    if spec is None:
        return None
    lifecycle = _choice(spec, "lifecycle", _VOLUME_LIFECYCLES)
    access_mode = _choice(spec, "access_mode", _VOLUME_ACCESS_MODES)
    consumers = _consumers(resource, spec.get("consumers"), nodes, diagnostics)
    if lifecycle is None or access_mode is None or not consumers:
        _append_invalid(resource, diagnostics)
        return None
    return DeploymentPersistentVolumeRealization(
        address=resource.address,
        name=_resource_name(resource),
        lifecycle=cast(VolumeLifecycle, lifecycle),
        access_mode=cast(VolumeAccessMode, access_mode),
        consumers=tuple(consumers),
        ordering_dependencies=resource.ordering_dependencies,
        refresh_dependencies=resource.refresh_dependencies,
    )


def _spec(
    resource: PlannedResource,
    diagnostics: list[Diagnostic],
) -> Mapping[str, Any] | None:
    """Return a resource's mapping-valued spec or record invalid input."""

    raw = resource.payload.get("spec")
    if isinstance(raw, Mapping):
        return raw
    _append_invalid(resource, diagnostics)
    return None


def _outputs(
    resource: PlannedResource,
    raw_outputs: object,
    diagnostics: list[Diagnostic],
) -> list[DeploymentGeneratedArtifactOutput]:
    """Parse a generated artifact's unique typed output declarations."""

    if not isinstance(raw_outputs, list):
        return []
    parsed_outputs = [_output(raw) for raw in raw_outputs]
    if any(output is None for output in parsed_outputs):
        return []
    outputs = [output for output in parsed_outputs if output is not None]
    if len({output.name for output in outputs}) != len(outputs):
        _append_invalid(resource, diagnostics)
        outputs = []
    return outputs


def _output(raw: object) -> DeploymentGeneratedArtifactOutput | None:
    """Parse one generated-artifact output declaration."""

    if not isinstance(raw, Mapping):
        return None
    name = _text(raw.get("name"))
    path = _text(raw.get("path"))
    sensitivity = _choice(raw, "sensitivity", _SENSITIVITIES)
    # disposition defaults to consumer_selected when the SDL omits it (the RAES
    # default), so certificate/rendered-config outputs authored before the
    # disposition field keep lowering unchanged.
    disposition = raw.get("disposition", "consumer_selected")
    if (
        name is None
        or path is None
        or sensitivity is None
        or disposition not in _DISPOSITIONS
    ):
        return None
    return DeploymentGeneratedArtifactOutput(
        name=name,
        path=path,
        sensitivity=cast(ResourceSensitivity, sensitivity),
        disposition=cast(GeneratedArtifactOutputDisposition, disposition),
    )


def _consumers(
    resource: PlannedResource,
    raw_consumers: object,
    nodes: dict[str, NodeRealization],
    diagnostics: list[Diagnostic],
) -> list[DeploymentStatefulConsumer]:
    """Parse every consumer, rejecting an incomplete consumer collection."""

    if not isinstance(raw_consumers, list):
        return []
    consumers: list[DeploymentStatefulConsumer] = []
    for raw in raw_consumers:
        consumer = _consumer(resource, raw, nodes, diagnostics)
        if consumer is None:
            return []
        consumers.append(consumer)
    return consumers


def _consumer(
    resource: PlannedResource,
    raw: object,
    nodes: dict[str, NodeRealization],
    diagnostics: list[Diagnostic],
) -> DeploymentStatefulConsumer | None:
    """Resolve one stateful consumer to exactly one admitted backend service."""

    if not isinstance(raw, Mapping):
        _append_invalid(resource, diagnostics)
        return None
    target_address = _text(raw.get("target_address"))
    node_name = _text(raw.get("node"))
    mount_destination = _text(raw.get("mount_destination"))
    access_mode = _choice(raw, "access_mode", _CONSUMER_ACCESS_MODES)
    node = nodes.get(target_address or "")
    service_name = _only(node.backend_services) if node is not None else None
    if node is None:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.stateful-consumer-unresolved",
                resource.address,
                "Stateful resource consumer does not resolve to an admitted node.",
            )
        )
    elif service_name is None:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.stateful-consumer-service-unresolved",
                resource.address,
                "Stateful resource consumer does not resolve to one backend service.",
            )
        )
    elif node_name is None or mount_destination is None or access_mode is None:
        _append_invalid(resource, diagnostics)
    else:
        selected = _selected_outputs(raw.get("selected_outputs"))
        if selected is None:
            _append_invalid(resource, diagnostics)
        else:
            return DeploymentStatefulConsumer(
                target_address=node.address,
                node_name=node_name,
                service_name=service_name,
                mount_destination=mount_destination,
                access_mode=cast(StatefulConsumerAccessMode, access_mode),
                selected_outputs=selected,
            )
    return None


def _selected_outputs(raw: object) -> tuple[str, ...] | None:
    """Parse a consumer's ``selected_outputs`` (empty when absent)."""

    if raw is None:
        return ()
    if not isinstance(raw, list):
        return None
    return _distinct_output_names(raw)


def _distinct_output_names(raw: list[object]) -> tuple[str, ...] | None:
    """Return the declared names, or None when one is malformed or repeated."""

    names = [_text(item) for item in raw]
    if any(name is None for name in names) or len(set(names)) != len(names):
        return None
    return tuple(cast(str, name) for name in names)


def _append_destination_conflicts(
    artifacts: list[DeploymentGeneratedArtifactRealization],
    volumes: list[DeploymentPersistentVolumeRealization],
    diagnostics: list[Diagnostic],
) -> None:
    """Report multiple stateful resources claiming one consumer destination."""

    occupied: dict[tuple[str, str], str] = {}
    for resource in [*artifacts, *volumes]:
        for consumer in resource.consumers:
            destination = (consumer.target_address, consumer.mount_destination)
            owner = occupied.setdefault(destination, resource.address)
            if owner != resource.address:
                diagnostics.append(
                    diagnostic(
                        "aptl.provisioner.stateful-mount-conflict",
                        resource.address,
                        "Stateful resources claim the same consumer mount destination.",
                    )
                )


def _append_invalid(
    resource: PlannedResource,
    diagnostics: list[Diagnostic],
) -> None:
    """Append the stable invalid-resource diagnostic at most once per address."""

    if any(
        item.address == resource.address
        and item.code == "aptl.provisioner.stateful-resource-invalid"
        for item in diagnostics
    ):
        return
    diagnostics.append(
        diagnostic(
            "aptl.provisioner.stateful-resource-invalid",
            resource.address,
            "Stateful resource payload is incomplete or unsupported by APTL.",
        )
    )


def _resource_name(resource: PlannedResource) -> str:
    """Return the authored resource name or its address suffix."""

    return _text(resource.payload.get("name")) or resource.address.rsplit(".", 1)[-1]


def _choice(
    mapping: Mapping[str, object],
    key: str,
    allowed: frozenset[str],
) -> str | None:
    """Return a non-empty string only when it belongs to the allowed vocabulary."""

    value = _text(mapping.get(key))
    return value if value in allowed else None


def _text(value: object) -> str | None:
    """Return a non-empty string value without altering authored whitespace."""

    return value if isinstance(value, str) and value.strip() else None


def _only(values: tuple[str, ...]) -> str | None:
    """Return the sole tuple member, rejecting absent or ambiguous bindings."""

    return values[0] if len(values) == 1 else None
