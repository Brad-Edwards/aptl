"""Lower ACES stateful resources into typed deployment operations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import PlannedResource

from aptl.backends.aces_diagnostics import diagnostic
from aptl.backends.aces_realization_model import NodeRealization
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactOutput,
    DeploymentGeneratedArtifactRealization,
    DeploymentPersistentVolumeRealization,
    DeploymentStatefulConsumer,
    GeneratedArtifactKind,
    GeneratedArtifactLifecycle,
    ResourceSensitivity,
    StatefulConsumerAccessMode,
    VolumeAccessMode,
    VolumeLifecycle,
)

_GENERATORS = frozenset({"certificate_bundle", "rendered_config"})
_ARTIFACT_LIFECYCLES = frozenset({"regenerate_on_change", "reuse_valid"})
_SENSITIVITIES = frozenset({"public", "restricted", "secret"})
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
    spec = _spec(resource, diagnostics)
    if spec is None:
        return None
    generator = _choice(spec, "generator", _GENERATORS)
    lifecycle = _choice(spec, "lifecycle", _ARTIFACT_LIFECYCLES)
    provenance = _text(spec.get("provenance"))
    outputs = _outputs(resource, spec.get("outputs"), diagnostics)
    consumers = _consumers(resource, spec.get("consumers"), nodes, diagnostics)
    if (
        generator is None
        or lifecycle is None
        or provenance is None
        or not outputs
        or not consumers
    ):
        _append_invalid(resource, diagnostics)
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


def _persistent_volume(
    resource: PlannedResource,
    nodes: dict[str, NodeRealization],
    diagnostics: list[Diagnostic],
) -> DeploymentPersistentVolumeRealization | None:
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
    if not isinstance(raw_outputs, list):
        return []
    outputs: list[DeploymentGeneratedArtifactOutput] = []
    for raw in raw_outputs:
        if not isinstance(raw, Mapping):
            return []
        name = _text(raw.get("name"))
        path = _text(raw.get("path"))
        sensitivity = _choice(raw, "sensitivity", _SENSITIVITIES)
        if name is None or path is None or sensitivity is None:
            return []
        outputs.append(
            DeploymentGeneratedArtifactOutput(
                name=name,
                path=path,
                sensitivity=cast(ResourceSensitivity, sensitivity),
            )
        )
    if len({output.name for output in outputs}) != len(outputs):
        _append_invalid(resource, diagnostics)
        return []
    return outputs


def _consumers(
    resource: PlannedResource,
    raw_consumers: object,
    nodes: dict[str, NodeRealization],
    diagnostics: list[Diagnostic],
) -> list[DeploymentStatefulConsumer]:
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
    if not isinstance(raw, Mapping):
        _append_invalid(resource, diagnostics)
        return None
    target_address = _text(raw.get("target_address"))
    node_name = _text(raw.get("node"))
    mount_destination = _text(raw.get("mount_destination"))
    access_mode = _choice(raw, "access_mode", _CONSUMER_ACCESS_MODES)
    node = nodes.get(target_address or "")
    if node is None:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.stateful-consumer-unresolved",
                resource.address,
                "Stateful resource consumer does not resolve to an admitted node.",
            )
        )
        return None
    service_name = _only(node.backend_services)
    if service_name is None:
        diagnostics.append(
            diagnostic(
                "aptl.provisioner.stateful-consumer-service-unresolved",
                resource.address,
                "Stateful resource consumer does not resolve to one backend service.",
            )
        )
        return None
    if node_name is None or mount_destination is None or access_mode is None:
        _append_invalid(resource, diagnostics)
        return None
    return DeploymentStatefulConsumer(
        target_address=node.address,
        node_name=node_name,
        service_name=service_name,
        mount_destination=mount_destination,
        access_mode=cast(StatefulConsumerAccessMode, access_mode),
    )


def _append_destination_conflicts(
    artifacts: list[DeploymentGeneratedArtifactRealization],
    volumes: list[DeploymentPersistentVolumeRealization],
    diagnostics: list[Diagnostic],
) -> None:
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
    return _text(resource.payload.get("name")) or resource.address.rsplit(".", 1)[-1]


def _choice(
    mapping: Mapping[str, object],
    key: str,
    allowed: frozenset[str],
) -> str | None:
    value = _text(mapping.get(key))
    return value if value in allowed else None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _only(values: tuple[str, ...]) -> str | None:
    return values[0] if len(values) == 1 else None
