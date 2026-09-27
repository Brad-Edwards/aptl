"""Compose ownership overrides derived from a workspace's admitted resource model."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from aptl.utils.pathsafe import (
    PathContainmentError,
    create_exclusive_nofollow,
    read_contained_nofollow,
)

if TYPE_CHECKING:
    from aptl.core.deployment._compose_resource_ownership import WorkspaceOwnership

_SAFE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+\-=]{0,254}$")
_OVERRIDE_UNAVAILABLE = "Compose ownership override is unavailable"


class _ComposeLoader(yaml.SafeLoader):
    """Safe YAML loader with Compose's provider-only ``!reset`` tag."""


def _compose_reset(loader: _ComposeLoader, node: yaml.Node) -> object:
    """Decode a Compose reset value without permitting arbitrary YAML types."""

    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    raise yaml.constructor.ConstructorError(
        None, None, "unsupported !reset value", node.start_mark
    )


_ComposeLoader.add_constructor("!reset", _compose_reset)


class OwnershipConflictError(RuntimeError):
    """Raised when backend ownership cannot be established unambiguously."""


def write_compose_ownership_override(
    ownership: WorkspaceOwnership,
    *,
    attempt_id: str,
    compose_files: tuple[Path, ...],
) -> tuple[Path, dict[str, str], dict[str, tuple[str, ...]]]:
    """Write the final provider-only ownership override and resource plan."""

    services, networks, volumes = _merged_compose_sections(compose_files)
    if not services:
        raise OwnershipConflictError("Compose ownership model has no services")
    if any(
        "networks" not in service and "network_mode" not in service
        for service in services.values()
    ):
        networks.setdefault("default", {})

    labels = ownership.labels(attempt_id=attempt_id)
    overrides, semantic_by_service, external_by_semantic = _service_overrides(
        ownership, services, labels
    )
    _add_receipted_container_names(ownership, external_by_semantic)
    _scope_container_network_modes(services, overrides, external_by_semantic)
    network_overrides, expected_networks = _resource_overrides(
        ownership, networks, labels=labels
    )
    volume_overrides, expected_volumes = _resource_overrides(
        ownership, volumes, labels=labels
    )
    document: dict[str, object] = {
        "services": overrides,
        **({"networks": network_overrides} if network_overrides else {}),
        **({"volumes": volume_overrides} if volume_overrides else {}),
    }
    payload = yaml.safe_dump(document, sort_keys=True).encode("utf-8")
    # A bounded apply retry can add direct-container receipts before writing a
    # new override. Both versions remain immutable, but they cannot share a
    # path merely because the start attempt is the same.
    digest = hashlib.sha256(attempt_id.encode("utf-8") + payload).hexdigest()[:16]
    relative = Path(".aptl/lifecycle/compose-ownership") / f"{digest}.yml"
    _write_override_payload(ownership.root, relative, payload)
    expected = {
        "container": tuple(sorted(external_by_semantic.values())),
        "network": tuple(sorted(expected_networks)),
        "volume": tuple(sorted(expected_volumes)),
    }
    return ownership.root / relative, semantic_by_service, expected


def _service_overrides(
    ownership: WorkspaceOwnership,
    services: dict[str, dict[str, object]],
    labels: dict[str, str],
) -> tuple[dict[str, dict[str, object]], dict[str, str], dict[str, str]]:
    """Build scoped service overrides and both semantic lookup maps."""

    overrides: dict[str, dict[str, object]] = {}
    semantic_by_service: dict[str, str] = {}
    external_by_semantic: dict[str, str] = {}
    for service_name, raw_service in sorted(services.items()):
        raw_name = raw_service.get("container_name")
        semantic_name = (
            raw_name
            if isinstance(raw_name, str) and "${" not in raw_name
            else f"aptl-{service_name}"
        )
        external_name = ownership.container_name(semantic_name)
        semantic_by_service[service_name] = semantic_name
        external_by_semantic[semantic_name] = external_name
        overrides[service_name] = {
            "container_name": external_name,
            "labels": labels,
        }
    return overrides, semantic_by_service, external_by_semantic


def _add_receipted_container_names(
    ownership: WorkspaceOwnership,
    external_by_semantic: dict[str, str],
) -> None:
    """Add directly materialized containers to reference rewriting.

    A Compose-managed sidecar may join the network namespace of an image-free
    node that was started directly by the generic materializer. That node is
    absent from the final Compose file set, so its immutable ownership receipt
    is the authoritative semantic-to-external-name mapping.
    """

    for receipt in ownership.receipts("container"):
        existing = external_by_semantic.get(receipt.semantic_name)
        if existing is not None and existing != receipt.external_name:
            raise OwnershipConflictError("container semantic binding conflicts")
        external_by_semantic[receipt.semantic_name] = receipt.external_name


def _scope_container_network_modes(
    services: dict[str, dict[str, object]],
    overrides: dict[str, dict[str, object]],
    external_by_semantic: dict[str, str],
) -> None:
    """Translate ``network_mode: container:`` targets to scoped names."""

    for service_name, raw_service in services.items():
        network_mode = raw_service.get("network_mode")
        if not isinstance(network_mode, str) or not network_mode.startswith(
            "container:"
        ):
            continue
        scoped = external_by_semantic.get(network_mode.partition(":")[2])
        if scoped is not None:
            overrides[service_name]["network_mode"] = f"container:{scoped}"


def _write_override_payload(root: Path, relative: Path, payload: bytes) -> None:
    """Create one immutable override, accepting a byte-identical retry."""

    try:
        create_exclusive_nofollow(root, relative, payload)
    except FileExistsError:
        try:
            existing = read_contained_nofollow(root, relative)
        except (OSError, PathContainmentError) as exc:
            raise OwnershipConflictError(_OVERRIDE_UNAVAILABLE) from exc
        if existing != payload:
            raise OwnershipConflictError("Compose ownership override conflicts")
    except (OSError, PathContainmentError) as exc:
        raise OwnershipConflictError(_OVERRIDE_UNAVAILABLE) from exc


def _resource_overrides(
    ownership: WorkspaceOwnership,
    resources: dict[str, dict[str, object]],
    *,
    labels: dict[str, str],
) -> tuple[dict[str, dict[str, object]], set[str]]:
    """Return ownership labels and exact native names for Compose resources."""

    overrides: dict[str, dict[str, object]] = {}
    expected: set[str] = set()
    for semantic_name, definition in sorted(resources.items()):
        if definition.get("external") is True:
            raise OwnershipConflictError("external Compose resources are not ownable")
        raw_name = definition.get("name")
        external_name = (
            raw_name
            if isinstance(raw_name, str) and "${" not in raw_name
            else f"{ownership.project_name}_{semantic_name}"
        )
        if not _SAFE_VALUE.fullmatch(external_name):
            raise OwnershipConflictError("invalid Compose resource name")
        overrides[semantic_name] = {"labels": labels}
        expected.add(external_name)
    return overrides, expected


def _merged_compose_sections(
    compose_files: tuple[Path, ...],
) -> tuple[
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
]:
    """Return merged service, network, and volume fragments."""

    services: dict[str, dict[str, object]] = {}
    networks: dict[str, dict[str, object]] = {}
    volumes: dict[str, dict[str, object]] = {}
    for compose_file in compose_files:
        if compose_file is None or not compose_file.is_file():
            continue
        try:
            payload = (
                yaml.load(
                    compose_file.read_text(encoding="utf-8"), Loader=_ComposeLoader
                )
                or {}
            )
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise OwnershipConflictError(
                "Compose ownership model is unreadable"
            ) from exc
        if not isinstance(payload, dict):
            continue
        _merge_compose_section(services, payload.get("services"))
        _merge_compose_section(networks, payload.get("networks"))
        _merge_compose_section(volumes, payload.get("volumes"))
    return services, networks, volumes


def _merge_compose_section(
    destination: dict[str, dict[str, object]], raw_section: object
) -> None:
    """Merge one normalized Compose mapping into the ownership view."""

    if not isinstance(raw_section, dict):
        return
    for semantic_name, raw_definition in raw_section.items():
        if not isinstance(semantic_name, str):
            continue
        definition = raw_definition if isinstance(raw_definition, dict) else {}
        destination.setdefault(semantic_name, {}).update(definition)
