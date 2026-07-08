"""Resolve ACES placement resources into APTL realization records.

Owns the node-scoped placement plumbing (feature-binding, content-placement,
account-placement target resolution) and the content-placement materialization
resolver. Content placements that carry a safe absolute container path and
materializable content (inline text, a project-contained repo source, or an
``items``-derived dataset representation) become typed
``DeploymentContentPlacement`` operations. Genuinely unsafe authored input (a
traversing/absolute/NUL-bearing/ambiguous/directory-shaped file target, or a
traversing/absolute source path) is rejected with a redacted content-policy
diagnostic that fails realization. Content that is simply non-materializable but
safe - a path-less dataset descriptor, a captured ``runtime-observed:`` source,
an absent repo source, an empty body, or an unmapped target node - is recorded
by the generic placement record without a diagnostic, because it has no repo
bytes to place and must not fail the apply of an inventory scenario whose
captured content is intentionally non-reproducible (ADR-046 content addendum).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import PlannedResource

from aptl.backends.aces_diagnostics import diagnostic
from aptl.backends.aces_profiles import normalize_identifier
from aptl.backends.aces_realization_model import NodeRealization, PlacementRealization
from aptl.backends.aces_realization_values import (
    first_nonempty_string as _first_nonempty_string,
    mapping as _mapping,
    placement_target_values as _placement_target_values,
    resolve_target_address as _resolve_target_address,
    resource_name as _resource_name,
)
from aptl.core.deployment.realization import (
    ContentPlacementType,
    DeploymentContentPlacement,
)

PLACEMENT_RESOURCE_TYPES = frozenset(
    {"feature-binding", "content-placement", "account-placement"}
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUNTIME_SOURCE_PREFIXES = ("runtime-observed:", "runtime-derived:")
_CONTENT_TYPES = frozenset({"file", "directory", "dataset"})


def realize_placements(
    payload_resources: list[PlannedResource],
    nodes: list[NodeRealization],
    project_dir: Path,
    diagnostics: list[Diagnostic],
) -> tuple[list[PlacementRealization], list[DeploymentContentPlacement]]:
    """Resolve placement resources into generic records and content operations."""

    node_lookup = _node_lookup(nodes)
    container_by_address = {
        node.address: node.container_name for node in nodes if node.container_name
    }
    placements: list[PlacementRealization] = []
    content: list[DeploymentContentPlacement] = []
    for resource in payload_resources:
        if resource.resource_type not in PLACEMENT_RESOURCE_TYPES:
            continue
        placement, placement_diagnostics = _realize_placement(
            resource, resource.payload, node_lookup
        )
        diagnostics.extend(placement_diagnostics)
        if placement is None:
            continue
        placements.append(placement)
        if resource.resource_type == "content-placement":
            content_placement = _resolve_content_placement(
                resource=resource,
                payload=resource.payload,
                target_address=placement.target_address,
                container_by_address=container_by_address,
                project_dir=project_dir,
                diagnostics=diagnostics,
            )
            if content_placement is not None:
                content.append(content_placement)
    return placements, content


def _realize_placement(
    resource: PlannedResource,
    payload: Mapping[str, Any],
    node_lookup: dict[str, str],
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
                        "ACES provisioning binding does not target a "
                        "declared APTL-realizable node."
                    ),
                )
            ],
        )
    return (
        PlacementRealization(
            address=resource.address,
            resource_type=resource.resource_type,
            name=_resource_name(resource.address, payload),
            target_address=target_address,
            target_node=_first_nonempty_string(target_values),
        ),
        [],
    )


def _node_lookup(nodes: list[NodeRealization]) -> dict[str, str]:
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


def _resolve_content_placement(
    *,
    resource: PlannedResource,
    payload: Mapping[str, Any],
    target_address: str,
    container_by_address: dict[str, str],
    project_dir: Path,
    diagnostics: list[Diagnostic],
) -> DeploymentContentPlacement | None:
    """Resolve one content-placement payload into a typed backend operation.

    Content that carries a safe absolute target path and materializable input
    (inline text, a project-contained repo source, or an ``items``-derived
    dataset) becomes a typed op. Genuinely unsafe authored input (a traversing,
    absolute, NUL-bearing, ambiguous, or directory-shaped file target, or a
    traversing/absolute source path) is rejected with a redacted diagnostic
    that fails realization. Content that is simply non-materializable but safe
    (path-less dataset descriptors, captured ``runtime-observed:`` sources, an
    absent repo source, an empty body, an unmapped target node) is recorded by
    the generic placement record without a diagnostic, because it has no repo
    bytes to place and must not fail the apply of an inventory scenario whose
    captured content is intentionally non-reproducible (ADR-046 content
    addendum).
    """

    spec = _mapping(payload.get("spec"))
    if spec is None:
        return None
    content_type = _content_type(spec)
    if content_type is None:
        return None
    target_path, reason = _resolve_target_path(content_type, spec)
    if reason is not None:
        diagnostics.append(_content_diagnostic(resource.address, content_type, reason))
        return None
    if target_path is None:
        return None
    container = container_by_address.get(target_address)
    if container is None:
        return None
    return _build_content_placement(
        resource=resource,
        spec=spec,
        content_type=content_type,
        container=container,
        target_path=target_path,
        project_dir=project_dir,
        diagnostics=diagnostics,
    )


def _content_type(spec: Mapping[str, Any]) -> ContentPlacementType | None:
    """Return the supported content type declared by a content spec."""

    value = spec.get("type")
    if isinstance(value, str) and value in _CONTENT_TYPES:
        return value  # type: ignore[return-value]
    return None


def _resolve_target_path(
    content_type: ContentPlacementType,
    spec: Mapping[str, Any],
) -> tuple[str | None, str | None]:
    """Return the validated container target path or a rejection reason code."""

    path = _clean(spec.get("path"))
    destination = _clean(spec.get("destination"))
    if path and destination and path != destination:
        return None, "ambiguous-target"
    chosen = path or destination
    if chosen is None:
        return None, None
    reason = _target_path_reason(content_type, chosen)
    if reason is not None:
        return None, reason
    return chosen, None


def _target_path_reason(
    content_type: ContentPlacementType,
    path: str,
) -> str | None:
    """Return the safety reason a container target path is unusable, if any."""

    if "\x00" in path:
        return "nul-byte"
    posix = PurePosixPath(path)
    if not posix.is_absolute():
        return "relative-path"
    if ".." in posix.parts:
        return "parent-traversal"
    if content_type == "file" and path.endswith("/"):
        return "directory-shaped-file-target"
    return None


def _build_content_placement(
    *,
    resource: PlannedResource,
    spec: Mapping[str, Any],
    content_type: ContentPlacementType,
    container: str,
    target_path: str,
    project_dir: Path,
    diagnostics: list[Diagnostic],
) -> DeploymentContentPlacement | None:
    """Build a typed content op from validated content spec fields.

    Returns a typed op for materializable content (directory, inline text,
    repo source, or ``items``-derived dataset), ``None`` (record-only) for
    safe-but-non-materializable content (an empty body), and appends a
    content-policy diagnostic only for a genuinely unsafe source path
    (ADR-046 content addendum).
    """

    sensitive = bool(spec.get("sensitive"))
    content_format = _clean(spec.get("format"))
    if content_type == "directory":
        return DeploymentContentPlacement(
            address=resource.address,
            content_type="directory",
            container_name=container,
            target_path=target_path,
            sensitive=sensitive,
        )
    text = spec.get("text")
    if isinstance(text, str):
        return DeploymentContentPlacement(
            address=resource.address,
            content_type=content_type,
            container_name=container,
            target_path=target_path,
            content_text=text,
            digest=_text_digest(text),
            sensitive=sensitive,
            content_format=content_format,
        )
    source = _mapping(spec.get("source"))
    if source is not None:
        return _source_content_placement(
            resource=resource,
            source=source,
            content_type=content_type,
            container=container,
            target_path=target_path,
            sensitive=sensitive,
            content_format=content_format,
            project_dir=project_dir,
            diagnostics=diagnostics,
        )
    items = spec.get("items")
    if content_type == "dataset" and isinstance(items, list) and items:
        rendered = _render_dataset(items, content_format)
        return DeploymentContentPlacement(
            address=resource.address,
            content_type="dataset",
            container_name=container,
            target_path=target_path,
            content_text=rendered,
            digest=_text_digest(rendered),
            sensitive=sensitive,
            item_count=len(items),
            content_format=content_format,
        )
    return None


def _source_content_placement(
    *,
    resource: PlannedResource,
    source: Mapping[str, Any],
    content_type: ContentPlacementType,
    container: str,
    target_path: str,
    sensitive: bool,
    content_format: str | None,
    project_dir: Path,
    diagnostics: list[Diagnostic],
) -> DeploymentContentPlacement | None:
    """Resolve a source-backed placement to a project-contained copy.

    Returns ``None`` (record-only) for a source that cannot be reproduced from
    the repo - a nameless source, a captured ``runtime-observed:`` reference, or
    a declared-but-absent repo file - because there are no bytes to place, and
    an inventory scenario's captured content must not fail the apply. Only a
    traversing/absolute source path is rejected with a diagnostic (ADR-046
    content addendum).
    """

    name = _clean(source.get("name"))
    if name is None:
        return None
    if name.startswith(_RUNTIME_SOURCE_PREFIXES):
        return None
    relative = _project_relative_source(project_dir, name)
    if relative is None:
        diagnostics.append(
            _content_diagnostic(resource.address, content_type, "unsafe-source-path")
        )
        return None
    if not (project_dir / relative).is_file():
        return None
    version = _clean(source.get("version"))
    digest = version if version and _DIGEST_RE.fullmatch(version) else None
    return DeploymentContentPlacement(
        address=resource.address,
        content_type=content_type,
        container_name=container,
        target_path=target_path,
        source_path=str(relative),
        digest=digest,
        sensitive=sensitive,
        source_name=name,
        source_version=version,
        content_format=content_format,
    )


def _project_relative_source(project_dir: Path, raw_path: str) -> Path | None:
    """Resolve a project-contained relative source path or return None."""

    posix = PurePosixPath(raw_path)
    if posix.is_absolute() or ".." in posix.parts:
        return None
    relative = Path(*posix.parts)
    resolved = (project_dir / relative).resolve()
    try:
        resolved.relative_to(project_dir.resolve())
    except ValueError:
        return None
    return relative


def _render_dataset(items: list[Any], content_format: str | None) -> str:
    """Render dataset items into a deterministic, container-writable payload."""

    if content_format == "jsonl":
        lines = [
            json.dumps(item, sort_keys=True, ensure_ascii=False) for item in items
        ]
        return "\n".join(lines) + "\n"
    return json.dumps(items, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _text_digest(text: str) -> str:
    """Return the sha256 digest of content bytes for realization evidence."""

    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _clean(value: object) -> str | None:
    """Return a stripped non-empty string, or None for other values."""

    return value.strip() if isinstance(value, str) and value.strip() else None


def _content_diagnostic(
    address: str,
    content_type: str,
    reason: str,
) -> Diagnostic:
    """Build a content-policy diagnostic without exposing paths or content."""

    return diagnostic(
        "aptl.provisioner.content-placement-rejected",
        address,
        (
            "ACES content placement was rejected by the APTL content policy "
            f"(content_type={content_type}, reason={reason})."
        ),
    )
