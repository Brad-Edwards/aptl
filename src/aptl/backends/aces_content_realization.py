"""Resolve ACES content-placement payloads into deployment content operations.

Issue #689 / ADR-046's TechVault addendum: a `content-placement` resource
must lower into typed backend realization (:class:`DeploymentContentRealization`)
or fail closed with an error diagnostic before any `aptl lab start` side
effect. Mirrors the worked pattern in `aces_image_realization.py`: parse,
apply a narrow policy, and lower one resource, emitting redacted diagnostics
rather than silently counting an unrealizable placement.

Realizable content (ADR-046):

- a bounded inline-text file (``text`` set, no ``source``);
- a file/directory sourced from a project-contained, checked-in path
  (``source.name`` is a project-relative path that resolves inside the
  project root and exists);
- an explicit empty-directory declaration (``type: directory`` with no
  ``source``).

Unrealizable content (error diagnostic, no side effects):

- ``type: dataset`` (never dynamically realizable — CyRIS-style dataset
  content has no bounded, portable materialization contract);
- any ``source.name`` prefixed ``runtime-observed:`` (captured-but-not-
  recreatable content per the ADR's TechVault Operational Standup Addendum);
- a ``source.name`` that resolves outside the project root;
- a destination whose target node has no registered content-capable
  backend service / project-scoped volume.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import PlannedResource

from aptl.backends.aces_diagnostics import diagnostic
from aptl.backends.aces_realization_values import (
    content_source_name as _content_source_name,
    content_text as _content_text,
    optional_string as _optional_string,
    placement_spec as _placement_spec,
)
from aptl.core.credentials import PathContainmentError, _resolve_within_project
from aptl.core.deployment.realization import DeploymentContentRealization

# Backend services APTL knows how to plant content into, and the
# project-scoped named-volume key (docker-compose.yml `volumes:` key,
# unprefixed — Compose project-scopes it) that backs each one. Adding a
# new content-capable service is one new entry here, not a scenario-name
# branch (ADR-046 §Extensibility).
_CONTENT_REALIZABLE_SERVICES: dict[str, str] = {
    "fileshare": "fileshare_data",
    # Kali carries the paper scenario's participant-visible task brief. The
    # `kali_operations` named volume already exists in docker-compose.yml
    # (mounted at /home/kali/operations), so a volume-relative content path
    # lowers straight through the ADR-043 seed mechanism (issue #691).
    "kali": "kali_operations",
}

_RUNTIME_OBSERVED_PREFIX = "runtime-observed:"
_SAFE_DEST_RELPATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


@dataclass(frozen=True)
class _ContentPlacementInputs(object):
    """Validated content-placement fields ready for file/directory dispatch."""

    content_type: str
    source_name: str | None
    volume_suffix: str


@dataclass(frozen=True)
class _ContentPlacement(object):
    """Placement-identity fields shared by a resolved content realization."""

    content_name: str
    target_address: str
    dest_relpath: str
    volume_suffix: str
    sensitive: bool


def resolve_content_placement(
    *,
    resource: PlannedResource,
    payload: Mapping[str, Any],
    target_address: str,
    target_service: str | None,
    project_dir: Path,
) -> tuple[DeploymentContentRealization | None, list[Diagnostic]]:
    """Lower one content-placement resource or return fail-closed diagnostics."""

    spec = _placement_spec(payload)
    content_name = (
        _optional_string(payload, "content_name")
        or _optional_string(payload, "name")
        or resource.address
    )
    inputs, reason = _content_placement_inputs(spec, target_service)

    content: DeploymentContentRealization | None = None
    diagnostics: list[Diagnostic] = []
    if inputs is None:
        diagnostics = [_reject(resource.address, reason)]
    else:
        resolver = (
            _resolve_file_content
            if inputs.content_type == "file"
            else _resolve_directory_content
        )
        content, diagnostics = resolver(
            resource=resource,
            spec=spec,
            content_name=content_name,
            target_address=target_address,
            source_name=inputs.source_name,
            volume_suffix=inputs.volume_suffix,
            project_dir=project_dir,
        )
    return content, diagnostics


def _content_placement_inputs(
    spec: Mapping[str, Any] | None,
    target_service: str | None,
) -> tuple[_ContentPlacementInputs | None, str | None]:
    """Validate content-placement type/source/target fields for dispatch.

    Returns the validated fields on success, or the fail-closed rejection
    reason (with no fields) on the first policy violation.
    """

    inputs = None
    reason = None
    if spec is None:
        reason = "invalid-content-spec"
    else:
        content_type = spec.get("type")
        source_name = _content_source_name(spec)
        volume_suffix = (
            _CONTENT_REALIZABLE_SERVICES.get(target_service)
            if target_service is not None
            else None
        )
        if content_type == "dataset":
            reason = "dataset-not-realizable"
        elif content_type not in ("file", "directory"):
            reason = "unknown-content-type"
        elif source_name is not None and source_name.startswith(_RUNTIME_OBSERVED_PREFIX):
            reason = "runtime-observed-source"
        elif volume_suffix is None:
            reason = "destination-without-backing-mount"
        else:
            inputs = _ContentPlacementInputs(
                content_type=content_type,
                source_name=source_name,
                volume_suffix=volume_suffix,
            )
    return inputs, reason


def _resolve_file_content(
    *,
    resource: PlannedResource,
    spec: Mapping[str, Any],
    content_name: str,
    target_address: str,
    source_name: str | None,
    volume_suffix: str,
    project_dir: Path,
) -> tuple[DeploymentContentRealization | None, list[Diagnostic]]:
    """Lower a `type: file` content spec."""

    dest_relpath = _optional_string(spec, "path")
    content: DeploymentContentRealization | None = None
    diagnostics: list[Diagnostic] = []
    if dest_relpath is None or not _safe_dest_relpath(dest_relpath):
        diagnostics = [_reject(resource.address, "unsafe-destination-path")]
    else:
        text = _content_text(spec)
        if text is not None:
            content = DeploymentContentRealization(
                address=resource.address,
                target_address=target_address,
                content_name=content_name,
                volume_suffix=volume_suffix,
                dest_relpath=dest_relpath,
                source_kind="inline-text",
                inline_text=text,
                sensitive=_is_sensitive(spec),
            )
        else:
            content, diagnostics = _resolve_file_content_from_source(
                resource=resource,
                placement=_ContentPlacement(
                    content_name=content_name,
                    target_address=target_address,
                    dest_relpath=dest_relpath,
                    volume_suffix=volume_suffix,
                    sensitive=_is_sensitive(spec),
                ),
                source_name=source_name,
                project_dir=project_dir,
            )
    return content, diagnostics


def _resolve_file_content_from_source(
    *,
    resource: PlannedResource,
    placement: _ContentPlacement,
    source_name: str | None,
    project_dir: Path,
) -> tuple[DeploymentContentRealization | None, list[Diagnostic]]:
    """Resolve a project-sourced `type: file` content spec (no inline text)."""

    content: DeploymentContentRealization | None = None
    if source_name is None:
        diagnostics = [_reject(resource.address, "file-content-missing-source")]
    else:
        resolved, diagnostics = _resolve_project_source(
            resource.address, source_name, project_dir
        )
        if resolved is not None:
            if not resolved.is_file():
                diagnostics = [_reject(resource.address, "source-file-missing")]
            else:
                content = DeploymentContentRealization(
                    address=resource.address,
                    target_address=placement.target_address,
                    content_name=placement.content_name,
                    volume_suffix=placement.volume_suffix,
                    dest_relpath=placement.dest_relpath,
                    source_kind="project-file",
                    source_relpath=source_name,
                    sensitive=placement.sensitive,
                )
    return content, diagnostics


def _resolve_directory_content(
    *,
    resource: PlannedResource,
    spec: Mapping[str, Any],
    content_name: str,
    target_address: str,
    source_name: str | None,
    volume_suffix: str,
    project_dir: Path,
) -> tuple[DeploymentContentRealization | None, list[Diagnostic]]:
    """Lower a `type: directory` content spec."""

    dest_relpath = _optional_string(spec, "destination")
    content: DeploymentContentRealization | None = None
    diagnostics: list[Diagnostic] = []
    if dest_relpath is None or not _safe_dest_relpath(dest_relpath):
        diagnostics = [_reject(resource.address, "unsafe-destination-path")]
    elif source_name is None:
        content = DeploymentContentRealization(
            address=resource.address,
            target_address=target_address,
            content_name=content_name,
            volume_suffix=volume_suffix,
            dest_relpath=dest_relpath,
            source_kind="empty-directory",
            sensitive=_is_sensitive(spec),
        )
    else:
        content, diagnostics = _resolve_directory_content_from_source(
            resource=resource,
            placement=_ContentPlacement(
                content_name=content_name,
                target_address=target_address,
                dest_relpath=dest_relpath,
                volume_suffix=volume_suffix,
                sensitive=_is_sensitive(spec),
            ),
            source_name=source_name,
            project_dir=project_dir,
        )
    return content, diagnostics


def _resolve_directory_content_from_source(
    *,
    resource: PlannedResource,
    placement: _ContentPlacement,
    source_name: str,
    project_dir: Path,
) -> tuple[DeploymentContentRealization | None, list[Diagnostic]]:
    """Resolve a project-sourced `type: directory` content spec."""

    content: DeploymentContentRealization | None = None
    resolved, diagnostics = _resolve_project_source(resource.address, source_name, project_dir)
    if resolved is not None:
        if not resolved.is_dir():
            diagnostics = [_reject(resource.address, "source-directory-missing")]
        else:
            content = DeploymentContentRealization(
                address=resource.address,
                target_address=placement.target_address,
                content_name=placement.content_name,
                volume_suffix=placement.volume_suffix,
                dest_relpath=placement.dest_relpath,
                source_kind="project-directory",
                source_relpath=source_name,
                sensitive=placement.sensitive,
            )
    return content, diagnostics


def _resolve_project_source(
    address: str, source_name: str, project_dir: Path
) -> tuple[Path | None, list[Diagnostic]]:
    """Resolve a checked-in source path, failing closed on containment escape."""

    try:
        resolved = _resolve_within_project(project_dir, Path(source_name))
    except PathContainmentError:
        return None, [_reject(address, "source-path-escapes-project")]
    return resolved, []


def _safe_dest_relpath(relpath: str) -> bool:
    """Return whether a destination relpath is safe to embed in a seed script."""

    return (
        ".." not in PurePosixPath(relpath).parts
        and _SAFE_DEST_RELPATH.match(relpath) is not None
    )


def _is_sensitive(spec: Mapping[str, Any]) -> bool:
    """Return the Content spec's `sensitive` flag as a plain bool."""

    value = spec.get("sensitive")
    return bool(value) if isinstance(value, (bool, str)) else False


def _reject(address: str, reason_code: str) -> Diagnostic:
    """Build a fail-closed content realization diagnostic."""

    return diagnostic(
        "aptl.provisioner.content-placement-rejected",
        address,
        (
            "ACES content placement was rejected by the APTL content "
            f"realization policy (reason={reason_code})."
        ),
    )


_ImageFreeResult = tuple[DeploymentContentRealization | None, list[Diagnostic]]


def _inline_text_image_free_placement(
    resource: PlannedResource,
    target_address: str,
    *,
    dest: str,
    name: str,
    text: str | None,
    spec: Mapping[str, Any],
) -> _ImageFreeResult | None:
    """Lower an inline-text placement, or None if this spec is not one."""

    if text is None or not dest:
        return None
    return (
        DeploymentContentRealization(
            address=resource.address,
            target_address=target_address,
            content_name=name,
            volume_suffix="",
            dest_relpath=dest.lstrip("/"),
            source_kind="inline-text",
            inline_text=text,
            sensitive=spec.get("sensitive") is True,
        ),
        [],
    )


def _project_source_rejection(
    resource: PlannedResource, source_name: str
) -> list[Diagnostic] | None:
    """Return fail-closed diagnostics if a project source can't be realized, else None."""

    if source_name.startswith(_RUNTIME_OBSERVED_PREFIX):
        return [
            diagnostic(
                "aptl.provisioner.content-not-realizable",
                resource.address,
                "runtime-observed content cannot be recreated from source.",
            )
        ]
    try:
        _resolve_within_project(Path(""), source_name)
    except PathContainmentError:
        return [
            diagnostic(
                "aptl.provisioner.content-source-escapes-project",
                resource.address,
                "content source path escapes the project root.",
            )
        ]
    return None


def _project_source_image_free_placement(
    resource: PlannedResource,
    target_address: str,
    *,
    dest: str,
    name: str,
    source_name: str,
    content_type: str,
    spec: Mapping[str, Any],
) -> _ImageFreeResult | None:
    """Lower a project-contained source placement, or None if this spec is not one."""

    if not source_name or not dest:
        return None
    diagnostics = _project_source_rejection(resource, source_name)
    if diagnostics is not None:
        return None, diagnostics
    kind = "project-directory" if content_type == "directory" else "project-file"
    return (
        DeploymentContentRealization(
            address=resource.address,
            target_address=target_address,
            content_name=name,
            volume_suffix="",
            dest_relpath=dest.lstrip("/"),
            source_kind=kind,
            source_relpath=source_name,
            sensitive=spec.get("sensitive") is True,
        ),
        [],
    )


def resolve_image_free_content_placement(
    resource: PlannedResource,
    payload: Mapping[str, Any],
    target_address: str,
) -> _ImageFreeResult:
    """Resolve content for an image-free node (ADR-048).

    The generic materializer places declared config directly into the node's
    container, so there is no compose service / named-volume requirement.
    ``path``/``destination`` is the authored, literal absolute destination
    (never volume-relative). Inline text and project-contained file/directory
    sources both lower to a ``DeploymentContentRealization``; dataset content
    and runtime-observed sources are not realizable and fail closed rather
    than being silently dropped.
    """

    spec = _placement_spec(payload)
    if spec is None:
        return None, [
            diagnostic(
                "aptl.provisioner.invalid-content-spec",
                resource.address,
                "content placement has no spec.",
            )
        ]
    dest = _optional_string(spec, "path") or _optional_string(spec, "destination")
    name = _optional_string(payload, "content_name") or _optional_string(payload, "name") or ""

    result = _inline_text_image_free_placement(
        resource, target_address, dest=dest, name=name, text=_content_text(spec), spec=spec
    )
    if result is None:
        result = _project_source_image_free_placement(
            resource,
            target_address,
            dest=dest,
            name=name,
            source_name=_content_source_name(spec),
            content_type=_optional_string(spec, "type") or "",
            spec=spec,
        )
    if result is None:
        result = None, [
            diagnostic(
                "aptl.provisioner.image-free-content-unsupported",
                resource.address,
                "image-free content placement supports an inline-text file or a "
                "project-contained file/directory source with a destination path.",
            )
        ]
    return result
