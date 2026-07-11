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
}

_RUNTIME_OBSERVED_PREFIX = "runtime-observed:"
_SAFE_DEST_RELPATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


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
    if spec is None:
        return None, [_reject(resource.address, "invalid-content-spec")]

    content_name = (
        _optional_string(payload, "content_name")
        or _optional_string(payload, "name")
        or resource.address
    )

    content_type = spec.get("type")
    if content_type == "dataset":
        return None, [_reject(resource.address, "dataset-not-realizable")]
    if content_type not in ("file", "directory"):
        return None, [_reject(resource.address, "unknown-content-type")]

    source_name = _content_source_name(spec)
    if source_name is not None and source_name.startswith(_RUNTIME_OBSERVED_PREFIX):
        return None, [_reject(resource.address, "runtime-observed-source")]

    volume_suffix = (
        _CONTENT_REALIZABLE_SERVICES.get(target_service)
        if target_service is not None
        else None
    )
    if volume_suffix is None:
        return None, [_reject(resource.address, "destination-without-backing-mount")]

    if content_type == "file":
        return _resolve_file_content(
            resource=resource,
            spec=spec,
            content_name=content_name,
            target_address=target_address,
            source_name=source_name,
            volume_suffix=volume_suffix,
            project_dir=project_dir,
        )
    return _resolve_directory_content(
        resource=resource,
        spec=spec,
        content_name=content_name,
        target_address=target_address,
        source_name=source_name,
        volume_suffix=volume_suffix,
        project_dir=project_dir,
    )


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
    if dest_relpath is None or not _safe_dest_relpath(dest_relpath):
        return None, [_reject(resource.address, "unsafe-destination-path")]

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
        return content, []

    if source_name is None:
        return None, [_reject(resource.address, "file-content-missing-source")]

    resolved, diagnostics = _resolve_project_source(resource.address, source_name, project_dir)
    if resolved is None:
        return None, diagnostics
    if not resolved.is_file():
        return None, [_reject(resource.address, "source-file-missing")]

    content = DeploymentContentRealization(
        address=resource.address,
        target_address=target_address,
        content_name=content_name,
        volume_suffix=volume_suffix,
        dest_relpath=dest_relpath,
        source_kind="project-file",
        source_relpath=source_name,
        sensitive=_is_sensitive(spec),
    )
    return content, []


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
    if dest_relpath is None or not _safe_dest_relpath(dest_relpath):
        return None, [_reject(resource.address, "unsafe-destination-path")]

    if source_name is None:
        content = DeploymentContentRealization(
            address=resource.address,
            target_address=target_address,
            content_name=content_name,
            volume_suffix=volume_suffix,
            dest_relpath=dest_relpath,
            source_kind="empty-directory",
            sensitive=_is_sensitive(spec),
        )
        return content, []

    resolved, diagnostics = _resolve_project_source(resource.address, source_name, project_dir)
    if resolved is None:
        return None, diagnostics
    if not resolved.is_dir():
        return None, [_reject(resource.address, "source-directory-missing")]

    content = DeploymentContentRealization(
        address=resource.address,
        target_address=target_address,
        content_name=content_name,
        volume_suffix=volume_suffix,
        dest_relpath=dest_relpath,
        source_kind="project-directory",
        source_relpath=source_name,
        sensitive=_is_sensitive(spec),
    )
    return content, []


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
