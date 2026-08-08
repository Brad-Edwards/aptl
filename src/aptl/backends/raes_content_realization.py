"""Resolve RAES content-placement payloads into deployment content operations.

Issue #689 / ADR-046's TechVault addendum: a `content-placement` resource
must lower into typed backend realization (:class:`DeploymentContentRealization`
or :class:`ParticipantDatasetRealization`)
or fail closed with an error diagnostic before any `aptl lab start` side
effect. Mirrors the worked pattern in `raes_image_realization.py`: parse,
apply a narrow policy, and lower one resource, emitting redacted diagnostics
rather than silently counting an unrealizable placement.

Realizable content (ADR-046):

- a bounded inline-text file (``text`` set, no ``source``);
- a file/directory sourced from a project-contained, checked-in path
  (``source.name`` is a project-relative path that resolves inside the
  project root and exists);
- an explicit empty-directory declaration (``type: directory`` with no
  ``source``).

Logical participant datasets are admitted only as an empty, append-only,
run-scoped evidence carrier. They are not planted into a container and cannot
name a source, path, destination, text payload, or arbitrary schema.

Unrealizable content (error diagnostic, no side effects):

- a dataset carrying pre-seeded bytes, a filesystem destination, or malformed
  item declarations;
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
from pathlib import Path
from typing import Any

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import PlannedResource

from aptl.backends._raes_content_spec import (
    _is_sensitive,
    _reject,
    _safe_dest_relpath,
)
from aptl.backends._raes_dataset_content import (
    _resolve_dataset_content,
)
from aptl.backends._raes_service_index_placement import (
    resolve_service_search_index_schema as _resolve_service_search_index_schema,
)
from aptl.backends.raes_content_source_policy import forbidden_source_reason
from aptl.backends.raes_realization_model import ParticipantDatasetRealization
from aptl.backends.raes_realization_values import (
    content_source_exact_artifact as _content_source_exact_artifact,
    content_source_name as _content_source_name,
    content_text as _content_text,
    optional_string as _optional_string,
    placement_spec as _placement_spec,
)
from aptl.backends.raes_service_index_schema import (
    INTERFACE_PROFILE as _SEARCH_INDEX_SCHEMA_PROFILE,
)
from aptl.core.credentials import PathContainmentError, _resolve_within_project
from aptl.core.deployment.realization import (
    DeploymentContentRealization,
    DeploymentServiceSearchIndexSchemaRealization,
)

# Backend services APTL knows how to plant content into, and the
# project-scoped named-volume key (docker-compose.yml `volumes:` key,
# unprefixed — Compose project-scopes it) that backs each one. Adding a
# new content-capable service is one new entry here, not a scenario-name
# branch (ADR-046 §Extensibility).
_CONTENT_REALIZABLE_SERVICES: dict[str, str] = {
    "fileshare": "fileshare_data",
    # Retained scenarios place participant-visible task material on Kali's
    # existing operations volume. Keep this scenario-independent realization.
    "kali": "kali_operations",
}

_RUNTIME_OBSERVED_PREFIX = "runtime-observed:"


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
) -> tuple[
    DeploymentContentRealization
    | ParticipantDatasetRealization
    | DeploymentServiceSearchIndexSchemaRealization
    | None,
    list[Diagnostic],
]:
    """Lower one content-placement resource or return fail-closed diagnostics."""

    spec = _placement_spec(payload)
    content_name = (
        _optional_string(payload, "content_name")
        or _optional_string(payload, "name")
        or resource.address
    )

    # ADR-088 service-target materialization (#889): a content-placement carrying
    # a service_materialization binding is initial *service* state, not a node
    # file/dataset placement. The search-index-schema profile lowers to a typed
    # native materialization the backend realizes through the service's native
    # interface and proves by fresh readback. Dispatch it before the ordinary
    # file/dataset paths, which would otherwise reject its item-less dataset.
    binding = payload.get("service_materialization")
    if (
        isinstance(binding, Mapping)
        and binding.get("interface_profile") == _SEARCH_INDEX_SCHEMA_PROFILE
    ):
        return _resolve_service_search_index_schema(
            resource=resource,
            binding=binding,
            content_name=content_name,
            target_address=target_address,
        )

    inputs, reason = _content_placement_inputs(spec, target_service)

    content: DeploymentContentRealization | ParticipantDatasetRealization | None = None
    diagnostics: list[Diagnostic] = []
    if spec is not None and spec.get("type") == "dataset":
        content, diagnostics = _resolve_dataset_content(
            resource=resource,
            spec=spec,
            content_name=content_name,
            target_address=target_address,
        )
    elif inputs is None:
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
            inputs = None
        elif content_type not in ("file", "directory"):
            reason = "unknown-content-type"
        elif source_name is not None and source_name.startswith(
            _RUNTIME_OBSERVED_PREFIX
        ):
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
        placement = _ContentPlacement(
            content_name=content_name,
            target_address=target_address,
            dest_relpath=dest_relpath,
            volume_suffix=volume_suffix,
            sensitive=_is_sensitive(spec),
        )
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
        elif _content_source_exact_artifact(spec) is not None:
            content, diagnostics = _resolve_pack_artifact_content(
                resource=resource,
                spec=spec,
                placement=placement,
                source_kind="pack-file",
            )
        else:
            content, diagnostics = _resolve_file_content_from_source(
                resource=resource,
                placement=placement,
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
    elif _content_source_exact_artifact(spec) is not None:
        content, diagnostics = _resolve_pack_artifact_content(
            resource=resource,
            spec=spec,
            placement=_ContentPlacement(
                content_name=content_name,
                target_address=target_address,
                dest_relpath=dest_relpath,
                volume_suffix=volume_suffix,
                sensitive=_is_sensitive(spec),
            ),
            source_kind="pack-directory",
        )
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
    resolved, diagnostics = _resolve_project_source(
        resource.address, source_name, project_dir
    )
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


_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _resolve_pack_artifact_content(
    *,
    resource: PlannedResource,
    spec: Mapping[str, Any],
    placement: _ContentPlacement,
    source_kind: str,
) -> tuple[DeploymentContentRealization | None, list[Diagnostic]]:
    """Lower content declared by an exact env-pack artifact identity + digest.

    No host path is read here: the placement carries the opaque ``artifact_id``
    and its ``sha256`` digest, and the backend seed resolves and byte-verifies
    the bytes from the validated pack through ``resolve_pack_artifact``. A
    directory artifact must be an ``application/x-tar`` archive (extracted at the
    destination). Missing identity, a malformed digest, or a directory that is
    not an archive fails closed before any side effect.
    """

    exact = _content_source_exact_artifact(spec) or {}
    artifact_id = _optional_string(exact, "artifact_id")
    digest = _optional_string(exact, "digest")
    media_type = _optional_string(exact, "media_type")
    reason = _pack_artifact_reject_reason(
        artifact_id=artifact_id,
        digest=digest,
        media_type=media_type,
        source_kind=source_kind,
    )
    if reason is not None:
        return None, [_reject(resource.address, reason)]
    content = DeploymentContentRealization(
        address=resource.address,
        target_address=placement.target_address,
        content_name=placement.content_name,
        volume_suffix=placement.volume_suffix,
        dest_relpath=placement.dest_relpath,
        source_kind=source_kind,  # type: ignore[arg-type]
        artifact_id=artifact_id,
        artifact_digest=digest,
        media_type=media_type,
        sensitive=placement.sensitive,
    )
    return content, []


def _pack_artifact_reject_reason(
    *,
    artifact_id: str | None,
    digest: str | None,
    media_type: str | None,
    source_kind: str,
) -> str | None:
    """Return the rejection reason for a malformed pack identity, else None.

    Checked in the order the identity is established: an artifact id + digest
    must be declared, the digest must be a canonical sha256, and directory
    content must arrive as a tar archive.
    """

    if not artifact_id or not digest:
        reason = "pack-artifact-missing-identity"
    elif not _SHA256_DIGEST_RE.match(digest):
        reason = "pack-artifact-invalid-digest"
    elif source_kind == "pack-directory" and media_type != "application/x-tar":
        reason = "pack-directory-not-archive"
    else:
        reason = None
    return reason


def _resolve_project_source(
    address: str, source_name: str, project_dir: Path
) -> tuple[Path | None, list[Diagnostic]]:
    """Resolve a checked-in source path, failing closed on containment escape."""

    forbidden_reason = forbidden_source_reason(source_name)
    if forbidden_reason is not None:
        return None, [_reject(address, forbidden_reason)]
    try:
        resolved = _resolve_within_project(project_dir, Path(source_name))
    except PathContainmentError:
        return None, [_reject(address, "source-path-escapes-project")]
    return resolved, []
