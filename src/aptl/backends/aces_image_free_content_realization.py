"""Resolve ACES content-placement payloads for image-free nodes (ADR-048).

Split out of ``aces_content_realization.py`` (module-length budget). The
generic materializer places declared config directly into a node's own
container filesystem, never a Compose-managed named volume, so this path
carries no ``volume_suffix``/``target_service`` and the authored
``path``/``destination`` is a literal absolute destination.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import PlannedResource

from aptl.backends.aces_content_source_policy import forbidden_source_reason
from aptl.backends.aces_diagnostics import diagnostic
from aptl.backends.aces_realization_values import (
    content_source_name as _content_source_name,
    content_text as _content_text,
    optional_string as _optional_string,
    placement_spec as _placement_spec,
)
from aptl.core.credentials import PathContainmentError, _resolve_within_project
from aptl.core.deployment.realization import DeploymentContentRealization

_RUNTIME_OBSERVED_PREFIX = "runtime-observed:"

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

    rejection: tuple[str, str] | None = None
    if source_name.startswith(_RUNTIME_OBSERVED_PREFIX):
        rejection = (
            "aptl.provisioner.content-not-realizable",
            "runtime-observed content cannot be recreated from source.",
        )
    else:
        forbidden_reason = forbidden_source_reason(source_name)
        if forbidden_reason is not None:
            rejection = (
                "aptl.provisioner.content-source-forbidden",
                f"content source is not permitted (reason={forbidden_reason}).",
            )
        else:
            try:
                _resolve_within_project(Path(""), source_name)
            except PathContainmentError:
                rejection = (
                    "aptl.provisioner.content-source-escapes-project",
                    "content source path escapes the project root.",
                )
    if rejection is None:
        return None
    code, message = rejection
    return [diagnostic(code, resource.address, message)]


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
