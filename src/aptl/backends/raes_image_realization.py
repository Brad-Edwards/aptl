"""Resolve RAES node source payloads into deployment image operations."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.planning import PlannedResource

from aptl.backends._raes_image_policy import (
    _ALLOWED_DIGEST_SOURCE_NAMES,
    _ALLOWED_SOURCE_IMAGE_REFS,
    _COMPOSE_SOURCE_NAME_RE,
    _DIGEST_RE,
    _PROJECT_DOCKERFILE_PATH_RE,
    _SAFE_TAG_RE,
    _policy_diagnostic,
    _provenance_counts,
)
from aptl.core.deployment.realization import DeploymentImageRealization


@dataclass(frozen=True)
class _NodeSource:
    """Normalized RAES source fields relevant to image realization."""

    name: str
    version: str
    build: object
    artifact_requirement: object = None


def resolve_node_image(
    *,
    resource: PlannedResource,
    payload: Mapping[str, Any],
    project_dir: Path,
    service_name: str | None,
    diagnostics: list[Diagnostic],
) -> DeploymentImageRealization | None:
    """Return the deployment image operation declared by one node source."""

    image: DeploymentImageRealization | None = None
    source = _node_source(payload, resource.address, diagnostics)
    if source is not None:
        if service_name is None:
            diagnostics.append(_policy_diagnostic(resource.address, "unmapped-service"))
        else:
            image = _resolve_trusted_image(
                resource=resource,
                source=source,
                project_dir=project_dir,
                service_name=service_name,
                diagnostics=diagnostics,
            )
            # A node that authored artifact demand must fail loudly when that
            # demand cannot be resolved. The Compose-owned carve-out below only
            # applies to nodes whose binding Compose still owns, never to one
            # that declared an artifact identity of its own.
            if image is None and (
                source.artifact_requirement is not None
                or not _is_compose_owned_source(source.name, source.version)
            ):
                diagnostics.append(
                    _policy_diagnostic(resource.address, "untrusted-image")
                )
    return image


def _node_source(
    payload: Mapping[str, Any],
    address: str,
    diagnostics: list[Diagnostic],
) -> _NodeSource | None:
    """Extract and normalize a node source from a planned resource payload."""

    spec = payload.get("spec")
    if not isinstance(spec, Mapping):
        return None
    node = spec.get("node")
    if not isinstance(node, Mapping):
        return None
    source = node.get("source")
    normalized: _NodeSource | None = None
    if source is not None:
        if isinstance(source, Mapping):
            source_name = _source_string(source.get("name"))
            if source_name:
                normalized = _NodeSource(
                    name=source_name,
                    version=_source_string(source.get("version")) or "*",
                    build=source.get("build"),
                    artifact_requirement=source.get("artifact_requirement"),
                )
            else:
                diagnostics.append(_policy_diagnostic(address, "invalid-source"))
        else:
            diagnostics.append(_policy_diagnostic(address, "invalid-source"))
    return normalized


def _source_string(value: object) -> str | None:
    """Return a non-empty stripped string value when the source field is text."""

    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    return None


def _authored_artifact_image(
    *,
    resource: PlannedResource,
    source: _NodeSource,
    service_name: str,
    project_dir: Path,
) -> DeploymentImageRealization | None:
    """Resolve the image from the node's authored exact artifact requirement.

    When the SDL names an immutable artifact identity, that identity is the
    authority (ADR-050): the digest the author pinned is the reference APTL
    pulls. The local product allowlist below is legacy compatibility for
    scenarios that have not been migrated, and is not consulted here — an
    authored pin must not depend on APTL-side membership of a hand-maintained
    table, which is exactly what ADR-098 replaces.

    Reference syntax is still validated as defence in depth before the value
    reaches the deployment backend.
    """

    requirement = source.artifact_requirement
    if isinstance(requirement, Mapping):
        exact = requirement.get("exact_artifact")
        specifications = requirement.get("materialization_specifications") or []
    else:
        exact = getattr(requirement, "exact_artifact", None)
        specifications = getattr(requirement, "materialization_specifications", []) or []
    if exact is None:
        return _materialized_component_image(
            resource=resource,
            source=source,
            service_name=service_name,
            project_dir=project_dir,
            specifications=specifications,
        )
    if isinstance(exact, Mapping):
        artifact_id = _source_string(exact.get("artifact_id")) or ""
        digest = _source_string(exact.get("digest")) or ""
    else:
        artifact_id = getattr(exact, "artifact_id", "")
        digest = getattr(exact, "digest", "")
    if not _safe_image_name(artifact_id) or _DIGEST_RE.fullmatch(digest) is None:
        return None
    return DeploymentImageRealization(
        address=resource.address,
        service_name=service_name,
        source_name=source.name,
        source_version=source.version,
        image_ref=f"{artifact_id}@{digest}",
        mode="pull",
        policy_rule="authored-exact-artifact",
        provenance=_provenance_counts(source.build),
    )


def _materialized_component_image(
    *,
    resource: PlannedResource,
    source: _NodeSource,
    service_name: str,
    project_dir: Path,
    specifications: object,
) -> DeploymentImageRealization | None:
    """Build one component image from an authored materialization specification.

    The specification id names a contained build context, and the specification
    digest must equal the sha256 of that context's Dockerfile. A drifted context
    is not the artifact the author authorised, so it resolves to nothing and
    admission refuses the node rather than building something else.

    Selection is deterministic by specification id, so the same authored contract
    always builds the same context.
    """

    if not isinstance(specifications, (list, tuple)) or not specifications:
        return None
    chosen: tuple[str, str] | None = None
    for specification in sorted(
        specifications, key=lambda item: _specification_id(item)
    ):
        identifier = _specification_id(specification)
        digest = _specification_digest(specification)
        dockerfile = _contained_context_dockerfile(project_dir, identifier)
        if dockerfile is None or not digest:
            continue
        actual = "sha256:" + hashlib.sha256(dockerfile.read_bytes()).hexdigest()
        if actual == digest:
            chosen = (identifier, digest)
            break
    if chosen is None or not _safe_image_name(chosen[0]):
        return None
    identifier, digest = chosen
    return DeploymentImageRealization(
        address=resource.address,
        service_name=service_name,
        source_name=source.name,
        source_version=source.version,
        image_ref=f"{identifier}:local",
        mode="build",
        policy_rule="authored-materialization-specification",
        dockerfile_path=f"containers/{identifier}/Dockerfile",
        context_path=".",
        provenance=_provenance_counts(source.build),
    )


def _specification_id(specification: object) -> str:
    """Return a specification's id whether it is a mapping or a model."""

    if isinstance(specification, Mapping):
        return _source_string(specification.get("specification_id")) or ""
    return getattr(specification, "specification_id", "") or ""


def _specification_digest(specification: object) -> str:
    """Return a specification's digest whether it is a mapping or a model."""

    if isinstance(specification, Mapping):
        return _source_string(specification.get("digest")) or ""
    return getattr(specification, "digest", "") or ""


def _contained_context_dockerfile(project_dir: Path, identifier: str) -> Path | None:
    """Return the contained Dockerfile for one specification id, or nothing."""

    if (
        not identifier
        or "/" in identifier
        or "\\" in identifier
        or identifier in {".", ".."}
    ):
        return None
    root = (project_dir / "containers").resolve()
    candidate = (root / identifier / "Dockerfile").resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _resolve_trusted_image(
    *,
    resource: PlannedResource,
    source: _NodeSource,
    project_dir: Path,
    service_name: str,
    diagnostics: list[Diagnostic],
) -> DeploymentImageRealization | None:
    """Resolve one normalized source through build, alias, and digest policies."""

    if source.artifact_requirement is not None:
        # Authored artifact demand is the sole authority for this node. When it
        # cannot be resolved — a non-exact posture APTL does not advertise, or a
        # malformed identity — the answer is no image, which the caller turns
        # into a refusal. Falling through to build provenance or the local
        # product allowlist would substitute an APTL-chosen artifact for the one
        # the author declared, which SEM-218 I1/I2 forbid.
        return _authored_artifact_image(
            resource=resource,
            source=source,
            service_name=service_name,
            project_dir=project_dir,
        )
    image: DeploymentImageRealization | None = None
    if isinstance(source.build, Mapping):
        image = _build_image(
            resource=resource,
            source=source,
            build=source.build,
            project_dir=project_dir,
            service_name=service_name,
            diagnostics=diagnostics,
        )
    if image is None:
        image = _pull_image(resource.address, source, service_name)
    return image


def _build_image(
    *,
    resource: PlannedResource,
    source: _NodeSource,
    build: Mapping[str, Any],
    project_dir: Path,
    service_name: str,
    diagnostics: list[Diagnostic],
) -> DeploymentImageRealization | None:
    """Resolve local project build provenance into an image operation."""

    image = None
    dockerfile_path = _project_dockerfile_candidate(build)
    if dockerfile_path is not None:
        rejection = _build_rejection_reason(project_dir, dockerfile_path, build)
        if rejection is not None:
            diagnostics.append(_policy_diagnostic(resource.address, rejection))
        else:
            image_ref = _local_build_ref(source.name, source.version)
            if image_ref is None:
                diagnostics.append(
                    _policy_diagnostic(resource.address, "invalid-local-tag")
                )
            else:
                image = DeploymentImageRealization(
                    address=resource.address,
                    service_name=service_name,
                    source_name=source.name,
                    source_version=source.version,
                    image_ref=image_ref,
                    mode="build",
                    policy_rule="project-build-provenance",
                    dockerfile_path=dockerfile_path,
                    context_path=".",
                    provenance=_provenance_counts(build),
                )
    return image


def _pull_image(
    address: str,
    source: _NodeSource,
    service_name: str,
) -> DeploymentImageRealization | None:
    """Resolve allowed pull policies into an image operation."""

    policy_rule = "allowed-source"
    image_ref = _ALLOWED_SOURCE_IMAGE_REFS.get((source.name, source.version))
    if image_ref is None:
        policy_rule = "allowed-digest"
        image_ref = _allowed_digest_pinned_ref(source.name, source.version)
    if image_ref is not None:
        return DeploymentImageRealization(
            address=address,
            service_name=service_name,
            source_name=source.name,
            source_version=source.version,
            image_ref=image_ref,
            mode="pull",
            policy_rule=policy_rule,
            provenance=_provenance_counts(source.build),
        )
    return None


def _project_dockerfile_candidate(build: Mapping[str, Any]) -> str | None:
    """Return a project Dockerfile path candidate from build provenance."""

    dockerfile_path = _source_string(build.get("dockerfile_path"))
    return (
        dockerfile_path
        if dockerfile_path and _looks_like_project_dockerfile_path(dockerfile_path)
        else None
    )


def _build_rejection_reason(
    project_dir: Path,
    dockerfile_path: str,
    build: Mapping[str, Any],
) -> str | None:
    """Return the policy reason that prevents a local build operation."""

    reason = None
    resolved = _project_relative_file(project_dir, dockerfile_path)
    if resolved is None or not resolved.is_file():
        reason = "unsafe-build-path"
    elif not isinstance(build.get("instructions"), list) or not build["instructions"]:
        reason = "insufficient-build-provenance"
    return reason


def _looks_like_project_dockerfile_path(raw_path: str) -> bool:
    """Return whether a build path should be treated as repo-local input."""

    posix = PurePosixPath(raw_path)
    return (
        not raw_path.startswith(("upstream:", "upstream "))
        and _PROJECT_DOCKERFILE_PATH_RE.fullmatch(raw_path) is not None
        and (
            posix.is_absolute()
            or ".." in posix.parts
            or "/" in raw_path
            or posix.name == "Dockerfile"
        )
    )


def _project_relative_file(project_dir: Path, raw_path: str) -> Path | None:
    """Resolve a contained project-relative path or return None."""

    posix = PurePosixPath(raw_path)
    if posix.is_absolute() or ".." in posix.parts:
        return None
    resolved = (project_dir / Path(*posix.parts)).resolve()
    try:
        resolved.relative_to(project_dir.resolve())
    except ValueError:
        return None
    return resolved


def _local_build_ref(source_name: str, source_version: str) -> str | None:
    """Return the local tag used for a trusted project build."""

    if _is_digest_pinned_version(source_version):
        tag = "local"
    elif source_version not in {"", "*"} and _SAFE_TAG_RE.fullmatch(source_version):
        tag = source_version
    else:
        tag = "local"
    if not _safe_image_name(source_name):
        return None
    return f"{source_name}:{tag}"


def _allowed_digest_pinned_ref(source_name: str, source_version: str) -> str | None:
    """Return a digest-pinned pull ref only for allowed source names."""

    image_ref = None
    if source_name in _ALLOWED_DIGEST_SOURCE_NAMES:
        if "@sha256:" in source_version:
            image_name, digest = source_version.rsplit("@", 1)
            if (
                image_name == source_name
                and _DIGEST_RE.fullmatch(digest)
                and _safe_image_name(image_name)
            ):
                image_ref = source_version
        elif _DIGEST_RE.fullmatch(source_version) and _safe_image_name(source_name):
            image_ref = f"{source_name}@{source_version}"
    return image_ref


def _is_digest_pinned_version(source_version: str) -> bool:
    """Return whether a version value carries a sha256 image digest."""

    if "@sha256:" in source_version:
        _, digest = source_version.rsplit("@", 1)
        return _DIGEST_RE.fullmatch(digest) is not None
    return _DIGEST_RE.fullmatch(source_version) is not None


def _is_compose_owned_source(source_name: str, source_version: str) -> bool:
    """Return whether Compose already owns the image binding for this source."""

    return source_version in {"local", "reference"} and (
        _COMPOSE_SOURCE_NAME_RE.fullmatch(source_name) is not None
    )


def _safe_image_name(value: str) -> bool:
    """Return whether an image name is syntactically safe for generated tags."""

    if not value or value.startswith(("-", ".")) or value.endswith(("/", ":")):
        return False
    return all(part not in {"", ".", ".."} for part in re.split(r"[/:]", value))
