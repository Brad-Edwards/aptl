"""Resolve ACES node source payloads into deployment image operations."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import PlannedResource

from aptl.backends.aces_diagnostics import diagnostic
from aptl.core.deployment.realization import DeploymentImageRealization

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_COMPOSE_SOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_PROJECT_DOCKERFILE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

_ALLOWED_SOURCE_IMAGE_REFS = {
    ("postgres", "16"): "postgres:16-alpine",
    ("postgres", "16-alpine"): "postgres:16-alpine",
    ("wazuh-manager", "4.x"): "wazuh/wazuh-manager:4.12.0",
    ("wazuh-indexer", "4.x"): "wazuh/wazuh-indexer:4.12.0",
    ("wazuh-dashboard", "4.x"): "wazuh/wazuh-dashboard:4.12.0",
}

_ALLOWED_DIGEST_SOURCE_NAMES = frozenset(
    {
        "cassandra",
        "docker.elastic.co/elasticsearch/elasticsearch",
        "ghcr.io/docker-mailserver/docker-mailserver",
        "ghcr.io/misp/misp-docker/misp-core",
        "ghcr.io/shuffle/shuffle-backend",
        "ghcr.io/shuffle/shuffle-frontend",
        "ghcr.io/shuffle/shuffle-orborus",
        "grafana/grafana",
        "grafana/tempo",
        "jasonish/suricata",
        "mariadb",
        "opensearchproject/opensearch",
        "otel/opentelemetry-collector-contrib",
        "postgres",
        "redis",
        "strangebee/thehive",
        "thehiveproject/cortex",
        "wazuh/wazuh-dashboard",
        "wazuh/wazuh-indexer",
        "wazuh/wazuh-manager",
    }
)


@dataclass(frozen=True)
class _NodeSource:
    """Normalized ACES source fields relevant to image realization."""

    name: str
    version: str
    build: object


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
            if image is None and not _is_compose_owned_source(
                source.name, source.version
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


def _resolve_trusted_image(
    *,
    resource: PlannedResource,
    source: _NodeSource,
    project_dir: Path,
    service_name: str,
    diagnostics: list[Diagnostic],
) -> DeploymentImageRealization | None:
    """Resolve one normalized source through build, alias, and digest policies."""

    image = None
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


def _provenance_counts(build: object) -> dict[str, int] | None:
    """Return non-secret provenance list sizes for realization details."""

    if not isinstance(build, Mapping):
        return None
    counts = {
        key: len(value)
        for key in ("instructions", "layers", "source_inputs")
        if isinstance((value := build.get(key)), list)
    }
    return counts or None


def _policy_diagnostic(address: str, reason_code: str) -> Diagnostic:
    """Build a policy diagnostic without exposing rejected source values."""

    return diagnostic(
        "aptl.provisioner.image-policy-rejected",
        address,
        (
            "ACES node image source was rejected by the APTL image policy "
            f"(reason={reason_code})."
        ),
    )
