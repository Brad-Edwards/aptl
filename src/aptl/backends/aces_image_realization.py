"""Resolve ACES node source payloads into deployment image operations."""

from __future__ import annotations

import re
from collections.abc import Mapping
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
        "jasonish/suricata",
        "mariadb",
        "opensearchproject/opensearch",
        "postgres",
        "redis",
        "strangebee/thehive",
        "thehiveproject/cortex",
        "wazuh/wazuh-dashboard",
        "wazuh/wazuh-indexer",
        "wazuh/wazuh-manager",
    }
)


def resolve_node_image(
    *,
    resource: PlannedResource,
    payload: Mapping[str, Any],
    project_dir: Path,
    service_name: str | None,
    diagnostics: list[Diagnostic],
) -> DeploymentImageRealization | None:
    """Return the deployment image operation declared by one node source."""

    source = _node_source(payload)
    if source is None:
        return None
    if not isinstance(source, Mapping):
        diagnostics.append(_policy_diagnostic(resource.address, "invalid-source"))
        return None

    source_name = _source_string(source.get("name"))
    source_version = _source_string(source.get("version")) or "*"
    if not source_name:
        diagnostics.append(_policy_diagnostic(resource.address, "invalid-source"))
        return None

    build = source.get("build")
    if service_name is None:
        diagnostics.append(_policy_diagnostic(resource.address, "unmapped-service"))
        return None

    if isinstance(build, Mapping):
        image = _build_image(
            resource=resource,
            source_name=source_name,
            source_version=source_version,
            build=build,
            project_dir=project_dir,
            service_name=service_name,
            diagnostics=diagnostics,
        )
        if image is not None:
            return image

    allowed_ref = _ALLOWED_SOURCE_IMAGE_REFS.get((source_name, source_version))
    if allowed_ref is not None:
        return DeploymentImageRealization(
            address=resource.address,
            service_name=service_name,
            source_name=source_name,
            source_version=source_version,
            image_ref=allowed_ref,
            mode="pull",
            policy_rule="allowed-source",
            provenance=_provenance_counts(build),
        )

    image_ref = _allowed_digest_pinned_ref(source_name, source_version)
    if image_ref is not None:
        return DeploymentImageRealization(
            address=resource.address,
            service_name=service_name,
            source_name=source_name,
            source_version=source_version,
            image_ref=image_ref,
            mode="pull",
            policy_rule="allowed-digest",
            provenance=_provenance_counts(build),
        )

    if _is_compose_owned_source(source_name, source_version):
        return None

    diagnostics.append(_policy_diagnostic(resource.address, "untrusted-image"))
    return None


def _node_source(payload: Mapping[str, Any]) -> object:
    spec = payload.get("spec")
    if not isinstance(spec, Mapping):
        return None
    node = spec.get("node")
    if not isinstance(node, Mapping):
        return None
    return node.get("source")


def _source_string(value: object) -> str | None:
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    return None


def _build_image(
    *,
    resource: PlannedResource,
    source_name: str,
    source_version: str,
    build: Mapping[str, Any],
    project_dir: Path,
    service_name: str,
    diagnostics: list[Diagnostic],
) -> DeploymentImageRealization | None:
    dockerfile_path = _source_string(build.get("dockerfile_path"))
    if dockerfile_path is None:
        return None
    if not _looks_like_project_dockerfile_path(dockerfile_path):
        return None

    resolved = _project_relative_file(project_dir, dockerfile_path)
    if resolved is None or not resolved.is_file():
        diagnostics.append(_policy_diagnostic(resource.address, "unsafe-build-path"))
        return None
    if not isinstance(build.get("instructions"), list) or not build["instructions"]:
        diagnostics.append(
            _policy_diagnostic(resource.address, "insufficient-build-provenance")
        )
        return None

    image_ref = _local_build_ref(source_name, source_version)
    if image_ref is None:
        diagnostics.append(_policy_diagnostic(resource.address, "invalid-local-tag"))
        return None

    return DeploymentImageRealization(
        address=resource.address,
        service_name=service_name,
        source_name=source_name,
        source_version=source_version,
        image_ref=image_ref,
        mode="build",
        policy_rule="project-build-provenance",
        dockerfile_path=dockerfile_path,
        context_path=".",
        provenance=_provenance_counts(build),
    )


def _looks_like_project_dockerfile_path(raw_path: str) -> bool:
    if raw_path.startswith(("upstream:", "upstream ")):
        return False
    if not _PROJECT_DOCKERFILE_PATH_RE.fullmatch(raw_path):
        return False

    posix = PurePosixPath(raw_path)
    if posix.is_absolute() or ".." in posix.parts:
        return True
    return "/" in raw_path or posix.name == "Dockerfile"


def _project_relative_file(project_dir: Path, raw_path: str) -> Path | None:
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
    if source_name not in _ALLOWED_DIGEST_SOURCE_NAMES:
        return None
    if "@sha256:" in source_version:
        image_name, digest = source_version.rsplit("@", 1)
        if (
            image_name == source_name
            and _DIGEST_RE.fullmatch(digest)
            and _safe_image_name(image_name)
        ):
            return source_version
        return None
    if _DIGEST_RE.fullmatch(source_version) and _safe_image_name(source_name):
        return f"{source_name}@{source_version}"
    return None


def _is_digest_pinned_version(source_version: str) -> bool:
    if "@sha256:" in source_version:
        _, digest = source_version.rsplit("@", 1)
        return _DIGEST_RE.fullmatch(digest) is not None
    return _DIGEST_RE.fullmatch(source_version) is not None


def _is_compose_owned_source(source_name: str, source_version: str) -> bool:
    return source_version in {"local", "reference"} and (
        _COMPOSE_SOURCE_NAME_RE.fullmatch(source_name) is not None
    )


def _safe_image_name(value: str) -> bool:
    if not value or value.startswith(("-", ".")) or value.endswith(("/", ":")):
        return False
    return all(part not in {"", ".", ".."} for part in re.split(r"[/:]", value))


def _provenance_counts(build: object) -> dict[str, int] | None:
    if not isinstance(build, Mapping):
        return None
    counts = {
        key: len(value)
        for key in ("instructions", "layers", "source_inputs")
        if isinstance((value := build.get(key)), list)
    }
    return counts or None


def _policy_diagnostic(address: str, reason_code: str) -> Diagnostic:
    return diagnostic(
        "aptl.provisioner.image-policy-rejected",
        address,
        (
            "ACES node image source was rejected by the APTL image policy "
            f"(reason={reason_code})."
        ),
    )
