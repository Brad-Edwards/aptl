"""Image-policy constants and diagnostic helpers for RAES image realization.

The trusted-source allowlists, the syntactic patterns image references are
validated against, and the two pure helpers that summarize build provenance and
build a redacting policy diagnostic. Split out of
:mod:`aptl.backends.raes_image_realization` to keep that module within its size
budget; this is a leaf — it imports nothing from the realizer — so the import is
one-directional.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING

from aptl.backends.raes_diagnostics import diagnostic

if TYPE_CHECKING:
    from raes_contracts.diagnostics import Diagnostic

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
            "RAES node image source was rejected by the APTL image policy "
            f"(reason={reason_code})."
        ),
    )


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
