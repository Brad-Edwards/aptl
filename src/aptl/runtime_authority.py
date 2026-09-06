"""Typed graph admission for host-root-equivalent runtime authorities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
import os
from pathlib import PurePosixPath
import re

from aptl.core.provenance.identity import derive_identity

DOCKER_SOCKET_PATH = "/var/run/docker.sock"
_DIGEST_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_DIGEST_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_PRODUCT_EXECUTION_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


@dataclass(frozen=True)
class DeploymentSpawnImageRequirement:
    """One exact child image plus its effective runtime contract."""

    node_address: str
    authority_id: str
    template_id: str
    image_ref: str
    execution_timeout_seconds: int
    runtime_alias: str | None
    delegated_docker_authority: bool


@dataclass(frozen=True)
class DeploymentDockerAuthorityAdmission:
    """Complete trusted decision allowing one management-only holder."""

    node_address: str
    service_name: str
    engine: str
    privilege_class: str
    endpoint_kind: str
    endpoint_source: str
    endpoint_target: str
    endpoint_read_write: bool
    spawn_requirements: tuple[DeploymentSpawnImageRequirement, ...]
    pack_id: str
    pack_version: str
    pack_set_digest: str
    run_id: str
    attempt_id: str
    correlation_id: str
    product_execution_ids: tuple[str, ...] = ()
    allowed_mount_targets: tuple[str, ...] = ()

    def bind_product_execution(
        self, product_execution_id: str
    ) -> DeploymentDockerAuthorityAdmission:
        """Return this run admission narrowed to one observed product execution."""

        if _PRODUCT_EXECUTION_ID.fullmatch(product_execution_id) is None:
            raise ValueError("runtime product execution identity is invalid")
        identities = (*self.product_execution_ids, product_execution_id)
        if len(identities) != len(set(identities)):
            raise ValueError("runtime product execution identity is duplicated")
        return replace(self, product_execution_ids=identities)


@dataclass(frozen=True)
class DeploymentSpawnedChildObservation:
    """Safe normalized evidence for one positively owned runtime child."""

    node_address: str
    authority_id: str
    template_id: str
    correlation_id: str
    authority_correlation_id: str
    run_id: str
    attempt_id: str
    product_execution_id: str
    container_id: str
    image_id: str
    parent_container_id: str
    delegated_docker_authority: bool
    terminal: bool


def exact_docker_image_reference_is_valid(image_ref: object) -> bool:
    """Whether a value is one canonical digest-qualified Docker reference."""

    return bool(_DIGEST_IMAGE.fullmatch(str(image_ref or "")))


def sha256_identity_is_valid(identity: object) -> bool:
    """Whether a value is one canonical SHA-256 identity."""

    return bool(_DIGEST_ID.fullmatch(str(identity or "")))


def runtime_product_execution_id_is_valid(identity: object) -> bool:
    """Whether a product marker is bounded enough for exact runtime matching."""

    return bool(_PRODUCT_EXECUTION_ID.fullmatch(str(identity or "")))


def runtime_alias_for_exact_image(image_ref: str) -> str | None:
    """Return the authored tag alias without confusing registry-port colons."""

    if not exact_docker_image_reference_is_valid(image_ref):
        return None
    name, _separator, _digest = image_ref.rpartition("@")
    final_segment = name.rsplit("/", 1)[-1]
    if ":" not in final_segment:
        return None
    repository, _separator, tag = final_segment.rpartition(":")
    return name if repository and tag else None


def runtime_child_correlation_id(
    admission: DeploymentDockerAuthorityAdmission,
    requirement: DeploymentSpawnImageRequirement,
    product_execution_id: str,
) -> str:
    """Bind one product-supported execution marker to run and template scope."""

    if product_execution_id not in admission.product_execution_ids:
        raise ValueError("runtime product execution identity is not admitted")
    return derive_identity(
        "runtime-child",
        {
            "authority_correlation_id": admission.correlation_id,
            "run_id": admission.run_id,
            "attempt_id": admission.attempt_id,
            "template_id": requirement.template_id,
            "product_execution_id": product_execution_id,
        },
    )


def bind_source_exposes_docker_socket(source: object) -> bool:
    """Whether a host bind source contains the selected Docker socket."""

    raw = str(source or "")
    if not raw.startswith("/"):
        return False
    sources = {os.path.normpath(raw), os.path.realpath(raw)}
    sockets = {
        os.path.normpath(DOCKER_SOCKET_PATH),
        os.path.realpath(DOCKER_SOCKET_PATH),
    }
    return any(
        socket == source_path
        or PurePosixPath(socket).is_relative_to(PurePosixPath(source_path))
        for source_path in sources
        for socket in sockets
    )


def mount_exposes_or_mentions_docker_socket(
    mount: object,
    *,
    source_key: str,
    target_key: str,
    type_key: str,
    bind_type: str,
) -> bool:
    """Whether a bind exposes the socket or targets its canonical location."""

    return bool(
        isinstance(mount, Mapping)
        and mount.get(type_key) == bind_type
        and (
            bind_source_exposes_docker_socket(mount.get(source_key))
            or mount.get(target_key) == DOCKER_SOCKET_PATH
        )
    )


def has_undeclared_runtime_mounts(
    realized_mounts: Sequence[object],
    *,
    allowed_targets: set[str],
    docker_authority_admitted: bool,
) -> bool:
    """Whether observed bind/tmpfs state exceeds an admitted target set."""

    for realized in realized_mounts:
        if not isinstance(realized, Mapping):
            continue
        mount_type = realized.get("Type")
        if mount_type not in {"bind", "tmpfs"}:
            continue
        exposes_socket = mount_exposes_or_mentions_docker_socket(
            realized,
            source_key="Source",
            target_key="Destination",
            type_key="Type",
            bind_type="bind",
        )
        if exposes_socket:
            canonical = bool(
                realized.get("Source") == DOCKER_SOCKET_PATH
                and realized.get("Destination") == DOCKER_SOCKET_PATH
                and realized.get("RW") is True
            )
            if not (docker_authority_admitted and canonical):
                return True
            continue
        if realized.get("Destination") not in allowed_targets:
            return True
    return False
