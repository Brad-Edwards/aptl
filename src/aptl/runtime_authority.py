"""Typed graph admission for host-root-equivalent runtime authorities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import os
from pathlib import PurePosixPath

DOCKER_SOCKET_PATH = "/var/run/docker.sock"


@dataclass(frozen=True)
class DeploymentSpawnImageRequirement:
    """One exact child image plus its runtime-observation contract."""

    node_address: str
    authority_id: str
    template_id: str
    image_ref: str
    execution_timeout_seconds: int
    child_label: str
    expected_count: int


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
    allowed_mount_targets: tuple[str, ...] = ()


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
