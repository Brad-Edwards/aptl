"""Pure normalization and policy helpers for runtime observation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from aptl.runtime_authority import (
    DOCKER_SOCKET_PATH,
    DeploymentDockerAuthorityAdmission,
    has_undeclared_runtime_mounts,
    mount_exposes_or_mentions_docker_socket,
)


def inspect_mounts(info: object) -> Sequence[object]:
    """Return normalized Docker inspect mount entries."""

    mounts = info.get("Mounts") if isinstance(info, Mapping) else None
    if isinstance(mounts, Sequence) and not isinstance(mounts, (str, bytes)):
        return mounts
    return ()


def inspect_environment(info: object) -> Sequence[object]:
    """Return normalized Docker inspect environment entries."""

    config = info.get("Config") if isinstance(info, Mapping) else None
    raw_env = config.get("Env") if isinstance(config, Mapping) else None
    if isinstance(raw_env, Sequence) and not isinstance(raw_env, (str, bytes)):
        return raw_env
    return ()


def inspect_has_endpoint_override(info: object) -> bool:
    """Whether inspect environment redirects Docker commands elsewhere."""

    return any(
        str(item).split("=", 1)[0] in {"DOCKER_HOST", "DOCKER_CONTEXT"}
        for item in inspect_environment(info)
    )


def inspect_has_socket_route(info: object) -> bool:
    """Whether any observed bind contains or targets the Docker socket."""

    return any(
        mount_exposes_or_mentions_docker_socket(
            mount,
            source_key="Source",
            target_key="Destination",
            type_key="Type",
            bind_type="bind",
        )
        for mount in inspect_mounts(info)
    )


def _mount_is_canonical_authority_socket(mount: object) -> bool:
    """Whether one observed mount is the declared host-root-equivalent bind."""

    if not isinstance(mount, Mapping):
        return False
    return bool(
        mount.get("Type") == "bind"
        and mount.get("Source") == DOCKER_SOCKET_PATH
        and mount.get("Destination") == DOCKER_SOCKET_PATH
        and mount.get("RW") is True
    )


def authority_mount_is_valid(
    entries: Sequence[object],
    admission: DeploymentDockerAuthorityAdmission,
) -> bool:
    """Whether a holder exposes only its admitted runtime mount footprint."""

    socket_mounts = [
        mount
        for mount in entries
        if mount_exposes_or_mentions_docker_socket(
            mount,
            source_key="Source",
            target_key="Destination",
            type_key="Type",
            bind_type="bind",
        )
    ]
    return bool(
        len(socket_mounts) == 1
        and _mount_is_canonical_authority_socket(socket_mounts[0])
        and not has_undeclared_runtime_mounts(
            entries,
            allowed_targets=set(admission.allowed_mount_targets),
            docker_authority_admitted=True,
        )
    )


__all__ = (
    "authority_mount_is_valid",
    "inspect_environment",
    "inspect_has_endpoint_override",
    "inspect_has_socket_route",
    "inspect_mounts",
)
