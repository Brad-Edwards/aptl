"""Trusted Compose model for the mediated Docker authority apparatus.

A scenario that declares an orchestration authority is declaring that a node
must be able to run workloads. It is not declaring that the node should hold
the host's own Docker socket -- the Docker API is a host-root API, and handing
it over unmediated would let a compromise of that node create a container with
a host bind or `Privileged` and leave the range entirely. Which mechanism
grants the declared authority is a backend choice, so APTL puts the socket
behind an authorization boundary and gives the declaring node that instead.

This module owns where the mediated socket lives and what the boundary is told
to permit. The permitted image set is exactly the admitted spawn requirements,
so the pack's declaration remains the only source of what may run.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat

import yaml

from aptl.core.credentials import _canonical_generated_path
from aptl.core.deployment._compose_realization_networks import _compose_network_key
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.runtime_authority import (
    DOCKER_SOCKET_PATH,
    MEDIATED_DOCKER_SOCKET_RELPATH,
)

AUTHORITY_COMPOSE_FILE = "docker-compose.authority.yml"
AUTHORITY_SERVICE = "docker-authority-proxy"
AUTHORITY_CONTAINER = "aptl-docker-authority-proxy"

#: Host-side directory holding the mediated socket. It is a directory rather
#: than a bare file so the proxy can create and recreate its socket inside a
#: bind that already exists.
AUTHORITY_SOCKET_RELDIR = Path(MEDIATED_DOCKER_SOCKET_RELPATH.parent.as_posix())
AUTHORITY_SOCKET_NAME = MEDIATED_DOCKER_SOCKET_RELPATH.name
AUTHORITY_OWNER_LABEL_KEY = "org.aptl.docker-authority"
AUTHORITY_OWNER_LABEL_VALUE = "managed"
AUTHORITY_OWNER_LABEL = f"{AUTHORITY_OWNER_LABEL_KEY}={AUTHORITY_OWNER_LABEL_VALUE}"
_SOCKET_DIR_PLACEHOLDER = "generated:docker-authority-socket-dir"


def authority_requested(realization: DeploymentRealizationSpec) -> bool:
    """Return whether the admitted plan carries any Docker authority."""

    return bool(realization.docker_authority_admissions)


def authority_socket_dir(realization_root: Path) -> Path:
    """Return the host directory the mediated socket is created in."""

    return _canonical_generated_path(realization_root, AUTHORITY_SOCKET_RELDIR)


def authority_socket_path(realization_root: Path) -> Path:
    """Return the host path of the mediated socket itself."""

    return authority_socket_dir(realization_root) / AUTHORITY_SOCKET_NAME


def _runtime_identity() -> tuple[int, int, int]:
    """Return the host uid/gid and daemon-socket gid the proxy must carry."""

    try:
        socket_info = os.stat(DOCKER_SOCKET_PATH)
    except OSError as exc:
        raise ValueError("Docker authority upstream socket is unavailable") from exc
    if not stat.S_ISSOCK(socket_info.st_mode):
        raise ValueError("Docker authority upstream endpoint is not a socket")
    return os.getuid(), os.getgid(), socket_info.st_gid


def admitted_authority_images(
    realization: DeploymentRealizationSpec,
) -> tuple[str, ...]:
    """Return every exact image reference the admitted authorities may run.

    An authority with no admitted spawn requirement contributes nothing, so the
    boundary permits nothing for it. That is the correct posture: a declaration
    that names no image has not authorized one.
    """

    return tuple(
        sorted(
            {
                requirement.image_ref
                for admission in realization.docker_authority_admissions
                for requirement in admission.spawn_requirements
                if requirement.image_ref
            }
        )
    )


def admitted_authority_networks(
    realization: DeploymentRealizationSpec, project_name: str
) -> tuple[str, ...]:
    """Return exact Docker network names the sole authority holder may join."""

    return tuple(
        sorted(
            f"{project_name}_{key}"
            for admission in realization.docker_authority_admissions
            for network in admission.allowed_networks
            if (key := _compose_network_key(network))
        )
    )


def authority_compose_file(
    project_dir: Path,
    realization: DeploymentRealizationSpec,
    realization_root: Path,
    project_name: str,
) -> Path:
    """Write the apparatus model with engine-anchored sources and image policy."""

    root = project_dir.resolve()
    model = yaml.safe_load((root / AUTHORITY_COMPOSE_FILE).read_text(encoding="utf-8"))
    service = model["services"][AUTHORITY_SERVICE]
    service["build"]["context"] = str(root)

    socket_dir = authority_socket_dir(realization_root)
    socket_dir.mkdir(parents=True, exist_ok=True)
    socket_dir.chmod(0o700)
    resolved = False
    for mount in service.get("volumes", ()):
        if mount.get("source") == _SOCKET_DIR_PLACEHOLDER:
            mount["source"] = str(socket_dir)
            resolved = True
    if not resolved:
        raise ValueError("Docker authority apparatus has no mediated socket mount")

    service["environment"]["APTL_DOCKER_AUTHORITY_IMAGES"] = "\n".join(
        admitted_authority_images(realization)
    )
    service["environment"]["APTL_DOCKER_AUTHORITY_OWNER_LABEL"] = AUTHORITY_OWNER_LABEL
    service["environment"]["APTL_DOCKER_AUTHORITY_NETWORKS"] = "\n".join(
        admitted_authority_networks(realization, project_name)
    )
    user_id, group_id, socket_group_id = _runtime_identity()
    service["user"] = f"{user_id}:{group_id}"
    service["group_add"] = [str(socket_group_id)]

    target = root / ".aptl" / "realization" / AUTHORITY_COMPOSE_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        yaml.safe_dump(model, sort_keys=True), encoding="utf-8", newline="\n"
    )
    return target


def authority_declaration_error(
    realization: DeploymentRealizationSpec,
) -> str | None:
    """Return a bounded error when the apparatus cannot mediate the authority.

    The failure mode this exists to prevent is silent: if the apparatus is not
    composed, the declaring node would still need a socket, and the only socket
    available would be the host's own.
    """

    error = None
    if authority_requested(realization):
        if len(realization.docker_authority_admissions) != 1:
            error = "aptl.docker-authority.multiple-authorities-unsupported"
        else:
            holders = {
                admission.service_name
                for admission in realization.docker_authority_admissions
            }
            container_names = {node.container_name for node in realization.nodes}
            if AUTHORITY_SERVICE in holders or AUTHORITY_CONTAINER in container_names:
                error = "aptl.docker-authority.ownership-conflict"
    return error


__all__ = (
    "AUTHORITY_COMPOSE_FILE",
    "AUTHORITY_CONTAINER",
    "AUTHORITY_SERVICE",
    "AUTHORITY_OWNER_LABEL",
    "AUTHORITY_OWNER_LABEL_KEY",
    "AUTHORITY_OWNER_LABEL_VALUE",
    "AUTHORITY_SOCKET_NAME",
    "AUTHORITY_SOCKET_RELDIR",
    "DOCKER_SOCKET_PATH",
    "admitted_authority_images",
    "admitted_authority_networks",
    "authority_compose_file",
    "authority_declaration_error",
    "authority_requested",
    "authority_socket_dir",
    "authority_socket_path",
)
