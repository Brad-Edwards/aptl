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

from pathlib import Path

import yaml

from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.runtime_authority import DOCKER_SOCKET_PATH

AUTHORITY_COMPOSE_FILE = "docker-compose.authority.yml"
AUTHORITY_SERVICE = "docker-authority-proxy"
AUTHORITY_CONTAINER = "aptl-docker-authority-proxy"

#: Host-side directory holding the mediated socket. It is a directory rather
#: than a bare file so the proxy can create and recreate its socket inside a
#: bind that already exists.
AUTHORITY_SOCKET_RELDIR = Path(".aptl/realization/docker-authority")
AUTHORITY_SOCKET_NAME = "docker.sock"
_SOCKET_DIR_PLACEHOLDER = "generated:docker-authority-socket-dir"


def authority_requested(realization: DeploymentRealizationSpec) -> bool:
    """Return whether the admitted plan carries any Docker authority."""

    return bool(realization.docker_authority_admissions)


def authority_socket_dir(realization_root: Path) -> Path:
    """Return the host directory the mediated socket is created in."""

    return (realization_root.resolve() / AUTHORITY_SOCKET_RELDIR).resolve()


def authority_socket_path(realization_root: Path) -> Path:
    """Return the host path of the mediated socket itself."""

    return authority_socket_dir(realization_root) / AUTHORITY_SOCKET_NAME


def admitted_authority_images(realization: DeploymentRealizationSpec) -> tuple[str, ...]:
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


def authority_compose_file(
    project_dir: Path,
    realization: DeploymentRealizationSpec,
    realization_root: Path,
) -> Path:
    """Write the apparatus model with engine-anchored sources and image policy."""

    root = project_dir.resolve()
    model = yaml.safe_load(
        (root / AUTHORITY_COMPOSE_FILE).read_text(encoding="utf-8")
    )
    service = model["services"][AUTHORITY_SERVICE]
    service["build"]["context"] = str(root)

    socket_dir = authority_socket_dir(realization_root)
    socket_dir.mkdir(parents=True, exist_ok=True)
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

    if not authority_requested(realization):
        return None
    holders = {
        admission.service_name
        for admission in realization.docker_authority_admissions
    }
    if AUTHORITY_SERVICE in holders or AUTHORITY_CONTAINER in {
        node.container_name for node in realization.nodes
    }:
        return "aptl.docker-authority.ownership-conflict"
    return None


__all__ = (
    "AUTHORITY_COMPOSE_FILE",
    "AUTHORITY_CONTAINER",
    "AUTHORITY_SERVICE",
    "AUTHORITY_SOCKET_NAME",
    "AUTHORITY_SOCKET_RELDIR",
    "DOCKER_SOCKET_PATH",
    "admitted_authority_images",
    "authority_compose_file",
    "authority_declaration_error",
    "authority_requested",
    "authority_socket_dir",
    "authority_socket_path",
)
