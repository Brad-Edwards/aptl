"""Live materialization checks for bounded participant readiness."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from aptl.backends.raes_realization_model import AptlRealization

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

# SDL-authority class remediation (issue #875): this fixed tuple bakes one
# scenario's participant-action topology into the backend. The correct source is
# the scenario's participant-action-node identity (which nodes participants act
# on), which is NOT carried in AptlRealization today — deriving it requires
# threading participant-behaviour data into this validator, tracked as follow-up
# alongside the other genuine affordance gaps. Until then this stays a documented
# fixed set; it is validation coupling only, never injected container content, and
# does not gate `aptl lab start`.
_REALIZED_NODES = (
    "webapp",
    "db",
    "workstation",
    "kali",
    "defender-console",
    "event-store",
)


def verify_live_materialization(
    backend: DeploymentBackend,
    realization: AptlRealization,
) -> tuple[str, ...]:
    """Verify the already-running lab carries this exact scenario's inputs."""

    containers = {
        node.name: node.container_name
        for node in realization.nodes
        if node.container_name
    }
    diagnostics = _verify_nodes(backend, containers)
    diagnostics.extend(_verify_placements(backend, containers, realization))
    return tuple(diagnostics)


def _verify_nodes(
    backend: DeploymentBackend,
    containers: dict[str, str],
) -> list[str]:
    """Check every participant action node is live and executable."""

    diagnostics: list[str] = []
    for node_name in _REALIZED_NODES:
        container = containers.get(node_name)
        result = None
        if container is not None:
            try:
                result = backend.container_exec(container, ["true"], timeout=10)
            except (OSError, subprocess.SubprocessError):
                result = None
        if (
            not isinstance(result, subprocess.CompletedProcess)
            or result.returncode != 0
        ):
            diagnostic = (
                f"required realized node is absent: {node_name}"
                if container is None
                else f"required lab target is unavailable: {node_name}"
            )
            diagnostics.append(diagnostic)
    return diagnostics


def _verify_placements(
    backend: DeploymentBackend,
    containers: dict[str, str],
    realization: AptlRealization,
) -> list[str]:
    """Check authored scenario content is present at every realized target."""

    diagnostics: list[str] = []
    for placement in realization.placements:
        content = placement.content
        if content is None:
            continue
        container = containers.get(
            placement.target_address.removeprefix("provision.node.")
        )
        path = _live_content_path(content.volume_suffix, content.dest_relpath)
        if container is None or path is None:
            diagnostics.append(
                f"content carrier is not live-verifiable: {placement.address}"
            )
            continue
        try:
            result = backend.container_exec(
                container,
                ["test", "-e", path],
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            result = None
        if (
            not isinstance(result, subprocess.CompletedProcess)
            or result.returncode != 0
        ):
            diagnostics.append(
                f"authored scenario content is absent: {placement.address}"
            )
    return diagnostics


def _live_content_path(volume_suffix: str, dest_relpath: str) -> str | None:
    """Resolve a content placement to its live container path."""

    if not volume_suffix:
        return f"/{dest_relpath}"
    return None
