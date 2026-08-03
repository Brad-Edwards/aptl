"""Realize one node by materializing its declared state (ADR-048).

Ties a node's realization (its `os` + typed `RuntimeConfiguration`) to a
deployment backend: start the node's generic base container, then run the
generic materialization engine over the backend's `container_exec`. No
product-specific branch: the node's software/identity/services all come from its
declared state, verified by read-after-write.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Protocol

# Image-free nodes are materialized concurrently: each is an independent
# container whose realization (start base, install packages, place content,
# configure services) shells out to Docker, and the project networks are already
# created before this step. Serial materialization made a full range's boot the
# SUM of every node's runtime apt install (~1 min each); a bounded pool makes it
# the slowest single node instead. The cap keeps concurrent apt/network load
# sane on a laptop-class host (issue #875).
_MAX_MATERIALIZATION_WORKERS = 8

from raes.runtime_configuration import RuntimeConfiguration

from aptl.backends.raes_base_substrate import BaseContainerSpec, VolumeMount, plan_node
from aptl.backends.raes_docker_materializer import DockerMaterializationExecutor
from aptl.backends.raes_materializer import MaterializationOp
from aptl.backends.raes_materializer_engine import materialize_node
from aptl.core.lab_types import LabResult


class _NodeBackend(Protocol):
    """The narrow backend surface node materialization needs."""

    @property
    def project_dir(self) -> Path | None: ...
    def start_base_container(self, spec: BaseContainerSpec) -> None: ...
    def container_exec(
        self, name: str, cmd: list[str], *, timeout: int | None = None
    ) -> subprocess.CompletedProcess: ...
    def copy_into_container(
        self, container: str, source_path: str, dest_path: str, is_directory: bool
    ) -> None: ...


class _MaterializableNode(Protocol):
    """A node carrying the declared desired state to materialize.

    Satisfied by both the RAES-side ``NodeRealization`` and the backend-facing
    ``DeploymentNodeRealization``; the coordinator needs only these fields.
    """

    address: str
    os: str
    os_version: str
    runtime: RuntimeConfiguration | None
    # ADR-051 route 3 (issue #876): carried onto the base spec so a route-3
    # node's substrate starts immutably from the verified config id.
    dynamic_composition: bool


def realize_node(
    node: _MaterializableNode,
    backend: _NodeBackend,
    content: tuple[MaterializationOp, ...] = (),
    scenario_root: Path | None = None,
    extra_volume_mounts: tuple[VolumeMount, ...] = (),
) -> LabResult | None:
    """Materialize one node's declared state onto its generic base container.

    ``scenario_root`` is the bundle root scenario-declared content copied into
    the node resolves against; ``None`` falls back to the backend's in-tree
    project directory (issue #874). Returns ``None`` on fully-verified success,
    or a fail-closed :class:`LabResult` naming the node and the unmet contract.
    """

    spec, ops = plan_node(
        node.address,
        os=node.os,
        os_version=node.os_version,
        runtime=node.runtime,
        content=content,
        dynamic_composition=node.dynamic_composition,
        extra_volume_mounts=extra_volume_mounts,
    )
    container = spec.container_name

    def start_base(_addr: str, _image_ref: str) -> None:
        """Start this node's already-planned base container, ignoring the
        placeholder address/image the engine passes (the real spec is closed
        over)."""
        backend.start_base_container(spec)

    def run_in(container_name: str, argv: list[str]) -> subprocess.CompletedProcess:
        """Run one materialization command inside the node's container."""
        return backend.container_exec(container_name, argv)

    executor = DockerMaterializationExecutor(
        run=run_in,
        container_for=lambda _addr: container,
        start_base=start_base,
        copy_in=backend.copy_into_container,
        scenario_root=(
            scenario_root
            if scenario_root is not None
            else getattr(backend, "project_dir", None)
        ),
    )
    return materialize_node(node.address, ops, executor)


def realize_nodes(
    nodes: Iterable[_MaterializableNode],
    backend: _NodeBackend,
    content_by_node: dict[str, tuple[MaterializationOp, ...]] | None = None,
    scenario_root: Path | None = None,
    volume_mounts_by_node: dict[str, tuple[VolumeMount, ...]] | None = None,
) -> LabResult | None:
    """Materialize every node that declares desired state, failing closed.

    Nodes with no declared `os` (switches, unaddressed nodes) are skipped: there
    is nothing to materialize onto a substrate. Nodes are materialized
    concurrently (a bounded pool) since each is an independent container; if any
    node fails to materialize-and-verify, its fail-closed `LabResult` is returned
    (the first failure in declared node order, for a deterministic message) so a
    partial range never masquerades as realized.
    """

    content_by_node = content_by_node or {}
    volume_mounts_by_node = volume_mounts_by_node or {}
    materializable = [node for node in nodes if node.os]
    if not materializable:
        return None

    workers = min(len(materializable), _MAX_MATERIALIZATION_WORKERS)
    if workers <= 1:
        return realize_node(
            materializable[0],
            backend,
            content_by_node.get(materializable[0].address, ()),
            scenario_root=scenario_root,
            extra_volume_mounts=volume_mounts_by_node.get(
                materializable[0].address, ()
            ),
        )

    results: dict[str, LabResult | None] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                realize_node,
                node,
                backend,
                content_by_node.get(node.address, ()),
                scenario_root=scenario_root,
                extra_volume_mounts=volume_mounts_by_node.get(node.address, ()),
            ): node
            for node in materializable
        }
        for future, node in futures.items():
            results[node.address] = future.result()

    # Fail closed on the first failure in declared node order so the surfaced
    # error is deterministic regardless of completion order.
    for node in materializable:
        result = results.get(node.address)
        if result is not None:
            return result
    return None
