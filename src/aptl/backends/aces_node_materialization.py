"""Realize one node by materializing its declared state (ADR-048).

Ties a node's realization (its `os` + typed `RuntimeConfiguration`) to a
deployment backend: start the node's generic base container, then run the
generic materialization engine over the backend's `container_exec`. No
product-specific branch: the node's software/identity/services all come from its
declared state, verified by read-after-write.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from aces_sdl.runtime_configuration import RuntimeConfiguration

from aptl.backends.aces_base_substrate import BaseContainerSpec, plan_node
from aptl.backends.aces_docker_materializer import DockerMaterializationExecutor
from aptl.backends.aces_materializer import PlaceFileOp
from aptl.backends.aces_materializer_engine import materialize_node
from aptl.core.lab_types import LabResult


class _NodeBackend(Protocol):
    """The narrow backend surface node materialization needs."""

    @property
    def project_dir(self): ...
    def start_base_container(self, spec: BaseContainerSpec) -> None: ...
    def container_exec(self, name: str, cmd: list[str], *, timeout: int | None = None): ...
    def copy_into_container(
        self, container: str, source_path: str, dest_path: str, is_directory: bool
    ) -> None: ...


class _MaterializableNode(Protocol):
    """A node carrying the declared desired state to materialize.

    Satisfied by both the ACES-side ``NodeRealization`` and the backend-facing
    ``DeploymentNodeRealization``; the coordinator needs only these fields.
    """

    address: str
    os: str
    os_version: str
    runtime: RuntimeConfiguration | None


def realize_node(
    node: _MaterializableNode,
    backend: _NodeBackend,
    content: tuple[MaterializationOp, ...] = (),
) -> LabResult | None:
    """Materialize one node's declared state onto its generic base container.

    Returns ``None`` on fully-verified success, or a fail-closed
    :class:`LabResult` naming the node and the unmet contract.
    """

    spec, ops = plan_node(
        node.address,
        os=node.os,
        os_version=node.os_version,
        runtime=node.runtime,
        content=content,
    )
    container = spec.container_name

    def start_base(_addr: str, _image_ref: str) -> None:
        backend.start_base_container(spec)

    def run_in(container_name: str, argv: list[str]):
        return backend.container_exec(container_name, argv)

    executor = DockerMaterializationExecutor(
        run=run_in,
        container_for=lambda _addr: container,
        start_base=start_base,
        copy_in=backend.copy_into_container,
        project_dir=getattr(backend, "project_dir", None),
    )
    return materialize_node(node.address, ops, executor)


def realize_nodes(
    nodes: Iterable[_MaterializableNode],
    backend: _NodeBackend,
    content_by_node: dict[str, tuple[MaterializationOp, ...]] | None = None,
) -> LabResult | None:
    """Materialize every node that declares desired state, failing closed.

    Nodes with no declared `os` (switches, unaddressed nodes) are skipped: there
    is nothing to materialize onto a substrate. The first node that fails to
    materialize-and-verify returns its fail-closed `LabResult`; the rest are not
    started, so a partial range never masquerades as realized.
    """

    content_by_node = content_by_node or {}
    for node in nodes:
        if not node.os:
            continue
        result = realize_node(node, backend, content_by_node.get(node.address, ()))
        if result is not None:
            return result
    return None
