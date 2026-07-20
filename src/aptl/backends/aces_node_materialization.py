"""Realize one node by materializing its declared state (ADR-047).

Ties a node's realization (its `os` + typed `RuntimeConfiguration`) to a
deployment backend: start the node's generic base container, then run the
generic materialization engine over the backend's `container_exec`. No
product-specific branch: the node's software/identity/services all come from its
declared state, verified by read-after-write.
"""

from __future__ import annotations

from typing import Protocol

from aptl.backends.aces_base_substrate import BaseContainerSpec, plan_node
from aptl.backends.aces_docker_materializer import DockerMaterializationExecutor
from aptl.backends.aces_materializer_engine import materialize_node
from aptl.backends.aces_realization_model import NodeRealization
from aptl.core.lab_types import LabResult


class _NodeBackend(Protocol):
    """The narrow backend surface node materialization needs."""

    def start_base_container(self, spec: BaseContainerSpec) -> None: ...
    def container_exec(self, name: str, cmd: list[str], *, timeout: int | None = None): ...


def realize_node(node: NodeRealization, backend: _NodeBackend) -> LabResult | None:
    """Materialize one node's declared state onto its generic base container.

    Returns ``None`` on fully-verified success, or a fail-closed
    :class:`LabResult` naming the node and the unmet contract.
    """

    spec, ops = plan_node(
        node.address, os=node.os, os_version=node.os_version, runtime=node.runtime
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
    )
    return materialize_node(node.address, ops, executor)
