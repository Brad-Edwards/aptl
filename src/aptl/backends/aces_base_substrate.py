"""Generic base-substrate decision for a node (ADR-047).

Decides which generic base-OS container a node runs on, and whether that
container must be init-capable (so declared `service_manager_units` can run under
a service manager). The decision is scenario-independent: it reads only the
declared `os`/`os_version` and whether the node declares any service units. It
never selects a per-node or appliance image.

The concrete init mechanism (how the backend makes `systemctl` work inside the
container) is host/backend integration proven in AWS, not encoded here; this
module carries only the typed, testable decision.
"""

from __future__ import annotations

from dataclasses import dataclass

from aces_sdl.runtime_configuration import RuntimeConfiguration

from aptl.backends.aces_materializer import (
    MaterializationOp,
    base_image_for_os,
    plan_node_materialization,
)


@dataclass(frozen=True)
class BaseContainerSpec:
    """The generic base container a node is realized onto."""

    node_address: str
    container_name: str
    image_ref: str
    runs_services: bool


def _container_name(node_address: str) -> str:
    # Project-scoped, node-derived; never product-specific. The leaf of the
    # address is the node's local name.
    return "aptl-" + node_address.rsplit(".", 1)[-1]


def base_container_spec(
    node_address: str,
    *,
    os: str,
    os_version: str,
    runtime: RuntimeConfiguration | None,
) -> BaseContainerSpec:
    """Return the generic base-container decision for one node.

    Fails closed (`UnsupportedOsFamilyError`) when APTL has no generic base for
    the declared OS family, rather than guessing an image.
    """

    runs_services = bool(runtime is not None and runtime.service_manager_units)
    return BaseContainerSpec(
        node_address=node_address,
        container_name=_container_name(node_address),
        image_ref=base_image_for_os(os, os_version),
        runs_services=runs_services,
    )


def plan_node(
    node_address: str,
    *,
    os: str,
    os_version: str,
    runtime: RuntimeConfiguration | None,
) -> tuple[BaseContainerSpec, tuple[MaterializationOp, ...]]:
    """Plan one node: its generic base container plus its materialization ops.

    The single entry point a deployment backend consumes per node. It starts the
    container described by the returned :class:`BaseContainerSpec` (with an init
    when ``runs_services`` is set), then runs the returned operations through the
    materialization engine. Both halves are derived only from declared state, so
    the substrate decision and the ops stay coherent.
    """

    spec = base_container_spec(
        node_address, os=os, os_version=os_version, runtime=runtime
    )
    ops = plan_node_materialization(os=os, os_version=os_version, runtime=runtime)
    return spec, ops
