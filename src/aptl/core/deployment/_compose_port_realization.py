"""Host publishing for scenario-declared runtime ports (issue #578).

An SDL node may declare host-published ports at
``nodes.<n>.runtime.network.published_ports``. Realizing them writes a contained
Compose override, the same mechanism scenario-resolved images already use, so
Compose owns the actual binding and APTL adds no raw Docker passthrough.

Two properties this surface must hold, both security boundaries (ADR-034 Host
Exposure Amendment, ADR-046 runtime addendum):

* **An omitted host address binds loopback, never all interfaces.** Silently
  defaulting to ``0.0.0.0`` would put a scenario-declared port on the operator's
  LAN. An author who wants that must say so with an explicit ``host_ip``. The
  default lives on :class:`DeploymentPublishedPort` so it cannot be forgotten
  here.
* **An exact host binding fails closed.** ``host_ports.resolve_host_ports``
  deliberately *remaps* a taken port for the checked-in compose stack, which is
  right for an operator convenience port but wrong here: a scenario that
  declares a host port is declaring a realization requirement, and quietly
  publishing it somewhere else is the silent approximation SEM-218 forbids. We
  probe with the same ``port_available`` primitive and refuse instead.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from aptl.core.deployment.realization import (
    DeploymentPublishedPort,
    DeploymentRealizationSpec,
)
from aptl.core.host_ports import port_available

_PORT_OVERRIDE_RELATIVE_PATH = Path(".aptl") / "realization" / "compose.ports.yml"


def published_port_conflicts(realization: DeploymentRealizationSpec) -> list[str]:
    """Return one message per exact host binding that cannot be published.

    Only bindings with an author-declared ``host_port`` are exact; a binding
    with no host port asks Compose for an ephemeral publish and cannot conflict.
    """

    conflicts: list[str] = []
    for node in realization.nodes:
        if not node.published_ports:
            continue
        # A node whose alias maps to no single compose service has nowhere to
        # attach a port override, so its declared bindings would be dropped by
        # write_port_override without a trace. A declared host port is a
        # realization requirement, so that silent drop is itself a failure.
        if not node.service_name:
            conflicts.append(
                f"node {node.name!r} declares host-published ports but does not "
                f"resolve to a single compose service, so APTL cannot publish "
                f"them — give the node an unambiguous service binding or drop "
                f"the published ports."
            )
            continue
        for binding in node.published_ports:
            if binding.host_port is None:
                continue
            if not port_available(
                binding.host_port,
                binding.protocol,
                binding.host_ip,
            ):
                conflicts.append(
                    f"node {node.name!r} declares host port "
                    f"{binding.host_ip}:{binding.host_port}/{binding.protocol} "
                    f"for container port {binding.container_port}, but that "
                    f"host port is already in use. The scenario declares an "
                    f"exact binding, so APTL will not silently publish it "
                    f"elsewhere — free the port or change the scenario."
                )
    return conflicts


def compose_port_entry(binding: DeploymentPublishedPort) -> dict[str, object]:
    """Return one Compose long-form port entry for a declared host publish.

    Long form keeps host IP, host port, container port, and protocol as distinct
    fields rather than a ``"ip:host:container/proto"`` string that has to be
    re-parsed downstream.
    """

    entry: dict[str, object] = {
        "target": binding.container_port,
        "protocol": binding.protocol,
        "host_ip": binding.host_ip,
    }
    if binding.host_port is not None:
        entry["published"] = binding.host_port
    return entry


def write_port_override(
    project_dir: Path,
    realization: DeploymentRealizationSpec,
) -> Path | None:
    """Write a contained Compose override publishing declared runtime ports.

    Returns ``None`` when no realized node declares a published port, so the
    caller adds no override file and the checked-in compose stack is untouched.
    """

    services = {
        node.service_name: {
            "ports": [compose_port_entry(binding) for binding in node.published_ports]
        }
        for node in realization.nodes
        if node.published_ports and node.service_name
    }
    if not services:
        return None
    override_path = project_dir / _PORT_OVERRIDE_RELATIVE_PATH
    override_path.parent.mkdir(parents=True, exist_ok=True)
    override_path.write_text(
        yaml.safe_dump({"services": services}, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )
    return override_path
