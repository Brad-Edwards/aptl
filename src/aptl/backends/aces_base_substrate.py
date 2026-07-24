"""Generic base-substrate decision for a node (ADR-048).

Decides which generic base-OS container a node runs on, and whether that
container must be init-capable (so declared `service_manager_units` can run under
a service manager). The decision is scenario-independent: it reads only the
declared `os`/`os_version` and whether the node declares any service units. It
never selects a per-node or appliance image.

The concrete init mechanism (how the backend makes `systemctl` work inside the
container) is host/backend integration proven against real local Docker, not
encoded here; this module carries only the typed, testable decision.
"""

from __future__ import annotations

from dataclasses import dataclass

from aces_sdl.runtime_configuration import RuntimeConfiguration
from aces_sdl.runtime_mounts import RuntimeMountSourceKind

from aptl.backends.aces_materializer import (
    MaterializationOp,
    base_image_for_os,
    package_family,
    plan_node_materialization,
)
from aptl.core.deployment.realization import LOOPBACK_HOST_IP


@dataclass(frozen=True)
class InitRequirements:
    """Run requirements for a node whose declared service units need a service
    manager (systemd) as container init.

    These are the flags APTL already uses for its systemd nodes, validated
    locally against Docker: a host cgroup namespace, a read-write cgroupfs
    mount, `/run` and `/tmp` tmpfs, the capabilities systemd needs, an
    unconfined seccomp profile, and `/usr/sbin/init` as PID 1. They are
    generic (init mechanics), never product-specific.
    """

    # Empty: the generic systemd base image's own CMD runs init (/sbin/init or
    # /usr/sbin/init), so the run does not override the command.
    init_command: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ("SYS_ADMIN", "SYS_NICE", "SYS_RESOURCE")
    cgroup_host: bool = True
    cgroupfs_rw_mount: bool = True
    tmpfs: tuple[str, ...] = ("/run", "/run/lock", "/tmp")  # NOSONAR python:S5443 - tmpfs mount targets for the container's own init, not application file I/O into a shared host directory
    seccomp_unconfined: bool = True
    env: tuple[tuple[str, str], ...] = (("container", "docker"),)
    stop_signal: str = "SIGRTMIN+3"


@dataclass(frozen=True)
class PublishedPort:
    """A host-published port binding for the node's base container."""

    container_port: int
    protocol: str = "tcp"
    host_ip: str = ""
    host_port: int | None = None


@dataclass(frozen=True)
class VolumeMount:
    """A named Docker volume mounted into the node's base container.

    ``source`` is the bare (project-unscoped) volume name declared in
    ``runtime.mounts`` (ACES ``RuntimeMount`` with ``source_kind: volume``);
    the backend resolves it to the project-scoped name at run time.
    """

    target: str
    source: str
    read_only: bool = False


@dataclass(frozen=True)
class BaseContainerSpec:
    """The generic base container a node is realized onto."""

    node_address: str
    container_name: str
    image_ref: str
    runs_services: bool
    init: InitRequirements | None = None
    published_ports: tuple[PublishedPort, ...] = ()
    volume_mounts: tuple[VolumeMount, ...] = ()


def _container_name(node_address: str) -> str:
    """Derive the project-scoped container name from a node's address.

    Never product-specific: the leaf of the address is the node's local name.
    """

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
        image_ref=base_image_for_os(
            os, os_version, runs_services=runs_services, family=package_family(runtime)
        ),
        runs_services=runs_services,
        init=_init_requirements(runtime) if runs_services else None,
        published_ports=_published_ports(runtime),
        volume_mounts=_volume_mounts(runtime),
    )


def _published_ports(runtime: RuntimeConfiguration | None) -> tuple[PublishedPort, ...]:
    """Lower declared ``runtime.network.published_ports`` into base-container ports.

    An author who omits ``host_ip`` gets loopback, never all interfaces
    (ADR-034 Host Exposure Amendment) — the same default
    ``DeploymentPublishedPort`` (the Compose-rendering path's equivalent DTO)
    already applies.
    """

    network = runtime.network if runtime is not None else None
    if network is None:
        return ()
    return tuple(
        PublishedPort(
            container_port=int(port.container_port),
            protocol=port.protocol,
            host_ip=port.host_ip or LOOPBACK_HOST_IP,
            host_port=int(port.host_port) if port.host_port is not None else None,
        )
        for port in network.published_ports
    )


def _volume_mounts(runtime: RuntimeConfiguration | None) -> tuple[VolumeMount, ...]:
    """Lower declared ``runtime.mounts`` volume entries into base-container mounts.

    Only ``source_kind: volume`` entries are materializable here: a node
    mounting an existing named Docker volume (shared with a still-Compose-
    managed service, ADR-048/issue #581). Bind/tmpfs/other mount kinds have
    no run-time meaning for a generic base container and are not lowered.
    """

    if runtime is None:
        return ()
    return tuple(
        VolumeMount(target=mount.target, source=mount.source, read_only=bool(mount.read_only))
        for mount in runtime.mounts
        if mount.source_kind == RuntimeMountSourceKind.VOLUME and mount.source
    )


def _init_requirements(runtime: RuntimeConfiguration | None) -> InitRequirements:
    """Build init requirements, extended with any declared extra capabilities.

    ``runtime.linux_capabilities.add`` entries are in Linux ``CAP_*`` form
    (ACES's typed convention); the container run flag form Docker expects
    (and this module's own fixed defaults already use) drops that prefix.
    """

    extra = tuple(
        name.removeprefix("CAP_")
        for name in (runtime.linux_capabilities.add if runtime and runtime.linux_capabilities else ())
    )
    if not extra:
        return InitRequirements()
    base = InitRequirements()
    merged = base.capabilities + tuple(cap for cap in extra if cap not in base.capabilities)
    return InitRequirements(capabilities=merged)


def plan_node(
    node_address: str,
    *,
    os: str,
    os_version: str,
    runtime: RuntimeConfiguration | None,
    content: tuple[MaterializationOp, ...] = (),
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
    ops = plan_node_materialization(
        os=os, os_version=os_version, runtime=runtime, content=content
    )
    return spec, ops
