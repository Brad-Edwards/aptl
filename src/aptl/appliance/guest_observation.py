"""Fresh guest-side appliance boundary observation and active traffic probes."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
)
from aptl.core.appliance_boundary_inventory import (
    BoundaryEnforcementObservation,
    BoundaryProbeObservation,
    DockerAuthorityHolder,
    GuestBoundaryObservation,
)
from aptl.core.deployment.boundary import AcesBoundarySpec, PlatformBoundarySpec
from aptl.core.deployment.realization import DeploymentRealizationSpec

_CONTAINER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_PROBE_PATH = "/usr/local/bin/aptl-boundary-probe"


def _read_guest_boot_id() -> str:
    """Read a stable boot identity on Linux and portable test hosts."""

    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        try:
            observed = subprocess.run(
                ["sysctl", "-n", "kern.boottime"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            observed = ""
        if not observed:
            raise ValueError("guest boot identity is unavailable")
        value = "sha256:" + hashlib.sha256(observed.encode()).hexdigest()
    if not value:
        raise ValueError("guest boot identity is unavailable")
    return value


class _ProbeBackend(Protocol):
    _docker_daemon_id: str | None

    def _run(self, command: list[str], *, timeout: int | None = None): ...

    def host_list_lab_containers(self) -> list[dict[str, object]]: ...

    def container_inspect(self, container: str) -> dict[str, object]: ...


@dataclass(frozen=True)
class _LiveContainer:
    identity: str
    name: str
    addresses: tuple[str, ...]
    inspection: dict[str, object]


@dataclass(frozen=True)
class _ProbePath:
    identity: str
    authority: str
    source: _LiveContainer
    destination: _LiveContainer
    destination_address: str
    port: int
    expectation: str


def _live_containers(backend: _ProbeBackend) -> tuple[_LiveContainer, ...]:
    observed: list[_LiveContainer] = []
    for row in backend.host_list_lab_containers():
        if row.get("state") not in {None, "running"}:
            continue
        candidate = row.get("id") or row.get("name")
        if not isinstance(candidate, str) or not _CONTAINER.fullmatch(candidate):
            continue
        inspection = backend.container_inspect(candidate)
        identity = inspection.get("Id", candidate)
        raw_name = inspection.get("Name", row.get("name", candidate))
        if not isinstance(identity, str) or not isinstance(raw_name, str):
            continue
        name = raw_name.removeprefix("/")
        networks = inspection.get("NetworkSettings", {})
        networks = networks.get("Networks", {}) if isinstance(networks, Mapping) else {}
        addresses = tuple(
            str(details["IPAddress"])
            for details in networks.values()
            if isinstance(details, Mapping)
            and isinstance(details.get("IPAddress"), str)
            and details["IPAddress"]
        )
        if addresses and _CONTAINER.fullmatch(name):
            observed.append(_LiveContainer(identity, name, addresses, inspection))
    return tuple(observed)


def _container_by_identity(
    containers: tuple[_LiveContainer, ...], identity: str
) -> _LiveContainer | None:
    return next(
        (
            item
            for item in containers
            if identity in {item.identity, item.name}
            or item.name.endswith("-" + identity)
        ),
        None,
    )


def _container_by_ip(
    containers: tuple[_LiveContainer, ...], address: str
) -> _LiveContainer | None:
    return next((item for item in containers if address in item.addresses), None)


def _peer_on_network(
    containers: tuple[_LiveContainer, ...],
    network: ipaddress.IPv4Network,
    *,
    exclude: _LiveContainer | None = None,
) -> tuple[_LiveContainer, str] | None:
    for item in containers:
        if item == exclude:
            continue
        for address in item.addresses:
            if ipaddress.ip_address(address) in network:
                return item, address
    return None


def _probe_command(
    *, image: str, network_container: str, arguments: list[str]
) -> list[str]:
    if not _CONTAINER.fullmatch(network_container):
        raise ValueError("boundary probe container identity is invalid")
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        f"container:{network_container}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--entrypoint",
        "python3",
        image,
        _PROBE_PATH,
        *arguments,
    ]


def _connect(
    backend: _ProbeBackend,
    *,
    image: str,
    source: _LiveContainer,
    address: str,
    port: int,
) -> bool:
    result = backend._run(
        _probe_command(
            image=image,
            network_container=source.name,
            arguments=[
                "connect",
                "--address",
                address,
                "--port",
                str(port),
                "--timeout",
                "3",
            ],
        ),
        timeout=10,
    )
    return result.returncode == 0


def _start_listener(
    backend: _ProbeBackend,
    *,
    image: str,
    destination: _LiveContainer,
    address: str,
    port: int,
) -> str | None:
    name = "aptl-boundary-probe-" + secrets.token_hex(8)
    command = _probe_command(
        image=image,
        network_container=destination.name,
        arguments=[
            "listen",
            "--address",
            address,
            "--port",
            str(port),
            "--timeout",
            "15",
        ],
    )
    command[1:3] = ["run", "-d"]
    command[3:3] = ["--name", name]
    started = backend._run(command, timeout=10)
    if started.returncode != 0:
        return None
    for _attempt in range(50):
        logs = backend._run(["docker", "logs", name], timeout=5)
        if logs.returncode == 0 and logs.stdout.strip() == "ready":
            return name
        time.sleep(0.1)
    backend._run(["docker", "rm", "-f", name], timeout=10)
    return None


def _probe_path(
    backend: _ProbeBackend,
    path: _ProbePath,
    *,
    image: str,
) -> BoundaryProbeObservation:
    listener: str | None = None
    try:
        target_ready = _connect(
            backend,
            image=image,
            source=path.destination,
            address=path.destination_address,
            port=path.port,
        )
        if not target_ready:
            listener = _start_listener(
                backend,
                image=image,
                destination=path.destination,
                address=path.destination_address,
                port=path.port,
            )
            target_ready = listener is not None and _connect(
                backend,
                image=image,
                source=path.destination,
                address=path.destination_address,
                port=path.port,
            )
        reachable = target_ready and _connect(
            backend,
            image=image,
            source=path.source,
            address=path.destination_address,
            port=path.port,
        )
        passed = target_ready and (
            reachable if path.expectation == "reachable" else not reachable
        )
    finally:
        if listener is not None:
            backend._run(["docker", "rm", "-f", listener], timeout=10)
    return BoundaryProbeObservation(
        identity=path.identity,
        authority=path.authority,
        source=path.source.name,
        destination=path.destination.name,
        protocol="tcp",
        port=path.port,
        expectation=path.expectation,
        passed=passed,
    )


def _platform_probe_paths(
    spec: PlatformBoundarySpec,
    containers: tuple[_LiveContainer, ...],
) -> tuple[_ProbePath, ...]:
    crossing = next((item for item in spec.crossings if item.protocol == "tcp"), None)
    if crossing is None:
        return ()
    anchors = dict(spec.anchors)
    source = _container_by_identity(containers, anchors[crossing.source].identity)
    destination = _container_by_identity(
        containers, anchors[crossing.destination].identity
    )
    if source is None or destination is None:
        return ()
    destination_addresses = dict(anchors[crossing.destination].ipv4_by_network)
    shared = sorted(
        set(dict(anchors[crossing.source].ipv4_by_network)) & set(destination_addresses)
    )
    if not shared:
        return ()
    allowed_ports = {
        port for item in spec.crossings for port in item.ports if item.protocol == "tcp"
    }
    denied_port = next(
        (port for port in range(65535, 63999, -1) if port not in allowed_ports),
        None,
    )
    if denied_port is None:
        return ()
    address = destination_addresses[shared[0]]
    return (
        _ProbePath(
            identity="platform-allowed-crossing",
            authority="platform",
            source=source,
            destination=destination,
            destination_address=address,
            port=crossing.ports[0],
            expectation="reachable",
        ),
        _ProbePath(
            identity="platform-default-deny",
            authority="platform",
            source=source,
            destination=destination,
            destination_address=address,
            port=denied_port,
            expectation="blocked",
        ),
    )


def _network_cidrs(spec: AcesBoundarySpec) -> dict[str, ipaddress.IPv4Network]:
    return {
        item.name: ipaddress.ip_network(item.ipv4_cidr)
        for item in spec.networks
        if item.ipv4_cidr is not None
    }


def _raes_rule_path(
    spec: AcesBoundarySpec,
    rule,
    containers: tuple[_LiveContainer, ...],
) -> _ProbePath | None:
    if rule.protocol != "tcp" or not rule.ports:
        return None
    networks = _network_cidrs(spec)
    bindings = {item.owner_address: item for item in spec.owner_bindings}
    binding = bindings.get(rule.owner_address)
    if binding is None:
        return None
    direction = "out" if rule.direction == "inout" else rule.direction
    if binding.owner_resource_type == "node":
        owner_addresses = dict(binding.ipv4_by_network)
        owner_network = rule.from_network if direction == "out" else rule.to_network
        owner_ip = owner_addresses.get(owner_network or "")
        owner = _container_by_ip(containers, owner_ip or "")
        peer_network = rule.to_network if direction == "out" else rule.from_network
        peer = (
            _peer_on_network(containers, networks[peer_network], exclude=owner)
            if peer_network in networks
            else None
        )
        if owner is None or peer is None:
            return None
        if direction == "out":
            source, destination, destination_address = owner, peer[0], peer[1]
        else:
            source, destination, destination_address = peer[0], owner, owner_ip
    else:
        owner_network = networks.get(rule.owner_name)
        peer_network_name = rule.to_network if direction == "out" else rule.from_network
        peer_network = networks.get(peer_network_name or "")
        if owner_network is None or peer_network is None:
            return None
        owner = _peer_on_network(containers, owner_network)
        peer = _peer_on_network(
            containers, peer_network, exclude=owner[0] if owner else None
        )
        if owner is None or peer is None:
            return None
        if direction == "out":
            source, destination, destination_address = owner[0], peer[0], peer[1]
        else:
            source, destination, destination_address = peer[0], owner[0], owner[1]
    return _ProbePath(
        identity=f"{rule.owner_address}/{rule.name}",
        authority="raes",
        source=source,
        destination=destination,
        destination_address=str(destination_address),
        port=rule.ports[0],
        expectation="reachable" if rule.action == "allow" else "blocked",
    )


def _raes_probe_paths(
    spec: AcesBoundarySpec,
    containers: tuple[_LiveContainer, ...],
) -> tuple[_ProbePath, ...]:
    selected: list[_ProbePath] = []
    for action in ("allow", "deny"):
        for rule in spec.rules:
            if rule.action != action:
                continue
            path = _raes_rule_path(spec, rule, containers)
            if path is not None:
                selected.append(path)
                break
    return tuple(selected)


def _enforcement_observations(
    receipts: dict[str, dict[str, object]],
) -> tuple[BoundaryEnforcementObservation, ...]:
    observations = []
    for authority in sorted(receipts):
        receipt = receipts[authority]
        observations.append(
            BoundaryEnforcementObservation(
                authority=authority,
                source_digest=str(receipt["source_digest"]),
                enforcement_digest=str(receipt["enforcement_digest"]),
                families=tuple(receipt["families"]),
                default_deny_observed=bool(receipt["default_deny"]),
            )
        )
    return tuple(observations)


def _authority_holders(
    *,
    realization: DeploymentRealizationSpec,
    policy: ApplianceBoundaryPolicy,
    containers: tuple[_LiveContainer, ...],
    daemon_id: str,
) -> tuple[DockerAuthorityHolder, ...]:
    nodes = {item.address: item for item in realization.nodes}
    holders = []
    for admission in realization.docker_authority_admissions:
        node = nodes.get(admission.node_address)
        identity = (node.container_name or node.service_name) if node else None
        container = (
            _container_by_identity(containers, identity)
            if identity is not None
            else None
        )
        if container is None:
            continue
        inspection = container.inspection
        config = inspection.get("Config", {})
        labels = config.get("Labels", {}) if isinstance(config, Mapping) else {}
        selector = next(
            (
                value
                for value in policy.docker_authority.allowed_holder_labels
                if isinstance(labels, Mapping)
                and labels.get(value.split("=", 1)[0]) == value.split("=", 1)[1]
            ),
            "org.aptl.unapproved=holder",
        )
        host = inspection.get("HostConfig", {})
        host = host if isinstance(host, Mapping) else {}
        devices = host.get("Devices", [])
        holders.append(
            DockerAuthorityHolder(
                identity=container.identity,
                label_selector=selector,
                daemon_id=daemon_id,
                access="socket",
                privileged=host.get("Privileged") is True,
                host_pid_namespace=host.get("PidMode") == "host",
                host_network_namespace=host.get("NetworkMode") == "host",
                device_count=len(devices) if isinstance(devices, list) else 0,
            )
        )
    return tuple(holders)


def collect_guest_observation(
    *,
    backend: _ProbeBackend,
    policy: ApplianceBoundaryPolicy,
    binding: ApplianceBoundaryBinding,
    boundary_specs: dict[str, object],
    boundary_receipts: dict[str, dict[str, object]],
    realization: DeploymentRealizationSpec,
) -> GuestBoundaryObservation:
    """Collect fresh kernel readback, active probes, and Docker authority state."""

    daemon_id = backend._docker_daemon_id
    if not daemon_id:
        raise ValueError("guest Docker daemon identity is unavailable")
    containers = _live_containers(backend)
    paths: tuple[_ProbePath, ...] = ()
    platform = boundary_specs.get("platform")
    if isinstance(platform, PlatformBoundarySpec):
        paths += _platform_probe_paths(platform, containers)
    raes = boundary_specs.get("raes")
    if isinstance(raes, AcesBoundarySpec):
        paths += _raes_probe_paths(raes, containers)
    probes = tuple(
        _probe_path(backend, path, image=binding.boundary_helper_image)
        for path in paths
    )
    enforcements = _enforcement_observations(boundary_receipts)
    expected_authorities = {
        "platform",
        *(("raes",) if binding.raes_boundary_required else ()),
    }
    complete = {
        item.authority for item in enforcements
    } == expected_authorities and all(
        any(
            item.authority == authority and item.expectation == expectation
            for item in probes
        )
        for authority in expected_authorities
        for expectation in ("reachable", "blocked")
    )
    return GuestBoundaryObservation(
        policy_digest=binding.policy_digest,
        raes_plan_digest=binding.raes_plan_digest,
        boot_id=_read_guest_boot_id(),
        guest_daemon_id=daemon_id,
        workbench_policy_version=policy.workbench_policy_version,
        enforcements=enforcements,
        observation_complete=complete,
        probes=probes,
        docker_authority_holders=_authority_holders(
            realization=realization,
            policy=policy,
            containers=containers,
            daemon_id=daemon_id,
        ),
    )
