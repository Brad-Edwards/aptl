"""Generate a base Docker Compose model from a realized scenario (issue #875).

An env-pack ships no ``docker-compose.yml``: APTL realizes the scenario from the
SDL's declared desired state instead. Image-backed nodes still run as Compose
services, so their service definitions must be *generated* from the realization
rather than read from a hand-authored file. Image-free nodes are realized by the
generic materializer (ADR-048) and are not emitted here.

This module is a pure renderer: it turns a :class:`DeploymentRealizationSpec`
into the same Compose document shape APTL previously hand-authored (service
image, container name, networks, published ports, ``depends_on`` ordering,
operator profile), and the networks section with the same ``aptl-<stem>`` keys
and ipam the in-tree file used. Operational realization that a runtime family
supplies (command, environment, mounts, healthcheck) is layered on top of this
base by the family realizers; this module owns only what every image node needs
to start and be addressable.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml
from aptl.core.deployment._compose_realization_networks import _compose_network_key
from aptl.core.deployment._compose_runtime_config import _operational_config
from aptl.core.deployment._compose_runtime_orchestration import (
    docker_authority_admissions_by_address,
    docker_socket_volume,
)
from aptl.core.deployment._compose_service_health import runtime_expects_completion
from aptl.core.deployment._compose_stateful_constants import (
    WAZUH_INDEXER_SERVICE,
    WAZUH_MANAGER_SERVICE,
)
from aptl.core.deployment._wazuh_identity import wazuh_cluster_identity
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.runtime_authority import DeploymentDockerAuthorityAdmission

GENERATED_COMPOSE_RELPATH = Path(".aptl") / "realization" / "compose-base.yml"

# The hand-authored base Compose file an in-tree scenario ships. Its presence at
# a scenario root is what distinguishes in-tree (use it as-is) from an env-pack
# (generate the base from the realization), so the two decisions cannot drift.
STATIC_COMPOSE_FILENAME = "docker-compose.yml"


def render_realization_compose(spec: DeploymentRealizationSpec) -> dict[str, object]:
    """Return a Compose document for the spec's image-backed nodes and networks.

    Image-free nodes (no backing image) are omitted: the generic materializer
    realizes them directly. ``depends_on`` edges are kept only when the target
    is itself an emitted service, so the document never references an undefined
    service.
    """

    image_by_address = {image.address: image for image in spec.images}
    admissions = docker_authority_admissions_by_address(spec)
    emitted_services: dict[str, str] = {
        node.service_name: node.address
        for node in spec.nodes
        if node.service_name and node.address in image_by_address
    }
    service_names = set(emitted_services)
    completion_services = {
        node.service_name
        for node in spec.nodes
        if node.service_name in service_names
        and runtime_expects_completion(node.runtime)
    }
    wazuh_identity = wazuh_cluster_identity(spec)
    canonical_aliases = {
        wazuh_identity.manager_service: (WAZUH_MANAGER_SERVICE,),
        wazuh_identity.indexer_service: (WAZUH_INDEXER_SERVICE,),
    }

    services: dict[str, dict[str, object]] = {}
    for node in spec.nodes:
        if not node.service_name or node.address not in image_by_address:
            continue
        services[node.service_name] = _render_service(
            node,
            image_by_address[node.address],
            service_names,
            completion_services,
            docker_authority_admission=admissions.get(node.address),
            network_aliases=canonical_aliases.get(node.service_name, ()),
        )

    document: dict[str, object] = {"services": services}
    networks = _render_networks(spec)
    if networks:
        document["networks"] = networks
    return document


def _render_service(
    node: DeploymentNodeRealization,
    image: DeploymentImageRealization,
    service_names: set[str],
    completion_services: set[str],
    *,
    docker_authority_admission: DeploymentDockerAuthorityAdmission | None,
    network_aliases: tuple[str, ...] = (),
) -> dict[str, object]:
    """Render one image node into a Compose service definition."""

    service: dict[str, object] = {
        "image": image.image_ref,
        "container_name": node.container_name or f"aptl-{node.name}",
    }
    if node.profiles:
        service["profiles"] = sorted(node.profiles)
    netns_container = _network_namespace_container(node)
    if netns_container:
        # This node joins another node's network namespace (OBS-003: the
        # kali-capture sidecar shares Kali's netns so the abstract capture
        # control socket is mutually visible). Docker rejects ``hostname``,
        # a ``networks`` map, and published ports alongside
        # ``network_mode: container:`` -- the joined container already owns the
        # network identity, addressing, and ports -- so none are emitted here.
        service["network_mode"] = f"container:{netns_container}"
    else:
        service["hostname"] = node.name
        networks = _service_networks(node, aliases=network_aliases)
        if networks:
            service["networks"] = networks
    # Published host ports are owned by the dedicated port override
    # (write_port_override); declaring them here too would publish each host
    # port twice and fail with "address already in use" (issue #875).
    depends = _service_dependencies(node, service_names, completion_services)
    if depends:
        service["depends_on"] = depends
    service.update(_operational_config(node.runtime))
    socket_volume = docker_socket_volume(docker_authority_admission)
    if socket_volume is not None:
        volumes = service.setdefault("volumes", [])
        if not isinstance(volumes, list):
            raise ValueError(
                f"Generated service volumes are not a list for {node.address}."
            )
        volumes.append(socket_volume)
    service.setdefault("ulimits", _DEFAULT_IMAGE_NODE_ULIMITS)
    return service


# Minimal deployment ulimits every image node receives. RuntimeContainer has no
# ulimits affordance yet (tracked upstream in OpenRAE/rae#1066), and some images fail
# a bootstrap check without a raised file-descriptor limit -- OpenSearch (the
# Wazuh indexer, Shuffle's opensearch) refuses to start when nofile is below
# 65535 and network.host is non-loopback. These are universally safe raises
# (unlimited memlock, 65536 file descriptors); they are an explicitly-flagged
# APTL deployment default, not authored range content, and are superseded once
# the SDL can declare per-node ulimits (issue #875, SDL-authority class).
_DEFAULT_IMAGE_NODE_ULIMITS = {
    "memlock": {"soft": -1, "hard": -1},
    "nofile": {"soft": 65536, "hard": 65536},
}


def _service_networks(
    node: DeploymentNodeRealization, *, aliases: tuple[str, ...] = ()
) -> dict[str, dict[str, object]]:
    """Return the Compose ``networks`` attachment map for a node."""

    attachments = node.network_attachments or tuple(
        _Attachment(network) for network in node.networks
    )
    networks: dict[str, dict[str, object]] = {}
    for attachment in attachments:
        key = _compose_network_key(attachment.network)
        if not key:
            continue
        options: dict[str, object] = {}
        address = getattr(attachment, "ipv4_address", None)
        if address:
            options["ipv4_address"] = address
        selected_aliases = [alias for alias in aliases if alias != node.service_name]
        if selected_aliases:
            options["aliases"] = selected_aliases
        networks[key] = options
    return networks


def _network_namespace_container(node: DeploymentNodeRealization) -> str | None:
    """Return the container whose netns this node joins, or ``None``.

    A node declaring ``runtime.container.namespaces.network.target_node_ref``
    (RAES ``RuntimeNetworkNamespace``) shares another node's network namespace.
    The target is an image-free node the generic materializer starts before
    Compose runs (ADR-048 ordering), so Compose references it by container name
    via ``network_mode: container:<name>``. The name derivation matches the
    image-free substrate's (``aptl-<ref>``, not doubling an existing prefix) so
    both sides agree on the container identity (issue #875 / #906).
    """

    runtime = node.runtime
    container = getattr(runtime, "container", None) if runtime is not None else None
    namespaces = (
        getattr(container, "namespaces", None) if container is not None else None
    )
    network = getattr(namespaces, "network", None) if namespaces is not None else None
    ref = getattr(network, "target_node_ref", None) if network is not None else None
    if not ref:
        return None
    tail = ref.rsplit(".", 1)[-1]
    return tail if tail.startswith("aptl-") else f"aptl-{tail}"


def _service_dependencies(
    node: DeploymentNodeRealization,
    service_names: set[str],
    completion_services: set[str],
) -> list[str] | dict[str, dict[str, str]]:
    """Return ordering dependencies restricted to emitted services."""

    depends: list[str] = []
    for dependency in node.ordering_dependencies:
        name = dependency.rsplit(".", 1)[-1]
        if name in service_names and name != node.service_name and name not in depends:
            depends.append(name)
    if not any(name in completion_services for name in depends):
        return depends
    return {
        name: {
            "condition": (
                "service_completed_successfully"
                if name in completion_services
                else "service_started"
            )
        }
        for name in depends
    }


def _pinned_addresses_by_network(
    spec: DeploymentRealizationSpec,
) -> dict[str, set[str]]:
    """Return, per network name, the set of statically-pinned node IPs.

    A node pins an address by declaring ``ipv4_address`` on a network
    attachment (SDL ``static_address_assignments``). These are the addresses
    Docker's dynamic allocator must be kept away from.
    """

    pinned: dict[str, set[str]] = {}
    for node in spec.nodes:
        for attachment in node.network_attachments:
            if attachment.ipv4_address:
                pinned.setdefault(attachment.network, set()).add(
                    attachment.ipv4_address
                )
    return pinned


def _dynamic_ip_range(cidr: str, gateway: str | None, pinned: set[str]) -> str | None:
    """Return an IPAM ``ip_range`` confining dynamic allocation off the pins.

    Docker assigns dynamic addresses from the bottom of the subnet and does not
    reserve the static IPs of not-yet-started containers, so a dynamically-placed
    node (a DNS-reachable SOC service) can seize an address another node pinned in
    the SDL, and the pinned container then fails networking with "Address already
    in use" (issue #875). Restricting the dynamic pool to the subnet's upper half
    keeps it clear of the low, pinned addresses.

    Returns ``None`` when no confinement is needed (nothing pinned). Raises when a
    pinned address or the gateway falls in the upper half, rather than emitting a
    range that would still collide — a loud signal that the split no longer holds
    for this topology.
    """

    if not pinned:
        return None
    subnet = ipaddress.ip_network(cidr, strict=False)
    upper = list(subnet.subnets(prefixlen_diff=1))[1]
    intruders = sorted(
        str(address)
        for address in (*pinned, *((gateway,) if gateway else ()))
        if ipaddress.ip_address(address) in upper
    )
    if intruders:
        raise ValueError(
            f"network {cidr}: pinned/gateway address(es) {', '.join(intruders)} "
            f"fall in the dynamic pool {upper}; the upper-half split no longer "
            "isolates static addresses from dynamic allocation (issue #875)."
        )
    return str(upper)


def _render_networks(spec: DeploymentRealizationSpec) -> dict[str, dict[str, object]]:
    """Return the Compose ``networks`` section for the realized networks."""

    pinned_by_network = _pinned_addresses_by_network(spec)
    networks: dict[str, dict[str, object]] = {}
    for network in spec.networks:
        key = _compose_network_key(network.name)
        if not key:
            continue
        definition: dict[str, object] = {"driver": "bridge"}
        if network.internal:
            definition["internal"] = True
        ipam_config: dict[str, str] = {}
        if network.cidr:
            ipam_config["subnet"] = network.cidr
            ip_range = _dynamic_ip_range(
                network.cidr,
                network.gateway,
                pinned_by_network.get(network.name, set()),
            )
            if ip_range:
                ipam_config["ip_range"] = ip_range
        if network.gateway:
            ipam_config["gateway"] = network.gateway
        if ipam_config:
            definition["ipam"] = {"config": [ipam_config]}
        networks[key] = definition
    return networks


def write_realization_compose(
    spec: DeploymentRealizationSpec, scenario_root: Path
) -> Path:
    """Render and write the generated base Compose file under ``scenario_root``."""

    path = scenario_root / GENERATED_COMPOSE_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(render_realization_compose(spec), sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )
    return path


def base_compose_file(
    spec: DeploymentRealizationSpec,
    content_root: Path,
    realization_root: Path | None = None,
) -> Path:
    """Return the base Compose file for a realization.

    An in-tree scenario ships a hand-authored ``docker-compose.yml`` at its
    ``content_root`` and it is used as-is. An env-pack ships none, so the base is
    generated from the realization (issue #875) and written under
    ``realization_root`` — the writable engine checkout — never under the
    pristine pack, whose digest-validated inventory must not gain generated
    files. ``realization_root`` defaults to ``content_root`` so in-tree
    (where the two coincide) is behaviour-neutral.
    """

    static = content_root / STATIC_COMPOSE_FILENAME
    if static.exists():
        return static
    return write_realization_compose(spec, realization_root or content_root)


class _Attachment:
    """Minimal network attachment for a node that declares only bare names."""

    __slots__ = ("network", "ipv4_address")

    def __init__(self, network: str) -> None:
        self.network = network
        self.ipv4_address = None
