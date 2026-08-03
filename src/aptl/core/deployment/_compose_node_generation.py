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

from aptl.backends._component_profiles import component_profiles
from aptl.core.deployment._compose_realization_networks import _compose_network_key
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)

GENERATED_COMPOSE_RELPATH = Path(".aptl") / "realization" / "compose-base.yml"


def render_realization_compose(spec: DeploymentRealizationSpec) -> dict:
    """Return a Compose document for the spec's image-backed nodes and networks.

    Image-free nodes (no backing image) are omitted: the generic materializer
    realizes them directly. ``depends_on`` edges are kept only when the target
    is itself an emitted service, so the document never references an undefined
    service.
    """

    image_by_address = {image.address: image for image in spec.images}
    emitted_services: dict[str, str] = {
        node.service_name: node.address
        for node in spec.nodes
        if node.service_name and node.address in image_by_address
    }
    service_names = set(emitted_services)

    services: dict[str, dict] = {}
    for node in spec.nodes:
        if not node.service_name or node.address not in image_by_address:
            continue
        services[node.service_name] = _render_service(
            node, image_by_address[node.address], service_names
        )

    document: dict = {"services": services}
    networks = _render_networks(spec)
    if networks:
        document["networks"] = networks
    return document


def _render_service(
    node: DeploymentNodeRealization,
    image: DeploymentImageRealization,
    service_names: set[str],
) -> dict:
    """Render one image node into a Compose service definition."""

    service: dict = {
        "image": image.image_ref,
        "container_name": node.container_name or f"aptl-{node.name}",
        "hostname": node.name,
        "restart": "unless-stopped",
    }
    profiles = component_profiles(node.name)
    if profiles:
        service["profiles"] = sorted(profiles)
    netns_container = _network_namespace_container(node)
    if netns_container:
        # This node joins another node's network namespace (OBS-003: the
        # kali-capture sidecar shares Kali's netns so the abstract capture
        # control socket is mutually visible). Compose forbids a per-service
        # ``networks`` map alongside ``network_mode``; the joined stack owns all
        # addressing and published ports, so this node declares neither.
        service["network_mode"] = f"container:{netns_container}"
    else:
        networks = _service_networks(node)
        if networks:
            service["networks"] = networks
    # Published host ports are owned by the dedicated port override
    # (write_port_override); declaring them here too would publish each host
    # port twice and fail with "address already in use" (issue #875).
    depends = _service_dependencies(node, service_names)
    if depends:
        service["depends_on"] = depends
    service.update(_operational_config(node.runtime))
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


def _truthy(value: object) -> bool:
    """Return whether a ``bool | str | None`` RAES flag is enabled."""

    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() in {"true", "1", "yes"}


_OPERATOR_SECRET_CLASSIFICATION = "operator_secret"


def _environment_config(runtime: object) -> dict:
    """Return the Compose ``environment`` map from a node's declared env.

    A variable classified ``operator_secret`` carries no value in the SDL (a real
    deployment credential is authored empty and supplied by the operator, never
    baked into the pack); it is emitted as a Compose interpolation reference
    ``NAME=${NAME}`` so Docker resolves it from the operator ``.env`` at up time,
    exactly as the graph-owned Wazuh services already did. Every other
    classification — including the planted range credentials classified
    ``secret_fixture`` — carries its authored value as content (issue #875).
    """

    environment: dict[str, str] = {}
    for variable in getattr(runtime, "environment", ()):
        name = getattr(variable, "name", "")
        if not name:
            continue
        raw = getattr(variable, "value_classification", "")
        classification = str(getattr(raw, "value", raw) or "")
        if classification == _OPERATOR_SECRET_CLASSIFICATION:
            environment[name] = f"${{{name}}}"
        else:
            environment[name] = variable.value
    return environment


def _operational_config(runtime: object) -> dict:
    """Translate a node's declared runtime desired-state into Compose fields.

    APTL is a faithful translator here, not an authority: it emits only what the
    SDL declared through RAES's own runtime vocabulary (``container`` command and
    flags, ``environment`` variables, ``linux_capabilities``). It never supplies
    implementation-specific defaults of its own, so a node runs exactly the
    operational shape its pack declared (issue #875). Bare nodes declare no
    runtime and get nothing here.
    """

    if runtime is None:
        return {}
    config: dict = {}
    environment = _environment_config(runtime)
    if environment:
        config["environment"] = environment

    container = getattr(runtime, "container", None)
    if container is not None:
        if getattr(container, "command", None):
            config["command"] = list(container.command)
        if getattr(container, "entrypoint", None):
            config["entrypoint"] = list(container.entrypoint)
        if _truthy(getattr(container, "privileged", None)):
            config["privileged"] = True
        if _truthy(getattr(container, "autoremove", None)):
            # A node declaring autoremove is a one-shot (an init job that runs to
            # completion and exits, e.g. an index bootstrap). Compose has no --rm,
            # so the run-once intent is expressed as restart: "no"; without this
            # the base "unless-stopped" policy restarts the finished job forever
            # (issue #875).
            config["restart"] = "no"
        if getattr(container, "shm_size", None):
            config["shm_size"] = container.shm_size
        if getattr(container, "security_opt", None):
            config["security_opt"] = list(container.security_opt)
        if getattr(container, "dns", None):
            config["dns"] = list(container.dns)

    capabilities = getattr(runtime, "linux_capabilities", None)
    added = list(getattr(capabilities, "add", ()) or ()) if capabilities else []
    if added:
        # RAES uses the kernel CAP_* form; Docker's cap_add wants it without
        # the prefix (NET_ADMIN, not CAP_NET_ADMIN).
        config["cap_add"] = [
            capability.removeprefix("CAP_") for capability in added
        ]
    return config


def _service_networks(node: DeploymentNodeRealization) -> dict:
    """Return the Compose ``networks`` attachment map for a node."""

    attachments = node.network_attachments or tuple(
        _Attachment(network) for network in node.networks
    )
    networks: dict[str, dict] = {}
    for attachment in attachments:
        key = _compose_network_key(attachment.network)
        if not key:
            continue
        options: dict = {}
        address = getattr(attachment, "ipv4_address", None)
        if address:
            options["ipv4_address"] = address
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
    namespaces = getattr(container, "namespaces", None) if container is not None else None
    network = getattr(namespaces, "network", None) if namespaces is not None else None
    ref = getattr(network, "target_node_ref", None) if network is not None else None
    if not ref:
        return None
    tail = ref.rsplit(".", 1)[-1]
    return tail if tail.startswith("aptl-") else f"aptl-{tail}"


def _service_dependencies(
    node: DeploymentNodeRealization,
    service_names: set[str],
) -> list[str]:
    """Return ordering dependencies restricted to emitted services."""

    depends: list[str] = []
    for dependency in node.ordering_dependencies:
        name = dependency.rsplit(".", 1)[-1]
        if name in service_names and name != node.service_name and name not in depends:
            depends.append(name)
    return depends


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


def _dynamic_ip_range(
    cidr: str, gateway: str | None, pinned: set[str]
) -> str | None:
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
        for address in (*pinned, *( (gateway,) if gateway else ()))
        if ipaddress.ip_address(address) in upper
    )
    if intruders:
        raise ValueError(
            f"network {cidr}: pinned/gateway address(es) {', '.join(intruders)} "
            f"fall in the dynamic pool {upper}; the upper-half split no longer "
            "isolates static addresses from dynamic allocation (issue #875)."
        )
    return str(upper)


def _render_networks(spec: DeploymentRealizationSpec) -> dict:
    """Return the Compose ``networks`` section for the realized networks."""

    pinned_by_network = _pinned_addresses_by_network(spec)
    networks: dict[str, dict] = {}
    for network in spec.networks:
        key = _compose_network_key(network.name)
        if not key:
            continue
        definition: dict = {"driver": "bridge"}
        if network.internal:
            definition["internal"] = True
        ipam_config: dict = {}
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

    static = content_root / "docker-compose.yml"
    if static.exists():
        return static
    return write_realization_compose(spec, realization_root or content_root)


class _Attachment:
    """Minimal network attachment for a node that declares only bare names."""

    __slots__ = ("network", "ipv4_address")

    def __init__(self, network: str) -> None:
        self.network = network
        self.ipv4_address = None
