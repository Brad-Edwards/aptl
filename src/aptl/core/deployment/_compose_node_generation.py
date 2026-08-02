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
    networks = _service_networks(node)
    if networks:
        service["networks"] = networks
    ports = _service_ports(node)
    if ports:
        service["ports"] = ports
    depends = _service_dependencies(node, service_names)
    if depends:
        service["depends_on"] = depends
    service.update(_operational_config(node.runtime))
    return service


def _truthy(value: object) -> bool:
    """Return whether a ``bool | str | None`` RAES flag is enabled."""

    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() in {"true", "1", "yes"}


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
    environment = {
        variable.name: variable.value
        for variable in getattr(runtime, "environment", ())
        if getattr(variable, "name", "")
    }
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


def _service_ports(node: DeploymentNodeRealization) -> list[str]:
    """Return loopback-bound published port mappings for a node."""

    ports: list[str] = []
    for binding in node.published_ports:
        host_port = binding.host_port or binding.container_port
        mapping = (
            f"{binding.host_ip}:{host_port}:{binding.container_port}"
            if binding.host_ip
            else f"{host_port}:{binding.container_port}"
        )
        if (binding.protocol or "tcp") != "tcp":
            mapping = f"{mapping}/{binding.protocol}"
        ports.append(mapping)
    return ports


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


def _render_networks(spec: DeploymentRealizationSpec) -> dict:
    """Return the Compose ``networks`` section for the realized networks."""

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
