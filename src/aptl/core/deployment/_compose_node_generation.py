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

from aptl.core.deployment._compose_runtime_config import _operational_config
from aptl.core.deployment._compose_runtime_orchestration import (
    docker_authority_admissions_by_address,
    docker_socket_volume,
)
from aptl.core.deployment._compose_node_topology import (
    network_namespace_container as _network_namespace_container,
    render_networks as _render_networks,
    service_dependencies as _service_dependencies,
    service_networks as _service_networks,
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

    Authority holders receive the exact host-root-equivalent endpoint they
    declared.
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

    services = _render_services(
        spec,
        image_by_address,
        service_names,
        completion_services,
        admissions,
        canonical_aliases,
    )

    document: dict[str, object] = {"services": services}
    networks = _render_networks(spec)
    if networks:
        document["networks"] = networks
    return document


def _render_services(
    spec: DeploymentRealizationSpec,
    image_by_address: dict[str, DeploymentImageRealization],
    service_names: set[str],
    completion_services: set[str],
    admissions: dict[str, DeploymentDockerAuthorityAdmission],
    canonical_aliases: dict[str, tuple[str, ...]],
) -> dict[str, dict[str, object]]:
    """Render image-backed services with carried authority and aliases."""

    services: dict[str, dict[str, object]] = {}
    for node in spec.nodes:
        if node.service_name and node.address in image_by_address:
            services[node.service_name] = _render_service(
                node,
                image_by_address[node.address],
                service_names,
                completion_services,
                docker_authority_admission=admissions.get(node.address),
                network_aliases=canonical_aliases.get(node.service_name, ()),
            )
    return services


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
        "labels": {"aptl.node.address": node.address},
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
