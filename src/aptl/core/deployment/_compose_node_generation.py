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
from aptl.core.deployment._compose_docker_authority import (
    AUTHORITY_OWNER_LABEL_KEY,
    AUTHORITY_OWNER_LABEL_VALUE,
    AUTHORITY_SERVICE,
    authority_requested,
    authority_socket_path,
)
from aptl.core.deployment._compose_runtime_orchestration import (
    docker_authority_admissions_by_address,
    docker_socket_volume,
)
from aptl.core.deployment._compose_node_topology import (
    dynamic_ip_range as _dynamic_ip_range,
    network_namespace_container as _network_namespace_container,
    pinned_addresses_by_network as _pinned_addresses_by_network,
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


def _require_healthy_authority(service: dict[str, object]) -> None:
    """Make an authority holder wait for its mediating apparatus."""

    depends = service.get("depends_on")
    if not isinstance(depends, dict):
        depends = {name: {"condition": "service_started"} for name in depends or ()}
    depends[AUTHORITY_SERVICE] = {"condition": "service_healthy"}
    service["depends_on"] = depends


def render_realization_compose(
    spec: DeploymentRealizationSpec, realization_root: Path | None = None
) -> dict[str, object]:
    """Return a Compose document for the spec's image-backed nodes and networks.

    Image-free nodes (no backing image) are omitted: the generic materializer
    realizes them directly. ``depends_on`` edges are kept only when the target
    is itself an emitted service, so the document never references an undefined
    service.

    ``realization_root`` locates the mediated Docker socket an authority holder
    is given in place of the host's own. It is required whenever the spec
    carries an authority; a holder is never rendered with an unmediated socket.
    """

    image_by_address = {image.address: image for image in spec.images}
    admissions = docker_authority_admissions_by_address(spec)
    mediated_socket = (
        authority_socket_path(realization_root)
        if realization_root is not None and authority_requested(spec)
        else None
    )
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
        mediated_socket,
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
    mediated_socket: Path | None,
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
                mediated_socket=mediated_socket,
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
    mediated_socket: Path | None = None,
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
    socket_volume = docker_socket_volume(docker_authority_admission, mediated_socket)
    if socket_volume is not None:
        # The mediated socket is bind-mounted as a *file*, so it has to exist
        # on the host before this container is created -- Docker would
        # otherwise create a directory in its place and the holder would find
        # no socket at all. Waiting for the apparatus to report healthy is what
        # makes that ordering deterministic rather than a race.
        _require_healthy_authority(service)
        labels = service.setdefault("labels", {})
        if not isinstance(labels, dict):
            raise ValueError(
                f"Generated service labels are not a mapping for {node.address}."
            )
        labels[AUTHORITY_OWNER_LABEL_KEY] = AUTHORITY_OWNER_LABEL_VALUE
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


def _truthy(value: object) -> bool:
    """Return whether a ``bool | str | None`` RAES flag is enabled."""

    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() in {"true", "1", "yes"}


_OPERATOR_SECRET_CLASSIFICATION = "operator_secret"


def _environment_config(runtime: object) -> dict[str, str]:
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
        if getattr(variable, "value_from", None) is not None:
            # Generated values are delivered by the admitted artifact binding;
            # an empty entry here would override Compose's env_file value.
            continue
        raw = getattr(variable, "value_classification", "")
        classification = str(getattr(raw, "value", raw) or "")
        if classification == _OPERATOR_SECRET_CLASSIFICATION:
            environment[name] = f"${{{name}}}"
        else:
            environment[name] = variable.value
    return environment


# RuntimeContainer sequence fields that translate one-to-one into the Compose
# field of the same name, copied as a list.
_CONTAINER_SEQUENCE_FIELDS = ("command", "entrypoint", "security_opt", "dns")


def _operational_config(runtime: object) -> dict[str, object]:
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
    config: dict[str, object] = {}
    environment = _environment_config(runtime)
    if environment:
        config["environment"] = environment
    policy = getattr(runtime, "operational_policy", None)
    if policy is not None:
        restart = getattr(policy, "restart", None)
        restart_value = str(getattr(restart, "value", restart) or "")
        if restart_value:
            config["restart"] = restart_value.replace("_", "-")
        limits = getattr(policy, "resource_limits", None)
        memory = getattr(limits, "memory", None) if limits is not None else None
        if memory is not None:
            config["mem_limit"] = memory
    config.update(_container_config(getattr(runtime, "container", None)))
    capabilities = _capability_config(runtime)
    if capabilities:
        config["cap_add"] = capabilities
    return config


def _container_config(container: object) -> dict[str, object]:
    """Return the Compose fields a node's declared ``container`` runtime sets."""

    if container is None:
        return {}
    config: dict[str, object] = {}
    for field in _CONTAINER_SEQUENCE_FIELDS:
        value = getattr(container, field, None)
        if value:
            config[field] = list(value)
    if getattr(container, "shm_size", None):
        config["shm_size"] = container.shm_size
    if _truthy(getattr(container, "privileged", None)):
        config["privileged"] = True
    if _truthy(getattr(container, "autoremove", None)):
        # A node declaring autoremove is a one-shot (an init job that runs to
        # completion and exits, e.g. an index bootstrap). Compose has no
        # service-level --rm, so restart: "no" lets post-start reconciliation
        # first observe its successful exit and then remove it (issue #992).
        config["restart"] = "no"
    return config


def _capability_config(runtime: object) -> list[str]:
    """Return the Compose ``cap_add`` list a node's declared runtime asks for.

    RAES uses the kernel CAP_* form; Docker's cap_add wants it without the
    prefix (NET_ADMIN, not CAP_NET_ADMIN).
    """

    capabilities = getattr(runtime, "linux_capabilities", None)
    added = list(getattr(capabilities, "add", ()) or ()) if capabilities else []
    return [capability.removeprefix("CAP_") for capability in added]


def write_realization_compose(
    spec: DeploymentRealizationSpec, scenario_root: Path
) -> Path:
    """Render and write the generated base Compose file under ``scenario_root``."""

    path = scenario_root / GENERATED_COMPOSE_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(render_realization_compose(spec, scenario_root), sort_keys=True),
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
