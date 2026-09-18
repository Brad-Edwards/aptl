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
_CONTAINER_SEQUENCE_FIELDS = ("command", "entrypoint", "dns", "group_add")
_UNSUPPORTED_CONTAINER_FIELDS = (
    "masked_paths",
    "read_only_paths",
    "publish_all_ports",
)


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
    mounts = _runtime_mount_config(runtime)
    if mounts:
        config["volumes"] = mounts
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
    added = _capability_config(runtime, "add")
    dropped = _capability_config(runtime, "drop")
    if added:
        config["cap_add"] = added
    if dropped:
        config["cap_drop"] = dropped
    return config


def _runtime_mount_config(runtime: object) -> list[dict[str, object]]:
    """Lower faithfully supported authored runtime mounts to long-form Compose."""

    rendered: list[dict[str, object]] = []
    for mount in getattr(runtime, "mounts", ()):
        kind = str(
            getattr(
                getattr(mount, "source_kind", ""),
                "value",
                getattr(mount, "source_kind", ""),
            )
            or ""
        )
        source = str(getattr(mount, "source", "") or "")
        fields_set = getattr(mount, "model_fields_set", set())
        if kind not in {"bind", "volume", "tmpfs"}:
            raise ValueError(
                "aptl.provisioner.runtime-materialization-unsupported: "
                f"runtime.mounts source_kind={kind or 'unspecified'} has no faithful Compose lowering."
            )
        if kind in {"bind", "volume"} and not source:
            raise ValueError(
                "aptl.provisioner.runtime-materialization-unsupported: "
                f"runtime.mounts {kind} source is unresolved."
            )
        if getattr(mount, "filesystem_type", "") or getattr(mount, "options", ()):
            raise ValueError(
                "aptl.provisioner.runtime-materialization-unsupported: "
                "runtime.mounts filesystem options have no faithful Compose lowering."
            )
        item: dict[str, object] = {
            "type": kind,
            "target": mount.target,
            "read_only": _truthy(getattr(mount, "read_only", False)),
        }
        if source:
            item["source"] = source
        propagation = str(
            getattr(
                getattr(mount, "propagation", ""),
                "value",
                getattr(mount, "propagation", ""),
            )
            or ""
        )
        if "propagation" in fields_set:
            if kind != "bind" or propagation not in {
                "private",
                "rprivate",
                "shared",
                "rshared",
                "slave",
                "rslave",
            }:
                raise ValueError(
                    "aptl.provisioner.runtime-materialization-unsupported: "
                    "runtime.mounts propagation is not faithfully expressible."
                )
            item["bind"] = {"propagation": propagation}
        rendered.append(item)
    return rendered


def _container_config(container: object) -> dict[str, object]:
    """Return the Compose fields a node's declared ``container`` runtime sets."""

    if container is None:
        return {}
    unsupported = next(
        (
            field
            for field in _UNSUPPORTED_CONTAINER_FIELDS
            if getattr(container, field, None)
        ),
        None,
    )
    if unsupported is not None:
        raise ValueError(
            "aptl.provisioner.runtime-materialization-unsupported: "
            f"runtime.container.{unsupported} has no faithful Compose lowering."
        )
    config = _container_scalar_config(container)
    for field in _CONTAINER_SEQUENCE_FIELDS:
        value = getattr(container, field, None)
        if value:
            config[field] = list(value)
    for section in (
        _namespace_config(container),
        _device_config(container),
        _security_config(container),
        _host_integration_config(container),
        _logging_config(container),
        _init_config(container),
    ):
        config.update(section)
    if _truthy(getattr(container, "autoremove", None)):
        config["restart"] = "no"
    return config


def _container_scalar_config(container: object) -> dict[str, object]:
    """Return directly mapped scalar container settings."""

    config: dict[str, object] = {}
    if getattr(container, "shm_size", None):
        config["shm_size"] = container.shm_size
    if _truthy(getattr(container, "privileged", None)):
        config["privileged"] = True
    if _truthy(getattr(container, "read_only_rootfs", None)):
        config["read_only"] = True
    for runtime_field, compose_field in (
        ("cgroup_parent", "cgroup_parent"),
        ("runtime_name", "runtime"),
    ):
        value = getattr(container, runtime_field, "")
        if value:
            config[compose_field] = value
    return config


def _namespace_config(container: object) -> dict[str, object]:
    """Return supported namespace modes."""

    config: dict[str, object] = {}
    namespaces = getattr(container, "namespaces", None)
    if namespaces is not None:
        for runtime_field, compose_field in (
            ("pid", "pid"),
            ("ipc", "ipc"),
            ("userns", "userns_mode"),
            ("uts", "uts"),
            ("cgroup", "cgroup"),
        ):
            value = getattr(namespaces, runtime_field, "")
            if value:
                config[compose_field] = value
    return config


def _device_config(container: object) -> dict[str, object]:
    """Return exact device mappings and cgroup rules."""

    config: dict[str, object] = {}
    devices = getattr(container, "devices", ()) or ()
    if devices:
        config["devices"] = [
            ":".join(
                part
                for part in (
                    device.host_path,
                    device.container_path,
                    device.permissions,
                )
                if part
            )
            for device in devices
        ]
    rules = getattr(container, "device_cgroup_rules", ()) or ()
    if rules:
        config["device_cgroup_rules"] = list(rules)
    return config


def _security_config(container: object) -> dict[str, object]:
    """Return the combined security-option and seccomp contract."""

    security_opt = list(getattr(container, "security_opt", ()) or ())
    seccomp = getattr(container, "seccomp_profile", "")
    if seccomp:
        seccomp_option = f"seccomp={seccomp}"
        existing = [item for item in security_opt if item.startswith("seccomp=")]
        if existing and existing != [seccomp_option]:
            raise ValueError(
                "aptl.provisioner.runtime-materialization-unsupported: "
                "runtime.container.seccomp_profile conflicts with security_opt."
            )
        if seccomp_option not in security_opt:
            security_opt.append(seccomp_option)
    return {"security_opt": security_opt} if security_opt else {}


def _host_integration_config(container: object) -> dict[str, object]:
    """Return host, DNS, and supplemental-group selections."""

    config: dict[str, object] = {}
    extra_hosts = getattr(container, "extra_hosts", ()) or ()
    if extra_hosts:
        config["extra_hosts"] = [
            f"{entry.hostname}:{entry.address}" for entry in extra_hosts
        ]
    dns_options = getattr(container, "dns_options", ()) or ()
    if dns_options:
        config["dns_opt"] = list(dns_options)
    dns_search = getattr(container, "dns_search", ()) or ()
    if dns_search:
        config["dns_search"] = list(dns_search)
    return config


def _logging_config(container: object) -> dict[str, object]:
    """Return the selected daemon log driver and options."""

    log_driver = getattr(container, "log_driver", "")
    log_options = getattr(container, "log_options", {}) or {}
    if not log_driver and not log_options:
        return {}
    logging: dict[str, object] = {}
    if log_driver:
        logging["driver"] = log_driver
    if log_options:
        logging["options"] = dict(log_options)
    return {"logging": logging}


def _init_config(container: object) -> dict[str, object]:
    """Return the standard init toggle or reject custom init semantics."""

    init_process = getattr(container, "init_process", None)
    if init_process is None:
        return {}
    unsupported_init = bool(
        getattr(init_process, "implementation", "")
        or getattr(init_process, "executable_path", "")
        or getattr(init_process, "reaps_children", None)
        or getattr(init_process, "argv", ())
    )
    if unsupported_init:
        raise ValueError(
            "aptl.provisioner.runtime-materialization-unsupported: "
            "runtime.container.init_process requires an unsupported custom init."
        )
    return {"init": True} if _truthy(getattr(init_process, "enabled", None)) else {}


def _capability_config(runtime: object, field: str) -> list[str]:
    """Return one Compose capability list a node's runtime asks for.

    RAES uses the kernel CAP_* form; Docker's cap_add wants it without the
    prefix (NET_ADMIN, not CAP_NET_ADMIN).
    """

    capabilities = getattr(runtime, "linux_capabilities", None)
    selected = list(getattr(capabilities, field, ()) or ()) if capabilities else []
    return [capability.removeprefix("CAP_") for capability in selected]


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
