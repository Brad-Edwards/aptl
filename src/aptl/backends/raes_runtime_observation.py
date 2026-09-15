"""Provider-observed disclosure of runtime realization concerns (#876/#992).

APTL supplies daemon readback for container policy, environment, mounts,
capabilities, published ports, listeners, forwarding agents, and the canonical
Docker control interface, plus bounded guest readback for packages, filesystem,
service-manager, process-limit, local-identity, and dependency-manifest
concerns. RAES owns admission and the
fail-closed non-approximation gate (``realization_disclosure``); this module
supplies the BACKEND half: it OBSERVES each supported declared concern off the
realized container through typed ``DeploymentBackend`` operations and
DISCLOSES the observed value at the concern's payload path, projected through
RAES's own projector so RAES can compare declared-vs-observed.

Projection alignment (retained under RAES 4.1). The RAES planner
writes the node's *raw authored* runtime value into the plan op payload
(``node.model_dump(mode="json")``), not a pre-projected one, and the gate
projects that declared value with ``observed=False`` while projecting the value
this module discloses with ``observed=True``. So the disclosed value must be one
that, re-projected with ``observed=True``, equals ``project(raw_declared,
observed=False)``. :func:`_disclose` achieves that by projecting the observed
value with ``observed=False`` first (which commits a realized ``secret_fixture``
value to its hash rather than rejecting it, and strips every raw value from the
wire) and then re-validating with ``observed=True`` (which runs the concern's
observed-validator and enforces the secret boundary). A correctly realized node
matches; a node whose realized value differs -- or that APTL cannot realize --
projects to something else and the EXACT gate rejects it.

Two disclosure shapes are used, each honest about what the container reveals:

* ``runtime-environment`` takes the *actual realized value* out of the
  container's ``Config.Env`` for each declared variable, so the committed value
  differs the moment the realized value diverges from the declaration. A
  ``redacted`` / ``operator_secret`` variable carries only presence (its raw
  value never leaves the container); a ``secret_fixture`` value is committed to a
  hash, never disclosed raw.
* ``published-ports``, ``linux-capabilities``, ``runtime-mounts``, and
  ``service-listeners`` *corroborate* each declared element against the realized
  container (the same read-back-and-attest pattern the domain-topology observer
  already uses) and disclose the declared value only for corroborated elements.
  An element the container does not corroborate is dropped, so the disclosed
  value diverges from the declaration and the gate rejects it.

  These four also enforce completeness in the other direction: the concern fails
  closed when the container carries security-relevant state the contract does not
  declare -- an undeclared host-published port, a capability beyond the declared
  set, an undeclared bind mount, or a tcp/udp listener the contract omits. Only
  the fixed state APTL's own generic-substrate init adds (the init capabilities
  and the cgroup bind of a systemd node) is subtracted as a known baseline; a
  plain node adds nothing. Without this, the concrete lingering-state case the
  cycle-7 review raised would pass: an idempotently reused container keeps a port
  a later contract dropped, the declared-only projection never sees it, and the
  gate reports the node ready while the port stays reachable (issue #876).

Daemon-observed corroboration never executes a binary inside the attested
container. Environment, port, capability, and mount state comes from host-side
``docker inspect``; ``service-listeners`` comes from the kernel's per-netns
socket tables through ``backend.observe_container_listeners``. The package,
filesystem-inventory, service-manager, process-limit, local-identity, and
dependency-manifest concerns are explicitly ``guest-observed`` instead: they
use bounded native readbacks because those facts do not exist in Docker daemon
metadata. None of these paths adds an observer to the scenario.

``forwarding-agents`` *corroborates* each declared agent against the realized
container's mount footprint: a source's filesystem ``location`` and a
``unix_socket`` reload channel's serving volume are mounts the container must
carry, read back from ``docker inspect`` (daemon-observed) and cross-referenced
with the node's declared mounts. Only agents whose footprint is present are
disclosed; an agent whose footprint is absent (or that declares no
host-observable footprint) drops the whole concern, so the realized set diverges
from the declared one and the EXACT requirement is rejected rather than handed a
fabricated match.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from raes.runtime_configuration import RuntimeConfiguration
from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends._runtime_concern_disclosure import _PROTECTED, _disclose, _record
from aptl.backends._runtime_concern_excess import (
    _INIT_CAPABILITY_BASELINE,
    _capabilities_corroborate,
    _has_undeclared_network_listeners,
    _has_undeclared_ports,
    _normalized_capabilities,
    _port_entry_matches,
    _realized_scope_matches_declared,
    _runs_init,
    _sensitivity,
)
from aptl.backends._runtime_mount_observation import (
    _observe_forwarding_agents,
    _observe_mounts,
)
from aptl.backends.raes_runtime_guest_observation import (
    observe_dependency_manifests,
    observe_filesystem_inventory,
    observe_local_identity,
    observe_packages,
    observe_process_resource_limits,
    observe_service_manager_units,
)
from aptl.core.deployment.realization import LOOPBACK_HOST_IP
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment._proc_net_listeners import ContainerListeners
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.observation import DeploymentObservationContext

log = get_logger("realization-observe")

_ENVIRONMENT_PATH = CONCERN_PAYLOAD_PATH["runtime-environment"]
_MOUNTS_PATH = CONCERN_PAYLOAD_PATH["runtime-mounts"]
_CAPABILITIES_PATH = CONCERN_PAYLOAD_PATH["linux-capabilities"]
_PUBLISHED_PORTS_PATH = CONCERN_PAYLOAD_PATH["published-ports"]
_SERVICE_LISTENERS_PATH = CONCERN_PAYLOAD_PATH["service-listeners"]
_FORWARDING_AGENTS_PATH = CONCERN_PAYLOAD_PATH["forwarding-agents"]
_PACKAGES_PATH = CONCERN_PAYLOAD_PATH["runtime-packages"]
_FILESYSTEM_INVENTORY_PATH = CONCERN_PAYLOAD_PATH["runtime-filesystem-inventory"]
_SERVICE_MANAGER_UNITS_PATH = CONCERN_PAYLOAD_PATH["runtime-service-manager-units"]
_RESTART_POLICY_PATH = CONCERN_PAYLOAD_PATH["runtime-restart-policy"]
_MEMORY_LIMIT_PATH = CONCERN_PAYLOAD_PATH["runtime-node-memory-limit"]
_ENTRYPOINT_PATH = CONCERN_PAYLOAD_PATH["runtime-container-entrypoint"]
_COMMAND_PATH = CONCERN_PAYLOAD_PATH["runtime-container-command"]
_AUTOREMOVE_PATH = CONCERN_PAYLOAD_PATH["runtime-container-autoremove"]
_PROCESS_RESOURCE_LIMITS_PATH = CONCERN_PAYLOAD_PATH["process-resource-limits"]
_LOCAL_CONTROL_INTERFACES_PATH = CONCERN_PAYLOAD_PATH[
    "runtime-local-control-interfaces"
]
_LOCAL_IDENTITY_PATH = CONCERN_PAYLOAD_PATH["runtime-local-identity"]
_DEPENDENCY_MANIFESTS_PATH = CONCERN_PAYLOAD_PATH["runtime-dependency-manifests"]

# The excess-detection, scope, and init-baseline helpers this module's observers
# rely on live in :mod:`aptl.backends._runtime_concern_excess`; they are imported
# above so the disclosure and completeness logic stays in one place.


def observe_runtime_concerns(
    backend: "DeploymentBackend",
    container_name: str | None,
    info: Mapping[str, Any],
    declared_runtime: RuntimeConfiguration | None,
    *,
    observe_backend_process_defaults: bool = False,
    observation_context: DeploymentObservationContext | None = None,
) -> dict[tuple[str, ...], object]:
    """Return the disclosed runtime concerns a realized node declares.

    Keyed by ``CONCERN_PAYLOAD_PATH`` tuple. A concern APTL cannot be seen to
    have realized is absent, so the gate reads an omission (a rejected EXACT
    declaration) rather than an echo of the plan.
    """

    concerns: dict[tuple[str, ...], object] = {}
    if not container_name:
        return concerns
    runtime = declared_runtime or RuntimeConfiguration()
    if declared_runtime is not None:
        _record(concerns, _RESTART_POLICY_PATH, lambda: _observe_restart_policy(info))
    _record(
        concerns,
        _MEMORY_LIMIT_PATH,
        lambda: _observe_memory_limit(info, runtime),
    )
    _record(
        concerns,
        _ENTRYPOINT_PATH,
        lambda: _observe_container_sequence(
            info,
            runtime,
            inspect_field="Entrypoint",
            runtime_field="entrypoint",
            concern_kind="runtime-container-entrypoint",
        ),
    )
    _record(
        concerns,
        _COMMAND_PATH,
        lambda: _observe_container_sequence(
            info,
            runtime,
            inspect_field="Cmd",
            runtime_field="command",
            concern_kind="runtime-container-command",
        ),
    )
    _record(
        concerns,
        _AUTOREMOVE_PATH,
        lambda: _observe_autoremove(
            container_name,
            info,
            runtime,
            observation_context,
        ),
    )
    policy = runtime.operational_policy
    limits = policy.resource_limits if policy is not None else None
    declared_process_limits = bool(
        limits is not None and getattr(limits, "process_limits", ())
    )
    if declared_process_limits or observe_backend_process_defaults:
        _record(
            concerns,
            _PROCESS_RESOURCE_LIMITS_PATH,
            lambda: observe_process_resource_limits(backend, container_name, runtime),
        )
    _record(
        concerns,
        _LOCAL_CONTROL_INTERFACES_PATH,
        lambda: _observe_local_control_interfaces(info, runtime),
    )
    _record(
        concerns,
        _LOCAL_IDENTITY_PATH,
        lambda: observe_local_identity(backend, container_name, runtime),
    )
    _record(
        concerns,
        _DEPENDENCY_MANIFESTS_PATH,
        lambda: observe_dependency_manifests(backend, container_name, runtime),
    )
    _record(
        concerns,
        _ENVIRONMENT_PATH,
        lambda: _observe_environment(info, runtime),
    )
    _record(
        concerns,
        _PUBLISHED_PORTS_PATH,
        lambda: _observe_published_ports(info, runtime),
    )
    _record(
        concerns,
        _CAPABILITIES_PATH,
        lambda: _observe_capabilities(info, runtime),
    )
    _record(concerns, _MOUNTS_PATH, lambda: _observe_mounts(info, runtime))
    _record(
        concerns,
        _SERVICE_LISTENERS_PATH,
        lambda: _observe_service_listeners(backend, container_name, runtime),
    )
    _record(
        concerns,
        _FORWARDING_AGENTS_PATH,
        lambda: _observe_forwarding_agents(info, runtime),
    )
    _record(
        concerns,
        _PACKAGES_PATH,
        lambda: observe_packages(backend, container_name, runtime),
    )
    _record(
        concerns,
        _FILESYSTEM_INVENTORY_PATH,
        lambda: observe_filesystem_inventory(backend, container_name, runtime),
    )
    _record(
        concerns,
        _SERVICE_MANAGER_UNITS_PATH,
        lambda: observe_service_manager_units(backend, container_name, runtime),
    )
    return concerns


# --------------------------------------------------------------------------- #
# daemon-owned container policy
# --------------------------------------------------------------------------- #


def _host_config(info: Mapping[str, Any]) -> Mapping[str, Any]:
    value = info.get("HostConfig") if isinstance(info, Mapping) else None
    return value if isinstance(value, Mapping) else {}


def _container_config(info: Mapping[str, Any]) -> Mapping[str, Any]:
    value = info.get("Config") if isinstance(info, Mapping) else None
    return value if isinstance(value, Mapping) else {}


def _observe_restart_policy(info: Mapping[str, Any]) -> object | None:
    """Return the daemon's effective restart policy, including APTL defaults."""

    policy = _host_config(info).get("RestartPolicy")
    name = policy.get("Name") if isinstance(policy, Mapping) else None
    if not isinstance(name, str) or not name:
        return None
    return _disclose("runtime-restart-policy", name.replace("-", "_"))


def _observe_memory_limit(
    info: Mapping[str, Any], runtime: RuntimeConfiguration
) -> object | None:
    """Return the configured byte limit when the SDL selected that dimension."""

    policy = runtime.operational_policy
    limits = policy.resource_limits if policy is not None else None
    if limits is None or limits.memory is None:
        return None
    value = _host_config(info).get("Memory")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    return _disclose("runtime-node-memory-limit", value)


def _observe_container_sequence(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
    *,
    inspect_field: str,
    runtime_field: str,
    concern_kind: str,
) -> object | None:
    container = runtime.container
    declared = (
        getattr(container, runtime_field, None) if container is not None else None
    )
    if not declared:
        return None
    value = _container_config(info).get(inspect_field)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return _disclose(concern_kind, value)


def _observe_autoremove(
    container_name: str,
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
    observation_context: DeploymentObservationContext | None,
) -> object | None:
    container = runtime.container
    declared = getattr(container, "autoremove", None) if container is not None else None
    if declared is None:
        return None
    expects_removal = (
        declared
        if isinstance(declared, bool)
        else isinstance(declared, str)
        and declared.strip().lower() in {"true", "1", "yes"}
    )
    if expects_removal:
        if observation_context is None or not observation_context.autoremove_verified(
            container_name
        ):
            return None
        return _disclose("runtime-container-autoremove", True)
    value = _host_config(info).get("AutoRemove")
    if not isinstance(value, bool):
        return None
    return _disclose("runtime-container-autoremove", value)


def _observe_local_control_interfaces(
    info: Mapping[str, Any], runtime: RuntimeConfiguration
) -> object | None:
    """Corroborate the canonical Docker socket from daemon mount metadata."""

    interfaces = tuple(runtime.local_control_interfaces)
    if not interfaces:
        return None
    mounts = info.get("Mounts")
    if not isinstance(mounts, list):
        return None
    for interface in interfaces:
        kind = str(getattr(interface.kind, "value", interface.kind))
        access = str(getattr(interface.access, "value", interface.access))
        source = interface.bind_source or interface.path
        if (
            kind != "unix_socket"
            or access not in {"read_only", "read_write"}
            or interface.path != "/var/run/docker.sock"
            or source != "/var/run/docker.sock"
            or interface.protocol
        ):
            return None
        matched = any(
            isinstance(mount, Mapping)
            and mount.get("Type") == "bind"
            and mount.get("Source") == source
            and mount.get("Destination") == interface.path
            and bool(mount.get("RW")) == (access == "read_write")
            for mount in mounts
        )
        if not matched:
            return None
    return _disclose(
        "runtime-local-control-interfaces",
        [item.model_dump(mode="json", by_alias=True) for item in interfaces],
    )


# --------------------------------------------------------------------------- #
# runtime-environment
# --------------------------------------------------------------------------- #


def _observe_environment(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
) -> object | None:
    """Disclose declared env variables carrying their realized container values."""

    declared = runtime.environment
    if not declared:
        return None
    realized = _container_environment(info)
    records: list[dict[str, object]] = []
    for variable in declared:
        name = getattr(variable, "name", "")
        if not name:
            continue
        record = variable.model_dump(mode="json", by_alias=True)
        classification = record.get("value_classification")
        declared_value = record.get("value")
        if classification not in _PROTECTED and not declared_value:
            # A valueless non-secret variable is faithfully realized as "no value"
            # when the container omits it or carries it empty (a plain variable
            # the author left without a value is optional/operator-set) -- disclose
            # it as declared so a faithful realization matches. But a NON-empty
            # realized value is an undeclared operator value (an out-of-band `.env`
            # entry the scenario never authored): disclose it so the
            # non-approximation gate rejects the divergence rather than treating a
            # valueless declaration as a wildcard.
            realized_value = realized.get(name)
            if realized_value:
                record["value"] = realized_value
            records.append(record)
            continue
        if name not in realized:
            # A variable that must carry a realized value — an authored non-secret
            # value, or an operator-supplied secret — but is absent from the
            # container is not realized: omit it so the non-approximation gate
            # rejects the exact declaration rather than reading an echo.
            continue
        # A protected value is presence-only; its raw material is never read.
        record["value"] = "" if classification in _PROTECTED else realized[name]
        records.append(record)
    if not records:
        return None
    return _disclose("runtime-environment", records)


def _container_environment(info: Mapping[str, Any]) -> dict[str, str]:
    """Parse the realized container's ``Config.Env`` into a name -> value map."""

    config = info.get("Config") if isinstance(info, Mapping) else None
    entries = config.get("Env") if isinstance(config, Mapping) else None
    realized: dict[str, str] = {}
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, str) and "=" in entry:
                name, _, value = entry.partition("=")
                realized[name] = value
    return realized


# --------------------------------------------------------------------------- #
# published-ports
# --------------------------------------------------------------------------- #


def _observe_published_ports(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
) -> object | None:
    """Disclose declared host-published ports the container actually binds.

    Fails closed (returns None) when the container publishes ANY port the
    contract does not declare: the base substrate publishes nothing, so an
    undeclared host binding is excess exposure -- the concrete lingering-port case
    the cycle-7 review raised, where a reused container keeps a host port a later
    contract dropped. Every realized binding must map to a declared port.
    """

    network = runtime.network
    declared_ports = tuple(network.published_ports) if network is not None else ()
    bindings = _port_bindings(info)
    if _has_undeclared_ports(bindings, declared_ports) or not declared_ports:
        return None
    disclosed = [
        port.model_dump(mode="json", by_alias=True)
        for port in declared_ports
        if _port_binding_present(port, bindings)
    ]
    if not disclosed:
        return None
    return _disclose("published-ports", disclosed)


def _port_bindings(info: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return ``HostConfig.PortBindings`` as a mapping, or empty."""

    host_config = info.get("HostConfig") if isinstance(info, Mapping) else None
    bindings = (
        host_config.get("PortBindings") if isinstance(host_config, Mapping) else None
    )
    return bindings if isinstance(bindings, Mapping) else {}


def _port_binding_present(port: object, bindings: Mapping[str, Any]) -> bool:
    """Return whether the container realized this declared port binding.

    An author who omitted ``host_ip`` is realized on loopback (ADR-034 / the
    base substrate), so the corroboration expects loopback there, not the raw
    container value.
    """

    key = f"{getattr(port, 'container_port', '')}/{getattr(port, 'protocol', 'tcp')}"
    entries = bindings.get(key)
    if not isinstance(entries, Sequence):
        return False
    expected_ip = getattr(port, "host_ip", "") or LOOPBACK_HOST_IP
    host_port = getattr(port, "host_port", None)
    expected_port = str(host_port) if host_port is not None else None
    return any(
        _port_entry_matches(entry, expected_ip, expected_port)
        for entry in entries
        if isinstance(entry, Mapping)
    )


# --------------------------------------------------------------------------- #
# linux-capabilities
# --------------------------------------------------------------------------- #


def _observe_capabilities(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
) -> object | None:
    """Disclose a declared capability policy the container's grants corroborate.

    Only the container-config knobs ``add`` / ``drop`` are observable off a
    realized container; ``required`` is an author assertion and ``effective`` /
    ``process_overrides`` are process-runtime facts APTL does not realize through
    the docker capability flags. A policy that asserts any of those is not
    corroborable and is dropped so the gate does not receive a value APTL cannot
    stand behind.
    """

    policy = runtime.linux_capabilities
    if policy is None:
        return None
    declared = policy.model_dump(mode="json", by_alias=True)
    # ``required``/``effective``/``process_overrides`` are non-realizable
    # assertions, so a policy asserting any of them is dropped.
    unrealizable = bool(
        declared.get("required")
        or declared.get("effective")
        or declared.get("process_overrides")
    )
    host_config = info.get("HostConfig") if isinstance(info, Mapping) else None
    granted = _normalized_capabilities(
        host_config.get("CapAdd") if isinstance(host_config, Mapping) else None
    )
    dropped = _normalized_capabilities(
        host_config.get("CapDrop") if isinstance(host_config, Mapping) else None
    )
    # Corroboration folds three fail-closed checks (issue #876 cycle-7 review): a
    # declared drop actually granted is not dropped; a grant beyond the declared
    # set plus the init baseline is undeclared privilege; every declared add/drop
    # must be realized. A systemd node subtracts exactly its init capabilities.
    baseline = _INIT_CAPABILITY_BASELINE if _runs_init(runtime) else frozenset()
    corroborated = not unrealizable and _capabilities_corroborate(
        declared, granted, dropped, baseline
    )
    return _disclose("linux-capabilities", declared) if corroborated else None


# --------------------------------------------------------------------------- #
# service-listeners
# --------------------------------------------------------------------------- #


def _observe_service_listeners(
    backend: "DeploymentBackend",
    container_name: str,
    runtime: RuntimeConfiguration,
) -> object | None:
    """Disclose declared listeners the container is observed to be serving.

    Listener state comes from ``backend.observe_container_listeners`` -- the
    kernel's per-netns socket tables, read by a mechanism that executes no
    container-provided binary (issue #876 security review). A read that cannot be
    completed discloses nothing, so the gate rejects rather than assumes a match.
    """

    declared = runtime.service_listeners
    if not declared:
        return None
    observed = backend.observe_container_listeners(container_name)
    result: object | None = None
    # Excess check (issue #876 cycle-7 review): the base substrate opens no
    # network listener of its own, so a realized tcp/udp socket the contract does
    # not declare is a hostile or leftover exposure and must not pass behind an
    # echoed declaration. Unix sockets are deliberately not excess-checked -- a
    # systemd node's own init opens many internal ones -- so only network
    # exposure is bounded here.
    if observed is not None and not _has_undeclared_network_listeners(
        observed.sockets, declared
    ):
        disclosed = [
            listener.model_dump(mode="json", by_alias=True)
            for listener in declared
            if _listener_present(listener, observed)
        ]
        if disclosed:
            result = _disclose("service-listeners", disclosed)
    return result


def _listener_present(listener: object, observed: "ContainerListeners") -> bool:
    """Return whether the trusted observation corroborates one declared listener."""

    protocol = _sensitivity(getattr(listener, "protocol", ""))
    if protocol == "unix":
        socket_path = getattr(listener, "socket_path", "")
        return bool(socket_path) and socket_path in observed.unix_socket_paths
    return _network_listener_present(listener, protocol, observed)


def _network_listener_present(
    listener: object, protocol: str, observed: "ContainerListeners"
) -> bool:
    """Return whether a trusted observation corroborates a declared tcp/udp listener."""

    port = getattr(listener, "port", None)
    if port is None:
        return False
    declared_port = int(port)
    declared_address = getattr(listener, "address", "")
    # An unresolved symbolic address ($VAR) cannot be scope-checked, so it is
    # failed closed until the compiled binding resolves it to a concrete or
    # wildcard address -- otherwise a workload could bind all interfaces behind a
    # symbolic declaration (issue #876 cycle-7 review).
    if declared_address.startswith("$"):
        return False
    present = False
    for socket_protocol, socket_address, socket_port in observed.sockets:
        if socket_protocol != protocol or socket_port != declared_port:
            continue
        # Exact scope match in both directions: a concrete declaration realized on
        # a wildcard is over-exposed and a wildcard declaration realized on one
        # interface is under-exposed -- neither corroborates (issue #876 review).
        if _realized_scope_matches_declared(socket_address, declared_address):
            present = True
            break
    return present


__all__ = ["observe_runtime_concerns"]
