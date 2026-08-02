"""Provider-observed disclosure of the six runtime realization concerns (#876).

raes 3.1.0 lowers six per-node runtime dimensions into the RAES realization
concern registry -- ``runtime-environment``, ``runtime-mounts`` (bind/tmpfs
only), ``linux-capabilities``, ``published-ports``, ``forwarding-agents``, and
``service-listeners``. RAES owns admission and the fail-closed non-approximation
gate (``realization_disclosure``); this module supplies the BACKEND half: it
OBSERVES each declared runtime concern off the realized container through the
typed ``DeploymentBackend`` ops and DISCLOSES the observed value at the concern's
payload path, projected through RAES's own projector so RAES can compare
declared-vs-observed.

Projection alignment (resolved empirically against raes 3.1.0). The RAES planner
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

Corroboration evidence never comes from executing a binary inside the attested
container. The first four concerns read host-side ``docker inspect`` (daemon
state the container cannot forge); ``service-listeners`` reads the kernel's
per-netns socket tables through ``backend.observe_container_listeners`` -- a
sidecar in the target's network namespace using its own trusted binary -- so a
workload that shadows ``ss``/``test`` cannot narrow its attested bind scope
(issue #876 security review).

``forwarding-agents`` is deliberately never disclosed: APTL's dynamic-composition
path does not materialize a forwarding / intel-sync agent, so the honest
observation is absence. A node that declares one and compiles an EXACT
requirement is rejected by the gate rather than handed a fabricated match.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any

from raes.runtime_configuration import RuntimeConfiguration
from raes_processor.semantics.realization import (
    CONCERN_PAYLOAD_PATH,
    project_realization_concern,
)

from aptl.backends._runtime_concern_excess import (
    _INIT_CAPABILITY_BASELINE,
    _STATEFUL_MOUNT_KINDS,
    _capabilities_corroborate,
    _has_undeclared_mounts,
    _has_undeclared_network_listeners,
    _has_undeclared_ports,
    _normalized_capabilities,
    _port_entry_matches,
    _realized_scope_matches_declared,
    _runs_init,
    _sensitivity,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import LOOPBACK_HOST_IP
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment._proc_net_listeners import ContainerListeners
    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("realization-observe")

# Classifications whose raw material must never be observed or disclosed. Kept in
# lockstep with RAES's own ``_PROTECTED`` set on the concern projectors.
_PROTECTED = frozenset({"redacted", "operator_secret"})

_ENVIRONMENT_PATH = CONCERN_PAYLOAD_PATH["runtime-environment"]
_MOUNTS_PATH = CONCERN_PAYLOAD_PATH["runtime-mounts"]
_CAPABILITIES_PATH = CONCERN_PAYLOAD_PATH["linux-capabilities"]
_PUBLISHED_PORTS_PATH = CONCERN_PAYLOAD_PATH["published-ports"]
_SERVICE_LISTENERS_PATH = CONCERN_PAYLOAD_PATH["service-listeners"]

# The excess-detection, scope, and init-baseline helpers this module's observers
# rely on live in :mod:`aptl.backends._runtime_concern_excess`; they are imported
# above so the disclosure and completeness logic stays in one place.


def observe_runtime_concerns(
    backend: "DeploymentBackend",
    container_name: str | None,
    info: Mapping[str, Any],
    declared_runtime: RuntimeConfiguration | None,
) -> dict[tuple[str, ...], object]:
    """Return the disclosed runtime concerns a realized node declares.

    Keyed by ``CONCERN_PAYLOAD_PATH`` tuple. A concern APTL cannot be seen to
    have realized is absent, so the gate reads an omission (a rejected EXACT
    declaration) rather than an echo of the plan.
    """

    concerns: dict[tuple[str, ...], object] = {}
    if declared_runtime is None or not container_name:
        return concerns
    _record(concerns, _ENVIRONMENT_PATH, lambda: _observe_environment(info, declared_runtime))
    _record(concerns, _PUBLISHED_PORTS_PATH, lambda: _observe_published_ports(info, declared_runtime))
    _record(concerns, _CAPABILITIES_PATH, lambda: _observe_capabilities(info, declared_runtime))
    _record(concerns, _MOUNTS_PATH, lambda: _observe_mounts(info, declared_runtime))
    _record(
        concerns,
        _SERVICE_LISTENERS_PATH,
        lambda: _observe_service_listeners(backend, container_name, declared_runtime),
    )
    # forwarding-agents is intentionally never disclosed: see module docstring.
    return concerns


def _record(
    concerns: dict[tuple[str, ...], object],
    path: tuple[str, ...],
    observe: Callable[[], object | None],
) -> None:
    """Run one concern observation, failing closed on any error."""

    try:
        value = observe()
    except (BackendTimeoutError, OSError, ValueError, TypeError) as exc:
        log.warning("could not observe runtime concern %s (%s)", path, type(exc).__name__)
        return
    if value is not None:
        concerns[path] = value


def _disclose(concern_kind: str, observed_value: object) -> object | None:
    """Project an observed value into its secret-safe disclosed commitment.

    The ``observed=False`` pass converts realized raw material into commitments
    (and rejects protected raw material) rather than raising on a realized
    ``secret_fixture`` value; the ``observed=True`` pass runs the concern's
    observed-validator so a malformed observation fails closed here instead of
    landing an invalid value in the snapshot.
    """

    try:
        committed = project_realization_concern(concern_kind, observed_value, observed=False)
        return project_realization_concern(concern_kind, committed, observed=True)
    except (ValueError, TypeError) as exc:
        log.warning("dropping unprojectable %s observation (%s)", concern_kind, type(exc).__name__)
        return None


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
        if not name or name not in realized:
            continue
        record = variable.model_dump(mode="json", by_alias=True)
        classification = record.get("value_classification")
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
    bindings = host_config.get("PortBindings") if isinstance(host_config, Mapping) else None
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
    unrealizable = bool(declared.get("required") or declared.get("effective") or declared.get("process_overrides"))
    host_config = info.get("HostConfig") if isinstance(info, Mapping) else None
    granted = _normalized_capabilities(host_config.get("CapAdd") if isinstance(host_config, Mapping) else None)
    dropped = _normalized_capabilities(host_config.get("CapDrop") if isinstance(host_config, Mapping) else None)
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
# runtime-mounts (bind/tmpfs only)
# --------------------------------------------------------------------------- #


def _observe_mounts(
    info: Mapping[str, Any],
    runtime: RuntimeConfiguration,
) -> object | None:
    """Disclose declared bind/tmpfs mounts the container inspection corroborates.

    Fails closed (returns None) when the container carries a bind/tmpfs mount the
    contract does not declare and the substrate itself did not add (a systemd
    node's cgroup bind is the only baseline mount ``docker inspect`` reports). An
    undeclared bind mount is excess host access -- a leftover from a reused
    container or a hostile addition -- and must not pass (issue #876 cycle-7
    review).
    """

    declared = [mount for mount in runtime.mounts if _mount_kind(mount) in _STATEFUL_MOUNT_KINDS]
    realized = info.get("Mounts") if isinstance(info, Mapping) else None
    realized_mounts = realized if isinstance(realized, list) else []
    if _has_undeclared_mounts(realized_mounts, declared, runtime) or not declared:
        return None
    disclosed = [
        mount.model_dump(mode="json", by_alias=True)
        for mount in declared
        if _mount_present(mount, realized_mounts)
    ]
    if not disclosed:
        return None
    return _disclose("runtime-mounts", disclosed)


def _mount_kind(mount: object) -> str:
    """Return a declared mount's source kind (``bind`` / ``tmpfs`` / ...)."""

    source_kind = getattr(mount, "source_kind", None)
    return str(getattr(source_kind, "value", source_kind) or "")


def _mount_present(mount: object, realized_mounts: Sequence[object]) -> bool:
    """Return whether the container carries this declared bind/tmpfs mount."""

    kind = _mount_kind(mount)
    target = getattr(mount, "target", "")
    protected = _sensitivity(getattr(mount, "source_sensitivity", "")) in _PROTECTED
    source = getattr(mount, "source", "")
    read_only = bool(getattr(mount, "read_only", False))
    return any(
        _mount_entry_matches(
            realized,
            kind=kind,
            target=target,
            source=source,
            protected=protected,
            read_only=read_only,
        )
        for realized in realized_mounts
        if isinstance(realized, Mapping)
    )


def _mount_entry_matches(
    realized: Mapping[str, Any],
    *,
    kind: str,
    target: str,
    source: str,
    protected: bool,
    read_only: bool,
) -> bool:
    """Return whether one realized mount entry corroborates the declared mount."""

    if realized.get("Type") != kind or realized.get("Destination") != target:
        return False
    source_mismatch = bool(
        kind == "bind" and source and not protected and realized.get("Source") != source
    )
    # Read-only is a declared access-contract field; a realized RW state equal to
    # the declared read_only flag is contradictory (they are inverse), i.e. a
    # material mismatch, not a match (issue #876 core review).
    rw_mismatch = (
        kind in ("bind", "tmpfs")
        and "RW" in realized
        and read_only == bool(realized.get("RW"))
    )
    return not source_mismatch and not rw_mismatch


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
