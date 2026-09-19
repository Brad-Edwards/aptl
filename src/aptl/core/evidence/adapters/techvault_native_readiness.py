"""Native readiness queries for the two TechVault readiness demands.

Kept beside :mod:`techvault_native` rather than inside it so neither file grows
past its size budget, and so the readiness contract released with
``raes-env-packs`` 6.1.0 reads as one unit: what each demand asks for, and the
admitted realization facts the probes are pointed at.

Every value handed to a probe comes from the admitted realization -- the
authored canonical URL, the admitted network address, the declared forwarding
agents and their declared log sources. Nothing here is derived from a container
name pattern, a DNS zone, or a legacy Compose file.
"""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlparse

from pathlib import Path

from aptl.core.evidence.adapters.techvault_enrollment_baseline import (
    enrollment_baseline,
    record_enrollment_baseline,
)
from aptl.core.evidence.adapters.techvault_misp_readiness import AdmittedMispState
from aptl.core.evidence.adapters.techvault_readiness_probes import (
    agent_identity,
    misp_readiness_probe,
    telemetry_events,
    wazuh_roster,
)

#: Where the certificate check runs. The fact the demand asks for is whether
#: the leaf verifies for the authored host against the lab CA, and the probe
#: pins that host to the admitted address rather than resolving it, so the
#: result depends on the certificate rather than on which container happens to
#: have a resolver. MISP's own container is used because it is the one node
#: guaranteed to hold both the lab CA -- it is a declared consumer of it -- and
#: the HTTP client its own image health check already relies on.
MISP_TLS_VERIFIER_CONTAINER = "aptl-misp"
_MISP_NODE = "misp"
_BASE_URL = "BASE_URL"
_WAZUH_AGENT_IMPLEMENTATION = "wazuh_agent"
_TAILED_PATH = "tailed_path"


def misp_readiness(execute: object, realization: object) -> Mapping[str, object] | None:
    """Observe MISP application, database and cache readiness, or nothing."""

    canonical_url = _authored_base_url(realization)
    address = _node_address(realization, _MISP_NODE)
    if canonical_url is None or address is None:
        return None
    host = urlparse(canonical_url).hostname
    if not host:
        return None
    return misp_readiness_probe(
        execute,
        canonical_url=canonical_url,
        canonical_host=host,
        misp_address=address,
        verifier_container=MISP_TLS_VERIFIER_CONTAINER,
    )


def wazuh_agent_readiness(
    execute: object,
    realization: object,
    scenario_root: Path,
    start_iso: str,
    end_iso: str,
) -> Mapping[str, object] | None:
    """Correlate each declared endpoint agent with one active manager member."""

    context = _wazuh_readiness_context(execute, realization, scenario_root)
    if context is None:
        return None
    declared, roster, recorded = context
    observation_window = (start_iso, end_iso)
    hosts = [
        _wazuh_host_readiness(
            execute,
            node,
            enrollment_name,
            sources,
            roster,
            recorded,
            observation_window,
        )
        for node, (enrollment_name, sources) in sorted(declared.items())
    ]
    complete_hosts = [host for host in hosts if host is not None]
    if len(complete_hosts) != len(hosts):
        return None
    return {"hosts": complete_hosts}


def _wazuh_readiness_context(
    execute: object,
    realization: object,
    scenario_root: Path,
) -> (
    tuple[
        dict[str, tuple[str, tuple[str, ...]]],
        tuple[tuple[str, str, str], ...],
        dict[str, str],
    ]
    | None
):
    """Load the declared agents, manager roster, and immutable id baseline."""

    context = None
    declared = declared_endpoint_agents(realization)
    roster = wazuh_roster(execute) if declared else None
    if declared and roster is not None:
        observed_ids = _observed_agent_ids(execute, declared)
        baseline_ready = not observed_ids or record_enrollment_baseline(
            scenario_root, observed_ids
        )
        if baseline_ready:
            recorded = enrollment_baseline(scenario_root)
            if recorded is not None:
                context = (declared, roster, recorded)
    return context


def _wazuh_host_readiness(
    execute: object,
    node: str,
    enrollment_name: str,
    sources: tuple[str, ...],
    roster: tuple[tuple[str, str, str], ...],
    recorded: dict[str, str],
    observation_window: tuple[str, str],
) -> dict[str, object] | None:
    """Correlate one host with its unique member, telemetry, and baseline."""

    members = [row for row in roster if row[0] == enrollment_name]
    identity = agent_identity(execute, f"aptl-{node}", sources)
    if len(members) != 1 or identity is None:
        return None
    _name, agent_id, status = members[0]
    events = telemetry_events(execute, agent_id, *observation_window)
    if events is None:
        return None
    host_id = str(identity.get("agent_id", ""))
    baseline = recorded.get(node)
    return {
        "node_ref": node,
        "enrollment_name": enrollment_name,
        "agent_id": agent_id,
        "status": status,
        "sources_readable": identity.get("sources_readable") is True,
        "enrollment_preserved": bool(
            baseline is not None and host_id == agent_id and host_id == baseline
        ),
        "telemetry_fresh": events > 0,
        "telemetry_event_count": events,
    }


def _observed_agent_ids(
    execute: object, declared: dict[str, tuple[str, tuple[str, ...]]]
) -> dict[str, str]:
    """Return each declared host's currently retained agent id, when readable."""

    observed: dict[str, str] = {}
    for node, (_name, sources) in sorted(declared.items()):
        identity = agent_identity(execute, f"aptl-{node}", sources)
        host_id = str(identity.get("agent_id", "")) if identity else ""
        if host_id:
            observed[node] = host_id
    return observed


def admitted_misp_state(realization: object) -> AdmittedMispState | None:
    """Return the MISP/database/cache values the admitted plan requires.

    Read from the realization and the pack rather than restated here: the
    comparison is only meaningful if the expectation is the admitted one.
    """

    canonical_url = _authored_base_url(realization)
    environment = _misp_environment(realization)
    persistence = _cache_persistence(realization)
    if canonical_url is None or persistence is None:
        return None
    database = environment.get("MYSQL_DATABASE", "")
    role = environment.get("MYSQL_USER", "")
    if not database or not role:
        return None
    aof, eviction = persistence
    return AdmittedMispState(
        canonical_url=canonical_url,
        database_identity=database,
        database_role=role,
        # RAES states the cache's persistence posture semantically; Redis
        # reports the same posture in its own vocabulary.
        cache_persistence_policy="yes" if aof else "no",
        cache_eviction_policy=eviction,
    )


def _misp_environment(realization: object) -> dict[str, str]:
    """Return MISP's admitted runtime environment as a plain mapping."""

    for node in getattr(realization, "nodes", ()) or ():
        if str(getattr(node, "name", "")) != _MISP_NODE:
            continue
        return {
            str(variable.name): str(variable.value)
            for variable in getattr(getattr(node, "runtime", None), "environment", ())
            or ()
        }
    return {}


def _cache_persistence(realization: object) -> tuple[bool, str] | None:
    """Return MISP's bound cache's authored ``(aof, eviction)`` posture."""

    binding = _misp_cache_binding(realization)
    if binding is None:
        return None
    target_node, target_service = binding
    datastore = _bound_datastore(realization, target_node, target_service)
    return _redis_persistence(datastore)


def _bound_datastore(
    realization: object, target_node: str, target_service: str
) -> object | None:
    """Return the datastore selected by one exact authored binding."""

    for node in getattr(realization, "nodes", ()) or ():
        if str(getattr(node, "name", "")) != target_node:
            continue
        runtime = getattr(node, "runtime", None)
        for datastore in getattr(runtime, "datastore_services", ()) or ():
            if (
                str(getattr(datastore, "service", "")) == target_service
                and _redis_persistence(datastore) is not None
            ):
                return datastore
    return None


def _redis_persistence(datastore: object | None) -> tuple[bool, str] | None:
    """Project the persistence posture from an admitted Redis datastore."""

    if datastore is None or not str(getattr(datastore, "engine", "")).endswith("redis"):
        return None
    persistence = getattr(datastore, "persistence", None)
    eviction = getattr(persistence, "eviction", None)
    if persistence is None or eviction is None:
        return None
    value = str(getattr(eviction, "value", eviction))
    return bool(getattr(persistence, "aof", False)), value


def _misp_cache_binding(realization: object) -> tuple[str, str] | None:
    """Return MISP's one authored data-source node/service binding."""

    targets = {
        (
            str(getattr(binding, "target_node_ref", "")),
            str(getattr(binding, "target_service_ref", "")),
        )
        for node in getattr(realization, "nodes", ()) or ()
        if str(getattr(node, "name", "")) == _MISP_NODE
        for application in getattr(
            getattr(node, "runtime", None), "platform_applications", ()
        )
        or ()
        for binding in getattr(application, "upstream_bindings", ()) or ()
        if str(getattr(getattr(binding, "role", ""), "value", binding.role))
        == "data_source"
        and str(getattr(binding, "target_node_ref", ""))
        and str(getattr(binding, "target_service_ref", ""))
    }
    return targets.pop() if len(targets) == 1 else None


def declared_endpoint_agents(
    realization: object,
) -> dict[str, tuple[str, tuple[str, ...]]]:
    """Return ``{node: (enrollment_name, declared_source_paths)}`` as authored.

    Only an agent that enrolls is an endpoint agent: a node may also declare a
    forwarder that ships syslog to the manager without an identity of its own,
    and that one proves nothing about the host it runs on.
    """

    declared: dict[str, tuple[str, tuple[str, ...]]] = {}
    for node in getattr(realization, "nodes", ()) or ():
        valid, agent = _node_endpoint_agent(node)
        if not valid:
            return {}
        if agent is not None:
            declared[str(node.name)] = agent
    return declared


def _node_endpoint_agent(
    node: object,
) -> tuple[bool, tuple[str, tuple[str, ...]] | None]:
    """Return one node's unique enrolling agent, rejecting ambiguity."""

    runtime = getattr(node, "runtime", None)
    agents = [
        agent
        for agent in getattr(runtime, "forwarding_agents", ()) or ()
        if _is_enrolling_wazuh_agent(agent)
    ]
    valid = len(agents) <= 1
    result = None
    if valid and agents:
        agent = agents[0]
        sources = tuple(
            str(source.location)
            for source in getattr(agent, "sources", ()) or ()
            if _source_is_tailed_path(source)
        )
        valid = bool(sources)
        if valid:
            result = (str(agent.name), sources)
    return valid, result


def _source_is_tailed_path(source: object) -> bool:
    """Return whether a source is a non-empty authored tailed path."""

    kind = getattr(source, "kind", "")
    return str(getattr(kind, "value", kind)) == _TAILED_PATH and bool(
        str(getattr(source, "location", ""))
    )


def _is_enrolling_wazuh_agent(agent: object) -> bool:
    """Return whether one forwarding agent is a Wazuh agent that enrolls."""

    implementation = getattr(agent, "implementation", "")
    implementation = str(getattr(implementation, "value", implementation))
    enrolls = any(
        getattr(target, "enrollment_port", None)
        for target in getattr(agent, "ship_targets", ()) or ()
    )
    return (
        implementation == _WAZUH_AGENT_IMPLEMENTATION
        and enrolls
        and bool(str(getattr(agent, "name", "")))
    )


def _authored_base_url(realization: object) -> str | None:
    """Return MISP's admitted canonical URL from its realized environment."""

    for node in getattr(realization, "nodes", ()) or ():
        if str(getattr(node, "name", "")) != _MISP_NODE:
            continue
        for variable in (
            getattr(getattr(node, "runtime", None), "environment", ()) or ()
        ):
            if str(getattr(variable, "name", "")) == _BASE_URL:
                value = str(getattr(variable, "value", ""))
                return value or None
    return None


def _node_address(realization: object, name: str) -> str | None:
    """Return one node's single admitted network address."""

    for node in getattr(realization, "nodes", ()) or ():
        if str(getattr(node, "name", "")) != name:
            continue
        addresses = {
            str(attachment.address)
            for attachment in getattr(node, "network_attachments", ()) or ()
            if str(getattr(attachment, "address", ""))
        }
        # An ambiguous address would make the pinned certificate check point at
        # an arbitrary interface, so it fails closed rather than picking one.
        return addresses.pop() if len(addresses) == 1 else None
    return None


__all__ = (
    "MISP_TLS_VERIFIER_CONTAINER",
    "admitted_misp_state",
    "declared_endpoint_agents",
    "misp_readiness",
    "wazuh_agent_readiness",
)
