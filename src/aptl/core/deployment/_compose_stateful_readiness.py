"""Authenticated readiness for realized stateful services (issue #875).

Split out of ``_compose_stateful_realization.py`` (module-length budget): a
settled container proves little about its API. A generated Wazuh service may
define no healthcheck at all, in which case it settles as soon as it is
running, before its API listens. A realization is therefore not finished until
the graph-owned Wazuh APIs actually accept the configured credentials. This
module owns that observation -- the credential load, the published-port
lookup, and the poll loop that waits out the initialization window without
ever letting a genuinely bad credential or a persistent transport failure
pass. Warm-up attempts stay quiet; the last classified observation of each
unready service becomes the terminal reason at the deadline (issue #1002).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from aptl.core.deployment._wazuh_identity import (
    WazuhClusterIdentity,
    wazuh_cluster_identity,
)
from aptl.core.deployment._compose_stateful_constants import (
    WAZUH_MANAGER_CONFIG_PROVENANCES,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.env import (
    EnvVars,
    env_vars_from_dict,
    find_placeholder_env_values,
    load_dotenv,
)
from aptl.core.lab_types import LabResult
from aptl.core.services import probe_indexer_api, probe_manager_api
from aptl.utils.curl_safe import basic_auth_header, curl_json
from aptl.utils.logging import get_logger

log = get_logger("stateful-readiness")

# Budget for authenticated Wazuh readiness after container health settles. The
# indexer's security index and the manager API keep initializing past the point
# the container settles (a generated manager without a healthcheck settles
# before its API listens), so this polls rather than probing once. 300s is a
# generous margin over the observed few-minutes gap on a loaded host; a
# genuinely bad credential still fails closed after the budget (issue #875).
_AUTHENTICATED_READINESS_TIMEOUT = 300
_AUTHENTICATED_READINESS_INTERVAL = 5


@dataclass(frozen=True)
class _ServiceObservation:
    """Secret-free result of one authenticated readiness attempt."""

    ready: bool
    detail: str
    container_name: str | None = None
    facts: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class ReadinessPolling:
    """Budget and clock the authenticated-readiness poll loop runs on.

    ``time_source`` and ``sleep`` default to ``None`` rather than to the module's
    ``time`` functions so the clock is resolved at call time: a test that
    monkeypatches this module's ``time`` still intercepts both.
    """

    timeout: int = _AUTHENTICATED_READINESS_TIMEOUT
    interval: int = _AUTHENTICATED_READINESS_INTERVAL
    time_source: Callable[[], float] | None = None
    sleep: Callable[[float], None] | None = None

    @property
    def clock(self) -> Callable[[], float]:
        """Return the monotonic clock this poll loop measures its budget on."""

        return self.time_source if self.time_source is not None else time.monotonic

    @property
    def pause(self) -> Callable[[float], None]:
        """Return the sleep this poll loop waits between probes with."""

        return self.sleep if self.sleep is not None else time.sleep


class ComposeStatefulReadinessMixin:
    """Observe that realized stateful services accept their credentials."""

    @property
    def authenticated_readiness(self) -> dict[str, bool]:
        """Compatibility projection of declared Wazuh attestation outcomes."""

        return dict(getattr(self, "_stateful_authenticated_readiness", {}))

    @property
    def declared_wazuh_attestation(self) -> dict[str, tuple[dict[str, str], ...]]:
        """Return structured, secret-free observations for each declared fact."""

        return {
            service: tuple(dict(fact) for fact in facts)
            for service, facts in getattr(
                self, "_stateful_declared_wazuh_attestation", {}
            ).items()
        }

    def _verify_stateful_authenticated_readiness(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Authenticate to realized Wazuh APIs after container health settles."""

        identity = wazuh_cluster_identity(realization)
        services = _stateful_services(realization, identity)
        readiness_error = self._authenticated_services_error(
            realization, services, identity
        )
        if readiness_error is not None:
            return LabResult(success=False, error=readiness_error)
        manager = _rendered_manager_config_container(realization, identity)
        if manager is not None and not self._rendered_manager_config_is_active(manager):
            return LabResult(
                success=False,
                error="Wazuh manager did not activate its rendered configuration.",
            )
        return None

    def _authenticated_services_error(
        self,
        realization: DeploymentRealizationSpec,
        services: set[str],
        identity: WazuhClusterIdentity,
    ) -> str | None:
        """Observe configured services and return their bounded failure reason."""

        self._stateful_authenticated_readiness = {}
        self._stateful_declared_wazuh_attestation = {}
        error: str | None = None
        if services:
            env, _placeholder_input = _load_stateful_env(self._project_dir)
            if env is None:
                error = "Authenticated Wazuh readiness credentials are unavailable."
            else:
                nodes = {node.service_name: node for node in realization.nodes}
                budget = ReadinessPolling()
                observations = self._authenticated_readiness_results(
                    services, nodes, env, identity, budget
                )
                self._stateful_authenticated_readiness = {
                    service: observation.ready
                    for service, observation in observations.items()
                }
                self._stateful_declared_wazuh_attestation = {
                    service: observation.facts
                    for service, observation in observations.items()
                    if observation.facts
                }
                error = _readiness_failure(observations, budget.timeout)
        return error

    def _rendered_manager_config_is_active(self, container: str) -> bool:
        """Prove the manager activated the exact rendered config it received."""

        command = [
            "/bin/sh",
            "-c",
            (
                "test \"$(sha256sum /var/ossec/etc/ossec.conf | cut -d' ' -f1)\" "
                '= "$(sha256sum /wazuh-config-mount/etc/ossec.conf | '
                "cut -d' ' -f1)\""
            ),
        ]
        try:
            result = self.container_exec(container, command, timeout=30)
        except (BackendTimeoutError, OSError):
            return False
        return result.returncode == 0

    def _authenticated_readiness_results(
        self,
        services: set[str],
        nodes: dict[str | None, DeploymentNodeRealization],
        env: EnvVars,
        identity: WazuhClusterIdentity,
        polling: ReadinessPolling | None = None,
    ) -> dict[str, _ServiceObservation]:
        """Poll authenticated readiness for each Wazuh service until ready.

        A settled container does not mean its API accepts credentials: the
        indexer's security index (loaded by securityadmin from
        internal_users.yml) and the manager API finish initializing
        seconds-to-minutes later, and a generated service without a healthcheck
        settles before its API even listens. A single probe right after
        health-settle races that window. Poll on a generous budget so a
        genuinely misconfigured credential or a persistent transport failure
        still fails closed, just after the budget rather than before it (issues
        #875, #1002). Each service is probed until it is ready and then no
        longer, so the result carries each ready service's proof and the last
        classified state of every service still unready at the deadline.
        """

        checks = [
            (service, port)
            for service, port in (
                (identity.indexer_service, 9200),
                (identity.manager_service, 55000),
            )
            if service in services
        ]
        if not checks:
            return {}
        budget = polling if polling is not None else ReadinessPolling()
        clock = budget.clock
        deadline = clock() + budget.timeout
        results: dict[str, _ServiceObservation] = {}
        while True:
            # A service proven ready stays proven: re-probing it while another
            # service warms up could let a transient answer overwrite the proof.
            results.update(
                {
                    service: self._authenticated_service_ready(
                        service, port, nodes.get(service), env, identity
                    )
                    for service, port in checks
                    if not (service in results and results[service].ready)
                }
            )
            if all(r.ready for r in results.values()):
                return results
            now = clock()
            if now >= deadline:
                return results
            # Never sleep past the deadline: the last probe runs at the
            # deadline, not an interval after it.
            budget.pause(min(budget.interval, deadline - now))

    def _authenticated_service_ready(
        self,
        service: str,
        container_port: int,
        node: DeploymentNodeRealization | None,
        env: EnvVars,
        identity: WazuhClusterIdentity,
    ) -> _ServiceObservation:
        """Probe one graph-owned Wazuh API with the configured credentials."""

        container = node.container_name if node is not None else None
        info: object = None
        if container:
            try:
                info = self.container_inspect(container)
            except (BackendTimeoutError, OSError):
                info = None
        port = _published_host_port(info, container_port)
        if port is None:
            return _ServiceObservation(
                False,
                f"{service} has no published host port for {container_port}/tcp",
                container,
            )
        url = f"https://localhost:{port}"
        if service == identity.indexer_service:
            probe = probe_indexer_api(url, env.indexer_username, env.indexer_password)
            if probe.ready:
                declared = _declared_indexer(node)
                facts = observe_indexer_declared_facts(
                    url,
                    env.indexer_username,
                    env.indexer_password,
                    declared,
                )
                failed = [fact for fact in facts if fact["status"] != "matched"]
                if failed:
                    return _ServiceObservation(
                        False,
                        f"{service} at {url} attestation failed: "
                        f"{failed[0]['failure_category']}",
                        container,
                        facts,
                    )
                facts = (
                    _fact_observation(
                        "api:authenticated", "authenticated", "authenticated", True, ""
                    ),
                    *facts,
                )
                return _ServiceObservation(
                    True, f"{service} at {url} ready", container, facts
                )
        else:
            probe = probe_manager_api(url, env.api_username, env.api_password)
            if probe.ready:
                expected = _declared_manager_components(node)
                facts = (
                    _fact_observation(
                        "api:authenticated", "authenticated", "authenticated", True, ""
                    ),
                    *(
                        _fact_observation(
                            f"component:{component}",
                            "running",
                            "running"
                            if component in probe.observed_components
                            else "missing",
                            component in probe.observed_components,
                            "declared-component-not-running",
                        )
                        for component in sorted(expected)
                    ),
                )
                failed = [fact for fact in facts if fact["status"] != "matched"]
                if failed:
                    return _ServiceObservation(
                        False,
                        f"{service} at {url} attestation failed: "
                        "declared components not running: "
                        + ", ".join(
                            fact["fact_id"].split(":", 1)[1] for fact in failed
                        ),
                        container,
                        facts,
                    )
                return _ServiceObservation(
                    True, f"{service} at {url} ready", container, facts
                )
        ready = probe.ready
        detail = probe.describe()
        if not ready:
            # Expected while the API warms up; only the deadline makes it terminal.
            log.debug("%s not ready yet: %s", service, detail)
        return _ServiceObservation(ready, f"{service} at {url} {detail}", container)


def _readiness_failure(
    observations: Mapping[str, _ServiceObservation],
    timeout: int,
) -> str | None:
    """Render the terminal reason for services still unready at the deadline."""

    failed = [
        observation
        for _service, observation in sorted(observations.items())
        if not observation.ready
    ]
    if not failed:
        return None
    reasons = "; ".join(observation.detail for observation in failed)
    logs = " and ".join(
        f"`aptl container logs {observation.container_name}`"
        for observation in failed
        if observation.container_name
    )
    action = f" Inspect {logs}." if logs else ""
    return (
        f"Authenticated Wazuh readiness validation failed after {timeout}s: "
        f"{reasons}.{action}"
    )


def _load_stateful_env(project_dir: Path) -> tuple[EnvVars | None, bool]:
    """Load typed credentials and report whether placeholders caused rejection."""

    env: EnvVars | None = None
    placeholder_input = False
    try:
        raw_env = load_dotenv(project_dir / ".env")
        placeholder_input = bool(find_placeholder_env_values(raw_env))
        if not placeholder_input:
            candidate = env_vars_from_dict(raw_env)
            if all(
                (
                    candidate.indexer_username,
                    candidate.indexer_password,
                    candidate.api_username,
                    candidate.api_password,
                )
            ):
                env = candidate
    except (OSError, ValueError):
        env = None
    return env, placeholder_input


def _stateful_services(
    realization: DeploymentRealizationSpec,
    identity: WazuhClusterIdentity,
) -> set[str]:
    """Return graph-owned Wazuh services requiring authenticated probes."""

    return {
        node.service_name
        for node in realization.nodes
        if node.service_name in identity.services
        and _declares_wazuh_native_service(node, identity)
    }


def _declares_wazuh_native_service(
    node: DeploymentNodeRealization, identity: WazuhClusterIdentity
) -> bool:
    """Return whether the admitted runtime authorizes a native Wazuh query."""

    runtime = node.runtime
    if runtime is None:
        return False
    if node.service_name == identity.indexer_service:
        return _declared_indexer(node) is not None
    if node.service_name == identity.manager_service:
        return any(
            str(
                getattr(
                    getattr(manager, "implementation", ""),
                    "value",
                    getattr(manager, "implementation", ""),
                )
            )
            == "wazuh"
            for manager in getattr(runtime, "security_monitoring_managers", ())
        )
    return False


def _declared_indexer(node: DeploymentNodeRealization | None) -> object | None:
    """Return the node's single declared OpenSearch datastore, if present."""

    runtime = node.runtime if node is not None else None
    stores = [
        store
        for store in getattr(runtime, "datastore_services", ())
        if str(
            getattr(getattr(store, "engine", ""), "value", getattr(store, "engine", ""))
        )
        in {"opensearch", "elasticsearch"}
    ]
    return stores[0] if len(stores) == 1 else None


def _declared_manager_components(
    node: DeploymentNodeRealization | None,
) -> frozenset[str]:
    """Return manager-owned enabled processes declared by the realization."""

    runtime = node.runtime if node is not None else None
    managers = [
        manager
        for manager in getattr(runtime, "security_monitoring_managers", ())
        if str(
            getattr(
                getattr(manager, "implementation", ""),
                "value",
                getattr(manager, "implementation", ""),
            )
        )
        == "wazuh"
    ]
    if len(managers) != 1:
        return frozenset()
    return frozenset(
        str(component.name)
        for component in getattr(managers[0], "components", ())
        if getattr(component, "enabled", False)
        and str(getattr(component, "name", "")).startswith("wazuh-")
    )


def observe_indexer_declared_facts(
    url: str,
    username: str,
    password: str,
    datastore: object | None,
) -> tuple[dict[str, str], ...]:
    """Compare bounded indexer readback with every declared native fact."""

    if datastore is None:
        return ()
    partitions = tuple(getattr(datastore, "partitions", ()) or ())
    templates = tuple(getattr(datastore, "templates", ()) or ())
    mappings = tuple(getattr(datastore, "mappings", ()) or ())
    # A declaration with no native subfacts still requires the authenticated
    # service probe above, but has nothing further to compare.
    if not any((partitions, templates, mappings)):
        return ()
    header = basic_auth_header(username, password)
    base = url.rstrip("/")
    if partitions:
        names = ",".join(str(item.name) for item in partitions)
        payload = curl_json(
            f"{base}/_cluster/state/metadata/{names}",
            auth_header=header,
            insecure=True,
            timeout=30,
        )
        indices = _index_metadata(payload)
        partition_facts = tuple(
            _partition_observation(item, indices.get(str(item.name)))
            for item in partitions
        )
    else:
        partition_facts = ()
    if templates:
        names = ",".join(str(item.name) for item in templates)
        payload = curl_json(
            f"{base}/_template/{names}",
            auth_header=header,
            insecure=True,
            timeout=30,
        )
        template_facts = tuple(
            _fact_observation(
                f"template:{item.name}",
                "present",
                "present"
                if isinstance(payload, Mapping) and str(item.name) in payload
                else "missing",
                isinstance(payload, Mapping) and str(item.name) in payload,
                "declared-template-missing",
            )
            for item in templates
        )
    else:
        template_facts = ()
    if mappings:
        names = ",".join(str(item.name) for item in mappings)
        payload = curl_json(
            f"{base}/{names}/_mapping",
            auth_header=header,
            insecure=True,
            timeout=30,
        )
        mapping_facts = tuple(
            _mapping_observation(
                item,
                payload.get(str(item.name)) if isinstance(payload, Mapping) else None,
            )
            for item in mappings
        )
    else:
        mapping_facts = ()
    return partition_facts + template_facts + mapping_facts


def _fact_observation(
    fact_id: str,
    expected: str,
    observed: str,
    matched: bool,
    failure_category: str,
) -> dict[str, str]:
    """Build one bounded, stable, secret-free declared-fact observation."""

    return {
        "fact_id": fact_id,
        "expected": expected,
        "observed": observed,
        "status": "matched" if matched else "failed",
        "failure_category": "" if matched else failure_category,
    }


def _partition_observation(declared: object, observed: object) -> dict[str, str]:
    expected = f"shards={declared.shard_count},replicas={declared.replica_count}"
    settings = observed.get("settings") if isinstance(observed, Mapping) else None
    index = settings.get("index") if isinstance(settings, Mapping) else None
    actual = (
        f"shards={index.get('number_of_shards')},replicas={index.get('number_of_replicas')}"
        if isinstance(index, Mapping)
        else "missing"
    )
    return _fact_observation(
        f"partition:{declared.name}",
        expected,
        actual,
        _partition_matches(declared, observed),
        "declared-partition-missing-or-mismatched",
    )


def _mapping_observation(declared: object, observed: object) -> dict[str, str]:
    expected_count = getattr(declared, "top_level_field_count", None)
    mappings = observed.get("mappings") if isinstance(observed, Mapping) else None
    properties = mappings.get("properties") if isinstance(mappings, Mapping) else None
    actual_count = len(properties) if isinstance(properties, Mapping) else None
    return _fact_observation(
        f"mapping:{declared.name}",
        "present" if expected_count is None else f"top-level-fields={expected_count}",
        "missing" if actual_count is None else f"top-level-fields={actual_count}",
        _mapping_matches(declared, observed),
        "declared-mapping-missing-or-mismatched",
    )


def declared_wazuh_fact_ids(node: object) -> frozenset[str]:
    """Return the exact native facts required by one declared Wazuh node."""

    name = getattr(node, "name", "")
    if name == "wazuh-indexer":
        store = _declared_indexer(node)
        if store is None:
            return frozenset()
        return frozenset(
            ["api:authenticated"]
            + [f"partition:{item.name}" for item in getattr(store, "partitions", ())]
            + [f"template:{item.name}" for item in getattr(store, "templates", ())]
            + [f"mapping:{item.name}" for item in getattr(store, "mappings", ())]
        )
    if name == "wazuh-manager":
        return frozenset(
            ["api:authenticated"]
            + [
                f"component:{component}"
                for component in _declared_manager_components(node)
            ]
        )
    return frozenset()


def declared_wazuh_facts_match(
    attestation: object, service: str | None, node: object | None = None
) -> bool:
    """Require matched structured observations, optionally for an exact declaration."""

    if not isinstance(attestation, Mapping) or not service:
        return False
    facts = attestation.get(service)
    if not isinstance(facts, (tuple, list)) or not facts:
        return False
    observed = {
        fact.get("fact_id")
        for fact in facts
        if isinstance(fact, Mapping) and fact.get("status") == "matched"
    }
    if len(observed) != len(facts):
        return False
    expected = declared_wazuh_fact_ids(node) if node is not None else observed
    return bool(expected) and observed == expected


def _index_metadata(payload: object) -> Mapping[str, object]:
    metadata = payload.get("metadata") if isinstance(payload, Mapping) else None
    indices = metadata.get("indices") if isinstance(metadata, Mapping) else None
    return indices if isinstance(indices, Mapping) else {}


def _partition_matches(declared: object, observed: object) -> bool:
    if not isinstance(observed, Mapping):
        return False
    settings = observed.get("settings")
    index = settings.get("index") if isinstance(settings, Mapping) else None
    if not isinstance(index, Mapping):
        return False
    return str(index.get("number_of_shards")) == str(declared.shard_count) and str(
        index.get("number_of_replicas")
    ) == str(declared.replica_count)


def _mapping_matches(declared: object, observed: object) -> bool:
    mappings = observed.get("mappings") if isinstance(observed, Mapping) else None
    properties = mappings.get("properties") if isinstance(mappings, Mapping) else None
    expected = getattr(declared, "top_level_field_count", None)
    return isinstance(properties, Mapping) and (
        expected is None or len(properties) == expected
    )


def _published_host_port(
    info: object, container_port: int, protocol: str = "tcp"
) -> int | None:
    """Read one TCP host binding from container inspect output."""

    port: int | None = None
    if isinstance(info, dict):
        network_settings = info.get("NetworkSettings")
        ports = (
            network_settings.get("Ports")
            if isinstance(network_settings, dict)
            else None
        )
        bindings = (
            ports.get(f"{container_port}/{protocol}")
            if isinstance(ports, dict)
            else None
        )
        binding = bindings[0] if isinstance(bindings, list) and bindings else None
        value = binding.get("HostPort") if isinstance(binding, dict) else None
        try:
            candidate = int(value)
        except (TypeError, ValueError):
            candidate = 0
        if 1 <= candidate <= 65535:
            port = candidate
    return port


def _rendered_manager_config_container(
    realization: DeploymentRealizationSpec,
    identity: WazuhClusterIdentity,
) -> str | None:
    """Return the manager container when the graph declares rendered config."""

    manager_consumers = {
        consumer.target_address
        for artifact in realization.generated_artifacts
        if artifact.provenance in WAZUH_MANAGER_CONFIG_PROVENANCES
        for consumer in artifact.consumers
        if consumer.service_name == identity.manager_service
    }
    return next(
        (
            node.container_name
            for node in realization.nodes
            if node.address in manager_consumers and node.container_name
        ),
        None,
    )
