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
from collections.abc import Callable
from dataclasses import dataclass

from aptl.core.deployment._wazuh_identity import (
    WazuhClusterIdentity,
    wazuh_cluster_identity,
)
from aptl.core.deployment._compose_stateful_constants import (
    WAZUH_MANAGER_CONFIG_PROVENANCES,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment._wazuh_attestation import (
    AUTHENTICATED_FACT_ID,
    declared_indexer as _declared_indexer,
    declared_manager_components as _declared_manager_components,
    declared_wazuh_fact_ids,
    declared_wazuh_facts_match,
    declares_wazuh_native_service as _declares_wazuh_native_service,
    fact_observation as _fact_observation,
    load_stateful_env as _load_stateful_env,
    observe_indexer_declared_facts,
    readiness_failure as _readiness_failure,
)
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.env import EnvVars
from aptl.core.lab_types import LabResult
from aptl.core.services import probe_indexer_api, probe_manager_api
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


def _authenticated_fact() -> dict[str, str]:
    """Return the shared successful authenticated-API observation."""

    return _fact_observation(
        AUTHENTICATED_FACT_ID,
        "authenticated",
        "authenticated",
        True,
        "",
    )


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
            return self._indexer_service_observation(service, url, container, node, env)
        return self._manager_service_observation(service, url, container, node, env)

    @staticmethod
    def _unready_observation(
        service: str, url: str, container: str | None, probe: object
    ) -> _ServiceObservation:
        """Project one classified API probe that has not become ready yet."""

        detail = probe.describe()
        log.debug("%s not ready yet: %s", service, detail)
        return _ServiceObservation(False, f"{service} at {url} {detail}", container)

    def _indexer_service_observation(
        self,
        service: str,
        url: str,
        container: str | None,
        node: DeploymentNodeRealization | None,
        env: EnvVars,
    ) -> _ServiceObservation:
        """Attest the declared indexer service and its native facts."""

        probe = probe_indexer_api(url, env.indexer_username, env.indexer_password)
        if not probe.ready:
            return self._unready_observation(service, url, container, probe)
        facts = observe_indexer_declared_facts(
            url,
            env.indexer_username,
            env.indexer_password,
            _declared_indexer(node),
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
        return _ServiceObservation(
            True,
            f"{service} at {url} ready",
            container,
            (_authenticated_fact(), *facts),
        )

    def _manager_service_observation(
        self,
        service: str,
        url: str,
        container: str | None,
        node: DeploymentNodeRealization | None,
        env: EnvVars,
    ) -> _ServiceObservation:
        """Attest the declared manager service and enabled components."""

        probe = probe_manager_api(url, env.api_username, env.api_password)
        if not probe.ready:
            return self._unready_observation(service, url, container, probe)
        facts = (
            _authenticated_fact(),
            *(
                _fact_observation(
                    f"component:{component}",
                    "running",
                    "running" if component in probe.observed_components else "missing",
                    component in probe.observed_components,
                    "declared-component-not-running",
                )
                for component in sorted(_declared_manager_components(node))
            ),
        )
        failed = [fact for fact in facts if fact["status"] != "matched"]
        if failed:
            missing = ", ".join(fact["fact_id"].split(":", 1)[1] for fact in failed)
            return _ServiceObservation(
                False,
                f"{service} at {url} attestation failed: "
                f"declared components not running: {missing}",
                container,
                facts,
            )
        return _ServiceObservation(True, f"{service} at {url} ready", container, facts)


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
