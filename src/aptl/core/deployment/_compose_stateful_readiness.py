"""Authenticated readiness for realized stateful services (issue #875).

Split out of ``_compose_stateful_realization.py`` (module-length budget): a
container reporting healthy only proves its port listens, so a realization is
not finished until the graph-owned Wazuh APIs actually accept the configured
credentials. This module owns that observation -- the credential load, the
published-port lookup, and the poll loop that waits out the initialization
window without ever letting a genuinely bad credential pass.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from aptl.core.deployment._wazuh_identity import (
    WazuhClusterIdentity,
    wazuh_cluster_identity,
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
from aptl.core.services import check_indexer_ready, check_manager_api_ready

# Budget for authenticated Wazuh readiness after container health settles. The
# indexer's security index and the manager API keep initializing past the point
# the healthcheck first reports healthy, so this polls rather than probing once.
# 300s is a generous margin over the observed few-minutes gap on a loaded host;
# a genuinely bad credential still fails closed after the budget (issue #875).
_AUTHENTICATED_READINESS_TIMEOUT = 300
_AUTHENTICATED_READINESS_INTERVAL = 5


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
        """Return non-secret authenticated readiness observed this realization."""

        return dict(getattr(self, "_stateful_authenticated_readiness", {}))

    def _verify_stateful_authenticated_readiness(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Authenticate to realized Wazuh APIs after container health settles."""

        identity = wazuh_cluster_identity(realization)
        services = {
            consumer.service_name
            for artifact in realization.generated_artifacts
            for consumer in artifact.consumers
            if consumer.service_name in identity.services
        }
        results: dict[str, bool] = {}
        env: EnvVars | None = None
        if services:
            env, _placeholder_input = _load_stateful_env(self._project_dir)
        failure: LabResult | None = None
        if services and env is None:
            failure = LabResult(
                success=False,
                error="Authenticated Wazuh readiness credentials are unavailable.",
            )
        elif services and env is not None:
            nodes = {node.service_name: node for node in realization.nodes}
            results = self._authenticated_readiness_results(
                services, nodes, env, identity
            )
        self._stateful_authenticated_readiness = results
        if failure is None and results and not all(results.values()):
            failure = LabResult(
                success=False,
                error="Authenticated Wazuh readiness validation failed.",
            )
        return failure

    def _authenticated_readiness_results(
        self,
        services: set[str],
        nodes: dict[str | None, DeploymentNodeRealization],
        env: EnvVars,
        identity: WazuhClusterIdentity,
        polling: ReadinessPolling | None = None,
    ) -> dict[str, bool]:
        """Poll authenticated readiness for each Wazuh service until ready.

        A container reports healthy once its port listens, but accepting
        credentials lags that: the indexer's security index (loaded by
        securityadmin from internal_users.yml) and the manager API finish
        initializing seconds-to-minutes after the healthcheck first passes. A
        single probe right after health-settle races that window and sees a
        transient 401. Poll on a generous budget so a genuinely misconfigured
        credential still fails closed, just after the budget rather than before
        it (issue #875).
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
        while True:
            results = {
                service: self._authenticated_service_ready(
                    service, port, nodes.get(service), env, identity
                )
                for service, port in checks
            }
            if all(results.values()) or clock() >= deadline:
                return results
            budget.pause(budget.interval)

    def _authenticated_service_ready(
        self,
        service: str,
        container_port: int,
        node: DeploymentNodeRealization | None,
        env: EnvVars,
        identity: WazuhClusterIdentity,
    ) -> bool:
        """Probe one graph-owned Wazuh API with the configured credentials."""

        info: object = None
        if node is not None and node.container_name:
            try:
                info = self.container_inspect(node.container_name)
            except (BackendTimeoutError, OSError):
                info = None
        port = _published_host_port(info, container_port)
        ready = False
        if port is not None:
            url = f"https://localhost:{port}"
            if service == identity.indexer_service:
                ready = check_indexer_ready(
                    url,
                    env.indexer_username,
                    env.indexer_password,
                )
            else:
                ready = check_manager_api_ready(
                    url,
                    env.api_username,
                    env.api_password,
                )
        return ready


def _load_stateful_env(project_dir: Path) -> tuple[EnvVars | None, bool]:
    """Load typed credentials and report whether placeholders caused rejection."""

    env: EnvVars | None = None
    placeholder_input = False
    try:
        raw_env = load_dotenv(project_dir / ".env")
        placeholder_input = bool(find_placeholder_env_values(raw_env))
        if not placeholder_input:
            env = env_vars_from_dict(raw_env)
    except (OSError, ValueError):
        env = None
    return env, placeholder_input


def _published_host_port(info: object, container_port: int) -> int | None:
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
            ports.get(f"{container_port}/tcp") if isinstance(ports, dict) else None
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
