"""Identify the graph-owned Wazuh cluster nodes by declared semantics (#875).

The complete manager/indexer Compose definitions in
``_compose_stateful_services`` are graph-owned: APTL, not the SDL, carries the
wazuh-appliance-specific run shape (custom entrypoint, the rule/decoder bind
overlays, operator-secret env, healthchecks). Which realized nodes those
definitions apply to must come from *what the node declares*, not a hardcoded
service name: an in-tree scenario and an env-pack realize the same SIEM under
different service names (``wazuh.manager`` vs ``wazuh-manager``), so keying off a
fixed name silently skips the whole cluster for the pack.

The manager is the node whose runtime declares a ``security_monitoring_managers``
entry implemented by wazuh; the indexer is the OpenSearch datastore the manager
orders itself after (disambiguated from other OpenSearch datastores, e.g.
Shuffle's, by that dependency edge). A name-based fallback to the canonical
appliance names keeps older specs and unit fixtures — which name the services
canonically but may not carry the semantic families — working unchanged.

The canonical appliance DNS names (``wazuh.indexer``/``wazuh.manager``) stay
fixed regardless of the Compose service key: the appliance's own bundled config
(filebeat ``output.elasticsearch.hosts``, the dashboard API URL) and its
certificates are authored against them. When the realized service key differs,
the cluster definitions publish the canonical name as a network alias so those
references resolve.
"""

from __future__ import annotations

from dataclasses import dataclass

from aptl.core.deployment._compose_stateful_constants import (
    WAZUH_INDEXER_SERVICE,
    WAZUH_MANAGER_SERVICE,
)
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)

_WAZUH_MANAGER_IMPLEMENTATION = "wazuh"
_OPENSEARCH_ENGINES = frozenset({"opensearch", "elasticsearch"})


@dataclass(frozen=True)
class WazuhClusterIdentity:
    """The realized service keys and canonical DNS names of the Wazuh cluster."""

    manager_service: str | None
    indexer_service: str | None
    manager_dns: str = WAZUH_MANAGER_SERVICE
    indexer_dns: str = WAZUH_INDEXER_SERVICE

    @property
    def services(self) -> frozenset[str]:
        """Return the realized Wazuh service keys present in this realization."""

        return frozenset(
            service
            for service in (self.manager_service, self.indexer_service)
            if service
        )

    def dns_for(self, service: str) -> str | None:
        """Return the canonical appliance DNS name for a realized service key."""

        if service == self.manager_service:
            return self.manager_dns
        if service == self.indexer_service:
            return self.indexer_dns
        return None


def _is_wazuh_manager(node: DeploymentNodeRealization) -> bool:
    """Return whether a node declares a wazuh-implemented monitoring manager."""

    runtime = node.runtime
    managers = getattr(runtime, "security_monitoring_managers", ()) if runtime else ()
    return any(
        getattr(manager, "implementation", None) == _WAZUH_MANAGER_IMPLEMENTATION
        for manager in managers
    )


def _has_opensearch_datastore(node: DeploymentNodeRealization) -> bool:
    """Return whether a node declares an OpenSearch/Elasticsearch datastore."""

    runtime = node.runtime
    stores = getattr(runtime, "datastore_services", ()) if runtime else ()
    return any(getattr(store, "engine", None) in _OPENSEARCH_ENGINES for store in stores)


def wazuh_cluster_identity(
    realization: DeploymentRealizationSpec,
) -> WazuhClusterIdentity:
    """Return the realized Wazuh manager/indexer service keys, or ``None`` each.

    Derivation is semantic first (declared families), with a fallback to the
    canonical appliance service names so specs that predate the semantic
    declaration still resolve.
    """

    nodes = [node for node in realization.nodes if node.service_name]
    by_name = {node.service_name: node for node in nodes}

    manager_node = next((node for node in nodes if _is_wazuh_manager(node)), None)
    if manager_node is None:
        manager_node = by_name.get(WAZUH_MANAGER_SERVICE)
    manager_service = manager_node.service_name if manager_node else None

    indexer_service: str | None = None
    if manager_node is not None:
        dependencies = set(manager_node.ordering_dependencies)
        indexer_node = next(
            (
                node
                for node in nodes
                if node.address in dependencies and _has_opensearch_datastore(node)
            ),
            None,
        )
        if indexer_node is not None:
            indexer_service = indexer_node.service_name
    if indexer_service is None and WAZUH_INDEXER_SERVICE in by_name:
        indexer_service = WAZUH_INDEXER_SERVICE

    return WazuhClusterIdentity(
        manager_service=manager_service, indexer_service=indexer_service
    )
