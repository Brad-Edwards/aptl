"""Issue #875: derive the graph-owned Wazuh cluster by declared semantics.

An in-tree scenario and an env-pack realize the same SIEM under different
Compose service keys (``wazuh.manager`` vs ``wazuh-manager``). Keying the
complete manager/indexer definitions off a hardcoded name silently skips the
whole cluster for the pack, so the indexer boots on image defaults and
crash-loops. Identity must come from what the node declares.
"""

from __future__ import annotations

from raes.runtime_configuration import RuntimeConfiguration

from aptl.core.deployment._wazuh_identity import wazuh_cluster_identity
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)


def _manager_runtime() -> RuntimeConfiguration:
    return RuntimeConfiguration.model_validate(
        {
            "security_monitoring_managers": [
                {
                    "security_monitoring_manager_id": "wazuh-manager",
                    "implementation": "wazuh",
                    "manager_kind": "siem",
                }
            ]
        }
    )


def _opensearch_runtime() -> RuntimeConfiguration:
    return RuntimeConfiguration.model_validate(
        {
            "datastore_services": [
                {
                    "datastore_service_id": "wazuh-indexer",
                    "engine": "opensearch",
                    "data_model": "search_index",
                    "partitions": [
                        {
                            "partition_id": "alerts",
                            "kind": "index",
                            "name": "wazuh-alerts",
                            "shard_count": 1,
                            "replica_count": 0,
                        }
                    ],
                    "mappings": [
                        {
                            "mapping_id": "alerts-mapping",
                            "name": "wazuh-alerts",
                            "partition_ref": "alerts",
                            "top_level_field_count": 1,
                            "description": "Alert mapping.",
                        }
                    ],
                }
            ]
        }
    )


def _cluster_spec(indexer_service: str) -> DeploymentRealizationSpec:
    """A manager + its opensearch indexer, realized under env-pack names."""

    return DeploymentRealizationSpec(
        profiles=("wazuh",),
        nodes=(
            DeploymentNodeRealization(
                address="provision.node.wazuh-manager",
                name="wazuh-manager",
                service_name="wazuh-manager",
                container_name="aptl-wazuh-manager",
                networks=(),
                runtime=_manager_runtime(),
                ordering_dependencies=("provision.node.wazuh-indexer",),
            ),
            DeploymentNodeRealization(
                address="provision.node.wazuh-indexer",
                name="wazuh-indexer",
                service_name=indexer_service,
                container_name="aptl-wazuh-indexer",
                networks=(),
                runtime=_opensearch_runtime(),
            ),
            # A second OpenSearch datastore the manager does NOT order itself
            # after: it must not be mistaken for the SIEM indexer.
            DeploymentNodeRealization(
                address="provision.node.shuffle-opensearch",
                name="shuffle-opensearch",
                service_name="shuffle-opensearch",
                container_name="aptl-shuffle-opensearch",
                networks=(),
                runtime=_opensearch_runtime(),
            ),
        ),
        networks=(),
    )


def test_identity_is_derived_from_declared_semantics_not_the_service_name():
    """Hyphenated env-pack names resolve via the declared families."""

    identity = wazuh_cluster_identity(_cluster_spec("wazuh-indexer"))

    assert identity.manager_service == "wazuh-manager"
    assert identity.indexer_service == "wazuh-indexer"
    assert identity.services == frozenset({"wazuh-manager", "wazuh-indexer"})


def test_indexer_disambiguated_from_other_opensearch_datastores():
    """Only the OpenSearch datastore the manager depends on is the indexer."""

    identity = wazuh_cluster_identity(_cluster_spec("wazuh-indexer"))
    assert identity.indexer_service != "shuffle-opensearch"


def test_name_fallback_keeps_canonically_named_specs_working():
    """A spec that names services canonically but declares no families resolves."""

    spec = DeploymentRealizationSpec(
        profiles=("wazuh",),
        nodes=(
            DeploymentNodeRealization(
                address="provision.node.wazuh-manager",
                name="wazuh-manager",
                service_name="wazuh.manager",
                container_name="aptl-wazuh-manager",
                networks=(),
            ),
            DeploymentNodeRealization(
                address="provision.node.wazuh-indexer",
                name="wazuh-indexer",
                service_name="wazuh.indexer",
                container_name="aptl-wazuh-indexer",
                networks=(),
            ),
        ),
        networks=(),
    )

    identity = wazuh_cluster_identity(spec)
    assert identity.manager_service == "wazuh.manager"
    assert identity.indexer_service == "wazuh.indexer"


def test_no_wazuh_cluster_yields_empty_identity():
    spec = DeploymentRealizationSpec(profiles=(), nodes=(), networks=())
    identity = wazuh_cluster_identity(spec)
    assert identity.services == frozenset()
    assert identity.manager_service is None
    assert identity.indexer_service is None
