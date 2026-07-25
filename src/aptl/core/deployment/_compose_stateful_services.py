"""Complete Compose service definitions for graph-owned Wazuh services."""

from __future__ import annotations

from pathlib import Path

import yaml

from aptl.core.deployment._compose_realization_networks import _compose_network_key
from aptl.core.deployment._compose_stateful_constants import (
    OWNED_WAZUH_SERVICES,
    WAZUH_INDEXER_SERVICE,
    WAZUH_MANAGER_SERVICE,
)
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)


class OverrideMapping(dict):
    """A complete Compose service definition that replaces the base service."""


class StatefulDumper(yaml.SafeDumper):
    """Safe YAML dumper with Compose's explicit replacement tag."""


StatefulDumper.add_representer(
    OverrideMapping,
    lambda dumper, value: dumper.represent_mapping("!override", value),
)


def wazuh_service_definitions(
    project_dir: Path,
    realization: DeploymentRealizationSpec,
) -> dict[str, dict[str, object]]:
    """Build complete manager/indexer definitions from the admitted DTO graph."""

    owned = _stateful_consumers(realization) & OWNED_WAZUH_SERVICES
    if not owned:
        return {}
    nodes = {node.service_name: node for node in realization.nodes if node.service_name}
    images = {image.service_name: image.image_ref for image in realization.images}
    services: dict[str, dict[str, object]] = {}
    if WAZUH_INDEXER_SERVICE in owned:
        services[WAZUH_INDEXER_SERVICE] = _indexer_definition(
            project_dir,
            nodes[WAZUH_INDEXER_SERVICE],
            images[WAZUH_INDEXER_SERVICE],
        )
    if WAZUH_MANAGER_SERVICE in owned:
        services[WAZUH_MANAGER_SERVICE] = _manager_definition(
            project_dir,
            nodes[WAZUH_MANAGER_SERVICE],
            images[WAZUH_MANAGER_SERVICE],
            realization.nodes,
        )
    return services


def _stateful_consumers(realization: DeploymentRealizationSpec) -> set[str]:
    """Return service names consuming any stateful resource."""

    return {
        consumer.service_name
        for resource in (
            *realization.generated_artifacts,
            *realization.persistent_volumes,
        )
        for consumer in resource.consumers
    }


def _indexer_definition(
    project_dir: Path,
    node: DeploymentNodeRealization,
    image_ref: str,
) -> OverrideMapping:
    """Return the complete graph-owned Wazuh Indexer service definition."""

    return OverrideMapping(
        {
            "profiles": ["wazuh"],
            "container_name": node.container_name,
            "hostname": WAZUH_INDEXER_SERVICE,
            "image": image_ref,
            "restart": "always",
            "ports": ["127.0.0.1:${APTL_HP_WAZUH_INDEXER_9200:-9200}:9200"],
            "environment": ["OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"],
            "ulimits": {
                "memlock": {"soft": -1, "hard": -1},
                "nofile": {"soft": 65536, "hard": 65536},
            },
            "volumes": [
                _bind(
                    project_dir,
                    "config/wazuh_indexer/wazuh.indexer.yml",
                    "/usr/share/wazuh-indexer/opensearch.yml",
                ),
                _bind(
                    project_dir,
                    "config/wazuh_indexer/internal_users.yml",
                    "/usr/share/wazuh-indexer/opensearch-security/internal_users.yml",
                ),
            ],
            "healthcheck": {
                "test": [
                    "CMD-SHELL",
                    "curl -ks https://localhost:9200 || exit 1",
                ],
                "interval": "30s",
                "timeout": "10s",
                "retries": 10,
                "start_period": "180s",
            },
            "deploy": {"resources": {"limits": {"memory": "2g"}}},
            "networks": _service_networks(node),
        }
    )


def _manager_definition(
    project_dir: Path,
    node: DeploymentNodeRealization,
    image_ref: str,
    nodes: tuple[DeploymentNodeRealization, ...],
) -> OverrideMapping:
    """Return the complete graph-owned Wazuh Manager service definition."""

    return OverrideMapping(
        {
            "profiles": ["wazuh"],
            "container_name": node.container_name,
            "hostname": WAZUH_MANAGER_SERVICE,
            "image": image_ref,
            "restart": "always",
            "ports": _manager_ports(node),
            "environment": [
                f"INDEXER_URL=https://{WAZUH_INDEXER_SERVICE}:9200",
                "INDEXER_USERNAME=${INDEXER_USERNAME}",
                "INDEXER_PASSWORD=${INDEXER_PASSWORD}",
                "FILEBEAT_SSL_VERIFICATION_MODE=full",
                "SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/wazuh/root-ca-manager.pem",
                "SSL_CERTIFICATE=/etc/ssl/wazuh/wazuh.manager.pem",
                "SSL_KEY=/etc/ssl/wazuh/wazuh.manager-key.pem",
                "API_USERNAME=${API_USERNAME}",
                "API_PASSWORD=${API_PASSWORD}",
            ],
            "ulimits": {
                "memlock": {"soft": -1, "hard": -1},
                "nofile": {"soft": 655360, "hard": 655360},
            },
            "volumes": [
                _bind(
                    project_dir,
                    "config/wazuh_cluster/filebeat_wazuh_module.yml",
                    "/run/filebeat-override.yml",
                ),
                _bind(
                    project_dir,
                    "config/wazuh_cluster/patch-rule-path.py",
                    "/docker-entrypoint-initdb.d/patch-rule-path.py",
                ),
                # Custom detection content the manager loads through its
                # rendered ossec.conf (<rule_include>/<decoder_dir>) plus the
                # Shuffle SOAR integration. These are static, checked-in,
                # read-only files -- the same category as the two support
                # binds above -- so the graph-owned definition must carry them
                # here. Because this override replaces the base compose service
                # wholesale, omitting them drops the binds entirely and every
                # custom rule silently fails to load ("Could not open file
                # 'etc/rules/webapp_rules.xml'"), disabling webapp/AD/database/
                # Suricata detection and the Wazuh->Shuffle hand-off. Targets
                # sit under the wazuh-manager-etc volume (/var/ossec/etc);
                # Docker mounts by path depth, so the more-specific bind
                # overlays the volume and the files appear.
                _bind(
                    project_dir,
                    "config/wazuh_cluster/webapp_rules.xml",
                    "/var/ossec/etc/rules/webapp_rules.xml",
                ),
                _bind(
                    project_dir,
                    "config/wazuh_cluster/ad_rules.xml",
                    "/var/ossec/etc/rules/ad_rules.xml",
                ),
                _bind(
                    project_dir,
                    "config/wazuh_cluster/suricata_rules.xml",
                    "/var/ossec/etc/rules/suricata_rules.xml",
                ),
                _bind(
                    project_dir,
                    "config/wazuh_cluster/database_rules.xml",
                    "/var/ossec/etc/rules/database_rules.xml",
                ),
                _bind(
                    project_dir,
                    "config/wazuh_cluster/falco_rules.xml",
                    "/var/ossec/etc/rules/falco_rules.xml",
                ),
                _bind(
                    project_dir,
                    "config/wazuh_cluster/samba_decoders.xml",
                    "/var/ossec/etc/decoders/samba_decoders.xml",
                ),
                _bind(
                    project_dir,
                    "config/wazuh_cluster/postgresql_decoders.xml",
                    "/var/ossec/etc/decoders/postgresql_decoders.xml",
                ),
                _bind(
                    project_dir,
                    "config/wazuh_cluster/custom-shuffle",
                    "/var/ossec/integrations/custom-shuffle",
                ),
            ],
            "entrypoint": ["/bin/bash", "-c", _manager_entrypoint()],
            "healthcheck": {
                "test": [
                    "CMD-SHELL",
                    "curl -ks https://localhost:55000 || exit 1",
                ],
                "interval": "30s",
                "timeout": "10s",
                "retries": 5,
                "start_period": "120s",
            },
            "deploy": {"resources": {"limits": {"memory": "1g"}}},
            "depends_on": _service_dependencies(node, nodes),
            "networks": _service_networks(node),
        }
    )


def _manager_entrypoint() -> str:
    """Return the manager setup command carried by its complete definition."""

    return (
        "cp /run/filebeat-override.yml /etc/filebeat/filebeat.yml && "
        "chown root:root /etc/filebeat/filebeat.yml && "
        "python3 /docker-entrypoint-initdb.d/patch-rule-path.py "
        "2>/dev/null; exec /init"
    )


def _bind(project_dir: Path, source: str, target: str) -> dict[str, object]:
    """Return a read-only, project-rooted long-form bind mount."""

    return {
        "type": "bind",
        "source": str(project_dir.resolve() / source),
        "target": target,
        "read_only": True,
    }


def _service_networks(node: DeploymentNodeRealization) -> dict[str, object]:
    """Return Compose network attachments for one admitted node."""

    return {
        _compose_network_key(attachment.network): (
            {"ipv4_address": attachment.ipv4_address}
            if attachment.ipv4_address
            else None
        )
        for attachment in node.network_attachments
    }


def _service_dependencies(
    node: DeploymentNodeRealization,
    nodes: tuple[DeploymentNodeRealization, ...],
) -> dict[str, dict[str, str]]:
    """Translate node ordering addresses into healthy service dependencies."""

    services_by_address = {
        candidate.address: candidate.service_name
        for candidate in nodes
        if candidate.service_name
    }
    return {
        service: {"condition": "service_healthy"}
        for address in node.ordering_dependencies
        if (service := services_by_address.get(address))
    }


def _manager_ports(node: DeploymentNodeRealization) -> list[str]:
    """Return loopback host bindings for declared manager service ports."""

    declared = {(service.port, service.protocol) for service in node.services}
    env_names = {
        (1514, "tcp"): "APTL_HP_WAZUH_MANAGER_1514",
        (1515, "tcp"): "APTL_HP_WAZUH_MANAGER_1515",
        (514, "udp"): "APTL_HP_WAZUH_MANAGER_514",
        (55000, "tcp"): "APTL_HP_WAZUH_MANAGER_55000",
    }
    return [
        (
            f"127.0.0.1:${{{env_names[(port, protocol)]}:-{port}}}:{port}"
            + ("/udp" if protocol == "udp" else "")
        )
        for port, protocol in sorted(declared)
        if (port, protocol) in env_names
    ]
