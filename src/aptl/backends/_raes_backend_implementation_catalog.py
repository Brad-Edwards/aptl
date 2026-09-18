"""Immutable semantic implementation profile catalog for APTL's backend.

These are backend choices, not scenario declarations.  A profile is eligible
only when the planned node carries the matching portable runtime semantics;
the realization adapter separately checks that every selected concern is open
before using it.
"""

from __future__ import annotations

from aptl.backends._raes_backend_implementation_types import (
    BackendBaseSelection,
    BackendImplementationProfile,
    SemanticRuntimeSelector,
    environment as _environment,
    published_port as _port,
    variable as _variable,
)

_HALF_GIB_JVM_OPTIONS = "-Xms512m -Xmx512m"


BACKEND_IMPLEMENTATION_PROFILES = (
    BackendImplementationProfile(
        profile_id="wazuh-manager-4.12",
        selector=SemanticRuntimeSelector(
            "security_monitoring_managers", "implementation", "wazuh", "4.12.0"
        ),
        source_name="wazuh/wazuh-manager",
        source_version="4.12.0",
        image_ref=(
            "wazuh/wazuh-manager@sha256:"
            "dea2fa1e6d5062147b6a85b241f5f501c5f1ba4b817d12bda06f7870a89ad561"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("INDEXER_URL", "https://wazuh.indexer:9200"),
                _variable(
                    "INDEXER_USERNAME",
                    classification="operator_secret",
                    provenance="operator",
                ),
                _variable(
                    "INDEXER_PASSWORD",
                    classification="operator_secret",
                    provenance="operator",
                ),
                _variable("FILEBEAT_SSL_VERIFICATION_MODE", "full"),
                _variable(
                    "SSL_CERTIFICATE_AUTHORITIES",
                    "/etc/ssl/wazuh/root-ca-manager.pem",
                ),
                _variable("SSL_CERTIFICATE", "/etc/ssl/wazuh/wazuh.manager.pem"),
                _variable("SSL_KEY", "/etc/ssl/wazuh/wazuh.manager-key.pem"),
                _variable(
                    "API_USERNAME",
                    classification="operator_secret",
                    provenance="operator",
                ),
                _variable(
                    "API_PASSWORD",
                    classification="operator_secret",
                    provenance="operator",
                ),
            ),
            "published-ports": [
                _port(1514, 1514),
                _port(1515, 1515),
                _port(514, 514, "udp"),
                _port(55000, 55000),
            ],
        },
    ),
    BackendImplementationProfile(
        profile_id="wazuh-indexer-4.12",
        selector=SemanticRuntimeSelector(
            "datastore_services", "engine", "opensearch", "4.12.0"
        ),
        source_name="wazuh/wazuh-indexer",
        source_version="4.12.0",
        image_ref=(
            "wazuh/wazuh-indexer@sha256:"
            "3691b3b27658695aad0c6879b412a001caf233ebbc1a5ba15647053aa03a2299"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("OPENSEARCH_JAVA_OPTS", "-Xms1g -Xmx1g")
            ),
            "published-ports": [_port(9200, 9200)],
        },
    ),
    BackendImplementationProfile(
        profile_id="wazuh-dashboard-4.12",
        selector=SemanticRuntimeSelector(
            "platform_applications", "product", "Wazuh Dashboard", "4.12.0"
        ),
        source_name="wazuh/wazuh-dashboard",
        source_version="4.12.0",
        image_ref=(
            "wazuh/wazuh-dashboard@sha256:"
            "8f5b50fde67a0b1c4d2321aa26b12bbc5cef21269cf4f6225746f0b946458bd7"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("INDEXER_USERNAME", "admin"),
                _variable(
                    "INDEXER_PASSWORD",
                    "SecretPassword",
                    classification="secret_fixture",
                ),
                _variable("DASHBOARD_USERNAME", "kibanaserver"),
                _variable(
                    "DASHBOARD_PASSWORD",
                    "kibanaserver",
                    classification="secret_fixture",
                ),
                _variable("API_USERNAME", "wazuh-wui"),
                _variable(
                    "API_PASSWORD", "WazuhPass123!", classification="secret_fixture"
                ),
                _variable("WAZUH_API_URL", "https://wazuh.manager"),
            ),
            "published-ports": [_port(5601, 443)],
        },
    ),
    BackendImplementationProfile(
        profile_id="suricata-7",
        selector=SemanticRuntimeSelector(
            "network_detection_engines", "implementation", "suricata", "7.0"
        ),
        source_name="aptl/suricata-wazuh-agent",
        source_version="7.0",
        image_ref="aptl/suricata-wazuh-agent:latest",
        image_mode="build",
        dockerfile_relpath="containers/suricata-wazuh-agent/Dockerfile",
        context_relpath=".",
        runtime_selections={
            "runtime-container-entrypoint": [
                "/bin/sh",
                "-c",
                "exec suricata -c /etc/suricata/suricata.yaml --pcap=any",
            ],
            "linux-capabilities": {
                "add": ["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_NICE"]
            },
        },
    ),
    BackendImplementationProfile(
        profile_id="misp-2.5.44",
        selector=SemanticRuntimeSelector(
            "platform_applications", "product", "MISP", "2.5.44"
        ),
        source_name="ghcr.io/misp/misp-docker/misp-core",
        source_version="2.5.44",
        image_ref=(
            "ghcr.io/misp/misp-docker/misp-core@sha256:"
            "0eaa4e423d5cd965b7b76aa5665e81d5c05a35bc46a4ffec2ca52e0cfe627e86"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("MYSQL_HOST", "misp-db"),
                _variable("MYSQL_DATABASE", "misp"),
                _variable("MYSQL_USER", "misp"),
                _variable(
                    "MYSQL_PASSWORD",
                    "misp_db_password",
                    classification="secret_fixture",
                ),
                _variable("REDIS_HOST", "misp-redis"),
                _variable("BASE_URL", "https://localhost"),
                _variable("ADMIN_EMAIL", "admin@admin.test"),
                _variable("ADMIN_PASSWORD", "admin", classification="secret_fixture"),
                _variable(
                    "ADMIN_KEY",
                    classification="operator_secret",
                    provenance="operator",
                ),
            ),
            "published-ports": [_port(443, 8443)],
        },
    ),
    BackendImplementationProfile(
        profile_id="mariadb-10.11",
        selector=SemanticRuntimeSelector(
            "database_services", "engine", "mariadb", "10.11"
        ),
        source_name="mariadb",
        source_version="10.11",
        image_ref=(
            "mariadb@sha256:"
            "be981e4113326ada8d6004174dd09eeaefc03094037f811182a52d4f2e737350"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("MYSQL_DATABASE", "misp"),
                _variable("MYSQL_USER", "misp"),
                _variable(
                    "MYSQL_PASSWORD",
                    "misp_db_password",
                    classification="secret_fixture",
                ),
                _variable(
                    "MYSQL_ROOT_PASSWORD",
                    "misp_root_password",
                    classification="secret_fixture",
                ),
            )
        },
    ),
    BackendImplementationProfile(
        profile_id="redis-7",
        selector=SemanticRuntimeSelector("datastore_services", "engine", "redis", "7"),
        source_name="redis",
        source_version="7",
        image_ref=(
            "redis@sha256:"
            "6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
        ),
    ),
    BackendImplementationProfile(
        profile_id="thehive-5.4",
        selector=SemanticRuntimeSelector(
            "platform_applications", "product", "TheHive", "5.4"
        ),
        source_name="strangebee/thehive",
        source_version="5.4",
        image_ref=(
            "strangebee/thehive@sha256:"
            "ba3212a89be79de6ec8e6e66b84f3c0801c3b8d726aacc767ad6257030df7a13"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("JVM_OPTS", _HALF_GIB_JVM_OPTIONS),
                _variable(
                    "TH_SECRET",
                    "aptl-thehive-lab-secret-key-2024-purple",
                    classification="secret_fixture",
                ),
                {
                    "name": "TH_CORTEX_KEYS",
                    "value_from": {
                        "generated_artifact": "cortex-service-credentials",
                        "output": "connector-api-key",
                    },
                    "value_classification": "redacted",
                    "provenance": "runtime",
                },
            ),
            "runtime-container-command": [
                "--cql-hostnames",
                "thehive-cassandra",
                "--index-backend",
                "elasticsearch",
                "--es-hostnames",
                "thehive-es",
                "--cortex-proto",
                "http",
                "--cortex-hostnames",
                "cortex",
                "--cortex-port",
                "9001",
            ],
            "published-ports": [_port(9000, 9000)],
        },
    ),
    BackendImplementationProfile(
        profile_id="cassandra-4.1",
        selector=SemanticRuntimeSelector(
            "datastore_services", "engine", "cassandra", "4.1"
        ),
        source_name="cassandra",
        source_version="4.1",
        image_ref=(
            "cassandra@sha256:"
            "d25e8ee78d648fade002d0d176b7e8c953c69164b9f316ccbccf62f524c9dfbf"
        ),
    ),
    BackendImplementationProfile(
        profile_id="elasticsearch-7.17.28",
        selector=SemanticRuntimeSelector(
            "datastore_services", "engine", "elasticsearch", "7.17.28"
        ),
        source_name="docker.elastic.co/elasticsearch/elasticsearch",
        source_version="7.17.28",
        image_ref=(
            "docker.elastic.co/elasticsearch/elasticsearch@sha256:"
            "f2ce8a4c644a35762e6e115c9a373c5cd20df03c2dd75cb0a570011934cdffd1"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("discovery.type", "single-node"),
                _variable("xpack.security.enabled", "false"),
                _variable("cluster.routing.allocation.disk.threshold_enabled", "false"),
                _variable("ES_JAVA_OPTS", _HALF_GIB_JVM_OPTIONS),
            )
        },
    ),
    BackendImplementationProfile(
        profile_id="cortex-3.1.8",
        selector=SemanticRuntimeSelector(
            "platform_applications", "product", "Cortex", "3.1.8"
        ),
        source_name="thehiveproject/cortex",
        source_version="3.1.8",
        image_ref=(
            "thehiveproject/cortex@sha256:"
            "ae8b3d72eb5de785513bc33492d93278c32b79d9ff89401463c3a9c577e0bc0b"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("job_directory", "/opt/cortex/jobs")
            ),
            "published-ports": [_port(9001, 9001)],
        },
    ),
    BackendImplementationProfile(
        profile_id="shuffle-backend",
        selector=SemanticRuntimeSelector(
            "platform_applications", "product", "Shuffle", "unversioned"
        ),
        source_name="ghcr.io/shuffle/shuffle-backend",
        source_version="unversioned",
        image_ref=(
            "ghcr.io/shuffle/shuffle-backend@sha256:"
            "d4a5d2bf1f956955b68b099ba1c38997e4b257b2518215e0427f433515bea5c8"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("SHUFFLE_OPENSEARCH_URL", "https://shuffle-opensearch:9200"),
                _variable("SHUFFLE_OPENSEARCH_USERNAME", "admin"),
                _variable(
                    "SHUFFLE_OPENSEARCH_PASSWORD",
                    "StrongPassword123!",
                    classification="secret_fixture",
                ),
                _variable("SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY", "true"),
                _variable("SHUFFLE_DEFAULT_USERNAME", "admin"),
                _variable(
                    "SHUFFLE_DEFAULT_PASSWORD",
                    "ShuffleAdmin2024!",
                    classification="secret_fixture",
                ),
                _variable(
                    "SHUFFLE_DEFAULT_APIKEY",
                    "31a211c4-ea5c-4a49-b022-5e2434e758a7",
                    classification="secret_fixture",
                ),
                _variable("SHUFFLE_APP_SDK_TIMEOUT", "120"),
            )
        },
    ),
    BackendImplementationProfile(
        profile_id="shuffle-frontend",
        selector=SemanticRuntimeSelector(
            "software_components", "component_id", "shuffle-frontend", "unversioned"
        ),
        source_name="ghcr.io/shuffle/shuffle-frontend",
        source_version="unversioned",
        image_ref=(
            "ghcr.io/shuffle/shuffle-frontend@sha256:"
            "4d700a6f0822cb081822bd2fa6c633080553bdd4313aed2c4bdce75b87e82836"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("BACKEND_HOSTNAME", "shuffle-backend")
            ),
            "published-ports": [_port(443, 3443), _port(80, 3001)],
        },
    ),
    BackendImplementationProfile(
        profile_id="shuffle-orborus",
        selector=SemanticRuntimeSelector(
            "software_components", "component_id", "shuffle-orborus", "unversioned"
        ),
        source_name="ghcr.io/shuffle/shuffle-orborus",
        source_version="unversioned",
        image_ref=(
            "ghcr.io/shuffle/shuffle-orborus@sha256:"
            "94e61e7916aea28351fce3851f26f14fb85204f1567a8807d137321418366dba"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("BASE_URL", "http://shuffle-backend:5001"),
                _variable("CLEANUP", "false"),
                _variable("DOCKER_API_VERSION", "1.44"),
                _variable("ENVIRONMENT_NAME", "Shuffle"),
                _variable("SHUFFLE_APP_SDK_TIMEOUT", "300"),
                _variable("SHUFFLE_AUTO_IMAGE_DOWNLOAD", "false"),
                _variable("SHUFFLE_BASE_IMAGE_NAME", "frikky/shuffle"),
                _variable("SHUFFLE_ORBORUS_EXECUTION_TIMEOUT", "600"),
                _variable(
                    "SHUFFLE_WORKER_IMAGE",
                    "ghcr.io/shuffle/shuffle-worker@sha256:"
                    "fd0d420a5e0cd41f3979335e51912e8dd423e7ce540d1dfa24efdc98fb6071bd",
                ),
            )
        },
    ),
    BackendImplementationProfile(
        profile_id="shuffle-opensearch-2.14",
        selector=SemanticRuntimeSelector(
            "datastore_services", "engine", "opensearch", "2.14.0"
        ),
        source_name="opensearchproject/opensearch",
        source_version="2.14.0",
        image_ref=(
            "opensearchproject/opensearch@sha256:"
            "466a49f379bb8889af29d615475e69b7b990898c6987d28470cd7105df9046ff"
        ),
        runtime_selections={
            "runtime-environment": _environment(
                _variable("OPENSEARCH_JAVA_OPTS", _HALF_GIB_JVM_OPTIONS),
                _variable("discovery.type", "single-node"),
                _variable("cluster.routing.allocation.disk.threshold_enabled", "false"),
                _variable(
                    "OPENSEARCH_INITIAL_ADMIN_PASSWORD",
                    "StrongPassword123!",
                    classification="secret_fixture",
                ),
            )
        },
    ),
)

NODE22_SYSTEMD_BASE_IMAGE = "aptl/generic-systemd-node22-base:latest"
SAMBA_AD_BASE_IMAGE = "aptl/generic-samba-ad-base:latest"
WAZUH_DEBIAN_BASE_IMAGE = "aptl/generic-wazuh-agent-base-debian:latest"
WAZUH_DEBIAN_SYSTEMD_BASE_IMAGE = "aptl/generic-systemd-wazuh-agent-base-debian:latest"
WAZUH_RHEL_SYSTEMD_BASE_IMAGE = "aptl/generic-systemd-wazuh-agent-base:latest"
WAZUH_SAMBA_AD_BASE_IMAGE = "aptl/generic-samba-ad-wazuh-agent-base:latest"


__all__ = (
    "BACKEND_IMPLEMENTATION_PROFILES",
    "BackendBaseSelection",
    "BackendImplementationProfile",
    "NODE22_SYSTEMD_BASE_IMAGE",
    "SAMBA_AD_BASE_IMAGE",
    "WAZUH_DEBIAN_BASE_IMAGE",
    "WAZUH_DEBIAN_SYSTEMD_BASE_IMAGE",
    "WAZUH_RHEL_SYSTEMD_BASE_IMAGE",
    "WAZUH_SAMBA_AD_BASE_IMAGE",
    "SemanticRuntimeSelector",
)
