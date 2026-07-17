"""Shared constants for Compose-backed stateful realization."""

from pathlib import Path

STATEFUL_OVERRIDE_RELPATH = Path(".aptl/realization/compose.stateful.yml")
CERTIFICATE_ROOT_RELPATH = Path("config/wazuh_indexer_ssl_certs")
REALIZATION_ADDRESS_LABEL = "org.aptl.realization.address"
REALIZATION_LIFECYCLE_LABEL = "org.aptl.realization.lifecycle"
REALIZATION_PROJECT_LABEL = "org.aptl.realization.project"
MIN_OVERRIDE_COMPOSE_VERSION = (2, 24, 4)

WAZUH_INDEXER_SERVICE = "wazuh.indexer"
WAZUH_MANAGER_SERVICE = "wazuh.manager"
OWNED_WAZUH_SERVICES = frozenset({WAZUH_INDEXER_SERVICE, WAZUH_MANAGER_SERVICE})
