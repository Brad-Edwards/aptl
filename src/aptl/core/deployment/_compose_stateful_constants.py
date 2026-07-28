"""Shared constants for Compose-backed stateful realization."""

from pathlib import Path

STATEFUL_OVERRIDE_RELPATH = Path(".aptl/realization/compose.stateful.yml")
CERTIFICATE_ROOT_RELPATH = Path("config/wazuh_indexer_ssl_certs")
# A certificate bundle's host root depends on which producer generated it, not
# on the RAES generator kind: RAES's vocabulary is deliberately small
# (certificate_bundle, rendered_config), so several distinct producers share one
# kind. The artifact's declared provenance names the producer, and this maps it
# to the directory that producer writes into. An unmapped provenance falls back
# to the Wazuh indexer root, which is where every pre-existing bundle lands.
# This table is the single allowlist of accepted certificate-bundle producers.
# Admission validates membership and realization resolves the root from the same
# entry, so a producer cannot be accepted without a known root, or acquire a root
# without being accepted.
SOC_CA_PROVENANCE = "src/aptl/core/soc_ca.py"
CERTIFICATE_ROOT_BY_PROVENANCE: dict[str, Path] = {
    "config/certs.yml": CERTIFICATE_ROOT_RELPATH,
    SOC_CA_PROVENANCE: Path("config/soc_certs"),
}
REALIZATION_ADDRESS_LABEL = "org.aptl.realization.address"
REALIZATION_LIFECYCLE_LABEL = "org.aptl.realization.lifecycle"
REALIZATION_PROJECT_LABEL = "org.aptl.realization.project"
MIN_OVERRIDE_COMPOSE_VERSION = (2, 24, 4)

WAZUH_INDEXER_SERVICE = "wazuh.indexer"
WAZUH_MANAGER_SERVICE = "wazuh.manager"
OWNED_WAZUH_SERVICES = frozenset({WAZUH_INDEXER_SERVICE, WAZUH_MANAGER_SERVICE})
