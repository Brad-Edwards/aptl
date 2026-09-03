"""Shared constants for Compose-backed stateful realization."""

from pathlib import Path

STATEFUL_OVERRIDE_RELPATH = Path(".aptl/realization/compose.stateful.yml")
CERTIFICATE_ROOT_RELPATH = Path("config/wazuh_indexer_ssl_certs")
# Owner-only staging root for ssh_key_bundle generated artifacts (gitignored,
# under the scenario bundle root). Each declared output lands at its relative
# path here; only a consumer's selected_outputs are bind-mounted from it, and a
# producer_private output is never mounted.
SSH_KEY_BUNDLE_ROOT_RELPATH = Path(".aptl/realization/ssh-key-bundles")
# Owner-only staging root for flag-signing rendered_config artifacts. Keyed by
# artifact name so a flag-signing bundle never collides with the wazuh manager
# rendered config (both are the ``rendered_config`` generator). Same mount
# discipline as the ssh bundle: only a consumer's selected key is bound.
FLAG_SIGNING_ROOT_RELPATH = Path(".aptl/realization/flag-signing")
# The one accepted certificate-bundle producer. Adding a second needs more than
# a root path: the bundle validator in ``_stateful_certificates`` assumes this
# producer's shape throughout — the root is named ``root-ca.pem``, a manager root
# must agree with it, and identities must match a ``config/certs.yml``-shaped
# provenance document. A producer whose bundle differs in any of those fails
# validation regardless of where its root is found.
CERTIFICATE_PROVENANCE = "config/certs.yml"
# Env-pack producer profiles (issue #875). The pack declares generated artifacts
# by profile identity rather than the in-tree provenance file paths; APTL maps
# each to the generator that produces it. Wazuh node certs are all produced by a
# single ``ensure_ssl_certs`` run (config/wazuh_indexer_ssl_certs); SOC service
# certs by ``ensure_soc_certs`` (config/soc_certs).
WAZUH_CERT_PROFILES = frozenset(
    {
        "techvault:wazuh-indexer-certificate-profile/v1",
        "techvault:wazuh-manager-certificate-profile/v1",
        "techvault:wazuh-dashboard-certificate-profile/v1",
    }
)
SOC_CERT_PROFILE = "techvault:soc-certificate-profile/v1"
WAZUH_MANAGER_CONFIG_PROFILE = "techvault:wazuh-manager-config-profile/v1"
# Legacy in-tree provenance path for the wazuh manager rendered config. The
# in-tree scenario declares this producer as a config file path; an env-pack
# declares the same producer as WAZUH_MANAGER_CONFIG_PROFILE. Both are *declared
# producer identities* the generator dispatch maps to sync_manager_config; the
# generated-artifact realizer and the effective-model whole-file-binding check
# key off this single set instead of repeating the literals (issue #875). The
# in-tree path entry retires with the in-tree scenarios (task #8).
WAZUH_MANAGER_CONFIG_IN_TREE_PROVENANCE = "config/wazuh_cluster/wazuh_manager.conf"
WAZUH_MANAGER_CONFIG_PROVENANCES = frozenset(
    {WAZUH_MANAGER_CONFIG_IN_TREE_PROVENANCE, WAZUH_MANAGER_CONFIG_PROFILE}
)
SOC_CERTS_ROOT_RELPATH = Path("config/soc_certs")
REALIZATION_ADDRESS_LABEL = "org.aptl.realization.address"
REALIZATION_LIFECYCLE_LABEL = "org.aptl.realization.lifecycle"
REALIZATION_PROJECT_LABEL = "org.aptl.realization.project"
MIN_OVERRIDE_COMPOSE_VERSION = (2, 24, 4)

# Canonical Wazuh appliance DNS names. These are the names the appliance's own
# bundled config (filebeat output host, dashboard API URL) and certificates are
# authored against, independent of the realized Compose service key; the graph
# derives which realized node is the manager/indexer from declared semantics
# (see ``_wazuh_identity``) and publishes these as network aliases when the
# service key differs.
WAZUH_INDEXER_SERVICE = "wazuh.indexer"
WAZUH_MANAGER_SERVICE = "wazuh.manager"
