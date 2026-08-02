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
REALIZATION_ADDRESS_LABEL = "org.aptl.realization.address"
REALIZATION_LIFECYCLE_LABEL = "org.aptl.realization.lifecycle"
REALIZATION_PROJECT_LABEL = "org.aptl.realization.project"
MIN_OVERRIDE_COMPOSE_VERSION = (2, 24, 4)

WAZUH_INDEXER_SERVICE = "wazuh.indexer"
WAZUH_MANAGER_SERVICE = "wazuh.manager"
OWNED_WAZUH_SERVICES = frozenset({WAZUH_INDEXER_SERVICE, WAZUH_MANAGER_SERVICE})
