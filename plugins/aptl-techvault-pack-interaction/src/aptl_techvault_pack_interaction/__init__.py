"""TechVault deployment-serving labels for the APTL backend.

The provider maps only exact component addresses that APTL core already
lowered from one admitted RAES provisioning plan. It owns no artifacts,
services, images, commands, or materialization behavior.
"""

from __future__ import annotations

from aptl.backends.pack_interaction import (
    EXTENSION_API_VERSION,
    ComponentGroupMembership,
    PackBackendInteractionContext,
    PackBackendInteractionResult,
)

__version__ = "0.1.0"

_PACK_SET_DIGEST = (
    "sha256:f1c807f70540ca68c640cde72e8b5606b928f4ec40cc00a44d7fd37d6bbfd55f"
)

_GROUP_BY_COMPONENT = {
    # SIEM
    "provision.node.wazuh-manager": "wazuh",
    "provision.node.wazuh-indexer": "wazuh",
    "provision.node.wazuh-dashboard": "wazuh",
    # SOC stack
    "provision.node.suricata": "soc",
    "provision.node.misp": "soc",
    "provision.node.misp-db": "soc",
    "provision.node.misp-redis": "soc",
    "provision.node.misp-suricata-sync": "soc",
    "provision.node.thehive": "soc",
    "provision.node.thehive-cassandra": "soc",
    "provision.node.thehive-es": "soc",
    "provision.node.cortex": "soc",
    "provision.node.shuffle-backend": "soc",
    "provision.node.shuffle-frontend": "soc",
    "provision.node.shuffle-opensearch": "soc",
    "provision.node.shuffle-orborus": "soc",
    "provision.node.wazuh-sidecar-db": "soc",
    "provision.node.wazuh-sidecar-suricata": "soc",
    # Enterprise workloads
    "provision.node.ad": "enterprise",
    "provision.node.db": "enterprise",
    "provision.node.webapp": "enterprise",
    "provision.node.webapp-proxy": "enterprise",
    "provision.node.workstation": "enterprise",
    # Operator-selectable endpoints and infrastructure
    "provision.node.dns": "dns",
    "provision.node.fileshare": "fileshare",
    "provision.node.victim": "victim",
    "provision.node.kali": "kali",
    "provision.node.kali-capture": "kali",
    "provision.node.kali-ssh-proxy": "kali",
    # Backend-owned observability group
    "provision.node.aptl-otel-collector": "otel",
    "provision.node.aptl-tempo": "otel",
    "provision.node.aptl-grafana-otel": "otel",
}


class TechVaultPackInteraction:
    """Assign exact TechVault component addresses to APTL operator groups."""

    provider_id = "techvault-aptl-serving"
    extension_api_version = EXTENSION_API_VERSION
    supported_pack_id = "techvault"
    supported_pack_versions = ("0.1.0",)
    supported_pack_set_digests = (_PACK_SET_DIGEST,)
    backend_target_name = "aptl"
    backend_target_versions = ("0.1.0",)
    backend_profiles = ("full-remote-control-plane",)
    backend_transports: tuple[str, ...] = ()

    def resolve(
        self, context: PackBackendInteractionContext
    ) -> PackBackendInteractionResult:
        """Return a total mapping for the admitted TechVault node inventory."""

        unknown = set(context.component_addresses) - set(_GROUP_BY_COMPONENT)
        if unknown:
            raise ValueError("unsupported-component-address")
        return PackBackendInteractionResult(
            memberships=tuple(
                ComponentGroupMembership(address, (_GROUP_BY_COMPONENT[address],))
                for address in context.component_addresses
            )
        )


provider = TechVaultPackInteraction()

__all__ = ["TechVaultPackInteraction", "provider"]
