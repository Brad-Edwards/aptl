"""TechVault startup enrichment for the APTL deployment backend."""

from __future__ import annotations

from aptl.backends.scenario_startup import (
    EXTENSION_API_VERSION,
    ContainerEnvironmentBinding,
    EnvironmentAlias,
    ScenarioStartupPlan,
)
from aptl.core.scenario_bundle import ScenarioBundle
from aptl_techvault.runtime_parameters import TECHVAULT_PACK_SET_DIGEST



class TechVaultStartupProvider:
    """Describe the optional TechVault seed through the generic adapter seam."""

    extension_api_version = EXTENSION_API_VERSION
    supported_pack_id = "techvault"
    supported_pack_versions = ("0.1.0",)
    supported_pack_set_digests = (TECHVAULT_PACK_SET_DIGEST,)

    @staticmethod
    def resolve(_bundle: ScenarioBundle) -> ScenarioStartupPlan:
        return ScenarioStartupPlan(
            seed_script="scripts/seed-prime.sh",
            required_profiles=(
                "wazuh",
                "enterprise",
                "victim",
                "kali",
                "fileshare",
                "soc",
            ),
            activation_profiles=("soc",),
            environment_aliases=(
                EnvironmentAlias(target="ADMIN_KEY", source="MISP_API_KEY"),
            ),
            container_environment=(
                ContainerEnvironmentBinding("CORTEX_CONTAINER", "aptl-cortex"),
                ContainerEnvironmentBinding("THEHIVE_CONTAINER", "aptl-thehive"),
                ContainerEnvironmentBinding("MISP_CONTAINER", "aptl-misp"),
                ContainerEnvironmentBinding(
                    "SHUFFLE_CONTAINER", "aptl-shuffle-frontend"
                ),
                ContainerEnvironmentBinding("KALI_CONTAINER", "aptl-kali"),
                ContainerEnvironmentBinding(
                    "WAZUH_MANAGER_CONTAINER", "aptl-wazuh-manager"
                ),
            ),
        )


provider = TechVaultStartupProvider()

__all__ = ["TechVaultStartupProvider", "provider"]
