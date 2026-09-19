"""TechVault startup enrichment for the APTL deployment backend."""

from __future__ import annotations

from aptl.backends.scenario_startup import (
    EXTENSION_API_VERSION,
    ContainerEnvironmentBinding,
    EnvironmentAlias,
    ScenarioStartupPlan,
)
from aptl.backends.scenario_startup_policy import (
    ScenarioComposeStartupPolicy,
    StartupHealthDependency,
    StartupHealthProbe,
)
from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH
from aptl.core.scenario_bundle import ScenarioBundle
from aptl_techvault.log_sources import realize_log_sources
from aptl_techvault.redis_acl_observation import observe_redis_app_authorizations
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

    @staticmethod
    def compose_startup_policy() -> ScenarioComposeStartupPolicy:
        """Wait for TechVault's stateful backends before dependent JVM services.

        The pack declares these dependency edges, but its generated Compose
        base otherwise starts dependents as soon as their containers exist.
        Cassandra can still be initializing then, causing TheHive to exit on
        the first user-visible boot. These probes strengthen only those edges.
        """

        return ScenarioComposeStartupPolicy(
            probes=(
                StartupHealthProbe(
                    "thehive-cassandra",
                    ("CMD", "cqlsh", "-e", "describe cluster"),
                ),
                StartupHealthProbe(
                    "thehive-es",
                    ("CMD", "curl", "-fsS", "http://localhost:9200/_cluster/health"),
                ),
                StartupHealthProbe(
                    "cortex",
                    ("CMD", "curl", "-fsS", "http://localhost:9001/api/status"),
                    start_period_seconds=180,
                ),
            ),
            dependencies=(
                StartupHealthDependency("cortex", "thehive-es"),
                StartupHealthDependency("thehive", "thehive-cassandra"),
                StartupHealthDependency("thehive", "thehive-es"),
                StartupHealthDependency("thehive", "cortex"),
            ),
        )

    @staticmethod
    def realize_runtime(backend: object, nodes: tuple[object, ...]) -> list[str]:
        """Produce the pack's declared native logs before agent readback."""

        return realize_log_sources(backend, nodes)

    @staticmethod
    def observe_runtime(backend: object, node: object) -> dict[tuple[str, ...], object]:
        """Corroborate TechVault's generated cache ACL without exposing it."""

        runtime = getattr(node, "runtime", None)
        container = getattr(node, "container_name", "")
        if (
            getattr(node, "name", "") != "misp-redis"
            or runtime is None
            or not container
        ):
            return {}
        observed = observe_redis_app_authorizations(backend, container, runtime)
        if observed is None:
            return {}
        return {CONCERN_PAYLOAD_PATH["runtime-app-authorizations"]: observed}


provider = TechVaultStartupProvider()

__all__ = ["TechVaultStartupProvider", "provider"]
