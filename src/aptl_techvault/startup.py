"""TechVault startup enrichment for the APTL deployment backend."""

from __future__ import annotations

from aptl.backends.scenario_startup import (
    EXTENSION_API_VERSION,
    ContainerEnvironmentBinding,
    EnvironmentAlias,
    McpServerCredentials,
    ScenarioStartupPlan,
    StartupCapability,
    StartupHook,
    StartupHookContext,
)
from aptl.backends.scenario_startup_policy import (
    ScenarioComposeStartupPolicy,
    StartupHealthDependency,
    StartupHealthProbe,
)
from aptl.backends.scenario_service_policy import (
    ScenarioComposeServicePolicy,
    ServiceEnvironmentFile,
    ServiceFileMount,
    ServiceContainerNameEnvironment,
)
from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH
from aptl.core.scenario_bundle import ScenarioBundle
from aptl_techvault.log_sources import realize_log_sources
from aptl_techvault.evidence.techvault_enrollment_baseline import (
    clear_enrollment_baseline,
)
from aptl_techvault.redis_acl_observation import observe_redis_app_authorizations
from aptl_techvault.runtime_parameters import TECHVAULT_PACK_SET_DIGEST


class TechVaultStartupProvider:
    """Describe the optional TechVault seed through the generic adapter seam."""

    extension_api_version = EXTENSION_API_VERSION
    supported_pack_id = "techvault"
    supported_pack_versions = ("0.1.0",)
    supported_pack_set_digests = (TECHVAULT_PACK_SET_DIGEST,)

    @staticmethod
    def prepare_stack_environment(context: StartupHookContext) -> object:
        """Execute TechVault's selected preparation phase in core order."""

        return context.run_operation()

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
            lifecycle_capabilities=frozenset(
                {
                    StartupCapability.SSH,
                    StartupCapability.HOST_TOOLS,
                    StartupCapability.MCP,
                    StartupCapability.NATIVE_EVIDENCE,
                }
            ),
            startup_hooks=frozenset(
                {
                    StartupHook.STACK_ENVIRONMENT,
                    StartupHook.BEFORE_BACKEND_RETRY,
                    StartupHook.RESET,
                }
            ),
            seed_environment_keys=(
                "APTL_HP_WAZUH_INDEXER_9200",
                "APTL_SHUFFLE_WEBHOOK_FILE",
                "INDEXER_URL",
                "INDEXER_USERNAME",
                "INDEXER_PASSWORD",
                "MISP_API_KEY",
                "MISP_URL",
                "SHUFFLE_API_KEY",
                "SHUFFLE_URL",
                "CORTEX_API_KEY",
                "THEHIVE_API_KEY",
            ),
            mcp_build_script="mcp/build-all-mcps.sh",
            mcp_server_keys=(
                McpServerCredentials("aptl-casemgmt", ("THEHIVE_API_KEY",)),
                McpServerCredentials(
                    "aptl-indexer",
                    (
                        "INDEXER_USERNAME",
                        "INDEXER_PASSWORD",
                        "API_USERNAME",
                        "API_PASSWORD",
                    ),
                ),
                McpServerCredentials(
                    "aptl-network", ("INDEXER_USERNAME", "INDEXER_PASSWORD")
                ),
                McpServerCredentials("aptl-threatintel", ("MISP_API_KEY",)),
                McpServerCredentials("aptl-soar", ("SHUFFLE_API_KEY",)),
                McpServerCredentials(
                    "aptl-wazuh",
                    (
                        "INDEXER_USERNAME",
                        "INDEXER_PASSWORD",
                        "API_USERNAME",
                        "API_PASSWORD",
                    ),
                ),
            ),
            native_mcp_ingress=True,
        )

    @staticmethod
    def before_backend_retry(context: StartupHookContext) -> None:
        """Repair a stuck manager without moving retry policy out of core."""

        container = "aptl-wazuh-manager"
        probe = [
            "sh",
            "-c",
            "ls /proc/[0-9]*/comm 2>/dev/null | while read f; do "
            'read n < "$f"; case "$n" in wazuh-*) echo "$n";; esac; '
            "done | sort -u | wc -l",
        ]
        try:
            info = context.backend.container_inspect(container)
            if (info.get("State") or {}).get("Status") != "running":
                return
            result = context.backend.container_exec(container, probe, timeout=10)
            count = (
                int((result.stdout or "0").strip()) if result.returncode == 0 else None
            )
            if count == 0:
                context.backend.container_restart(container)
        except Exception:
            return

    @staticmethod
    def reset(context: StartupHookContext) -> None:
        """Clear adapter-owned retained evidence state after volume removal."""

        failures = clear_enrollment_baseline(
            getattr(context.backend, "project_dir", None)
        )
        if failures:
            raise RuntimeError("adapter reset failed")

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
    def compose_service_policy() -> ScenarioComposeServicePolicy:
        """Connect SDL-owned certificate files to upstream image TLS paths.

        The pack delivers these generated files at portable locations. The
        image-specific paths and TheHive Play config belong to this adapter.
        """

        return ScenarioComposeServicePolicy(
            mounts=(
                ServiceFileMount(
                    "shuffle-frontend",
                    "config/soc_certs/shuffle-frontend/server.pem",
                    "/etc/nginx/fullchain.cert.pem",
                ),
                ServiceFileMount(
                    "shuffle-frontend",
                    "config/soc_certs/shuffle-frontend/server.key",
                    "/etc/nginx/privkey.pem",
                ),
                ServiceFileMount(
                    "thehive",
                    "config/soc_certs/thehive/keystore.p12",
                    "/etc/thehive/keystore.p12",
                ),
                ServiceFileMount(
                    "thehive",
                    "config/thehive/application.conf",
                    "/etc/thehive/application.conf",
                ),
            ),
            environment_files=(
                ServiceEnvironmentFile(
                    "thehive", "config/soc_certs/thehive/keystore.p12.password"
                ),
            ),
            container_name_environment=(
                ServiceContainerNameEnvironment(
                    "shuffle-orborus", "ORBORUS_CONTAINER_NAME", "shuffle-orborus"
                ),
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
