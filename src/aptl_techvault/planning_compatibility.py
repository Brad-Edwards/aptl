"""TechVault release-scoped planning compatibility declaration."""

from __future__ import annotations

from aptl.backends._raes_runtime_container_observation import (
    RUNTIME_CONTAINER_DAEMON_CONCERNS,
)
from aptl.backends.raes_runtime_attestation import ARTIFACT_ATTESTED_RUNTIME_CONCERNS
from aptl.backends.scenario_planning_compatibility import (
    EXTENSION_API_VERSION,
    PlanningCompatibilityDecision,
    ScenarioPlanningCompatibilityContext,
)
from aptl_techvault.runtime_parameters import TECHVAULT_PACK_SET_DIGEST


class TechVaultPlanningCompatibilityProvider:
    """Return bounded data for the released TechVault/RAES compatibility."""

    provider_id = "techvault-aptl-planning-compatibility"
    extension_api_version = EXTENSION_API_VERSION
    supported_pack_id = "techvault"
    supported_pack_versions = ("0.1.0",)
    supported_pack_set_digests = (TECHVAULT_PACK_SET_DIGEST,)
    backend_target_name = "aptl"
    backend_target_versions = ("0.1.0",)
    backend_profiles = ("full-remote-control-plane",)
    backend_transports: tuple[str, ...] = ()

    @staticmethod
    def resolve(
        _context: ScenarioPlanningCompatibilityContext,
    ) -> PlanningCompatibilityDecision:
        return PlanningCompatibilityDecision(
            daemon_readback_concerns=frozenset(
                {
                    *ARTIFACT_ATTESTED_RUNTIME_CONCERNS,
                    "linux-capabilities",
                    "published-ports",
                    *RUNTIME_CONTAINER_DAEMON_CONCERNS,
                    "runtime-container-autoremove",
                    "runtime-container-command",
                    "runtime-container-entrypoint",
                    "runtime-environment",
                    "runtime-local-control-interfaces",
                    "runtime-mounts",
                    "runtime-node-memory-limit",
                    "runtime-restart-policy",
                    "service-listeners",
                }
            ),
            open_default_concerns=frozenset(
                {"process-resource-limits", "runtime-restart-policy"}
            ),
            minimum_intrusion_exact_concerns=frozenset(
                {
                    "forwarding-agents",
                    "runtime-applications",
                    "runtime-datastore-services",
                }
            ),
            runtime_max_nodes=131_072,
        )


provider = TechVaultPlanningCompatibilityProvider()

__all__ = ["TechVaultPlanningCompatibilityProvider", "provider"]
