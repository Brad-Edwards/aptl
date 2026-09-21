"""Provider-neutral bounded planning-compatibility decision contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from aptl.backends.identity import BackendIdentity
from aptl.core.scenario_bundle import PackIdentity

ENTRY_POINT_GROUP = "aptl.scenario_planning_compatibility"
EXTENSION_API_VERSION = "1"

# Providers may select only among compatibility behaviors that the APTL target
# already knows how to enforce.  Keeping these vocabularies here makes the
# extension a bounded policy choice, rather than an arbitrary concern-name
# injection surface.
PERMITTED_DAEMON_READBACK_CONCERNS = frozenset(
    {
        "linux-capabilities",
        "published-ports",
        "runtime-app-authorizations",
        "runtime-applications",
        "runtime-container-autoremove",
        "runtime-container-cgroup-parent",
        "runtime-container-command",
        "runtime-container-device-cgroup-rules",
        "runtime-container-devices",
        "runtime-container-dns",
        "runtime-container-dns-options",
        "runtime-container-dns-search",
        "runtime-container-entrypoint",
        "runtime-container-extra-hosts",
        "runtime-container-group-add",
        "runtime-container-init-process",
        "runtime-container-log-driver",
        "runtime-container-log-options",
        "runtime-container-namespaces",
        "runtime-container-privileged",
        "runtime-container-read-only-rootfs",
        "runtime-container-runtime-name",
        "runtime-container-seccomp-profile",
        "runtime-container-security-opt",
        "runtime-container-shm-size",
        "runtime-database-services",
        "runtime-datastore-services",
        "runtime-dns-services",
        "runtime-environment",
        "runtime-file-services",
        "runtime-identity-authorities",
        "runtime-local-control-interfaces",
        "runtime-mounts",
        "runtime-network-detection-engines",
        "runtime-network-sensors",
        "runtime-node-memory-limit",
        "runtime-orchestration-authorities",
        "runtime-platform-applications",
        "runtime-restart-policy",
        "runtime-security-monitoring-managers",
        "runtime-software-components",
        "service-listeners",
    }
)
PERMITTED_OPEN_DEFAULT_CONCERNS = frozenset(
    {"process-resource-limits", "runtime-restart-policy"}
)
PERMITTED_MINIMUM_INTRUSION_EXACT_CONCERNS = frozenset(
    {"forwarding-agents", "runtime-applications", "runtime-datastore-services"}
)


@dataclass(frozen=True)
class ScenarioPlanningCompatibilityContext:
    pack: PackIdentity
    backend: BackendIdentity


@dataclass(frozen=True)
class PlanningCompatibilityDecision:
    """Bounded data core may apply around one compile/plan operation."""

    daemon_readback_concerns: frozenset[str] = frozenset()
    open_default_concerns: frozenset[str] = frozenset()
    minimum_intrusion_exact_concerns: frozenset[str] = frozenset()
    runtime_max_nodes: int | None = None


class ScenarioPlanningCompatibilityProvider(Protocol):
    provider_id: str
    extension_api_version: str
    supported_pack_id: str
    supported_pack_versions: tuple[str, ...]
    supported_pack_set_digests: tuple[str, ...]
    backend_target_name: str
    backend_target_versions: tuple[str, ...]
    backend_profiles: tuple[str, ...]
    backend_transports: tuple[str, ...]

    def resolve(
        self, context: ScenarioPlanningCompatibilityContext
    ) -> PlanningCompatibilityDecision: ...


@dataclass(frozen=True)
class ResolvedPlanningCompatibility:
    decision: PlanningCompatibilityDecision
    provider_id: str
    extension_api_version: str
    distribution: str = ""
    distribution_version: str = ""
    entry_point: str = ""


__all__ = [
    "ENTRY_POINT_GROUP",
    "EXTENSION_API_VERSION",
    "PERMITTED_DAEMON_READBACK_CONCERNS",
    "PERMITTED_MINIMUM_INTRUSION_EXACT_CONCERNS",
    "PERMITTED_OPEN_DEFAULT_CONCERNS",
    "PlanningCompatibilityDecision",
    "ResolvedPlanningCompatibility",
    "ScenarioPlanningCompatibilityContext",
    "ScenarioPlanningCompatibilityProvider",
]
