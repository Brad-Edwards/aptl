"""APTL ACES backend manifest helpers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

APTL_ACES_TARGET_NAME = "aptl"


@dataclass(frozen=True)
class AptlProvisionerCapabilities(object):
    """Minimal capability shape consumed by the ACES planner."""

    name: str = "aptl-docker-compose-provisioner"
    supported_node_types: frozenset[str] = frozenset({"switch", "vm"})
    supported_os_families: frozenset[str] = frozenset(
        {"freebsd", "linux", "macos", "other", "windows"}
    )
    supported_content_types: frozenset[str] = frozenset(
        {"dataset", "directory", "file"}
    )
    supported_account_features: frozenset[str] = frozenset(
        {
            "auth_method",
            "disabled",
            "groups",
            "home",
            "mail",
            "other:password_strength",
            "shell",
            "spn",
        }
    )
    max_total_nodes: int | None = None
    supports_acls: bool = True
    supports_accounts: bool = True
    constraints: Mapping[str, str] | None = None


@dataclass(frozen=True)
class AptlBackendManifest(object):
    """Runtime-target manifest shape used by ``RuntimeManager``.

    The installed ACES package validates full manifests against the ACES
    contract corpus. APTL's direct-reference dependency does not vendor that
    corpus into ``.venv/contracts``, so the runtime target uses the attributes
    consumed by ``aces_processor.planner`` and ``aces_runtime.registry`` while
    leaving full manifest conformance to the ACES package distribution.
    """

    name: str = APTL_ACES_TARGET_NAME
    version: str = "0.1.0"
    provisioner: AptlProvisionerCapabilities = AptlProvisionerCapabilities()
    orchestrator: None = None
    evaluator: None = None
    participant_runtime: None = None

    @property
    def has_orchestrator(self) -> bool:
        """Return whether this provisional backend exposes orchestration."""
        return False

    @property
    def has_evaluator(self) -> bool:
        """Return whether this provisional backend exposes evaluation."""
        return False

    @property
    def has_participant_runtime(self) -> bool:
        """Return whether this backend exposes participant runtime hooks."""
        return False

    @property
    def evaluator_supported_sections(self) -> frozenset[str]:
        """Return evaluator SDL sections supported by this backend."""
        return frozenset()

    @property
    def supports_scoring(self) -> bool:
        """Return whether scoring is supported by this backend."""
        return False

    @property
    def supports_objectives(self) -> bool:
        """Return whether objective evaluation is supported by this backend."""
        return False


def create_aptl_manifest() -> AptlBackendManifest:
    """Return the APTL provisioning-only runtime manifest."""
    return AptlBackendManifest()
