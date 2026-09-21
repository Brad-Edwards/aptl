"""Provider-neutral capture contribution selected for one admitted pack."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from aptl.backends.identity import BackendIdentity
from aptl.core.experiment.capture_registry import (
    CollectorRegistration,
    CollectorRegistry,
)
from aptl.core.scenario_bundle import PackIdentity

ENTRY_POINT_GROUP = "aptl.scenario_capture"
EXTENSION_API_VERSION = "1"


@dataclass(frozen=True)
class ScenarioCaptureContext:
    """Exact pack/backend identity visible during capture selection."""

    pack: PackIdentity
    backend: BackendIdentity


@dataclass(frozen=True)
class ScenarioCaptureContribution:
    """Validated declarations and narrow executable capture adapter."""

    registrations: tuple[CollectorRegistration, ...]
    native_registration_ids: frozenset[str] = frozenset()
    runtime_environment_keys: tuple[str, ...] = ()
    transcript_registration_id: str | None = None
    runtime_adapter: object | None = field(default=None, repr=False, compare=False)
    proposition_interpreter: object | None = field(
        default=None, repr=False, compare=False
    )


class ScenarioCaptureProvider(Protocol):
    """Installed provider contract; installation grants normal Python authority."""

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
        self, context: ScenarioCaptureContext
    ) -> ScenarioCaptureContribution: ...


@dataclass(frozen=True)
class ResolvedScenarioCapture:
    """Core-owned copy of one exact installed capture contribution."""

    registry: CollectorRegistry
    contribution: ScenarioCaptureContribution
    context: ScenarioCaptureContext
    provider_id: str
    extension_api_version: str
    distribution: str = ""
    distribution_version: str = ""
    entry_point: str = ""


__all__ = [
    "ENTRY_POINT_GROUP",
    "EXTENSION_API_VERSION",
    "ResolvedScenarioCapture",
    "ScenarioCaptureContext",
    "ScenarioCaptureContribution",
    "ScenarioCaptureProvider",
]
