"""The trusted built-in provenance fleet (REP-003 / issue #452).

Holds the declaration DATA for every built-in provider plus the composition
that binds each declaration to its narrow owner adapter. Keeping the data here
— beside, not inside, :mod:`aptl.core.provenance.registry` — mirrors how
``capture_registrations`` relates to ``capture_registry`` and keeps the type
module free of owner imports.

Every built-in is policy-required in the default profile. That is deliberate:
requiring a provider does not assert it must succeed, it asserts that its
outcome must be STATED. A plain ``aptl lab start`` has no admitted experiment
plan and no installed participants, so those two providers report
``UNAVAILABLE`` and appear as declared limitations — which is the honest
record, and exactly what "missing/denied provenance is explicit" requires.
Whether any such limitation blocks a run is issue #472's readiness policy.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from aptl.core.provenance.coordinator import ProvenanceCollection, collect_provenance
from aptl.core.provenance.protocol import MonotonicClock, ProvenanceProvider
from aptl.core.provenance.providers.apparatus import (
    APPARATUS_PROVIDER_ID,
    ApparatusManifestProvider,
)
from aptl.core.provenance.providers.artifacts import (
    ARTIFACTS_PROVIDER_ID,
    DependencyArtifactProvider,
)
from aptl.core.provenance.providers.config_identity import (
    CONFIG_PROVIDER_ID,
    ConfigIdentityProvider,
)
from aptl.core.provenance.providers.detection import (
    DETECTION_PROVIDER_ID,
    DetectionContentProvider,
)
from aptl.core.provenance.providers.experiment import (
    EXPERIMENT_PROVIDER_ID,
    AdmittedExperimentProvider,
)
from aptl.core.provenance.providers.participant import (
    PARTICIPANT_PROVIDER_ID,
    ParticipantApparatusProvider,
)
from aptl.core.provenance.providers.runtime_facts import (
    RUNTIME_PROVIDER_ID,
    RuntimeFactsProvider,
    default_host_facts,
)
from aptl.core.provenance.registry import (
    ProvenanceLimits,
    ProvenanceProviderRegistration,
    ProvenanceProviderRegistry,
    SealPoint,
    SealProfile,
)

log = logging.getLogger(__name__)

#: Bumped whenever a built-in provider's collection behavior changes in a way
#: that could alter what it reports for identical inputs.
_IMPLEMENTATION_VERSION = "1.0.0"


def _registration(
    provider_id: str,
    provenance_kind: str,
    owner_adapter: str,
    *,
    max_bytes: int,
    max_entries: int,
    timeout_s: int,
) -> ProvenanceProviderRegistration:
    """Build one built-in registration with its declared bounds."""
    return ProvenanceProviderRegistration(
        provider_id=provider_id,
        implementation_version=_IMPLEMENTATION_VERSION,
        provenance_kind=provenance_kind,
        owner_adapter=owner_adapter,
        seal_point=SealPoint.RUN_READY_TO_SEAL,
        requiredness_policy_key=f"{provider_id}-required",
        limits=ProvenanceLimits(
            max_bytes=max_bytes, max_entries=max_entries, timeout_s=timeout_s
        ),
    )


#: The detection-content registration, named so callers that need only this
#: provider's declared limits (for example the snapshot adapter) can reference
#: it directly instead of looking it up and handling an impossible miss.
DETECTION_REGISTRATION = _registration(
    DETECTION_PROVIDER_ID,
    "detection-content",
    "provenance.providers.detection",
    max_bytes=64_000_000,
    max_entries=1024,
    timeout_s=60,
)

#: The declared built-in fleet. Limits are sized to the real surfaces: the
#: detection roots hold on the order of a dozen small text artifacts, while a
#: trial plan can carry many planned trials.
BUILTIN_REGISTRATIONS: tuple[ProvenanceProviderRegistration, ...] = (
    _registration(
        APPARATUS_PROVIDER_ID,
        "apparatus-manifest",
        "raes_manifest/raes_processor",
        max_bytes=4_000_000,
        max_entries=8,
        timeout_s=30,
    ),
    _registration(
        EXPERIMENT_PROVIDER_ID,
        "admitted-experiment",
        "experiment.trial_plan",
        max_bytes=4_000_000,
        max_entries=1024,
        timeout_s=30,
    ),
    _registration(
        PARTICIPANT_PROVIDER_ID,
        "participant-apparatus",
        "raes_participant_apparatus",
        max_bytes=1_000_000,
        max_entries=64,
        timeout_s=30,
    ),
    DETECTION_REGISTRATION,
    _registration(
        CONFIG_PROVIDER_ID,
        "effective-config",
        "core.config",
        max_bytes=1_000_000,
        max_entries=8,
        timeout_s=15,
    ),
    _registration(
        RUNTIME_PROVIDER_ID,
        "runtime-facts",
        "core.snapshot",
        max_bytes=8_000_000,
        max_entries=256,
        timeout_s=30,
    ),
    _registration(
        ARTIFACTS_PROVIDER_ID,
        "dependency-artifacts",
        "provenance.providers.artifacts",
        max_bytes=32_000_000,
        max_entries=128,
        timeout_s=30,
    ),
)

#: The production registry.
DEFAULT_PROVENANCE_REGISTRY = ProvenanceProviderRegistry(BUILTIN_REGISTRATIONS)

#: The default run-scoped seal profile: every built-in outcome must be stated.
DEFAULT_SEAL_PROFILE = SealProfile(
    seal_point=SealPoint.RUN_READY_TO_SEAL,
    required_provider_ids=frozenset(
        item.provider_id for item in BUILTIN_REGISTRATIONS
    ),
)


def build_default_providers(
    *,
    project_dir: Path | str,
    config: object | None,
    snapshot: object | None,
    admitted_plan: object | None = None,
    participant_apparatus: Mapping[str, object] | None = None,
) -> tuple[ProvenanceProvider, ...]:
    """Compose the trusted fleet, binding each provider to its owner input.

    Owner inputs are passed in already-resolved. Nothing here discovers a run,
    reopens a scenario, or reaches for a backend, an environment, or a shell.
    """
    return (
        ApparatusManifestProvider(),
        AdmittedExperimentProvider(admitted_plan),
        ParticipantApparatusProvider(participant_apparatus or {}),
        DetectionContentProvider(Path(project_dir)),
        ConfigIdentityProvider(config),
        # The live host probe is composed HERE, explicitly. It is the only
        # subprocess this fleet runs, so it is a composition decision rather
        # than a constructor default every caller inherits.
        RuntimeFactsProvider(snapshot, host_facts=default_host_facts),
        DependencyArtifactProvider(Path(project_dir)),
    )


def collect_run_provenance(
    *,
    project_dir: Path | str,
    config: object | None,
    snapshot: object | None,
    admitted_plan: object | None = None,
    participant_apparatus: Mapping[str, object] | None = None,
    monotonic: MonotonicClock = time.monotonic,
) -> ProvenanceCollection:
    """Collect run-scoped provenance from the default fleet."""
    providers: Sequence[ProvenanceProvider] = build_default_providers(
        project_dir=project_dir,
        config=config,
        snapshot=snapshot,
        admitted_plan=admitted_plan,
        participant_apparatus=participant_apparatus,
    )
    return collect_provenance(
        providers=providers,
        registry=DEFAULT_PROVENANCE_REGISTRY,
        profile=DEFAULT_SEAL_PROFILE,
        monotonic=monotonic,
    )
