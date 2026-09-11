"""Answer questions about an admitted scenario without starting anything.

Split out of :mod:`aptl.backends.raes` so that module keeps the start/apply flow
while this one carries the read-only queries the CLI and lab lifecycle ask
before (and instead of) a start: which Compose profiles a scenario selects, and
which stateful artifact mounts the admitted graph owns. Both project the same
admission the start path applies, so an answer here and a start cannot disagree;
neither applies the plan.

``aptl.backends.raes.admit_raes_scenario`` is resolved at call time rather than
bound at import: that module stays the single composition surface for the
planning seams, so substituting one there governs every path that plans a
scenario, this one included.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.backends.raes_diagnostics import render_raes_diagnostics
from aptl.backends.raes_profiles import select_backend_profiles
from aptl.core.config import AptlConfig
from aptl.core.deployment._compose_stateful_model import artifact_source_path
from aptl.core.scenario_bundle import ScenarioSourceKind

if TYPE_CHECKING:
    from aptl.backends.raes_realization_model import AptlRealization
    from aptl.backends.raes_start_model import AdmittedScenarioStart
    from aptl.core.deployment.backend import DeploymentBackend


@dataclass(frozen=True)
class AdmittedStartSurface:
    """The pre-mutation facts one admitted scenario execution settles.

    Lab start reads every scenario-dependent decision off this instead of
    guessing from the operator's configuration ceiling or a hardcoded default
    path (issue #951):

    - ``bundle_root`` is where the Compose model the run actually uses lives. A
      project-tree bundle ships a static ``docker-compose.yml`` there; an
      env-pack ships none and the backend generates the base model from the
      realization, so there is no static model to inspect.
    - ``source_kind`` is the *resolved* source. An explicit scenario selection
      is project-tree even when the configured default names an env-pack, so
      legacy host-side producers must key off this, never ``config.scenario``.
    - ``selected_profiles`` is the realized runtime surface — the profiles
      ``docker compose --profile`` receives — not ``containers.enabled_profiles()``.
    - ``stateful_artifact_ownership`` is the exact admitted consumer set.
    """

    bundle_root: Path
    source_kind: ScenarioSourceKind
    selected_profiles: tuple[str, ...]
    stateful_artifact_ownership: frozenset[tuple[str, str, str, str, str]]


def admit_start_surface(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
) -> tuple["AdmittedScenarioStart", AdmittedStartSurface]:
    """Admit the scenario once and project the pre-start facts off it.

    Returns the admission itself alongside the surface so the caller can hand
    the same admission to the apply path rather than planning a second time.
    """

    from aptl.backends.raes import admit_raes_scenario

    admitted = admit_raes_scenario(
        project_dir, config, backend, scenario_path=scenario_path
    )
    return admitted, start_surface_of(admitted, config)


def start_surface_of(
    admitted: "AdmittedScenarioStart",
    config: AptlConfig,
) -> AdmittedStartSurface:
    """Project one admitted execution onto the facts pre-start steps need."""

    realization = _admitted_realization(admitted)
    return AdmittedStartSurface(
        bundle_root=admitted.bundle.root,
        source_kind=admitted.bundle.source_kind,
        selected_profiles=tuple(
            select_backend_profiles(config, realization.profiles)
        ),
        stateful_artifact_ownership=_artifact_ownership(
            admitted.bundle.root, realization
        ),
    )


def _admitted_realization(admitted: "AdmittedScenarioStart") -> "AptlRealization":
    """Return the admitted realization, refusing a blocking-diagnostic plan.

    A plan or realization that carries an error diagnostic never becomes a
    pre-start answer: the caller must fail closed before any legacy mutation
    rather than proceed on a partial interpretation.
    """

    blocking = [
        diagnostic
        for diagnostic in admitted.execution_plan.diagnostics
        if diagnostic.is_error
    ]
    if blocking:
        raise ValueError(render_raes_diagnostics(blocking))
    realization = admitted.realization
    if realization is None:
        raise ValueError("Admitted scenario produced no APTL realization.")
    blocking = [
        diagnostic for diagnostic in realization.diagnostics if diagnostic.is_error
    ]
    if blocking:
        raise ValueError(render_raes_diagnostics(blocking))
    return realization


def _artifact_ownership(
    root: Path,
    realization: "AptlRealization",
) -> frozenset[tuple[str, str, str, str, str]]:
    """Return exact addressed artifact consumers from the admitted graph.

    Each entry is ``(address, generator, service_name, mount_destination,
    source_relpath)``. The canonical generated source travels with the
    consumer so downstream exemptions (the bind-mount pre-flight) can match
    a mount on both sides — a stray bind whose destination merely nests
    beneath an owned directory is not owned by the artifact (issue #677).
    """

    return frozenset(
        (
            artifact.address,
            artifact.generator,
            consumer.service_name,
            consumer.mount_destination,
            artifact_source_path(root, artifact).relative_to(root).as_posix(),
        )
        for artifact in realization.generated_artifacts
        for consumer in artifact.consumers
    )


def selected_profiles_for_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
) -> list[str]:
    """Return the Compose profiles selected by a scenario without side effects."""

    _, surface = admit_start_surface(project_dir, config, backend, scenario_path)
    return list(surface.selected_profiles)


def admitted_stateful_artifact_ownership(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
) -> frozenset[tuple[str, str, str, str, str]]:
    """Return exact addressed artifact consumers from the admitted graph."""

    _, surface = admit_start_surface(project_dir, config, backend, scenario_path)
    return surface.stateful_artifact_ownership
