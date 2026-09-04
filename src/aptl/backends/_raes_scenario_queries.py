"""Answer questions about an admitted scenario without starting anything.

Split out of :mod:`aptl.backends.raes` so that module keeps the start/apply flow
while this one carries the read-only queries the CLI and lab lifecycle ask
before (and instead of) a start: which Compose profiles a scenario selects, and
which stateful artifact mounts the admitted graph owns. Both plan through the
same RAES runtime manager the start path uses, so an answer here and a start
cannot disagree; neither applies the plan.

The planning seams (``create_aptl_runtime_target``, ``parse_sdl_file``,
``RuntimeManager``, ``artifact_availability_for_scenario``) are resolved from
``aptl.backends.raes`` at call time rather than bound at import: that module
stays the single composition surface for them, so substituting one there governs
every path that plans a scenario, this one included.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from aptl.backends.raes_diagnostics import render_raes_diagnostics
from aptl.backends.raes_profiles import select_backend_profiles
from aptl.backends.raes_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig
from aptl.core.deployment._compose_stateful_model import artifact_source_path

if TYPE_CHECKING:
    from raes_processor.models import ExecutionPlan

    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.scenario_bundle import ScenarioBundle


def _plan_without_applying(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None,
) -> tuple[ScenarioBundle, ExecutionPlan]:
    """Resolve, parse and plan a scenario, returning its bundle and plan."""

    from aptl.backends.raes import (
        RuntimeManager,
        artifact_availability_for_scenario,
        create_aptl_runtime_target,
        parse_sdl_file,
        prepare_runtime_orchestration_for_scenario,
        resolve_scenario_bundle,
    )

    bundle = resolve_scenario_bundle(project_dir, scenario_path, config)
    scenario = parse_sdl_file(bundle.sdl_path)
    prepare_runtime_orchestration_for_scenario(scenario, backend)
    target = create_aptl_runtime_target(
        project_dir=project_dir, config=config, backend=backend, bundle=bundle
    )
    execution_plan = RuntimeManager(target).plan(
        scenario,
        artifact_availability=artifact_availability_for_scenario(
            scenario,
            backend,
            scenario_root=bundle.root,
            component_root=project_dir,
        ),
    )
    return bundle, execution_plan


def selected_profiles_for_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
) -> list[str]:
    """Return the Compose profiles selected by a scenario without side effects."""
    bundle, execution_plan = _plan_without_applying(
        project_dir, config, backend, scenario_path
    )
    realization = interpret_provisioning_plan(
        plan=execution_plan.provisioning,
        config=config,
        bundle=bundle,
        component_root=project_dir,
    )
    return select_backend_profiles(config, realization.profiles)


def admitted_stateful_artifact_ownership(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
) -> frozenset[tuple[str, str, str, str, str]]:
    """Return exact addressed artifact consumers from the admitted graph.

    Each entry is ``(address, generator, service_name, mount_destination,
    source_relpath)``. The canonical generated source travels with the
    consumer so downstream exemptions (the bind-mount pre-flight) can match
    a mount on both sides — a stray bind whose destination merely nests
    beneath an owned directory is not owned by the artifact (issue #677).
    """

    bundle, execution_plan = _plan_without_applying(
        project_dir, config, backend, scenario_path
    )
    blocking = [
        diagnostic for diagnostic in execution_plan.diagnostics if diagnostic.is_error
    ]
    if blocking:
        raise ValueError(render_raes_diagnostics(blocking))
    realization = interpret_provisioning_plan(
        plan=execution_plan.provisioning,
        config=config,
        bundle=bundle,
        component_root=project_dir,
    )
    blocking = [
        diagnostic for diagnostic in realization.diagnostics if diagnostic.is_error
    ]
    if blocking:
        raise ValueError(render_raes_diagnostics(blocking))
    return frozenset(
        (
            artifact.address,
            artifact.generator,
            consumer.service_name,
            consumer.mount_destination,
            artifact_source_path(bundle.root, artifact)
            .relative_to(bundle.root)
            .as_posix(),
        )
        for artifact in realization.generated_artifacts
        for consumer in artifact.consumers
    )
