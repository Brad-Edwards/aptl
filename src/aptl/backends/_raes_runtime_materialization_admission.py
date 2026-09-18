"""Post-plan runtime qualification and deferred component materialization."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from raes_contracts.contracts import ArtifactAvailabilityContext

from aptl.backends.raes_artifact_availability import (
    artifact_availability_for_scenario,
)
from aptl.backends.raes_diagnostics import PROVISIONING_ADDRESS, diagnostic
from aptl.backends.raes_provisioner import AptlProvisioner

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.scenario_bundle import ScenarioBundle


def _failed_materialization_addresses(
    inspected: ArtifactAvailabilityContext,
    materialized: ArtifactAvailabilityContext,
) -> tuple[str, ...]:
    """Return addresses whose inspected build specification failed to build."""

    completed = {
        item.address: set(item.available_materialization_specification_digests)
        for item in materialized.requirements
    }
    return tuple(
        item.address
        for item in inspected.requirements
        if item.available_materialization_specification_digests
        and not set(item.available_materialization_specification_digests).issubset(
            completed.get(item.address, set())
        )
    )


def _has_materialization_specifications(
    availability: ArtifactAvailabilityContext,
) -> bool:
    """Whether the read-only facts contain a deferred component build."""

    return any(
        item.available_materialization_specification_digests
        for item in availability.requirements
    )


def _materialized_availability(
    *,
    scenario: object,
    backend: "DeploymentBackend",
    bundle: "ScenarioBundle",
    project_dir: Path,
) -> ArtifactAvailabilityContext:
    """Build component images only after graph qualification succeeds."""

    return artifact_availability_for_scenario(
        scenario,
        backend,
        scenario_root=bundle.root,
        component_root=project_dir,
        materialize=True,
    )


def _deployment_spec(
    provisioner: AptlProvisioner,
    realization: object,
    execution_plan: object,
) -> object | None:
    """Lower one admitted plan or append its bounded diagnostic."""

    selected_profiles = provisioner.selected_profiles(realization)
    try:
        result = realization.deployment_spec(selected_profiles)
    except (TypeError, ValueError) as exc:
        execution_plan.diagnostics.append(
            diagnostic(
                "aptl.provisioner.realization-not-lowerable",
                PROVISIONING_ADDRESS,
                str(exc),
            )
        )
        result = None
    return result


def _finish_materialization(
    execution_plan: object,
    provisioner: AptlProvisioner,
    availability: ArtifactAvailabilityContext,
    materialized: ArtifactAvailabilityContext,
) -> tuple[object, ArtifactAvailabilityContext]:
    """Apply materialized facts or append the bounded failure diagnostic."""

    unavailable = _failed_materialization_addresses(availability, materialized)
    result_plan = execution_plan
    result_availability = availability
    if unavailable:
        execution_plan.diagnostics.append(
            diagnostic(
                "aptl.provisioner.artifact-materialization-failed",
                unavailable[0],
                "Qualified component image materialization failed.",
            )
        )
    else:
        provisioner.artifact_availability = materialized
        result_plan = replace(execution_plan, artifact_availability=materialized)
        result_availability = materialized
    return result_plan, result_availability


def qualify_admitted_runtime(
    *,
    scenario: object,
    bundle: "ScenarioBundle",
    project_dir: Path,
    provisioner: object,
    realization: object | None,
    execution_plan: object,
    availability: ArtifactAvailabilityContext,
) -> tuple[object, ArtifactAvailabilityContext]:
    """Qualify one valid plan and materialize only on a supported backend."""

    eligible = (
        isinstance(provisioner, AptlProvisioner)
        and realization is not None
        and not any(item.is_error for item in execution_plan.diagnostics)
    )
    result = (execution_plan, availability)
    if eligible:
        backend = provisioner.deployment_backend
        deployment_spec = _deployment_spec(provisioner, realization, execution_plan)
        if deployment_spec is not None:
            qualification = backend.qualify_runtime_materialization(
                deployment_spec,
                scenario_root=bundle.root,
            )
            should_materialize = (
                qualification.success
                and _has_materialization_specifications(availability)
            )
            if should_materialize:
                materialized = _materialized_availability(
                    scenario=scenario,
                    backend=backend,
                    bundle=bundle,
                    project_dir=project_dir,
                )
                result = _finish_materialization(
                    execution_plan,
                    provisioner,
                    availability,
                    materialized,
                )
    return result
