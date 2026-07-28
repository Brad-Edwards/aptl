"""Trusted artifact availability facts for RAES planning (ADR-050, RAES ADR-098).

RAES admits an authored ``Source.artifact_requirement`` only when the operational
facts say the artifact can actually be obtained. Those facts are *inputs* to
planning, partitioned by compiled resource address, and they are deliberately not
computed inside the planner: a planner that consulted the local image cache
directly would conflate "already pulled here" with "this scenario requires this
artifact", and would make admission depend on machine state rather than on the
authored contract.

This module is that trust boundary. It compiles the scenario to discover which
addresses carry artifact demand, asks the deployment backend whether each
immutable identity is obtainable, and returns the resulting context for the
caller to hand to ``RuntimeManager.plan``.

Compiling here is not a second planning authority. ``compile_runtime_model`` is
pure and deterministic, the admitted execution identity remains the single
``plan()`` result, and availability must by definition be known before that call.
Nothing in this module decides admission; RAES's own
``artifact_requirement_diagnostics`` does that.

Facts are reported honestly: an artifact that cannot be obtained is simply
absent from the context, which makes RAES reject the requirement with
``artifact.unavailable-exact-artifact`` rather than let APTL substitute
something else.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from raes.explicitness import ExplicitnessClass
from raes_contracts.contracts import (
    ArtifactAvailabilityContext,
    ArtifactRequirementAvailability,
)
from raes_processor.compiler import compile_runtime_model

if TYPE_CHECKING:  # pragma: no cover - typing only
    from raes.artifact_requirements import ArtifactRequirement
    from raes_processor.semantics.realization import CompiledRealizationRequirement


class ArtifactProbe(Protocol):
    """The backend capability this trust boundary needs, and nothing more."""

    def artifact_available(
        self, image_ref: str, *, allow_remote: bool | None = None
    ) -> bool:
        """Return whether one immutable artifact reference is obtainable."""
        ...


def _artifact_reference(requirement: ArtifactRequirement) -> str | None:
    """Return the pullable reference for an exact requirement, if it has one.

    Only the exact posture names a single immutable identity. Constrained and
    open requirements are resolved through candidates or materialization
    specifications, which this module does not yet supply facts for because APTL
    does not yet advertise those mechanisms.
    """

    exact = requirement.exact_artifact
    if exact is None:
        return None
    return f"{exact.artifact_id}@{exact.digest}"


def _source_artifact_requirements(
    scenario: object,
) -> list[CompiledRealizationRequirement]:
    """Return every compiled requirement that carries artifact demand."""

    # Artifact demand is authored on node/content/feature sources, so a value
    # carrying no ``nodes`` section cannot declare any. Checking first keeps the
    # compile off the hot path for such inputs instead of wrapping it in an
    # except clause, which would also swallow genuine compilation errors.
    if not getattr(scenario, "nodes", None):
        return []
    model = compile_runtime_model(scenario)
    return [
        requirement
        for requirement in model.realization_requirements
        if requirement.artifact_requirement is not None
    ]


def artifact_availability_for_scenario(
    scenario: object,
    probe: ArtifactProbe,
    *,
    allow_remote: bool | None = None,
) -> ArtifactAvailabilityContext:
    """Return address-partitioned availability facts for ``scenario``.

    Args:
        scenario: The parsed scenario whose artifact demand is being checked.
        probe: Deployment backend exposing ``artifact_available``.
        allow_remote: Whether registry-resolvable artifacts count as available.
            None lets the backend decide from its own staging mode.

    Returns:
        Context carrying one entry per address with artifact demand. An address
        whose artifact is not obtainable still gets an entry, with an empty
        digest list, so RAES reports the precise unavailability rather than a
        missing-address ambiguity.
    """

    entries: list[ArtifactRequirementAvailability] = []
    for compiled in _source_artifact_requirements(scenario):
        requirement = compiled.artifact_requirement
        if requirement is None:  # pragma: no cover - filtered above
            continue
        digests: list[str] = []
        if requirement.explicitness is ExplicitnessClass.EXACT:
            reference = _artifact_reference(requirement)
            exact = requirement.exact_artifact
            if (
                reference is not None
                and exact is not None
                and probe.artifact_available(reference, allow_remote=allow_remote)
            ):
                digests.append(exact.digest)
        entries.append(
            ArtifactRequirementAvailability(
                address=compiled.address, available_artifact_digests=digests
            )
        )
    return ArtifactAvailabilityContext(requirements=entries)
