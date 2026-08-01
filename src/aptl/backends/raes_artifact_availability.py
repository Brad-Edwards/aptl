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
from raes.nodes import NodeType
from raes_contracts.contracts import (
    ArtifactAvailabilityContext,
    ArtifactRequirementAvailability,
)
from raes_processor.compiler import compile_runtime_model
from raes_processor.compiler.addresses import _node_address

import hashlib
from pathlib import Path

from aptl.backends.raes_artifact_mechanisms import (
    dynamic_composition_provenance_ref,
    exact_artifact_provenance_ref,
    is_dynamic_composition_requirement,
    materialization_provenance_ref,
)
from aptl.backends.raes_substrate import resolve_substrate

# The build-context root the materialization profile declares. A specification
# id names one directory beneath it and nothing else, so no scenario-specific
# path table is needed and no authored value can escape the root.
_CONTEXT_ROOT = "containers"

if TYPE_CHECKING:
    from raes.artifact_requirements import ArtifactRequirement
    from raes_processor.semantics.realization import CompiledRealizationRequirement


class ArtifactProbe(Protocol):
    """The backend capability this trust boundary needs, and nothing more."""

    def artifact_available(
        self, image_ref: str, *, allow_remote: bool | None = None
    ) -> bool:
        """Return whether one immutable artifact reference is obtainable."""
        ...

    def materialize_component_image(
        self, image_ref: str, dockerfile_path: str, context_path: str
    ) -> str | None:
        """Build one component image and return its resulting digest."""
        ...

    def substrate_image_identity(self, image_ref: str) -> "tuple[str, str] | None":
        """Return the ``(digest, media_type)`` of a locally present image ref."""
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


def _context_dockerfile(scenario_root: Path, specification_id: str) -> Path | None:
    """Return the contained Dockerfile a specification names, if it is safe.

    The specification id is authored data, so it is treated as untrusted: it must
    be a single path segment resolving beneath the profile's declared context
    root. Anything else returns nothing, which makes the specification
    unavailable rather than reaching outside the project.
    """

    if (
        not specification_id
        or "/" in specification_id
        or "\\" in specification_id
        or specification_id in {".", ".."}
    ):
        return None
    root = (scenario_root / _CONTEXT_ROOT).resolve()
    candidate = (root / specification_id / "Dockerfile").resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _materialized_specifications(
    requirement: ArtifactRequirement,
    probe: ArtifactProbe,
    scenario_root: Path | None,
    materialized: dict[str, str],
) -> tuple[list[str], list[str]]:
    """Materialize each authored specification and report what it produced.

    A built image's digest cannot be predicted, so it is only knowable by
    building. That happens here, during backend preparation, which is the timing
    the per-component build profile declares. The result is a local artifact, not
    lab state, so establishing it is fact-gathering rather than a side effect on
    the scenario.

    Only a specification whose contained Dockerfile hashes to the authored digest
    is built: a drifted context is not the artifact that was authorised.

    One specification yields exactly one artifact. Local builds are not
    reproducible — building the same context twice produces two different image
    ids — so a specification shared by several nodes is materialized once and its
    result reused. Building per node would leave every node but the last
    disclosing a digest that no longer exists under the tag.
    """

    available: list[str] = []
    digests: list[str] = []
    if scenario_root is None:
        return available, digests
    # The caller may pass a relative root; every path below is compared against
    # the resolved form so containment holds either way.
    scenario_root = scenario_root.resolve()
    for specification in sorted(
        requirement.materialization_specifications,
        key=lambda item: item.specification_id,
    ):
        dockerfile = _context_dockerfile(scenario_root, specification.specification_id)
        if dockerfile is None:
            continue
        actual = "sha256:" + hashlib.sha256(dockerfile.read_bytes()).hexdigest()
        if actual != specification.digest:
            continue
        # The specification id is the one identity both the availability pass and
        # the realization pass can derive independently, so tagging on it keeps
        # the image they each refer to the same one.
        cached = materialized.get(specification.digest)
        if cached is not None:
            available.append(specification.digest)
            digests.append(cached)
            continue
        realized = probe.materialize_component_image(
            f"{specification.specification_id}:local",
            str(dockerfile.relative_to(scenario_root)),
            str(scenario_root),
        )
        if isinstance(realized, str) and realized.startswith("sha256:"):
            materialized[specification.digest] = realized
            available.append(specification.digest)
            digests.append(realized)
    return available, digests


def _source_artifact_requirements(
    scenario: object,
) -> list[tuple[CompiledRealizationRequirement, ArtifactRequirement]]:
    """Return each compiled requirement paired with its artifact requirement.

    Pairing the two here keeps the non-null artifact requirement narrowed for
    every caller, so no downstream code re-checks a value the filter already
    guaranteed.
    """

    # Artifact demand is authored on node/content/feature sources, so a value
    # carrying no ``nodes`` section cannot declare any. Checking first keeps the
    # compile off the hot path for such inputs instead of wrapping it in an
    # except clause, which would also swallow genuine compilation errors.
    if not getattr(scenario, "nodes", None):
        return []
    model = compile_runtime_model(scenario)
    return [
        (compiled, compiled.artifact_requirement)
        for compiled in model.realization_requirements
        if compiled.artifact_requirement is not None
    ]


def artifact_availability_for_scenario(
    scenario: object,
    probe: ArtifactProbe,
    *,
    allow_remote: bool | None = None,
    scenario_root: Path | None = None,
) -> ArtifactAvailabilityContext:
    """Return address-partitioned availability facts for ``scenario``.

    Args:
        scenario: The parsed scenario whose artifact demand is being checked.
        probe: Deployment backend exposing ``artifact_available``.
        allow_remote: Whether registry-resolvable artifacts count as available.
            None lets the backend decide from its own staging mode.
        scenario_root: Root the scenario's own inputs resolve against — the
            bundle root, not the engine checkout. A component build context is
            scenario content, so a scenario handed over from elsewhere must not
            resolve one out of APTL's tree.

    Returns:
        Context carrying one entry per address with artifact demand. An address
        whose artifact is not obtainable still gets an entry, with an empty
        digest list, so RAES reports the precise unavailability rather than a
        missing-address ambiguity.
    """

    materialized: dict[str, str] = {}
    nodes_by_address = _nodes_by_address(scenario)
    entries = [
        _availability_entry(
            compiled,
            requirement,
            probe,
            allow_remote=allow_remote,
            scenario_root=scenario_root,
            materialized=materialized,
            node=nodes_by_address.get(compiled.address),
        )
        for compiled, requirement in _source_artifact_requirements(scenario)
    ]
    return ArtifactAvailabilityContext(requirements=entries)


def _availability_entry(
    compiled: CompiledRealizationRequirement,
    requirement: ArtifactRequirement,
    probe: ArtifactProbe,
    *,
    allow_remote: bool | None,
    scenario_root: Path | None,
    materialized: dict[str, str],
    node: object = None,
) -> ArtifactRequirementAvailability:
    """Return the availability facts for one compiled address.

    The digest APTL confirmed obtainable is exactly the integrity fact it can
    vouch for, and the runtime gate requires the realized digest to be disclosed
    as an integrity ref drawn from this verified set. Nothing else is claimed:
    authenticity, admission, and evidence remain empty until a trust policy
    actually verifies them.
    """

    digests: list[str] = []
    specifications: list[str] = []
    verified_inputs: list[str] = []
    provenance: list[str] = []
    if requirement.materialization_specifications:
        specifications, digests = _materialized_specifications(
            requirement, probe, scenario_root, materialized
        )
        verified_inputs = _verified_locked_inputs(requirement, probe, allow_remote)
        if specifications:
            provenance.append(materialization_provenance_ref())
    exact = _exact_digest_and_provenance(requirement, probe, allow_remote=allow_remote)
    if exact is not None:
        digests.append(exact[0])
        provenance.append(exact[1])
    substrate = _substrate_digest_and_provenance(compiled, requirement, probe, node)
    if substrate is not None:
        digests.append(substrate[0])
        provenance.append(substrate[1])
    return ArtifactRequirementAvailability(
        address=compiled.address,
        available_artifact_digests=digests,
        verified_integrity_refs=list(digests),
        verified_provenance_refs=provenance,
        available_materialization_specification_digests=specifications,
        verified_locked_input_ids=verified_inputs,
    )


def _exact_digest_and_provenance(
    requirement: ArtifactRequirement,
    probe: ArtifactProbe,
    *,
    allow_remote: bool | None,
) -> tuple[str, str] | None:
    """Return the ``(digest, provenance_ref)`` an EXACT requirement verifies, if any."""

    if requirement.explicitness is not ExplicitnessClass.EXACT:
        return None
    reference = _artifact_reference(requirement)
    exact = requirement.exact_artifact
    if (
        reference is not None
        and exact is not None
        and probe.artifact_available(reference, allow_remote=allow_remote)
    ):
        return exact.digest, exact_artifact_provenance_ref()
    return None


def _substrate_digest_and_provenance(
    compiled: CompiledRealizationRequirement,
    requirement: ArtifactRequirement,
    probe: ArtifactProbe,
    node: object,
) -> tuple[str, str] | None:
    """Return the ``(digest, provenance_ref)`` a route-3 substrate verifies, if any.

    Route 3: verify the generic substrate the node would compose onto is present
    on the target daemon (strict local-lookup, no pull), and record its digest +
    dynamic-composition provenance. RAES's trust checks require both the integrity
    ref and the provenance ref to be verified here, and the runtime gate then
    matches the container's realized digest against this set. An unresolvable
    substrate yields no verified claim.
    """

    if node is None or not is_dynamic_composition_requirement(requirement):
        return None
    substrate = resolve_substrate(
        compiled.address,
        os=str(getattr(node, "os", "") or ""),
        os_version=str(getattr(node, "os_version", "") or ""),
        runtime=getattr(node, "runtime", None),
        probe=probe,
    )
    if substrate is None:
        return None
    return substrate.digest, dynamic_composition_provenance_ref()


def _nodes_by_address(scenario: object) -> dict[str, object]:
    """Map each vm node's compiled address to its typed scenario node.

    Built with RAES's canonical ``_node_address`` factory (never by parsing an
    address), so the open-substrate resolution reads a node's typed OS and
    runtime without a second compile pass. Switch nodes realize as networks, not
    containers, so they carry no substrate.
    """

    nodes = getattr(scenario, "nodes", None)
    if not nodes:
        return {}
    return {
        _node_address(name): node
        for name, node in nodes.items()
        if getattr(node, "type", None) is not NodeType.SWITCH
    }


def _verified_locked_inputs(
    requirement: ArtifactRequirement,
    probe: ArtifactProbe,
    allow_remote: bool | None,
) -> list[str]:
    """Return the locked inputs whose immutable base artifact is obtainable.

    A locked input is verified when its base artifact is genuinely obtainable;
    an unobtainable base means the build cannot be reproduced from what the
    author pinned.
    """

    return [
        locked.input_id
        for locked in requirement.locked_inputs
        if locked.artifact is not None
        and probe.artifact_available(
            f"{locked.artifact.artifact_id}@{locked.artifact.digest}",
            allow_remote=allow_remote,
        )
    ]
