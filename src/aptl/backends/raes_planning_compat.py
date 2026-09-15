"""Temporary RAES planning compatibility for the TechVault environment pack.

OpenRAE/rae#1285 tracks the upstream contract change that lets an author
require corroboration without selecting where the backend obtains it.  RAES
4.1 currently assigns ``guest-observed`` to runtime concern kinds regardless
of author intent.  TechVault is explicitly substrate-agnostic, while APTL
reads the concern set below from the Docker daemon without adding a probe to
the scenario.

Keep this adapter narrow and removable (APTL #1017): only a content-identified
TechVault environment pack and only concern kinds backed by APTL daemon
readback are adjusted.  Realization explicitness governs the value, not the
un-authored evidence source, so an exact value may still use daemon readback.
Unsupported concerns retain the upstream requirement and therefore continue
to fail admission when APTL cannot meet it.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from threading import RLock
from typing import TYPE_CHECKING

from raes.explicitness import ExplicitnessClass
from raes_contracts.artifact_requirements import ArtifactAvailabilityContext
from raes_contracts.contracts import (
    ExperimentStochasticControlModel,
    ParticipantInformationStateContextResolver,
)
from raes_contracts.planning import RealizationResolutionSource
from raes_contracts.realization_profiles import PlanProfileAuthority
from raes_contracts.runtime_state import ApplyResult, RuntimeSnapshot
from raes_contracts.vocabulary import ObservationStrength
from raes_processor.compiler import compile_scenario_runtime_model
from raes_processor.models import RuntimeModel
from raes_processor.planner import plan
from raes_runtime.manager import RuntimeManager as _RaesRuntimeManager

if TYPE_CHECKING:
    from raes_processor.models import ExecutionPlan
    from raes_runtime.registry import RuntimeTarget

from aptl.core.scenario_bundle import ScenarioBundle, ScenarioSourceKind
from aptl.backends.raes_runtime_attestation import (
    ARTIFACT_ATTESTED_RUNTIME_CONCERNS,
    TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST,
)

TECHVAULT_PACK_ID = "techvault"
TECHVAULT_PACK_VERSION = "0.1.0"

# RAES 4.1.0 expands the released TechVault plan to 87,526 portable-value
# nodes, above its general 65,536 backend input/snapshot traversal cap.  Keep a
# finite power-of-two ceiling for this exact content-identified release while
# the upstream runtime learns to admit a complete large authority inventory.
_TECHVAULT_RUNTIME_MAX_NODES = 131_072
_RAES_LIMIT_OVERRIDE_LOCK = RLock()

# Every member has a real host-side readback in raes_runtime_observation.py.
# Forwarding agents are already daemon-observed in RAES and need no rewrite.
DAEMON_READBACK_RUNTIME_CONCERNS = frozenset(
    {
        *ARTIFACT_ATTESTED_RUNTIME_CONCERNS,
        "linux-capabilities",
        "published-ports",
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
)

# APTL deliberately selects these values when an open node leaves them absent:
# the restart policy keeps long-lived services alive, and the process limits are
# the minimum required by the exact OpenSearch artifacts.  They therefore stay
# in the demand graph and must be observed/disclosed as backend-realized state.
_APTL_OPEN_DEFAULT_CONCERNS = frozenset(
    {"process-resource-limits", "runtime-restart-policy"}
)


def _is_identified_techvault_pack(bundle: ScenarioBundle) -> bool:
    """Return whether this is the exact pack authorized for compatibility."""

    identity = bundle.pack_identity
    return (
        bundle.source_kind is ScenarioSourceKind.ENV_PACK
        and identity is not None
        and identity.pack_id == TECHVAULT_PACK_ID
        and identity.pack_version == TECHVAULT_PACK_VERSION
        and identity.set_digest == TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST
    )


@contextmanager
def _techvault_runtime_value_limits(
    bundle: ScenarioBundle | None,
) -> Iterator[None]:
    """Temporarily retain RAES's finite bounds with a larger node budget."""

    if bundle is None or not _is_identified_techvault_pack(bundle):
        yield
        return

    from raes_runtime import backend_input_contracts, backend_snapshot_contracts

    with _RAES_LIMIT_OVERRIDE_LOCK:
        input_limits = backend_input_contracts.RUNTIME_SNAPSHOT_VALUE_LIMITS
        snapshot_limits = backend_snapshot_contracts._VALUE_LIMITS
        widened_input = input_limits.model_copy(
            update={
                "max_nodes": max(input_limits.max_nodes, _TECHVAULT_RUNTIME_MAX_NODES)
            }
        )
        widened_snapshot = snapshot_limits.model_copy(
            update={
                "max_nodes": max(
                    snapshot_limits.max_nodes, _TECHVAULT_RUNTIME_MAX_NODES
                )
            }
        )
        backend_input_contracts.RUNTIME_SNAPSHOT_VALUE_LIMITS = widened_input
        backend_snapshot_contracts._VALUE_LIMITS = widened_snapshot
        try:
            yield
        finally:
            backend_input_contracts.RUNTIME_SNAPSHOT_VALUE_LIMITS = input_limits
            backend_snapshot_contracts._VALUE_LIMITS = snapshot_limits


def _requirement_identity(item: object) -> tuple[object, ...]:
    """Return the stable identity joining a requirement to its authority."""

    return (
        getattr(item, "address", None),
        getattr(item, "field_path", None),
        getattr(item, "domain", None),
        getattr(item, "requirement_kind", None),
    )


def _authored_concern(scenario: object, requirement: object) -> bool:
    """Return whether the SDL explicitly contains this concern path.

    RAES preserves the parser's semantic explicitness map through variable
    instantiation, while Pydantic necessarily marks every reconstructed model
    default as set.  The explicitness map is therefore the authority boundary:
    an explicit empty collection has a record at its field path, while an
    equal-looking schema default does not.
    """

    explicitness = getattr(scenario, "explicitness", None)
    field_path = getattr(requirement, "field_path", None)
    if not isinstance(explicitness, Mapping) or not isinstance(field_path, str):
        return True
    return any(
        path == field_path
        or path.startswith(f"{field_path}.")
        or path.startswith(f"{field_path}[")
        for path in explicitness
    )


def _selected_open_requirement(scenario: object | None, requirement: object) -> bool:
    """Keep authored state and the two open defaults APTL actually selects."""

    kind = getattr(requirement, "requirement_kind", None)
    return (
        scenario is None
        or getattr(requirement, "explicitness", None) is not ExplicitnessClass.OPEN
        or _authored_concern(scenario, requirement)
        or (
            kind in _APTL_OPEN_DEFAULT_CONCERNS
            and _image_backed_node(scenario, requirement)
        )
    )


def _image_backed_node(scenario: object, requirement: object) -> bool:
    """Return whether a requirement's node has a materialized image source."""

    nodes = getattr(scenario, "nodes", None)
    address = getattr(requirement, "address", None)
    if not isinstance(nodes, Mapping) or not isinstance(address, str):
        return True
    node = next(
        (item for name, item in nodes.items() if address == f"provision.node.{name}"),
        None,
    )
    return node is None or getattr(node, "source", None) is not None


def apply_techvault_observation_strength_compatibility(
    model: RuntimeModel,
    bundle: ScenarioBundle,
    *,
    scenario: object | None = None,
) -> RuntimeModel:
    """Use honest daemon evidence for open TechVault concerns RAES overbinds.

    This changes only the required provenance floor.  Configuration-scope
    corroboration remains mandatory, and the runtime snapshot must still carry
    a matching daemon-observed disclosure.  No evidence is relabelled and no
    unsupported concern is admitted.
    """

    if not _is_identified_techvault_pack(bundle):
        return model

    authority_identities = {
        _requirement_identity(item) for item in model.realization_authority
    }
    adjusted_identities: set[tuple[object, ...]] = set()
    delegated_identities: set[tuple[object, ...]] = set()
    requirements = []
    for requirement in model.realization_requirements:
        requirement, adjusted, delegated = _adjust_requirement(
            requirement,
            scenario=scenario,
            authority_identities=authority_identities,
        )
        identity = _requirement_identity(requirement)
        if adjusted:
            adjusted_identities.add(_requirement_identity(requirement))
        if delegated:
            delegated_identities.add(identity)
        requirements.append(requirement)

    if not adjusted_identities and not delegated_identities:
        return model

    authority = tuple(
        _adjust_authority(item, adjusted_identities, delegated_identities)
        for item in model.realization_authority
    )
    return replace(
        model,
        realization_requirements=tuple(requirements),
        realization_authority=authority,
    )


def _adjust_requirement(
    requirement: object,
    *,
    scenario: object | None,
    authority_identities: set[tuple[object, ...]],
) -> tuple[object, bool, bool]:
    """Apply delegation and provenance compatibility to one requirement."""

    identity = _requirement_identity(requirement)
    delegated = identity in authority_identities and not _selected_open_requirement(
        scenario, requirement
    )
    if delegated:
        requirement = replace(requirement, explicitness=None, delegated=True)
    adjusted = (
        not requirement.delegated
        and requirement.requirement_kind in DAEMON_READBACK_RUNTIME_CONCERNS
        and requirement.required_observation_strength
        is ObservationStrength.GUEST_OBSERVED
    )
    if adjusted:
        requirement = replace(
            requirement,
            required_observation_strength=ObservationStrength.DAEMON_OBSERVED,
        )
    return requirement, adjusted, delegated


def _adjust_authority(
    authority: object,
    adjusted: set[tuple[object, ...]],
    delegated: set[tuple[object, ...]],
) -> object:
    """Mirror an adjusted requirement onto its compiled authority."""

    identity = _requirement_identity(authority)
    if identity in delegated:
        return replace(
            authority,
            delegated=True,
            source=RealizationResolutionSource.APPARATUS_DEFAULT,
        )
    if (
        identity in adjusted
        and authority.required_observation_strength
        is ObservationStrength.GUEST_OBSERVED
    ):
        return replace(
            authority,
            required_observation_strength=ObservationStrength.DAEMON_OBSERVED,
        )
    return authority


class AptlRuntimeManager(_RaesRuntimeManager):
    """RAES runtime manager with APTL's removable TechVault compile adapter."""

    def __init__(
        self,
        target: RuntimeTarget,
        *,
        bundle: ScenarioBundle | None = None,
        initial_snapshot: RuntimeSnapshot | None = None,
        stochastic_controls: Iterable[ExperimentStochasticControlModel] = (),
        information_state_context_resolver: (
            ParticipantInformationStateContextResolver | None
        ) = None,
    ) -> None:
        super().__init__(
            target,
            initial_snapshot=initial_snapshot,
            stochastic_controls=stochastic_controls,
            information_state_context_resolver=information_state_context_resolver,
        )
        self._aptl_bundle = bundle or getattr(target.provisioner, "bundle", None)

    def apply(self, execution_plan: ExecutionPlan) -> ApplyResult:
        """Apply with a finite node budget for the exact released large plan."""

        with _techvault_runtime_value_limits(self._aptl_bundle):
            return super().apply(execution_plan)

    def plan(
        self,
        scenario: object,
        snapshot: RuntimeSnapshot | None = None,
        *,
        parameters: dict[str, object] | None = None,
        profile: str | None = None,
        artifact_availability: ArtifactAvailabilityContext | None = None,
        profile_authority: PlanProfileAuthority | None = None,
    ) -> ExecutionPlan:
        """Compile once, adjust the identified pack, then invoke RAES once."""

        model = compile_scenario_runtime_model(
            scenario,
            parameters=parameters,
            profile=profile,
            profile_authority=profile_authority,
        )
        if isinstance(self._aptl_bundle, ScenarioBundle):
            model = apply_techvault_observation_strength_compatibility(
                model,
                self._aptl_bundle,
                scenario=scenario,
            )
        effective_snapshot = snapshot if snapshot is not None else self._snapshot
        return plan(
            model,
            self._target.manifest,
            effective_snapshot,
            target_name=self._target.name,
            artifact_availability=artifact_availability,
            profile_context=getattr(
                self._target.provisioner,
                "domain_profile_context",
                None,
            ),
        )


@dataclass(frozen=True)
class AptlPlanningOptions:
    """Optional inputs to one APTL-adjusted RAES planning operation."""

    snapshot: RuntimeSnapshot | None = None
    parameters: Mapping[str, object] | None = None
    profile: str | None = None
    artifact_availability: ArtifactAvailabilityContext | None = None
    profile_authority: PlanProfileAuthority | None = None
    runtime_manager: _RaesRuntimeManager | None = None


def plan_aptl_scenario(
    *,
    target: RuntimeTarget,
    bundle: ScenarioBundle,
    scenario: object,
    options: AptlPlanningOptions | None = None,
) -> ExecutionPlan:
    """Compile and plan through APTL's temporary TechVault compatibility seam."""

    selected = options or AptlPlanningOptions()
    manager = selected.runtime_manager or AptlRuntimeManager(target, bundle=bundle)
    plan_options: dict[str, object] = {}
    if selected.parameters is not None:
        plan_options["parameters"] = dict(selected.parameters)
    if selected.profile is not None:
        plan_options["profile"] = selected.profile
    if selected.artifact_availability is not None:
        plan_options["artifact_availability"] = selected.artifact_availability
    if selected.profile_authority is not None:
        plan_options["profile_authority"] = selected.profile_authority
    return (
        manager.plan(scenario, **plan_options)
        if selected.snapshot is None
        else manager.plan(scenario, selected.snapshot, **plan_options)
    )


__all__ = [
    "AptlRuntimeManager",
    "AptlPlanningOptions",
    "DAEMON_READBACK_RUNTIME_CONCERNS",
    "apply_techvault_observation_strength_compatibility",
    "plan_aptl_scenario",
]
