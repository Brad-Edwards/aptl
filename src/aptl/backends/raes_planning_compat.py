"""Apply bounded installed planning compatibility pending OpenRAE/rae#1285."""

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
from raes_contracts.planning import (
    RealizationAuthorityMode,
    RealizationResolutionSource,
)
from raes_contracts.realization_profiles import PlanProfileAuthority
from raes_contracts.run_scope import PlanScope
from raes_contracts.runtime_state import ApplyResult, RuntimeSnapshot
from raes_contracts.vocabulary import ObservationStrength
from raes_processor.compiler import compile_scenario_runtime_model
from raes_processor.models import RuntimeModel
from raes_processor.planner import plan
from raes_runtime.manager import RuntimeManager as _RaesRuntimeManager

if TYPE_CHECKING:
    from raes_processor.models import ExecutionPlan
    from raes_runtime.registry import RuntimeTarget

from aptl.core.scenario_bundle import ScenarioBundle
from aptl.backends import _raes_participant_snapshot as participant_snapshot
from aptl.backends.identity import (
    APTL_RAES_TARGET_NAME,
    APTL_RAES_TARGET_PROFILE,
    APTL_RAES_TARGET_VERSION,
    BackendIdentity,
)
from aptl.backends.scenario_planning_compatibility import (
    PlanningCompatibilityDecision,
    ResolvedPlanningCompatibility,
    ScenarioPlanningCompatibilityContext,
)
from aptl.backends.scenario_planning_compatibility_discovery import (
    resolve_scenario_planning_compatibility,
)
from aptl.backends._raes_backend_implementation_profiles import (
    backend_profile_selected_concerns,
)
from aptl.backends.raes_runtime_attestation import (
    ARTIFACT_ATTESTED_RUNTIME_CONCERNS,
)
from aptl.backends import _raes_runtime_container_observation as container_observation

_RAES_LIMIT_OVERRIDE_LOCK = RLock()

# Backend-manifest realization claims remain a core capability declaration.
# An adapter decision chooses which of these claims one pack release needs
# rewritten during planning; it cannot add a capability the manifest lacks.
DAEMON_READBACK_RUNTIME_CONCERNS = frozenset(
    {
        *ARTIFACT_ATTESTED_RUNTIME_CONCERNS,
        "linux-capabilities",
        "published-ports",
        *container_observation.RUNTIME_CONTAINER_DAEMON_CONCERNS,
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


def resolve_target_planning_compatibility(
    bundle: ScenarioBundle | None, config: object
) -> ResolvedPlanningCompatibility | None:
    """Resolve compatibility once while constructing the admitted target."""

    identity = bundle.pack_identity if isinstance(bundle, ScenarioBundle) else None
    if identity is None:
        return None
    deployment = getattr(config, "deployment", None)
    return resolve_scenario_planning_compatibility(
        ScenarioPlanningCompatibilityContext(
            pack=identity,
            backend=BackendIdentity(
                APTL_RAES_TARGET_NAME,
                APTL_RAES_TARGET_VERSION,
                APTL_RAES_TARGET_PROFILE,
                transport=str(getattr(deployment, "provider", "") or ""),
            ),
        )
    )


@contextmanager
def _runtime_value_limits(
    decision: PlanningCompatibilityDecision | None,
) -> Iterator[None]:
    """Temporarily apply an admitted finite node budget."""

    if decision is None or decision.runtime_max_nodes is None:
        yield
        return

    from raes_runtime import backend_input_contracts, backend_snapshot_contracts

    with _RAES_LIMIT_OVERRIDE_LOCK:
        input_limits = backend_input_contracts.RUNTIME_SNAPSHOT_VALUE_LIMITS
        snapshot_limits = backend_snapshot_contracts._VALUE_LIMITS
        widened_input = input_limits.model_copy(
            update={
                "max_nodes": max(input_limits.max_nodes, decision.runtime_max_nodes)
            }
        )
        widened_snapshot = snapshot_limits.model_copy(
            update={
                "max_nodes": max(snapshot_limits.max_nodes, decision.runtime_max_nodes)
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


def _selected_open_requirement(
    scenario: object | None,
    requirement: object,
    decision: PlanningCompatibilityDecision,
) -> bool:
    """Keep authored state and the two open defaults APTL actually selects."""

    kind = getattr(requirement, "requirement_kind", None)
    return (
        scenario is None
        or getattr(requirement, "explicitness", None) is not ExplicitnessClass.OPEN
        or _authored_concern(scenario, requirement)
        or _backend_profile_selects_concern(scenario, requirement)
        or (
            kind in decision.open_default_concerns
            and _image_backed_node(scenario, requirement)
        )
    )


def _backend_profile_selects_concern(scenario: object, requirement: object) -> bool:
    """Keep authority for mechanics selected by a semantic backend profile."""

    nodes = getattr(scenario, "nodes", None)
    address = getattr(requirement, "address", None)
    kind = getattr(requirement, "requirement_kind", None)
    if not isinstance(nodes, Mapping) or not isinstance(address, str):
        return False
    node = next(
        (item for name, item in nodes.items() if address == f"provision.node.{name}"),
        None,
    )
    runtime = getattr(node, "runtime", None) if node is not None else None
    return isinstance(kind, str) and kind in backend_profile_selected_concerns(runtime)


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


def apply_planning_compatibility(
    model: RuntimeModel,
    decision: PlanningCompatibilityDecision | None,
    *,
    scenario: object | None = None,
) -> RuntimeModel:
    """Apply one adapter's validated bounded compatibility decision.

    Configuration-scope corroboration remains mandatory and no evidence is
    relabelled.  For the finite concern set whose released OPEN relation RAES
    cannot evaluate, APTL commits its least-intrusive choice: exactly the
    authored value, with no backend additions, verified by native readback.
    """

    if decision is None:
        return model

    authority_identities = {
        _requirement_identity(item) for item in model.realization_authority
    }
    adjusted_identities: set[tuple[object, ...]] = set()
    delegated_identities: set[tuple[object, ...]] = set()
    exact_identities: set[tuple[object, ...]] = set()
    requirements = []
    for requirement in model.realization_requirements:
        requirement, adjusted, delegated, exact = _adjust_requirement(
            requirement,
            scenario=scenario,
            authority_identities=authority_identities,
            decision=decision,
        )
        identity = _requirement_identity(requirement)
        if adjusted:
            adjusted_identities.add(_requirement_identity(requirement))
        if delegated:
            delegated_identities.add(identity)
        if exact:
            exact_identities.add(identity)
        requirements.append(requirement)

    if not adjusted_identities and not delegated_identities and not exact_identities:
        return model

    authority = tuple(
        _adjust_authority(
            item,
            adjusted_identities,
            delegated_identities,
            exact_identities,
        )
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
    decision: PlanningCompatibilityDecision,
) -> tuple[object, bool, bool, bool]:
    """Apply delegation and provenance compatibility to one requirement."""

    identity = _requirement_identity(requirement)
    delegated = identity in authority_identities and not _selected_open_requirement(
        scenario, requirement, decision
    )
    if delegated:
        requirement = replace(requirement, explicitness=None, delegated=True)
    exact = _requires_exact_native_evidence(requirement, scenario, decision)
    if exact:
        requirement = replace(
            requirement,
            explicitness=ExplicitnessClass.EXACT,
            structure=None,
            constraint_document=None,
            constraint_binding=None,
            recursive_pending=False,
        )
    adjusted = (
        not requirement.delegated
        and requirement.requirement_kind in decision.daemon_readback_concerns
        and requirement.required_observation_strength
        is ObservationStrength.GUEST_OBSERVED
    )
    if adjusted:
        requirement = replace(
            requirement,
            required_observation_strength=ObservationStrength.DAEMON_OBSERVED,
        )
    return requirement, adjusted, delegated, exact


def _requires_exact_native_evidence(
    requirement: object,
    scenario: object | None,
    decision: PlanningCompatibilityDecision,
) -> bool:
    """Return whether minimum intrusion closes an authored open concern."""

    authored = scenario is None or _authored_concern(scenario, requirement)
    return bool(
        not requirement.delegated
        and requirement.explicitness is ExplicitnessClass.OPEN
        and requirement.requirement_kind in decision.minimum_intrusion_exact_concerns
        and authored
    )


def _adjust_authority(
    authority: object,
    adjusted: set[tuple[object, ...]],
    delegated: set[tuple[object, ...]],
    exact: set[tuple[object, ...]],
) -> object:
    """Mirror an adjusted requirement onto its compiled authority."""

    identity = _requirement_identity(authority)
    if identity in delegated:
        return replace(
            authority,
            delegated=True,
            source=RealizationResolutionSource.APPARATUS_DEFAULT,
        )
    if identity in exact:
        authority = replace(authority, mode=RealizationAuthorityMode.EXACT)
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
        self._aptl_planning_compatibility_selection = getattr(
            target.provisioner, "planning_compatibility", None
        )
        selection = self._aptl_planning_compatibility_selection
        self._aptl_planning_compatibility = (
            selection.decision if selection is not None else None
        )

    def apply(self, execution_plan: ExecutionPlan) -> ApplyResult:
        """Apply with a finite node budget for the exact released large plan."""

        with _runtime_value_limits(getattr(self, "_aptl_planning_compatibility", None)):
            return super().apply(execution_plan)

    def adopt_participant_delivery_snapshot(
        self,
        snapshot: RuntimeSnapshot,
    ) -> RuntimeSnapshot:
        """Resume manager-owned time from a governed participant delivery cut."""

        return participant_snapshot.adopt_participant_delivery_snapshot(self, snapshot)

    def plan(
        self,
        scenario: object,
        snapshot: RuntimeSnapshot | None = None,
        *,
        parameters: dict[str, object] | None = None,
        profile: str | None = None,
        artifact_availability: ArtifactAvailabilityContext | None = None,
        profile_authority: PlanProfileAuthority | None = None,
        run_scope: PlanScope | None = None,
    ) -> ExecutionPlan:
        """Compile once, adjust the identified pack, then invoke RAES once."""

        model = compile_scenario_runtime_model(
            scenario,
            parameters=parameters,
            profile=profile,
            profile_authority=profile_authority,
        )
        model = apply_planning_compatibility(
            model,
            getattr(self, "_aptl_planning_compatibility", None),
            scenario=scenario,
        )
        effective_snapshot = snapshot if snapshot is not None else self._snapshot
        scope = PlanScope(
            target_name=self._target.name,
            run_id=run_scope.run_id if run_scope is not None else None,
            instantiation_id=(
                run_scope.instantiation_id if run_scope is not None else None
            ),
        )
        return plan(
            model,
            self._target.manifest,
            effective_snapshot,
            scope=scope,
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
    "apply_planning_compatibility",
    "plan_aptl_scenario",
    "resolve_target_planning_compatibility",
]
