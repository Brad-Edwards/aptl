"""Temporary TechVault planning compatibility for OpenRAE/rae#1285."""

from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace

from raes.parser import parse_sdl
from raes.explicitness import ExplicitnessClass, ExplicitnessProvenance
from raes_contracts.planning import (
    RealizationAuthorityMode,
    RealizationResolutionSource,
)
from raes_contracts.runtime_state import RuntimeSnapshot
from raes_contracts.vocabulary import (
    ObservationStrength,
    RealizationVerificationScope,
)
from raes_processor.models import RuntimeModel
from raes_processor.semantics.realization import (
    CompiledRealizationAuthority,
    CompiledRealizationRequirement,
)

from aptl.backends.raes_planning_compat import (
    AptlRuntimeManager,
    _TECHVAULT_RUNTIME_MAX_NODES,
    apply_techvault_observation_strength_compatibility,
    plan_aptl_scenario,
)
from aptl.backends.raes_runtime_attestation import (
    TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST,
)
from aptl.core.scenario_bundle import (
    PackIdentity,
    ScenarioBundle,
    ScenarioSourceKind,
)

_ADDRESS = "provision.node.vm"
_FIELD_PREFIX = "nodes.vm.runtime"


def _bundle(tmp_path: Path, *, pack_id: str = "techvault") -> ScenarioBundle:
    return ScenarioBundle(
        identity=pack_id,
        root=tmp_path,
        sdl_path=tmp_path / "scenario.sdl.yaml",
        source_kind=ScenarioSourceKind.ENV_PACK,
        pack_identity=PackIdentity(
            pack_id=pack_id,
            pack_version="0.1.0",
            set_digest=TECHVAULT_RUNTIME_ATTESTATION_SET_DIGEST,
        ),
    )


def _requirement(
    kind: str,
    *,
    explicitness: ExplicitnessClass = ExplicitnessClass.OPEN,
    field_path: str | None = None,
) -> CompiledRealizationRequirement:
    return CompiledRealizationRequirement(
        field_path=field_path or f"{_FIELD_PREFIX}.{kind}",
        address=_ADDRESS,
        domain="runtime-realization",
        requirement_kind=kind,
        explicitness=explicitness,
        provenance=ExplicitnessProvenance.AUTHOR_DECLARED,
        governing_scope="/realization",
        verification_scope=RealizationVerificationScope.CONFIGURATION,
        required_observation_strength=ObservationStrength.GUEST_OBSERVED,
    )


def _authority(
    kind: str,
    *,
    mode: RealizationAuthorityMode = RealizationAuthorityMode.OPEN,
    field_path: str | None = None,
) -> CompiledRealizationAuthority:
    return CompiledRealizationAuthority(
        field_path=field_path or f"{_FIELD_PREFIX}.{kind}",
        address=_ADDRESS,
        domain="runtime-realization",
        requirement_kind=kind,
        payload_path=("spec", "node", "runtime", kind),
        mode=mode,
        source=RealizationResolutionSource.AUTHORED_SCOPE,
        provenance=ExplicitnessProvenance.AUTHOR_DECLARED,
        governing_scope="/realization",
        verification_scope=RealizationVerificationScope.CONFIGURATION,
        required_observation_strength=ObservationStrength.GUEST_OBSERVED,
    )


def _model(*requirements: CompiledRealizationRequirement) -> RuntimeModel:
    return RuntimeModel(
        scenario_name="techvault",
        realization_requirements=requirements,
        realization_authority=tuple(
            _authority(
                item.requirement_kind,
                field_path=item.field_path,
                mode=(
                    RealizationAuthorityMode.OPEN
                    if item.explicitness is ExplicitnessClass.OPEN
                    else RealizationAuthorityMode.EXACT
                ),
            )
            for item in requirements
        ),
    )


def test_techvault_shim_changes_only_daemon_readback_concerns(
    tmp_path: Path,
) -> None:
    environment = _requirement("runtime-environment")
    restart = _requirement("runtime-restart-policy")
    exact_ports = _requirement("published-ports", explicitness=ExplicitnessClass.EXACT)

    adjusted = apply_techvault_observation_strength_compatibility(
        _model(environment, restart, exact_ports),
        _bundle(tmp_path),
    )

    requirements = {
        item.requirement_kind: item for item in adjusted.realization_requirements
    }
    authorities = {
        item.requirement_kind: item for item in adjusted.realization_authority
    }
    assert (
        requirements["runtime-environment"].required_observation_strength
        is ObservationStrength.DAEMON_OBSERVED
    )
    assert (
        authorities["runtime-environment"].required_observation_strength
        is ObservationStrength.DAEMON_OBSERVED
    )
    assert (
        requirements["runtime-restart-policy"].required_observation_strength
        is ObservationStrength.DAEMON_OBSERVED
    )
    assert (
        requirements["published-ports"].required_observation_strength
        is ObservationStrength.DAEMON_OBSERVED
    )


def test_techvault_shim_omits_unselected_open_concerns(tmp_path: Path) -> None:
    """An open field APTL leaves absent needs neither realization nor a probe."""

    scenario = parse_sdl(
        dedent(
            """
            name: techvault
            realization: {default: open}
            nodes:
              vm:
                type: compute
                os: linux
                runtime:
                  environment:
                    - name: MODE
                      value: production
            """
        )
    )
    environment = _requirement(
        "runtime-environment", field_path="nodes.vm.runtime.environment"
    )
    processes = _requirement(
        "runtime-processes", field_path="nodes.vm.runtime.processes"
    )

    adjusted = apply_techvault_observation_strength_compatibility(
        _model(environment, processes),
        _bundle(tmp_path),
        scenario=scenario,
    )

    requirements = {
        item.requirement_kind: item for item in adjusted.realization_requirements
    }
    assert requirements["runtime-environment"].delegated is False
    assert requirements["runtime-processes"].delegated is True
    assert requirements["runtime-processes"].explicitness is None
    authority = {item.requirement_kind: item for item in adjusted.realization_authority}
    assert authority["runtime-environment"].mode is RealizationAuthorityMode.OPEN
    assert authority["runtime-processes"].delegated is True
    assert authority["runtime-processes"].mode is RealizationAuthorityMode.OPEN
    assert (
        authority["runtime-processes"].source
        is RealizationResolutionSource.APPARATUS_DEFAULT
    )


def test_techvault_shim_keeps_explicit_empty_open_concern(tmp_path: Path) -> None:
    """Explicit absence is authored state, unlike a model-provided empty default."""

    scenario = parse_sdl(
        dedent(
            """
            name: techvault
            realization: {default: open}
            nodes:
              vm:
                type: compute
                os: linux
                runtime:
                  processes: []
            """
        )
    )
    processes = _requirement(
        "runtime-processes", field_path="nodes.vm.runtime.processes"
    )

    adjusted = apply_techvault_observation_strength_compatibility(
        _model(processes),
        _bundle(tmp_path),
        scenario=scenario,
    )

    assert adjusted.realization_requirements == (processes,)


def test_techvault_shim_keeps_backend_defaults_only_for_image_nodes(
    tmp_path: Path,
) -> None:
    restart = _requirement(
        "runtime-restart-policy",
        field_path="nodes.vm.runtime.operational_policy.restart",
    )
    process_limits = _requirement(
        "process-resource-limits",
        field_path=(
            "nodes.vm.runtime.operational_policy.resource_limits.process_limits"
        ),
    )
    model = _model(restart, process_limits)
    source_backed = SimpleNamespace(
        nodes={"vm": SimpleNamespace(source=object())}, explicitness={}
    )
    image_free = SimpleNamespace(
        nodes={"vm": SimpleNamespace(source=None)}, explicitness={}
    )

    kept = apply_techvault_observation_strength_compatibility(
        model,
        _bundle(tmp_path),
        scenario=source_backed,
    )
    omitted = apply_techvault_observation_strength_compatibility(
        model,
        _bundle(tmp_path),
        scenario=image_free,
    )

    assert len(kept.realization_requirements) == 2
    assert all(item.delegated for item in omitted.realization_requirements)
    assert all(item.explicitness is None for item in omitted.realization_requirements)


def test_techvault_shim_does_not_use_scenario_name_as_pack_authority(
    tmp_path: Path,
) -> None:
    model = _model(_requirement("runtime-environment"))
    project_tree = ScenarioBundle(
        identity="techvault",
        root=tmp_path,
        sdl_path=tmp_path / "techvault.sdl.yaml",
    )

    assert (
        apply_techvault_observation_strength_compatibility(model, project_tree) is model
    )
    assert (
        apply_techvault_observation_strength_compatibility(
            model, _bundle(tmp_path, pack_id="another-pack")
        )
        is model
    )


def test_aptl_planning_applies_compatibility_before_raes_planner(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.backends import raes_planning_compat

    compiled = _model(_requirement("runtime-environment"))
    captured = {}
    monkeypatch.setattr(
        raes_planning_compat,
        "compile_scenario_runtime_model",
        lambda *args, **kwargs: compiled,
    )

    def _plan(model, manifest, snapshot, **kwargs):
        captured["model"] = model
        captured["manifest"] = manifest
        captured["snapshot"] = snapshot
        captured["options"] = kwargs
        return "planned"

    monkeypatch.setattr(raes_planning_compat, "plan", _plan)
    manifest = object()
    target = SimpleNamespace(
        name="aptl-full-remote-control-plane",
        manifest=manifest,
        provisioner=SimpleNamespace(domain_profile_context=None),
    )

    bundle = _bundle(tmp_path)
    manager = object.__new__(AptlRuntimeManager)
    manager._target = target
    manager._snapshot = RuntimeSnapshot()
    manager._aptl_bundle = bundle

    result = plan_aptl_scenario(
        target=target,
        bundle=bundle,
        scenario=object(),
        artifact_availability="availability",
        runtime_manager=manager,
    )

    assert result == "planned"
    adjusted = captured["model"].realization_requirements[0]
    assert adjusted.required_observation_strength is ObservationStrength.DAEMON_OBSERVED
    assert captured["manifest"] is manifest
    assert captured["options"]["artifact_availability"] == "availability"


def test_aptl_runtime_manager_preserves_raes_constructor_contract(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.backends import raes_planning_compat

    captured = {}

    def _init(_self, target, **kwargs):
        captured["target"] = target
        captured["options"] = kwargs

    monkeypatch.setattr(raes_planning_compat._RaesRuntimeManager, "__init__", _init)
    target = SimpleNamespace(provisioner=SimpleNamespace(bundle=None))
    snapshot = RuntimeSnapshot()
    stochastic_controls = (object(),)
    resolver = object()

    AptlRuntimeManager(
        target,
        bundle=_bundle(tmp_path),
        initial_snapshot=snapshot,
        stochastic_controls=stochastic_controls,
        information_state_context_resolver=resolver,
    )

    assert captured == {
        "target": target,
        "options": {
            "initial_snapshot": snapshot,
            "stochastic_controls": stochastic_controls,
            "information_state_context_resolver": resolver,
        },
    }


def test_aptl_runtime_manager_scopes_large_plan_limits_to_exact_pack(
    tmp_path: Path, monkeypatch
) -> None:
    from raes_runtime import backend_input_contracts, backend_snapshot_contracts
    from aptl.backends import raes_planning_compat

    original_input = backend_input_contracts.RUNTIME_SNAPSHOT_VALUE_LIMITS
    original_snapshot = backend_snapshot_contracts._VALUE_LIMITS
    captured = {}

    def _apply(_self, execution_plan):
        captured["execution_plan"] = execution_plan
        captured["input"] = backend_input_contracts.RUNTIME_SNAPSHOT_VALUE_LIMITS
        captured["snapshot"] = backend_snapshot_contracts._VALUE_LIMITS
        return "applied"

    monkeypatch.setattr(raes_planning_compat._RaesRuntimeManager, "apply", _apply)
    manager = object.__new__(AptlRuntimeManager)
    manager._aptl_bundle = _bundle(tmp_path)

    assert manager.apply("plan") == "applied"
    assert captured["execution_plan"] == "plan"
    assert captured["input"].max_nodes == _TECHVAULT_RUNTIME_MAX_NODES
    assert captured["snapshot"].max_nodes == _TECHVAULT_RUNTIME_MAX_NODES
    assert backend_input_contracts.RUNTIME_SNAPSHOT_VALUE_LIMITS is original_input
    assert backend_snapshot_contracts._VALUE_LIMITS is original_snapshot
