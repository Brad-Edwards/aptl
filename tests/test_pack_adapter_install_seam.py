"""Regression contract for issue #980's installed pack-adapter seams."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from aptl.backends.identity import BackendIdentity
from aptl.backends.pack_interaction import (
    ComponentGroupMembership,
    PackBackendInteractionContext,
    PackBackendInteractionResult,
)
from aptl.backends.pack_interaction_discovery import (
    PackBackendInteractionError,
    resolve_pack_backend_interaction,
)
from aptl.backends.scenario_capture import (
    ScenarioCaptureContribution,
    ScenarioCaptureContext,
)
from aptl.backends.scenario_capture_discovery import (
    ScenarioCaptureProviderError,
    resolve_scenario_capture,
)
from aptl.backends.scenario_planning_compatibility import (
    PlanningCompatibilityDecision,
    ScenarioPlanningCompatibilityContext,
)
from aptl.backends.scenario_planning_compatibility_discovery import (
    ScenarioPlanningCompatibilityError,
    resolve_scenario_planning_compatibility,
)
from aptl.backends.scenario_startup import (
    ScenarioStartupPlan,
    ScenarioStartupSelection,
    StartupCapability,
    StartupHook,
    StartupPreparationPhase,
    StartupProviderProvenance,
)
from aptl.core.config import AptlConfig
from aptl.core.evidence.adapters.wiring import build_collectors
from aptl.core.experiment.capture_registry import (
    CaptureLimits,
    CaptureVisibility,
    CollectorRegistration,
    CollectorRegistry,
)
from aptl.core.scenario_bundle import PackIdentity


PACK = PackIdentity("otherpack", "1.0.0", "sha256:" + "a" * 64)
BACKEND = BackendIdentity(
    "aptl", "0.1.0", "full-remote-control-plane", transport="docker"
)


class _EntryPoint:
    name = "otherpack.aptl"
    dist = SimpleNamespace(name="otherpack-adapter", version="1.0.0")

    def __init__(self, target: object) -> None:
        self.target = target

    def load(self) -> object:
        return self.target


def _registration() -> CollectorRegistration:
    return CollectorRegistration(
        registration_id="otherpack.collector.events",
        implementation_version="1.0.0",
        contract_version="experiment-capture-spec/v1",
        channel_kind="evaluation-history",
        capture_kind="observation",
        capture_scope="participant",
        window_kinds=frozenset({"run"}),
        media_types=frozenset({"application/json"}),
        required_artifact_roles=frozenset({"observation"}),
        supported_sensitivities=frozenset({"internal"}),
        supports_redaction=True,
        integrity_modes=frozenset({"sha256-digest"}),
        sealing_modes=frozenset({"digest"}),
        supports_chain_of_custody=False,
        supports_retention=True,
        supports_loss_disclosure=True,
        visibility_class=CaptureVisibility.EVALUATOR_ONLY,
        limits=CaptureLimits(4096, 10, 60),
    )


class _CaptureProvider:
    provider_id = "otherpack-capture"
    extension_api_version = "1"
    supported_pack_id = "otherpack"
    supported_pack_versions = ("1.0.0",)
    supported_pack_set_digests = (PACK.set_digest,)
    backend_target_name = "aptl"
    backend_target_versions = ("0.1.0",)
    backend_profiles = ("full-remote-control-plane",)
    backend_transports = ("docker",)

    @staticmethod
    def resolve(_context: ScenarioCaptureContext) -> ScenarioCaptureContribution:
        return ScenarioCaptureContribution(registrations=(_registration(),))


class _PlanningProvider:
    provider_id = "otherpack-planning"
    extension_api_version = "1"
    supported_pack_id = "otherpack"
    supported_pack_versions = ("1.0.0",)
    supported_pack_set_digests = (PACK.set_digest,)
    backend_target_name = "aptl"
    backend_target_versions = ("0.1.0",)
    backend_profiles = ("full-remote-control-plane",)
    backend_transports = ("docker",)

    @staticmethod
    def resolve(
        _context: ScenarioPlanningCompatibilityContext,
    ) -> PlanningCompatibilityDecision:
        return PlanningCompatibilityDecision(runtime_max_nodes=131_072)


def test_capture_provider_supplies_the_request_scoped_registry(monkeypatch) -> None:
    monkeypatch.setattr(
        "aptl.backends.scenario_capture_discovery._entry_points",
        lambda: [_EntryPoint(_CaptureProvider())],
    )

    resolved = resolve_scenario_capture(ScenarioCaptureContext(PACK, BACKEND))

    assert resolved.registry == CollectorRegistry((_registration(),))
    assert resolved.provider_id == "otherpack-capture"
    assert resolved.distribution == "otherpack-adapter"


def test_collector_wiring_accepts_only_the_supplied_registry() -> None:
    registry = CollectorRegistry((_registration(),))
    source = SimpleNamespace(fetch=lambda _start, _end: None)

    assert set(build_collectors({"otherpack.collector.events": source}, registry)) == {
        "otherpack.collector.events"
    }
    with pytest.raises(ValueError, match="unknown collector registration id"):
        build_collectors({"otherpack.collector.unknown": source}, registry)


def test_planning_compatibility_is_selected_from_the_exact_pack(monkeypatch) -> None:
    monkeypatch.setattr(
        "aptl.backends.scenario_planning_compatibility_discovery._entry_points",
        lambda: [_EntryPoint(_PlanningProvider())],
    )

    resolved = resolve_scenario_planning_compatibility(
        ScenarioPlanningCompatibilityContext(PACK, BACKEND)
    )

    assert resolved is not None
    assert resolved.decision.runtime_max_nodes == 131_072
    assert resolved.provider_id == "otherpack-planning"


def test_stale_adapter_claims_are_incompatible_not_malformed(monkeypatch) -> None:
    capture = _CaptureProvider()
    capture.supported_pack_versions = ("0.9.0",)
    monkeypatch.setattr(
        "aptl.backends.scenario_capture_discovery._entry_points",
        lambda: [_EntryPoint(capture)],
    )
    capture_context = ScenarioCaptureContext(PACK, BACKEND)
    with pytest.raises(ScenarioCaptureProviderError, match="provider-missing"):
        resolve_scenario_capture(capture_context)

    planning = _PlanningProvider()
    planning.supported_pack_versions = ("0.9.0",)
    monkeypatch.setattr(
        "aptl.backends.scenario_planning_compatibility_discovery._entry_points",
        lambda: [_EntryPoint(planning)],
    )
    assert (
        resolve_scenario_planning_compatibility(
            ScenarioPlanningCompatibilityContext(PACK, BACKEND)
        )
        is None
    )


def test_planning_compatibility_rejects_unbounded_concern_data(monkeypatch) -> None:
    provider = _PlanningProvider()
    provider.resolve = lambda _context: PlanningCompatibilityDecision(
        daemon_readback_concerns=frozenset({"not a concern id"})
    )
    monkeypatch.setattr(
        "aptl.backends.scenario_planning_compatibility_discovery._entry_points",
        lambda: [_EntryPoint(provider)],
    )

    planning_context = ScenarioPlanningCompatibilityContext(PACK, BACKEND)
    with pytest.raises(
        ScenarioPlanningCompatibilityError, match="provider-result-invalid"
    ):
        resolve_scenario_planning_compatibility(planning_context)


@pytest.mark.parametrize(
    ("field", "concern"),
    [
        ("daemon_readback_concerns", "syntactically-valid-but-unauthorized"),
        ("open_default_concerns", "service-listeners"),
        ("minimum_intrusion_exact_concerns", "service-listeners"),
    ],
)
def test_planning_compatibility_rejects_semantically_unauthorized_concerns(
    monkeypatch, field: str, concern: str
) -> None:
    provider = _PlanningProvider()
    provider.resolve = lambda _context: PlanningCompatibilityDecision(
        **{field: frozenset({concern})}
    )
    monkeypatch.setattr(
        "aptl.backends.scenario_planning_compatibility_discovery._entry_points",
        lambda: [_EntryPoint(provider)],
    )

    planning_context = ScenarioPlanningCompatibilityContext(PACK, BACKEND)
    with pytest.raises(
        ScenarioPlanningCompatibilityError, match="provider-result-invalid"
    ):
        resolve_scenario_planning_compatibility(planning_context)


def test_pack_provider_defines_safe_operator_groups(monkeypatch) -> None:
    provider = SimpleNamespace(
        provider_id="otherpack-serving",
        extension_api_version="1",
        supported_pack_id="otherpack",
        supported_pack_versions=("1.0.0",),
        supported_pack_set_digests=(PACK.set_digest,),
        backend_target_name="aptl",
        backend_target_versions=("0.1.0",),
        backend_profiles=("full-remote-control-plane",),
        backend_transports=("docker",),
        resolve=lambda context: PackBackendInteractionResult(
            tuple(
                ComponentGroupMembership(address, ("blue-team",))
                for address in context.component_addresses
            )
        ),
    )
    monkeypatch.setattr(
        "aptl.backends.pack_interaction_discovery._entry_points",
        lambda: [_EntryPoint(provider)],
    )
    context = PackBackendInteractionContext(PACK, BACKEND, ("provision.node.a",))

    assert resolve_pack_backend_interaction(context).operator_groups == ("blue-team",)

    provider.resolve = lambda context: PackBackendInteractionResult(
        (ComponentGroupMembership(context.component_addresses[0], ("--project",)),)
    )
    with pytest.raises(PackBackendInteractionError, match="mapping-invalid"):
        resolve_pack_backend_interaction(context)


def test_startup_contract_uses_generic_hook_slots() -> None:
    assert {item.name for item in StartupCapability}.isdisjoint(
        {"WAZUH", "SOC", "WAZUH_REPAIR"}
    )
    assert StartupHook.STACK_ENVIRONMENT.value == "stack_environment"
    assert StartupHook.BEFORE_BACKEND_RETRY.value == "before_backend_retry"


def test_installed_provider_owns_its_preparation_path(tmp_path: Path) -> None:
    from aptl.core.lab import (
        StartSelection,
        _LabStartContext,
        _run_start_stage,
        _step_sync_credentials,
    )
    from aptl.core.scenario_bundle import ScenarioBundle, ScenarioSourceKind

    phases: list[StartupPreparationPhase | None] = []

    class AlternateStartup:
        @staticmethod
        def prepare_stack_environment(context) -> None:
            # This pack deliberately performs no legacy stack operation.
            phases.append(context.preparation_phase)

    plan = ScenarioStartupPlan(
        "scripts/seed.sh",
        ("blue-team",),
        ("blue-team",),
        startup_hooks=frozenset({StartupHook.STACK_ENVIRONMENT}),
    )
    bundle = ScenarioBundle(
        "otherpack",
        tmp_path,
        tmp_path / "otherpack.sdl.yaml",
        ScenarioSourceKind.ENV_PACK,
        PACK,
    )
    provider_selection = ScenarioStartupSelection(
        PACK,
        AlternateStartup(),
        plan,
        StartupProviderProvenance("otherpack-adapter", "1.0.0", "otherpack"),
    )
    ctx = _LabStartContext(tmp_path, skip_seed=False)
    ctx.start_selection = StartSelection(AptlConfig(), bundle, plan, provider_selection)

    stage = _run_start_stage(ctx, _step_sync_credentials)

    assert stage.error is None
    assert phases == [StartupPreparationPhase.PRE_START_CONFIGURATION]
    assert not (tmp_path / "config").exists()


def test_admitted_pack_groups_drive_production_profile_selection(
    tmp_path: Path,
) -> None:
    from aptl.backends.raes_provisioner import AptlProvisioner
    from aptl.core.scenario_bundle import ScenarioBundle, ScenarioSourceKind

    bundle = ScenarioBundle(
        "otherpack",
        tmp_path,
        tmp_path / "otherpack.sdl.yaml",
        ScenarioSourceKind.ENV_PACK,
        PACK,
    )
    provisioner = AptlProvisioner(tmp_path, AptlConfig(), object(), bundle)
    realization = SimpleNamespace(
        profiles=frozenset({"blue-team"}),
        pack_interaction=SimpleNamespace(operator_groups=("blue-team",)),
    )

    assert provisioner.selected_profiles(realization) == ["blue-team"]


def test_reset_uses_persisted_adapter_when_current_config_is_absent(
    tmp_path: Path, monkeypatch
) -> None:
    from aptl.backends import scenario_startup
    from aptl.core.lab import _reset_selected_scenario_state
    from aptl.core.startup_reset_state import (
        StartupResetAuthority,
        persist_startup_reset_authority,
    )

    resets: list[object] = []
    provider = SimpleNamespace(
        extension_api_version="1",
        supported_pack_id=PACK.pack_id,
        supported_pack_versions=(PACK.pack_version,),
        supported_pack_set_digests=(PACK.set_digest,),
        resolve=lambda _bundle: None,
        reset=lambda context: resets.append(context.backend),
    )
    startup_entry = SimpleNamespace(
        name="otherpack",
        dist=SimpleNamespace(name="otherpack-adapter", version="1.0.0"),
        load=lambda: provider,
    )
    monkeypatch.setattr(scenario_startup, "_entry_points", lambda: [startup_entry])
    persist_startup_reset_authority(
        tmp_path,
        StartupResetAuthority(
            PACK.pack_id,
            PACK.pack_version,
            PACK.set_digest,
            "otherpack-adapter",
            "1.0.0",
            "otherpack",
        ),
    )
    backend = object()

    assert _reset_selected_scenario_state(tmp_path, backend) is None
    assert resets == [backend]

    upgraded_entry = SimpleNamespace(
        name="otherpack",
        dist=SimpleNamespace(name="otherpack-adapter", version="2.0.0"),
        load=lambda: provider,
    )
    monkeypatch.setattr(scenario_startup, "_entry_points", lambda: [upgraded_entry])

    # The retired 1.0.0 receipt must not select the obsolete adapter again.
    assert _reset_selected_scenario_state(tmp_path, backend) is None
    assert resets == [backend]

    persist_startup_reset_authority(
        tmp_path,
        StartupResetAuthority(
            PACK.pack_id,
            PACK.pack_version,
            PACK.set_digest,
            "otherpack-adapter",
            "2.0.0",
            "otherpack",
            admission_id="new-run",
        ),
    )
    assert _reset_selected_scenario_state(tmp_path, backend) is None
    assert resets == [backend, backend]


def test_failed_reset_authority_remains_retryable(tmp_path: Path, monkeypatch) -> None:
    from aptl.backends import scenario_startup
    from aptl.core.lab import _reset_selected_scenario_state
    from aptl.core.startup_reset_state import (
        StartupResetAuthority,
        persist_startup_reset_authority,
    )

    attempts = 0

    def reset(_context: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("transient")

    provider = SimpleNamespace(
        extension_api_version="1",
        supported_pack_id=PACK.pack_id,
        supported_pack_versions=(PACK.pack_version,),
        supported_pack_set_digests=(PACK.set_digest,),
        resolve=lambda _bundle: None,
        reset=reset,
    )
    startup_entry = SimpleNamespace(
        name="otherpack",
        dist=SimpleNamespace(name="otherpack-adapter", version="1.0.0"),
        load=lambda: provider,
    )
    monkeypatch.setattr(scenario_startup, "_entry_points", lambda: [startup_entry])
    persist_startup_reset_authority(
        tmp_path,
        StartupResetAuthority(
            PACK.pack_id,
            PACK.pack_version,
            PACK.set_digest,
            "otherpack-adapter",
            "1.0.0",
            "otherpack",
        ),
    )

    assert _reset_selected_scenario_state(tmp_path, object()) is not None
    assert _reset_selected_scenario_state(tmp_path, object()) is None
    assert attempts == 2


def test_framework_has_no_techvault_capture_implementation_imports() -> None:
    """Core owns the contract and dispatcher, never the first pack's behavior."""

    core = Path(__file__).resolve().parents[1] / "src" / "aptl"
    forbidden_imports: list[str] = []
    for path in core.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules: tuple[str, ...] = ()
            if isinstance(node, ast.Import):
                modules = tuple(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = (node.module,)
            if any(module.startswith("aptl_techvault") for module in modules):
                forbidden_imports.append(path.relative_to(core).as_posix())

    assert forbidden_imports == []
    assert not list((core / "core/evidence/adapters").glob("techvault*.py"))
    assert not (core / "core/experiment/capture_registrations.py").exists()


def test_admitted_operator_groups_are_reused_for_recovery(tmp_path: Path) -> None:
    from aptl.core.operator_group_state import (
        load_admitted_operator_groups,
        persist_admitted_operator_groups,
    )

    persist_admitted_operator_groups(tmp_path, {"blue-team", "red_team"})
    persist_admitted_operator_groups(tmp_path, {"exercise-control"})

    assert load_admitted_operator_groups(tmp_path) == (
        "blue-team",
        "exercise-control",
        "red_team",
    )
    with pytest.raises(ValueError, match="invalid admitted operator groups"):
        persist_admitted_operator_groups(tmp_path, {"--project"})
