"""Admitted scenario selection controls optional lab startup work."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from aptl.backends._raes_scenario_queries import AdmittedStartSurface
from aptl.core.scenario_bundle import ScenarioSourceKind
import pytest


def _surface(root: Path, kind: ScenarioSourceKind) -> AdmittedStartSurface:
    return AdmittedStartSurface(
        bundle_root=root,
        source_kind=kind,
        selected_profiles=("small",),
        stateful_artifact_ownership=frozenset(),
    )


def test_admitted_pack_without_adapter_uses_only_generic_startup(
    tmp_path: Path,
) -> None:
    from aptl.core.lab import _LabStartContext, _selected_start_steps

    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=False)
    ctx.admitted_surface = _surface(tmp_path, ScenarioSourceKind.ENV_PACK)

    names = {step.__name__ for step in _selected_start_steps(ctx)}

    assert "_step_start_containers" in names
    assert "_step_attest_project_containers" in names
    assert "_step_capture_snapshot" in names
    assert "_step_sync_credentials" not in names
    assert "_step_generate_soc_certs" not in names
    assert "_step_wait_for_services" not in names
    assert "_step_build_mcps" not in names
    assert "_step_sync_mcp_config" not in names


def test_project_tree_keeps_qualified_legacy_startup(tmp_path: Path) -> None:
    from aptl.core.lab import _LabStartContext, _selected_start_steps

    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=False)
    ctx.admitted_surface = _surface(tmp_path, ScenarioSourceKind.PROJECT_TREE)

    names = {step.__name__ for step in _selected_start_steps(ctx)}

    assert "_step_sync_credentials" in names
    assert "_step_wait_for_services" in names
    assert "_step_build_mcps" in names


def test_adapter_selects_only_its_declared_capabilities(tmp_path: Path) -> None:
    from aptl.backends.scenario_startup import ScenarioStartupPlan, StartupCapability
    from aptl.core.lab import _LabStartContext, _selected_start_steps

    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=False)
    ctx.admitted_surface = _surface(tmp_path, ScenarioSourceKind.ENV_PACK)
    ctx.scenario_startup = ScenarioStartupPlan(
        seed_script="scripts/seed.sh",
        required_profiles=("soc",),
        activation_profiles=("soc",),
        lifecycle_capabilities=frozenset({StartupCapability.SOC}),
    )

    names = {step.__name__ for step in _selected_start_steps(ctx)}

    assert "_step_seed_soc" in names
    assert "_step_generate_soc_certs" in names
    assert "_step_sync_credentials" not in names
    assert "_step_wait_for_services" not in names
    assert "_step_build_mcps" not in names


def test_startup_plan_rejects_unknown_capability() -> None:
    from aptl.backends.scenario_startup import (
        ScenarioStartupPlan,
        ScenarioStartupProviderError,
        _validated_plan,
    )

    with pytest.raises(ScenarioStartupProviderError):
        _validated_plan(
            ScenarioStartupPlan(
                seed_script="scripts/seed.sh",
                required_profiles=("soc",),
                activation_profiles=("soc",),
                lifecycle_capabilities=frozenset({"execute-anything"}),
            )
        )


def test_tiny_pack_environment_does_not_require_stack_templates(
    tmp_path: Path, mocker: Mock
) -> None:
    from aptl.core.config import AptlConfig
    from aptl.core.lab import _LabStartContext, _step_load_env
    from aptl.core.scenario_bundle import PackIdentity, ScenarioBundle

    (tmp_path / "aptl.json").write_text(AptlConfig().model_dump_json())
    pack = ScenarioBundle(
        identity="tiny",
        root=tmp_path / "pack",
        sdl_path=tmp_path / "pack" / "tiny.sdl.yaml",
        source_kind=ScenarioSourceKind.ENV_PACK,
        pack_identity=PackIdentity("tiny", "1.0.0", "digest"),
    )
    resolver = mocker.patch(
        "aptl.backends._raes_scenario_resolution.resolve_scenario_bundle",
        return_value=pack,
    )
    mocker.patch(
        "aptl.backends.scenario_startup.resolve_scenario_startup", return_value=None
    )
    hydration = mocker.patch("aptl.core.lab.hydrate_dotenv")
    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=False)

    assert _step_load_env(ctx) is None

    resolver.assert_called_once()
    hydration.assert_not_called()
    assert ctx.raw_env == {}
    assert ctx.env is None
    assert not (tmp_path / ".env").exists()
    assert ctx.start_selection.bundle is pack


def test_seed_process_receives_only_declared_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aptl.backends.scenario_startup import ScenarioStartupPlan
    from aptl.core.lab import _LabStartContext, _scenario_seed_environment

    monkeypatch.setenv("UNRELATED_OPERATOR_SECRET", "ambient-canary")
    monkeypatch.setenv("APTL_HP_WAZUH_INDEXER_9200", "19200")
    plan = ScenarioStartupPlan(
        seed_script="scripts/seed.sh",
        required_profiles=("soc",),
        activation_profiles=("soc",),
        seed_environment_keys=("APTL_HP_WAZUH_INDEXER_9200", "MISP_API_KEY"),
    )
    ctx = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        raw_env={"MISP_API_KEY": "declared-value", "OTHER_SECRET": "project-canary"},
    )

    environment = _scenario_seed_environment(ctx, plan)

    assert environment["MISP_API_KEY"] == "declared-value"
    assert environment["APTL_HP_WAZUH_INDEXER_9200"] == "19200"
    assert "UNRELATED_OPERATOR_SECRET" not in environment
    assert "OTHER_SECRET" not in environment


def test_ssh_seed_uses_selected_backend_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aptl.backends.scenario_startup import ScenarioStartupPlan
    from aptl.core.deployment.ssh_compose import SSHComposeBackend
    from aptl.core.lab import _LabStartContext, _scenario_seed_environment

    monkeypatch.setenv("DOCKER_HOST", "ssh://wrong@example.invalid")
    monkeypatch.setenv("DOCKER_CONTEXT", "wrong-context")
    monkeypatch.setenv("DOCKER_SSH_IDENTITY", "/wrong/key")
    monkeypatch.setenv("UNRELATED_OPERATOR_SECRET", "ambient-canary")
    backend = SSHComposeBackend(
        tmp_path,
        host="lab.example.com",
        user="deploy",
        ssh_key="/keys/lab",
    )
    plan = ScenarioStartupPlan("scripts/seed.sh", ("soc",), ("soc",))
    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=False, backend=backend)

    environment = _scenario_seed_environment(ctx, plan)

    assert environment["DOCKER_HOST"] == "ssh://deploy@lab.example.com"
    assert environment["DOCKER_SSH_IDENTITY"] == "/keys/lab"
    assert "DOCKER_CONTEXT" not in environment
    assert "UNRELATED_OPERATOR_SECRET" not in environment
    backend_env = backend._subprocess_kwargs(streaming=False, timeout=None)["env"]
    assert environment["DOCKER_HOST"] == backend_env["DOCKER_HOST"]
    assert environment["DOCKER_SSH_IDENTITY"] == backend_env["DOCKER_SSH_IDENTITY"]


def test_local_seed_uses_pinned_backend_daemon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aptl.backends.scenario_startup import ScenarioStartupPlan
    from aptl.core.deployment.docker_compose import DockerComposeBackend
    from aptl.core.lab import _LabStartContext, _scenario_seed_environment

    monkeypatch.setenv("DOCKER_HOST", "ssh://wrong@example.invalid")
    monkeypatch.setenv("DOCKER_CONTEXT", "wrong-context")
    monkeypatch.setenv("DOCKER_SSH_IDENTITY", "/wrong/key")
    backend = DockerComposeBackend(tmp_path)
    backend._docker_host_override = "unix:///run/user/1000/docker.sock"
    plan = ScenarioStartupPlan("scripts/seed.sh", ("soc",), ("soc",))
    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=False, backend=backend)

    environment = _scenario_seed_environment(ctx, plan)

    assert environment["DOCKER_HOST"] == "unix:///run/user/1000/docker.sock"
    assert "DOCKER_CONTEXT" not in environment
    assert "DOCKER_SSH_IDENTITY" not in environment


def test_seed_adapter_cannot_override_backend_transport(tmp_path: Path) -> None:
    from aptl.backends.scenario_startup import ScenarioStartupPlan
    from aptl.core.deployment.docker_compose import DockerComposeBackend
    from aptl.core.lab import _LabStartContext, _scenario_seed_environment

    ctx = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        backend=DockerComposeBackend(tmp_path),
        raw_env={"DOCKER_HOST": "ssh://wrong@example.invalid"},
    )
    plan = ScenarioStartupPlan(
        "scripts/seed.sh", ("soc",), ("soc",), seed_environment_keys=("DOCKER_HOST",)
    )

    with pytest.raises(OSError, match="cannot override"):
        _scenario_seed_environment(ctx, plan)


def test_coordinator_stage_result_carries_diagnostics_and_fatal_error(
    tmp_path: Path,
) -> None:
    from aptl.core.lab import _LabStartContext, _run_start_stage
    from aptl.core.lab_types import (
        DiagnosticImpact,
        DiagnosticSeverity,
        LabResult,
        StartupDiagnostic,
    )

    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=False)

    def failing_stage(state: _LabStartContext) -> LabResult:
        state.diagnostics.append(
            StartupDiagnostic(
                step="fixture",
                impact=DiagnosticImpact.READINESS,
                severity=DiagnosticSeverity.WARNING,
                message="bounded warning",
            )
        )
        return LabResult(success=False, error="bounded failure")

    result = _run_start_stage(ctx, failing_stage)

    assert result.error == "bounded failure"
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].message == "bounded warning"


def test_tiny_pack_cannot_trigger_legacy_soc_retry(tmp_path: Path) -> None:
    from aptl.core.lab import _LabStartContext, _backend_retry_callback

    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=False)
    ctx.admitted_surface = AdmittedStartSurface(
        bundle_root=tmp_path,
        source_kind=ScenarioSourceKind.ENV_PACK,
        selected_profiles=("soc",),
        stateful_artifact_ownership=frozenset(),
    )

    assert _backend_retry_callback(ctx) is None


def test_non_wazuh_adapter_can_bind_alias_without_stack_credentials(
    tmp_path: Path,
) -> None:
    from aptl.backends.scenario_startup import EnvironmentAlias, ScenarioStartupPlan
    from aptl.core.lab import _LabStartContext, _bind_scenario_startup_environment

    ctx = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        raw_env={"SOURCE_TOKEN": "opaque"},
    )
    plan = ScenarioStartupPlan(
        seed_script="scripts/seed.sh",
        required_profiles=("small",),
        activation_profiles=("small",),
        environment_aliases=(EnvironmentAlias("RUNTIME_TOKEN", "SOURCE_TOKEN"),),
    )

    assert _bind_scenario_startup_environment(ctx, plan) is None

    assert ctx.raw_env["RUNTIME_TOKEN"] == "opaque"
    assert ctx.env is None


def test_adapter_without_aliases_needs_no_dotenv(tmp_path: Path) -> None:
    from aptl.backends.scenario_startup import ScenarioStartupPlan
    from aptl.core.lab import _LabStartContext, _bind_scenario_startup_environment

    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=False)
    plan = ScenarioStartupPlan(
        seed_script="scripts/seed.sh",
        required_profiles=("small",),
        activation_profiles=("small",),
    )

    assert _bind_scenario_startup_environment(ctx, plan) is None

    assert ctx.scenario_startup is plan
    assert not (tmp_path / ".env").exists()


def test_admission_reuses_exact_selected_bundle_and_adapter(
    tmp_path: Path, mocker: Mock
) -> None:
    from aptl.backends.scenario_startup import (
        ScenarioStartupPlan,
        ScenarioStartupSelection,
    )
    from aptl.core.config import AptlConfig
    from aptl.core.lab import (
        StartSelection,
        _LabStartContext,
        _load_admitted_start_surface,
    )
    from aptl.core.scenario_bundle import ScenarioBundle

    bundle = ScenarioBundle(
        identity="tiny",
        root=tmp_path,
        sdl_path=tmp_path / "tiny.sdl.yaml",
        source_kind=ScenarioSourceKind.ENV_PACK,
    )
    startup = ScenarioStartupPlan(
        seed_script="scripts/seed.sh",
        required_profiles=("small",),
        activation_profiles=("small",),
    )
    provider_selection = ScenarioStartupSelection(None, object(), startup)
    ctx = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        config=AptlConfig(),
        backend=mocker.Mock(),
        start_selection=StartSelection(
            AptlConfig(), bundle, startup, provider_selection
        ),
    )
    admitted = SimpleNamespace(bundle=bundle, runtime_materialization_failure=None)
    admit = mocker.patch(
        "aptl.core.lab.admit_start_surface",
        return_value=(admitted, _surface(tmp_path, ScenarioSourceKind.ENV_PACK)),
    )
    discover = mocker.patch(
        "aptl.backends.scenario_startup.select_scenario_startup",
        side_effect=AssertionError("adapter was rediscovered"),
    )

    assert _load_admitted_start_surface(ctx) is None

    assert admit.call_args.kwargs["bundle"] is bundle
    assert admit.call_args.kwargs["startup_selection"] is provider_selection
    assert ctx.admitted_start is admitted
    assert ctx.scenario_startup is startup
    discover.assert_not_called()


def test_startup_adapter_selection_rejects_duplicate_exact_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aptl.backends import scenario_startup
    from aptl.backends.scenario_startup import ScenarioStartupPlan
    from aptl.core.scenario_bundle import PackIdentity, ScenarioBundle

    bundle = ScenarioBundle(
        identity="tiny",
        root=tmp_path,
        sdl_path=tmp_path / "tiny.sdl.yaml",
        source_kind=ScenarioSourceKind.ENV_PACK,
        pack_identity=PackIdentity("tiny", "1.0.0", "exact-digest"),
    )
    plan = ScenarioStartupPlan("scripts/seed.sh", ("small",), ("small",))
    provider = SimpleNamespace(
        extension_api_version="1",
        supported_pack_id="tiny",
        supported_pack_versions=("1.0.0",),
        supported_pack_set_digests=("exact-digest",),
        resolve=lambda _bundle: plan,
    )
    entry = SimpleNamespace(name="tiny", load=lambda: provider)
    monkeypatch.setattr(scenario_startup, "_entry_points", lambda: [entry, entry])

    with pytest.raises(
        scenario_startup.ScenarioStartupProviderError, match="ambiguous"
    ):
        scenario_startup.resolve_scenario_startup(bundle)


def test_interrupted_start_releases_lifecycle_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aptl.core import lab
    from aptl.core.lab_types import StartupOutcome

    def interrupted(_ctx: lab._LabStartContext) -> None:
        raise KeyboardInterrupt

    with monkeypatch.context() as patched:
        patched.setattr(lab, "_LAB_START_STEPS", (interrupted,))
        with pytest.raises(KeyboardInterrupt):
            lab.orchestrate_lab_start(tmp_path)

    def complete(_ctx: lab._LabStartContext) -> None:
        return None

    with monkeypatch.context() as patched:
        patched.setattr(lab, "_LAB_START_STEPS", (complete,))
        result = lab.orchestrate_lab_start(tmp_path)

    assert result.outcome is StartupOutcome.READY


def test_adapter_supplies_mcp_key_targets(tmp_path: Path) -> None:
    from aptl.backends.scenario_startup import (
        McpServerCredentials,
        ScenarioStartupPlan,
        StartupCapability,
    )
    from aptl.core.lab import _LabStartContext, _mcp_startup_policy

    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=False)
    ctx.admitted_surface = _surface(tmp_path, ScenarioSourceKind.ENV_PACK)
    ctx.scenario_startup = ScenarioStartupPlan(
        seed_script="scripts/seed.sh",
        required_profiles=("small",),
        activation_profiles=("small",),
        lifecycle_capabilities=frozenset({StartupCapability.MCP}),
        mcp_server_keys=(McpServerCredentials("tiny-tools", ("TINY_KEY",)),),
    )

    policy = _mcp_startup_policy(ctx)

    assert policy["tiny-tools"] == ("TINY_KEY",)
    assert "aptl-casemgmt" not in policy


def test_adapter_mcp_keys_do_not_refresh_legacy_clients() -> None:
    from aptl.core.lab import _refresh_mcp_server_keys

    config = {
        "mcpServers": {
            "tiny-tools": {"env": {}},
            "aptl-casemgmt": {"env": {}},
        }
    }

    updated = _refresh_mcp_server_keys(
        config,
        {"TINY_KEY": "tiny-value", "THEHIVE_API_KEY": "legacy-value"},
        server_keys={"tiny-tools": ("TINY_KEY",)},
    )

    assert updated == ["tiny-tools.TINY_KEY"]
    assert config["mcpServers"]["aptl-casemgmt"]["env"] == {}
    assert (
        _refresh_mcp_server_keys(
            config, {"THEHIVE_API_KEY": "legacy-value"}, server_keys={}
        )
        == []
    )


def test_adapter_selects_its_own_mcp_build_script(tmp_path: Path, mocker: Mock) -> None:
    from aptl.backends.scenario_startup import ScenarioStartupPlan
    from aptl.core.lab import _LabStartContext, _step_build_mcps

    script = tmp_path / "custom" / "build.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\nexit 0\n")
    ctx = _LabStartContext(project_dir=tmp_path, skip_seed=False)
    ctx.admitted_surface = _surface(tmp_path, ScenarioSourceKind.ENV_PACK)
    ctx.selected_profiles = {"small"}
    ctx.scenario_startup = ScenarioStartupPlan(
        seed_script="scripts/seed.sh",
        required_profiles=("small",),
        activation_profiles=("small",),
        mcp_build_script="custom/build.sh",
    )
    execute = mocker.patch(
        "aptl.utils.shell.run_shell_script",
        return_value=SimpleNamespace(returncode=0),
    )

    assert _step_build_mcps(ctx) is None

    execute.assert_called_once_with(script, cwd=tmp_path)
