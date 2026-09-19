"""Content-identified startup enrichment for the released TechVault pack."""

from importlib import metadata
from pathlib import Path

import yaml

from aptl.backends.scenario_startup import (
    ENTRY_POINT_GROUP,
    ScenarioStartupProviderError,
    _safe_relative_script,
    observe_scenario_runtime_concerns,
    run_scenario_runtime,
    resolve_scenario_startup,
)
from aptl.backends.scenario_startup_policy import (
    ScenarioComposeStartupPolicy,
    StartupHealthDependency,
    StartupHealthProbe,
    _validated_policy,
    write_scenario_startup_override,
)
import pytest
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.scenario_bundle import PackIdentity, ScenarioBundle, ScenarioSourceKind
from aptl_techvault.runtime_parameters import TECHVAULT_PACK_SET_DIGEST


def _bundle(*, digest: str = TECHVAULT_PACK_SET_DIGEST) -> ScenarioBundle:
    return ScenarioBundle(
        identity="techvault",
        root=Path("/pack"),
        sdl_path=Path("/pack/sdl/techvault.sdl.yaml"),
        source_kind=ScenarioSourceKind.ENV_PACK,
        pack_identity=PackIdentity("techvault", "0.1.0", digest),
    )


def _startup_spec(
    *, digest: str = TECHVAULT_PACK_SET_DIGEST
) -> DeploymentRealizationSpec:
    dependencies = {
        "cortex": ("provision.node.thehive-es",),
        "thehive": (
            "provision.node.thehive-cassandra",
            "provision.node.thehive-es",
            "provision.node.cortex",
        ),
    }
    names = ("thehive-cassandra", "thehive-es", "cortex", "thehive")
    nodes = tuple(
        DeploymentNodeRealization(
            address=f"provision.node.{name}",
            name=name,
            service_name=name,
            container_name=f"aptl-{name}",
            networks=("security-net",),
            ordering_dependencies=dependencies.get(name, ()),
        )
        for name in names
    )
    images = tuple(
        DeploymentImageRealization(
            address=node.address,
            service_name=node.service_name or "",
            source_name=node.name,
            source_version="test",
            image_ref=f"example/{node.name}:test",
            mode="pull",
            policy_rule="test",
        )
        for node in nodes
    )
    return DeploymentRealizationSpec(
        profiles=("soc",),
        nodes=nodes,
        networks=(),
        images=images,
        pack_identity=PackIdentity("techvault", "0.1.0", digest),
    )


def test_qualified_techvault_policy_waits_for_declared_healthy_dependencies(
    tmp_path,
) -> None:
    path = write_scenario_startup_override(_startup_spec(), tmp_path)

    assert path is not None
    services = yaml.safe_load(path.read_text(encoding="utf-8"))["services"]
    assert services["thehive-cassandra"]["healthcheck"]["test"] == [
        "CMD",
        "cqlsh",
        "-e",
        "describe cluster",
    ]
    assert services["cortex"]["depends_on"]["thehive-es"] == {
        "condition": "service_healthy"
    }
    assert services["thehive"]["depends_on"] == {
        name: {"condition": "service_healthy"}
        for name in ("thehive-cassandra", "thehive-es", "cortex")
    }
    assert (
        write_scenario_startup_override(
            _startup_spec(digest="sha256:" + "0" * 64), tmp_path
        )
        is None
    )


def test_startup_policy_cannot_add_undeclared_dependency_or_service() -> None:
    spec = _startup_spec()
    with pytest.raises(ScenarioStartupProviderError, match="result-invalid"):
        _validated_policy(
            ScenarioComposeStartupPolicy(
                probes=(StartupHealthProbe("thehive-cassandra", ("CMD", "true")),),
                dependencies=(StartupHealthDependency("cortex", "thehive-cassandra"),),
            ),
            spec,
        )
    with pytest.raises(ScenarioStartupProviderError, match="result-invalid"):
        _validated_policy(
            ScenarioComposeStartupPolicy(
                probes=(StartupHealthProbe("foreign", ("CMD", "true")),),
            ),
            spec,
        )


def test_exact_release_resolves_seed_and_runtime_bindings() -> None:
    plan = resolve_scenario_startup(_bundle())

    assert plan is not None
    assert plan.seed_script == "scripts/seed-prime.sh"
    assert set(plan.required_profiles) == {
        "wazuh",
        "enterprise",
        "victim",
        "kali",
        "fileshare",
        "soc",
    }
    assert plan.activation_profiles == ("soc",)
    assert [(item.target, item.source) for item in plan.environment_aliases] == [
        ("ADMIN_KEY", "MISP_API_KEY")
    ]
    assert {
        (item.variable, item.semantic_name) for item in plan.container_environment
    } >= {
        ("CORTEX_CONTAINER", "aptl-cortex"),
        ("WAZUH_MANAGER_CONTAINER", "aptl-wazuh-manager"),
    }


def test_changed_pack_digest_gets_no_startup_behavior() -> None:
    assert resolve_scenario_startup(_bundle(digest="sha256:" + "0" * 64)) is None


def test_runtime_hook_only_runs_for_the_qualified_pack(monkeypatch) -> None:
    from aptl_techvault.startup import provider

    calls = []
    monkeypatch.setattr(
        provider,
        "realize_runtime",
        lambda backend, nodes: calls.append((backend, nodes)) or [],
    )
    backend = object()
    nodes = (object(),)

    assert run_scenario_runtime(_bundle().pack_identity, backend, nodes) == []
    assert calls == [(backend, nodes)]
    assert (
        run_scenario_runtime(
            _bundle(digest="sha256:" + "0" * 64).pack_identity,
            backend,
            nodes,
        )
        == []
    )
    assert calls == [(backend, nodes)]


def test_runtime_observation_only_runs_for_the_qualified_pack(monkeypatch) -> None:
    from raes_processor.semantics.realization import CONCERN_PAYLOAD_PATH

    from aptl_techvault.startup import provider

    path = CONCERN_PAYLOAD_PATH["runtime-container-autoremove"]
    calls = []
    monkeypatch.setattr(
        provider,
        "observe_runtime",
        lambda backend, node: calls.append((backend, node)) or {path: False},
    )
    backend = object()
    node = object()

    assert observe_scenario_runtime_concerns(
        _bundle().pack_identity, backend, node
    ) == {path: False}
    assert (
        observe_scenario_runtime_concerns(
            _bundle(digest="sha256:" + "0" * 64).pack_identity, backend, node
        )
        == {}
    )
    assert calls == [(backend, node)]


@pytest.mark.parametrize(
    "path", ["/tmp/seed.sh", "a/../seed.sh", "a/./seed.sh", "a//seed.sh"]
)
def test_adapter_script_path_rejects_noncanonical_components(path: str) -> None:
    with pytest.raises(ScenarioStartupProviderError):
        _safe_relative_script(path)


def test_core_preparation_binds_operator_alias_without_scenario_import(
    tmp_path,
) -> None:
    from aptl.core.lab import _LabStartContext, _prepare_scenario_startup

    values = {
        "INDEXER_USERNAME": "indexer",
        "INDEXER_PASSWORD": "indexer-password",
        "API_USERNAME": "api",
        "API_PASSWORD": "api-password",
        "MISP_API_KEY": "opaque-misp-key",
    }
    env_file = tmp_path / ".env"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    ctx = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        raw_env=dict(values),
    )

    assert _prepare_scenario_startup(ctx, _bundle()) is None
    assert ctx.scenario_startup is not None
    assert ctx.raw_env["ADMIN_KEY"] == values["MISP_API_KEY"]


def test_seed_environment_uses_receipt_resolved_container_names(tmp_path) -> None:
    from unittest.mock import MagicMock

    from aptl.core.lab import _LabStartContext, _scenario_seed_environment

    plan = resolve_scenario_startup(_bundle())
    assert plan is not None
    backend = MagicMock()
    backend.container_inspect.side_effect = lambda semantic: {
        "Name": f"/workspace-{semantic.removeprefix('aptl-')}"
    }
    ctx = _LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        backend=backend,
        raw_env={"MISP_API_KEY": "opaque"},
    )

    environment = _scenario_seed_environment(ctx, plan)

    assert environment["CORTEX_CONTAINER"] == "workspace-cortex"
    assert environment["WAZUH_MANAGER_CONTAINER"] == "workspace-wazuh-manager"
    assert backend.container_inspect.call_count == len(plan.container_environment)


def test_startup_adapter_is_registered_outside_framework() -> None:
    entries = {
        entry.name: entry.value
        for entry in metadata.entry_points(group=ENTRY_POINT_GROUP)
    }

    assert entries["techvault"].startswith("aptl_techvault.")
    framework = Path(__file__).resolve().parents[1] / "src" / "aptl"
    offenders = {
        str(path.relative_to(framework))
        for path in framework.rglob("*.py")
        if "from aptl_techvault" in path.read_text(encoding="utf-8")
        or "import aptl_techvault" in path.read_text(encoding="utf-8")
    }
    assert offenders == set()
