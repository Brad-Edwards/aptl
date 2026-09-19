"""Static validation gate tests (SCN-010E / issue #322).

These exercise the scenario-generic gate composed in
``aptl.validation.techvault_gate``: the authoritative operational scenario
gate, fail-loud on a missing RAES corpus, and the anti-collapse / anti-preset
proofs that the realization is driven by declared content, not by the
scenario id.

``techvault-operational.sdl.yaml`` is the authoritative driving scenario the
gate validates.
"""

import copy
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from raes.module_registry import LOCKFILE_NAME
from raes_runtime.manager import RuntimeManager
from raes_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RuntimeDomain,
)

from aptl.backends.raes_profiles import (
    load_compose_profile_index,
    public_start_profiles,
    select_backend_profiles,
    steady_state_service_aliases_for_profiles,
)
from aptl.backends.raes import create_aptl_runtime_target
from aptl.backends.raes_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig, load_config
from aptl.core.scenario_bundle import project_tree_bundle
from aptl.validation import _account_parity
from aptl.validation import _gate_checks as gc
from aptl.validation import _gate_raes_cli as gcli
from aptl.validation._account_parity import check_account_provisioner_parity
from aptl.validation._gate_raes_cli import (
    _cli_detail,
    conformance_cli_diagnostics,
    verify_imports_diagnostics,
)
from aptl.validation._gate_checks import (
    _NoStartBackend,
    _outcome,
    _severity,
    _target_conformance_diagnostics,
    check_backend_conformance,
    check_compile,
    check_import_lock,
    check_parse,
    check_provisioning_realization,
)
from aptl.validation.techvault_gate import (
    GateCheck,
    GateOptions,
    GateReport,
    validate_scenario,
)
from tests.helpers import techvault_scenario_bundle

PROJECT_ROOT = Path(__file__).resolve().parents[1]
# The default TechVault scenario now ships as the bundled env-pack (#875); the
# in-tree techvault-operational.sdl.yaml was retired. Stage the pack once for the
# module and drive the gate from its validated SDL, exactly as config-driven
# resolution does at lab start.
_OPERATIONAL_BUNDLE = techvault_scenario_bundle(
    Path(tempfile.mkdtemp(prefix="aptl-static-gate-"))
)
OPERATIONAL_SCENARIO = _OPERATIONAL_BUNDLE.sdl_path
PAPER_SCENARIO = PROJECT_ROOT / "scenarios" / "paper-agent-loop.sdl.yaml"
PROFILE_INFRASTRUCTURE_SERVICES = frozenset(
    {
        "kali-ssh-proxy",
        "webapp-proxy",
        "wazuh-sidecar-db",
        "wazuh-sidecar-suricata",
    }
)


def _bundle(root, sdl_path=None):
    """Bundle for an in-tree scenario rooted at ``root`` (issue #874).

    Every call below previously passed ``root`` as ``project_dir``; anchoring
    the bundle to the same directory keeps these gates behaviourally identical.
    """
    return project_tree_bundle(root, sdl_path or root / "scenarios" / "demo.sdl.yaml")


# --------------------------------------------------------------------------- #
# Authoritative operational scenario gate (integration: backend_conformance
# spawns the `raes conformance backend` CLI). This is the driving-SDL completion
# gate — it validates that techvault-operational passes the composed gate.
#
# It calls `validate_scenario()` with default options, exactly as the CI job and
# the pre-push hook do. Hand-calling the individual checks here would test a
# sequence no caller runs and would let a check that fails only in composition
# (an absent import lockfile, say) pass unnoticed.
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_operational_gate_passes():
    config = load_config(PROJECT_ROOT / "aptl.json")

    report = validate_scenario(
        OPERATIONAL_SCENARIO,
        project_dir=PROJECT_ROOT,
        config=config,
        options=GateOptions(),
    )

    failed = [(c.name, c.diagnostics) for c in report.checks if not c.passed]
    assert report.passed, f"static gate failed: {failed}"
    # Every check in the composition ran; none was silently skipped.
    assert [c.name for c in report.checks] == [
        "parse",
        "import_lock",
        "compile",
        "backend_conformance",
        "provisioning_realization",
        "account_provisioner_parity",
    ]


def test_operational_scenario_matches_public_start_profiles_and_services():
    config = load_config(PROJECT_ROOT / "aptl.json")
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert scenario is not None
    assert parse_check.passed, parse_check.diagnostics

    details, check = check_provisioning_realization(
        scenario=scenario, project_dir=PROJECT_ROOT, config=config
    )
    assert details is not None
    assert check.passed, check.diagnostics

    expected_profiles = public_start_profiles(config)
    selected_profiles = select_backend_profiles(
        config, frozenset(details.get("profiles", []))
    )
    assert selected_profiles == expected_profiles

    expected_services = steady_state_service_aliases_for_profiles(
        PROJECT_ROOT, expected_profiles
    )
    realized_aliases = _realized_aliases(details)
    missing = {
        service: aliases
        for service, aliases in expected_services.items()
        if service not in PROFILE_INFRASTRUCTURE_SERVICES
        and not set(aliases) & realized_aliases
    }
    assert missing == {}


def test_operational_scenario_lowers_wazuh_stateful_resources():
    from aptl_techvault.runtime_parameters import runtime_parameters_for_bundle

    config = load_config(PROJECT_ROOT / "aptl.json")
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert scenario is not None
    assert parse_check.passed, parse_check.diagnostics

    bundle = _OPERATIONAL_BUNDLE
    parameters = runtime_parameters_for_bundle(bundle)
    assert parameters is not None
    execution_plan = RuntimeManager(
        create_aptl_runtime_target(
            project_dir=PROJECT_ROOT,
            config=config,
            backend=_NoStartBackend(),
            bundle=bundle,
        )
    ).plan(scenario, parameters=parameters)
    realization = interpret_provisioning_plan(
        plan=execution_plan.provisioning,
        config=config,
        bundle=bundle,
    )
    details = realization.details()

    assert not [
        diagnostic
        for diagnostic in realization.diagnostics
        if getattr(diagnostic.severity, "value", diagnostic.severity) == "error"
    ]
    assert details["resource_counts"]["generated-artifact"] >= 2
    assert details["resource_counts"]["persistent-volume"] >= 2
    generators = {item["generator"] for item in details["generated_artifacts"]}
    assert generators == {"certificate_bundle", "rendered_config", "ssh_key_bundle"}
    artifacts = {item["name"]: item for item in details["generated_artifacts"]}
    assert {
        output["path"] for output in artifacts["wazuh-indexer-certs"]["outputs"]
    } == {
        "root-ca.pem",
        "wazuh.indexer-key.pem",
        "wazuh.indexer.pem",
    }
    assert {
        output["path"] for output in artifacts["wazuh-manager-certs"]["outputs"]
    } == {
        "root-ca-manager.pem",
        "wazuh.manager-key.pem",
        "wazuh.manager.pem",
    }
    assert {
        output["path"] for output in artifacts["wazuh-dashboard-certs"]["outputs"]
    } == {
        "root-ca.pem",
        "wazuh.dashboard-key.pem",
        "wazuh.dashboard.pem",
    }
    assert all(
        len(artifacts[name]["consumers"]) == 1
        for name in (
            "wazuh-indexer-certs",
            "wazuh-manager-certs",
            "wazuh-dashboard-certs",
        )
    )
    nodes = {node["name"]: node for node in details["nodes"]}
    # Digest-pinned, resolved from the node's authored exact artifact
    # requirement rather than an APTL-side allowlist entry (ADR-050): a mutable
    # tag is not an admissible pin.
    assert nodes["wazuh-manager"]["image"]["image_ref"] == (
        "wazuh/wazuh-manager@sha256:dea2fa1e6d5062147b6a85b241f5f501c5f1ba4b817d12bda06f7870a89ad561"
    )
    assert nodes["wazuh-indexer"]["image"]["image_ref"] == (
        "wazuh/wazuh-indexer@sha256:3691b3b27658695aad0c6879b412a001caf233ebbc1a5ba15647053aa03a2299"
    )
    assert (
        "provision.node.wazuh-indexer"
        in nodes["wazuh-manager"]["ordering_dependencies"]
    )


def test_paper_scenario_lowers_same_wazuh_stateful_contract():
    config = load_config(PROJECT_ROOT / "aptl.json")
    scenario, parse_check = check_parse(PAPER_SCENARIO)
    assert scenario is not None
    assert parse_check.passed, parse_check.diagnostics

    bundle = _bundle(PROJECT_ROOT, PAPER_SCENARIO)
    execution_plan = RuntimeManager(
        create_aptl_runtime_target(
            project_dir=PROJECT_ROOT,
            config=config,
            backend=_NoStartBackend(),
            bundle=bundle,
        )
    ).plan(scenario)
    realization = interpret_provisioning_plan(
        plan=execution_plan.provisioning,
        config=config,
        bundle=bundle,
    )
    details = realization.details()

    assert not [
        diagnostic
        for diagnostic in realization.diagnostics
        if getattr(diagnostic.severity, "value", diagnostic.severity) == "error"
    ]
    assert details["resource_counts"]["generated-artifact"] == 3
    assert details["resource_counts"]["persistent-volume"] == 3


# --------------------------------------------------------------------------- #
# Fail-loud: a missing corpus/profile is a gate failure, never a warning.
# The in-process path (run_target_conformance) stays in the fast suite; the full
# check additionally spawns the `raes conformance backend` CLI, so its test is
# integration-marked (the repo classifies subprocess-spawning tests that way).
# --------------------------------------------------------------------------- #


def test_target_conformance_fails_loudly_on_missing_corpus(tmp_path):
    from raes_conformance.conformance import run_target_conformance

    from aptl.backends.raes import create_aptl_runtime_target
    from aptl.validation._gate_checks import _NoStartBackend

    config = AptlConfig(lab={"name": "techvault"})
    target = create_aptl_runtime_target(
        project_dir=PROJECT_ROOT,
        config=config,
        backend=_NoStartBackend(),
        bundle=_bundle(PROJECT_ROOT, OPERATIONAL_SCENARIO),
    )
    report = run_target_conformance(
        target,
        profile="full-remote-control-plane",
        root=tmp_path,
        profiles_root=tmp_path,
    )
    assert not report.passed


def test_no_start_backend_reads_back_simulated_content_kind():
    """The offline backend observes a materialized shape, not plan payload text."""
    from aptl.core.deployment.realization import (
        DeploymentContentRealization,
        DeploymentRealizationSpec,
    )

    file_item = DeploymentContentRealization(
        address="provision.content.notice",
        target_address="provision.node.fileshare",
        content_name="notice",
        volume_suffix="fileshare_data",
        dest_relpath="public/notice.txt",
        source_kind="inline-text",
        inline_text="must not be materialized by the static gate",
    )
    directory_item = DeploymentContentRealization(
        address="provision.content.onboarding",
        target_address="provision.node.fileshare",
        content_name="onboarding",
        volume_suffix="fileshare_data",
        dest_relpath="onboarding",
        source_kind="empty-directory",
    )
    backend = _NoStartBackend()

    result = backend.realize(
        DeploymentRealizationSpec(
            profiles=(),
            nodes=(),
            networks=(),
            content=(file_item, directory_item),
        )
    )

    assert result.success is True
    assert backend.observe_content_type(file_item) == "file"
    assert backend.observe_content_type(directory_item) == "directory"
    assert backend.container_exists("unrealized") is False


def test_no_start_backend_reads_back_image_free_content_kind_via_container_exec():
    """Image-free content (empty volume_suffix) is read back via container_exec.

    The generic materializer places content directly into a node's
    filesystem, so ``observed_content_type`` skips ``observe_content_type``
    (which reads a Compose volume that does not exist for this shape) and
    calls ``backend.container_exec`` instead. ``_NoStartBackend`` must answer
    that probe from its simulated shapes rather than starting Docker; a
    missing ``container_exec`` method previously crashed the static gate
    with an AttributeError the moment a scenario used image-free content
    (caught only by a real live-gate boot, not by any prior unit test).
    """
    from aptl.backends._raes_observation_helpers import observed_content_type
    from aptl.core.deployment.realization import (
        DeploymentContentRealization,
        DeploymentRealizationSpec,
    )

    file_item = DeploymentContentRealization(
        address="provision.content.webapp-service-unit",
        target_address="provision.node.webapp",
        content_name="webapp-service-unit",
        volume_suffix="",
        dest_relpath="etc/systemd/system/webapp.service",
        source_kind="inline-text",
        inline_text="must not be materialized by the static gate",
    )
    directory_item = DeploymentContentRealization(
        address="provision.content.webapp-app-code",
        target_address="provision.node.webapp",
        content_name="webapp-app-code",
        volume_suffix="",
        dest_relpath="opt/webapp",
        source_kind="project-directory",
    )
    backend = _NoStartBackend()

    result = backend.realize(
        DeploymentRealizationSpec(
            profiles=(),
            nodes=(),
            networks=(),
            content=(file_item, directory_item),
        )
    )

    assert result.success is True
    assert (
        observed_content_type(backend, file_item, container_name="aptl-webapp")
        == "file"
    )
    assert (
        observed_content_type(backend, directory_item, container_name="aptl-webapp")
        == "directory"
    )


@pytest.mark.integration
def test_backend_conformance_fails_loudly_on_missing_corpus(tmp_path):
    # Spawns the `raes conformance backend` CLI subprocess via
    # check_backend_conformance, so it is integration-marked.
    config = AptlConfig(lab={"name": "techvault"})
    check = check_backend_conformance(
        project_dir=PROJECT_ROOT,
        config=config,
        profile="full-remote-control-plane",
        profiles_root=tmp_path,  # empty corpus root -> profile artifact not found
        fixtures_root=tmp_path,
    )
    assert not check.passed
    assert check.diagnostics


# --------------------------------------------------------------------------- #
# Anti-collapse (#324) and anti-preset: realization is content-driven.
# --------------------------------------------------------------------------- #


def _write_compose(project_dir, services):
    lines = ["services:"]
    for name, profiles in services.items():
        rendered = ", ".join(f'"{profile}"' for profile in profiles)
        lines += [f"  {name}:", f"    profiles: [{rendered}]", "    image: x:latest"]
    (project_dir / "docker-compose.yml").write_text("\n".join(lines))


def _node_plan(node_name, *, node_kind="compute", os_family="linux"):
    address = f"provision.node.{node_name}"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload={
            "name": node_name,
            "node_name": node_name,
            "node_kind": node_kind,
            "os_family": os_family,
            "spec": {"node": {"name": node_name}, "infrastructure": {}},
        },
    )
    return ProvisioningPlan(
        resources={address: resource},
        operations=[
            ProvisionOp(
                action=ChangeAction.CREATE,
                address=address,
                resource_type="node",
                payload=resource.payload,
            )
        ],
    )


def test_distinct_scenarios_yield_distinct_realization(tmp_path):
    """#324: different declared content must not collapse to one realization."""
    _write_compose(
        tmp_path,
        {"kali": ["kali"], "victim": ["victim"]},
    )
    config = AptlConfig(lab={"name": "t"})

    first = interpret_provisioning_plan(
        plan=_node_plan("kali"), config=config, bundle=_bundle(tmp_path)
    )
    second = interpret_provisioning_plan(
        plan=_node_plan("victim"), config=config, bundle=_bundle(tmp_path)
    )

    assert not [d for d in first.diagnostics if _is_error(d)]
    assert not [d for d in second.diagnostics if _is_error(d)]
    assert first.details() != second.details()
    assert first.details()["profiles"] != second.details()["profiles"]


def test_realization_rejects_unrealizable_node_even_named_techvault(tmp_path):
    """Anti-preset: the scenario id cannot substitute for declared content."""
    _write_compose(tmp_path, {"kali": ["kali"]})
    config = AptlConfig(lab={"name": "techvault"})

    # A node with no compose-profile mapping cannot be realized, regardless of
    # the lab being named "techvault".
    realization = interpret_provisioning_plan(
        plan=_node_plan("totally-unknown-node"), config=config, bundle=_bundle(tmp_path)
    )
    assert [d for d in realization.diagnostics if _is_error(d)]


def _is_error(diagnostic):
    severity = getattr(diagnostic, "severity", None)
    return getattr(severity, "value", str(severity)).lower() == "error"


# --------------------------------------------------------------------------- #
# Compose-project validity: `docker compose --profile` activates every service
# in a selected profile, so an activated service that depends on a service the
# selection excludes is an invalid project. Node-level realization alone misses
# this, so interpret_provisioning_plan checks the full Compose graph.
# --------------------------------------------------------------------------- #


def _cross_profile_compose(project_dir):
    # webapp (enterprise) depends on wazuh-manager (wazuh): selecting enterprise
    # without wazuh excludes the dependency.
    (project_dir / "docker-compose.yml").write_text(
        "services:\n"
        "  webapp:\n"
        '    profiles: ["enterprise"]\n'
        "    image: x:latest\n"
        '    depends_on: ["wazuh-manager"]\n'
        "  wazuh-manager:\n"
        '    profiles: ["wazuh"]\n'
        "    image: x:latest\n"
    )


def test_cross_profile_dependency_gaps_detects_excluded_dependency(tmp_path):
    _cross_profile_compose(tmp_path)
    index = load_compose_profile_index(tmp_path)
    assert index.cross_profile_dependency_gaps({"enterprise"}) == {
        "webapp": ("wazuh-manager",)
    }
    assert index.cross_profile_dependency_gaps({"enterprise", "wazuh"}) == {}


# --------------------------------------------------------------------------- #
# The APTL-local manifest shim is gone (canonical backend-manifest-v2 only).
# --------------------------------------------------------------------------- #


def test_local_manifest_shim_is_removed():
    from aptl.backends import raes_manifest

    assert not hasattr(raes_manifest, "AptlBackendManifest")
    assert not hasattr(raes_manifest, "AptlProvisionerCapabilities")


# --------------------------------------------------------------------------- #
# Fast unit coverage of the gate helpers, check-function branches, the report
# shape, and the orchestrator. The full happy paths are integration-marked
# above; these cover the logic without parsing the full TechVault tree.
# --------------------------------------------------------------------------- #


def _proc(returncode, stdout="", stderr=""):
    return subprocess.CompletedProcess(["raes"], returncode, stdout, stderr)


def test_gate_report_passed_failures_and_render():
    ok = GateCheck("parse", True)
    bad = GateCheck("compile", False, ("boom",))
    report = GateReport("scn", "provisioning-only", (ok, bad))
    assert report.passed is False
    assert report.failures() == (bad,)
    text = report.render()
    assert "FAIL" in text
    assert "boom" in text
    assert GateReport("scn", "p", (ok,)).passed is True


def test_severity_reads_enum_or_str():
    class _Sev:
        value = "ERROR"

    class _Diag:
        severity = _Sev()

    assert _severity(_Diag()) == "error"

    class _Plain:
        severity = "WARNING"

    assert _severity(_Plain()) == "warning"


def test_outcome_packs_diagnostics():
    assert _outcome([]) == (True, ())
    assert _outcome(["x", "y"]) == (False, ("x", "y"))


def test_verify_imports_diagnostics():
    assert verify_imports_diagnostics(None)
    assert verify_imports_diagnostics(_proc(1, stderr="stale"))
    assert verify_imports_diagnostics(_proc(0)) == []


def test_target_conformance_diagnostics():
    class _Report:
        def __init__(self, passed, contract=(), cap=()):
            self.passed = passed
            self.diagnostics = ()
            self.unsupported_contract_gaps = contract
            self.unsupported_capability_gaps = cap

    assert _target_conformance_diagnostics(_Report(True)) == []
    diags = _target_conformance_diagnostics(
        _Report(False, contract=("c1",), cap=("orchestrator",))
    )
    assert any("target conformance failed" in d for d in diags)
    assert any("required contracts" in d for d in diags)
    assert any("required surfaces" in d for d in diags)


def test_conformance_cli_diagnostics(monkeypatch):
    monkeypatch.setattr(gcli, "run_raes", lambda *a, **k: None)
    assert conformance_cli_diagnostics("provisioning-only", None, None)
    monkeypatch.setattr(gcli, "run_raes", lambda *a, **k: _proc(1, stderr="x"))
    assert conformance_cli_diagnostics("provisioning-only", Path("f"), Path("p"))
    monkeypatch.setattr(gcli, "run_raes", lambda *a, **k: _proc(0))
    assert conformance_cli_diagnostics("provisioning-only", None, None) == []


@pytest.mark.parametrize("path_executable", [None, "/usr/bin/raes"])
def test_run_raes_uses_active_python_environment_without_path_activation(
    monkeypatch, tmp_path, path_executable
):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python = bin_dir / "python"
    python.touch()
    raes = bin_dir / "raes"
    raes.touch()
    raes.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(python))
    monkeypatch.setattr(gcli.shutil, "which", lambda name: path_executable)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return _proc(0)

    monkeypatch.setattr(gcli.subprocess, "run", fake_run)

    result = gcli.run_raes(["conformance", "backend"])
    assert result is not None and result.returncode == 0
    assert calls[0][0] == [str(raes), "conformance", "backend"]


def test_run_raes_falls_back_to_path_when_sibling_is_not_executable(
    monkeypatch, tmp_path
):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python = bin_dir / "python"
    python.touch()
    (bin_dir / "raes").touch()
    monkeypatch.setattr(sys, "executable", str(python))
    monkeypatch.setattr(gcli.shutil, "which", lambda name: "/usr/bin/raes")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return _proc(0)

    monkeypatch.setattr(gcli.subprocess, "run", fake_run)

    result = gcli.run_raes(["sdl", "verify-imports"])
    assert result is not None and result.returncode == 0
    assert calls == [["/usr/bin/raes", "sdl", "verify-imports"]]


def test_cli_detail_json_and_plain():
    payload = '{"diagnostics": [{"code": "conformance.profile-load-failed"}]}'
    assert "profile-load-failed" in _cli_detail(_proc(1, stdout=payload))
    assert "exit=2" in _cli_detail(_proc(2, stderr="boom\nlast line"))


def test_check_parse_rejects_missing_file(tmp_path):
    scenario, check = check_parse(tmp_path / "nope.sdl.yaml")
    assert scenario is None
    assert not check.passed


def _scenario_with_imports(*imports: object) -> SimpleNamespace:
    """Stand in for a parsed RAES ``Scenario`` carrying (or not) an import set."""
    return SimpleNamespace(imports=list(imports))


def test_check_import_lock_missing_and_unavailable(tmp_path, monkeypatch):
    path = tmp_path / "techvault.sdl.yaml"
    path.write_text("name: t\n")
    scenario = _scenario_with_imports("local:mod.sdl.yaml")

    check = check_import_lock(path, scenario)
    assert not check.passed
    assert any("missing import lockfile" in d for d in check.diagnostics)

    (tmp_path / LOCKFILE_NAME).write_text("{}")
    monkeypatch.setattr(gc, "run_raes", lambda *a, **k: None)
    check = check_import_lock(path, scenario)
    assert not check.passed
    assert any(
        "not found beside active Python or on PATH" in d for d in check.diagnostics
    )


def test_check_import_lock_passes_when_scenario_declares_no_imports(tmp_path):
    """No imports means nothing to resolve, so no lockfile is required."""
    path = tmp_path / "operational.sdl.yaml"
    path.write_text("name: t\n")

    check = check_import_lock(path, _scenario_with_imports())

    assert check.passed
    assert not (tmp_path / LOCKFILE_NAME).exists()


def test_operational_scenario_declares_no_imports():
    """The skip above is only correct while the driving SDL really imports nothing."""
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed, parse_check.diagnostics
    assert scenario is not None
    assert not scenario.imports


def test_check_compile_rejects_invalid_scenario():
    check = check_compile(object())
    assert not check.passed


def test_check_provisioning_realization_handles_raise(monkeypatch):
    def _boom(**_kwargs):
        raise RuntimeError("no target")

    monkeypatch.setattr(gc, "create_aptl_runtime_target", _boom)
    details, check = check_provisioning_realization(
        scenario=object(),
        project_dir=PROJECT_ROOT,
        config=AptlConfig(lab={"name": "t"}),
    )
    assert details is None
    assert not check.passed


def test_check_provisioning_realization_rejects_planner_errors(monkeypatch, tmp_path):
    """The static gate must not interpret a plan RAES already rejected."""

    scenario = SimpleNamespace(variables={})
    availability = object()
    target = object()
    plan_error = SimpleNamespace(
        severity="error",
        code="realization.unsupported-exact-requirement",
        message="backend cannot prove the authored exact runtime concern",
    )
    execution_plan = SimpleNamespace(
        diagnostics=(plan_error,),
        provisioning=object(),
    )
    planned: dict[str, object] = {}

    bundle = SimpleNamespace(root=tmp_path)
    monkeypatch.setattr(gc, "resolve_scenario_bundle", lambda *_args: bundle)
    monkeypatch.setattr(
        gc,
        "artifact_availability_for_scenario",
        lambda selected_scenario, backend, **kwargs: availability,
        raising=False,
    )
    monkeypatch.setattr(gc, "create_aptl_runtime_target", lambda **_kwargs: target)

    def _plan_aptl_scenario(**kwargs):
        assert kwargs.pop("target") is target
        assert kwargs.pop("bundle") is bundle
        planned.update(kwargs)
        return execution_plan

    monkeypatch.setattr(gc, "plan_aptl_scenario", _plan_aptl_scenario)
    interpreted = False

    def _interpret(**_kwargs):
        nonlocal interpreted
        interpreted = True
        raise AssertionError("a rejected plan must not be interpreted")

    monkeypatch.setattr(gc, "interpret_provisioning_plan", _interpret)

    details, check = check_provisioning_realization(
        scenario=scenario,
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "t"}),
    )

    assert details is None
    assert not check.passed
    assert not interpreted
    assert planned["options"].artifact_availability is availability
    assert any(plan_error.code in diagnostic for diagnostic in check.diagnostics)


def test_backend_conformance_uses_hermetic_probe_scenario(monkeypatch, tmp_path):
    """Scenario admission is separate from the backend adapter's probe corpus."""

    target = object()
    report = SimpleNamespace(
        passed=True,
        cases=(),
        diagnostics=(),
        unsupported_contract_gaps=(),
        unsupported_capability_gaps=(),
    )
    observed_options: dict[str, object] = {}
    monkeypatch.setattr(gc, "resolve_scenario_bundle", lambda *_args: object())
    monkeypatch.setattr(gc, "create_aptl_runtime_target", lambda **_kwargs: target)

    def _run(selected_target, **options):
        assert selected_target is target
        observed_options.update(options)
        return report

    monkeypatch.setattr(gc, "run_target_conformance", _run)
    monkeypatch.setattr(gc, "conformance_cli_diagnostics", lambda *_args: [])

    check = check_backend_conformance(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "t"}),
        profile="full-remote-control-plane",
        fixtures_root=None,
        profiles_root=None,
        reference_scenario=SimpleNamespace(variables={}),
    )

    assert check.passed
    assert "name: aptl-conformance" in observed_options["reference_scenario"]


def test_check_provisioning_realization_fails_on_profile_mismatch(tmp_path):
    from textwrap import dedent

    from raes.parser import parse_sdl

    _write_compose(tmp_path, {"kali": ["kali"], "victim": ["victim"]})
    scenario = parse_sdl(
        dedent(
            """
            name: partial-range
            nodes:
              internal-net:
                type: switch
              kali:
                type: compute
                services:
                  - {name: ssh, port: 22, protocol: tcp}
            infrastructure:
              internal-net:
                properties: {cidr: 172.20.2.0/24, gateway: 172.20.2.1, internal: true}
              kali:
                links: [internal-net]
            """
        )
    )
    config = AptlConfig(
        lab={"name": "t"},
        containers={
            "wazuh": False,
            "victim": True,
            "kali": True,
            "reverse": False,
            "enterprise": False,
            "soc": False,
            "mail": False,
            "fileshare": False,
            "dns": False,
        },
    )

    details, check = check_provisioning_realization(
        scenario=scenario, project_dir=tmp_path, config=config
    )

    assert details is not None
    assert not check.passed
    assert any("public lab start profiles" in d for d in check.diagnostics)


# --------------------------------------------------------------------------- #
# Content/account honesty (ADR-046 TechVault Operational Standup Addendum,
# issue #689): unrealizable content fails the existing provisioning
# realization check (its error diagnostics now cover content/account
# placements too); SDL<->provisioner account drift fails the new dedicated
# account_provisioner_parity check.
# --------------------------------------------------------------------------- #


def test_operational_scenario_content_and_accounts_are_honest():
    """The shipped operational SDL's content/accounts realize with no errors."""
    config = load_config(PROJECT_ROOT / "aptl.json")
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    assert scenario.content
    assert scenario.accounts

    details, check = check_provisioning_realization(
        scenario=scenario, project_dir=PROJECT_ROOT, config=config
    )
    assert details is not None
    assert check.passed, check.diagnostics
    placements = details["placements"]
    content_placements = [
        p for p in placements if p["resource_type"] == "content-placement"
    ]
    account_placements = [
        p for p in placements if p["resource_type"] == "account-placement"
    ]
    assert content_placements
    # A content-placement lowers to exactly one typed realization: an ordinary
    # file/directory ("content") or a logical evidence dataset ("dataset").
    # TechVault 6.0 removed the old Cortex job index schema placement.
    assert all(
        "content" in p or "dataset" in p or "service_index_schema" in p
        for p in content_placements
    )
    assert not any("service_index_schema" in p for p in content_placements)
    assert account_placements
    assert all("account" in p for p in account_placements)


def test_provisioning_realization_fails_on_unrealizable_content(tmp_path):
    from textwrap import dedent

    from raes.parser import parse_sdl

    _write_compose(tmp_path, {"fileshare": ["fileshare"]})
    scenario = parse_sdl(
        dedent(
            """
            name: bad-content
            nodes:
              fileshare:
                type: compute
                services:
                  - {name: smb, port: 445, protocol: tcp}
            content:
              leaked-log:
                type: file
                target: fileshare
                path: var/log/leak.log
                source:
                  name: "runtime-observed:/var/log/leak.log"
            """
        )
    )
    config = AptlConfig(
        lab={"name": "t"},
        containers={
            "wazuh": False,
            "victim": False,
            "kali": False,
            "reverse": False,
            "enterprise": False,
            "soc": False,
            "mail": False,
            "fileshare": True,
            "dns": False,
        },
    )

    details, check = check_provisioning_realization(
        scenario=scenario, project_dir=tmp_path, config=config
    )

    assert details is not None
    assert not check.passed
    assert any("content-placement-rejected" in d for d in check.diagnostics)
    assert any("runtime-observed-source" in d for d in check.diagnostics)


def test_account_provisioner_parity_passes_for_operational_scenario():
    config = load_config(PROJECT_ROOT / "aptl.json")
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None

    details, realization_check = check_provisioning_realization(
        scenario=scenario, project_dir=PROJECT_ROOT, config=config
    )
    assert realization_check.passed, realization_check.diagnostics
    assert details is not None

    check = check_account_provisioner_parity(
        scenario=scenario,
        project_dir=PROJECT_ROOT,
        realization_details=details,
    )

    assert check.passed, check.diagnostics


@pytest.fixture(scope="module")
def operational_realization_details():
    """Plan the released pack once for realized account-parity rejection tests."""

    config = load_config(PROJECT_ROOT / "aptl.json")
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    details, realization_check = check_provisioning_realization(
        scenario=scenario, project_dir=PROJECT_ROOT, config=config
    )
    assert realization_check.passed, realization_check.diagnostics
    assert details is not None
    return details


def _account_row(details, name):
    copied = copy.deepcopy(details)
    row = next(
        item
        for item in copied["placements"]
        if item.get("resource_type") == "account-placement" and item.get("name") == name
    )
    return copied, row


def test_account_provisioner_parity_fails_on_missing_realized_account(
    operational_realization_details,
):

    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    details, row = _account_row(operational_realization_details, "ad-jessica-williams")
    details["placements"].remove(row)

    check = check_account_provisioner_parity(
        scenario=scenario,
        project_dir=PROJECT_ROOT,
        realization_details=details,
    )

    assert not check.passed
    assert any(
        "ad-jessica-williams" in d and "no admitted account placement" in d
        for d in check.diagnostics
    )


def test_account_provisioner_parity_fails_on_wrong_realized_target(
    operational_realization_details,
):
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    details, row = _account_row(operational_realization_details, "ad-jessica-williams")
    row["target_node"] = "provision.node.webapp"

    check = check_account_provisioner_parity(
        scenario=scenario,
        project_dir=PROJECT_ROOT,
        realization_details=details,
    )

    assert not check.passed
    assert any("target_node" in d for d in check.diagnostics)


def test_account_provisioner_parity_fails_on_undeclared_group(
    operational_realization_details,
):
    """A declared group the provisioner never adds must fail closed."""
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    details, row = _account_row(operational_realization_details, "ad-jessica-williams")
    row["account"]["groups"] = [*row["account"]["groups"], "Finance"]

    check = check_account_provisioner_parity(
        scenario=scenario,
        project_dir=PROJECT_ROOT,
        realization_details=details,
    )

    assert not check.passed
    assert any("groups" in d for d in check.diagnostics)


def test_account_provisioner_parity_fails_on_mail_mismatch(
    operational_realization_details,
):
    """A declared mail address that doesn't match the provisioner's --mail must fail closed."""
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    details, row = _account_row(operational_realization_details, "ad-jessica-williams")
    row["account"]["mail"] = "jessica.williams@example.com"

    check = check_account_provisioner_parity(
        scenario=scenario,
        project_dir=PROJECT_ROOT,
        realization_details=details,
    )

    assert not check.passed
    assert any("mail" in d.lower() for d in check.diagnostics)


def test_account_provisioner_parity_fails_on_spn_mismatch(
    operational_realization_details,
):
    """A declared SPN the provisioner never sets via `samba-tool spn add` must fail closed."""
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    details, row = _account_row(operational_realization_details, "ad-svc-sql")
    row["account"]["spn"] = "HTTP/bogus.techvault.local"

    check = check_account_provisioner_parity(
        scenario=scenario,
        project_dir=PROJECT_ROOT,
        realization_details=details,
    )

    assert not check.passed
    assert any("spn" in d.lower() for d in check.diagnostics)


def test_account_provisioner_parity_fails_on_undisabled_account(
    operational_realization_details,
):
    """A declared disabled=True account the provisioner never disables must fail closed."""
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    details, row = _account_row(operational_realization_details, "ad-former-employee")
    row["account"]["disabled"] = not bool(
        scenario.accounts["ad-former-employee"].disabled
    )

    check = check_account_provisioner_parity(
        scenario=scenario,
        project_dir=PROJECT_ROOT,
        realization_details=details,
    )

    assert not check.passed
    assert any("disabled" in d.lower() for d in check.diagnostics)


def test_account_provisioner_parity_fails_without_an_admitted_realization(tmp_path):
    """No realization means nothing to compare accounts against, so fail closed.

    Parity used to fall back to scraping a checked-in ``provision-users.sh``
    from the ``ad`` image. The pack no longer declares that image and nothing
    builds it, so the admitted realization is the only authority left; absent
    it, the gate must refuse rather than pass (issue #1006).
    """
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None

    check = check_account_provisioner_parity(scenario=scenario, project_dir=tmp_path)

    assert not check.passed
    assert any(
        "no admitted provisioning realization" in d.lower() for d in check.diagnostics
    )


def test_validate_scenario_composes_checks(monkeypatch, tmp_path):
    monkeypatch.setattr(gc, "check_parse", lambda p: ("scn", GateCheck("parse", True)))
    monkeypatch.setattr(
        gc, "check_import_lock", lambda p, s: GateCheck("import_lock", True)
    )
    monkeypatch.setattr(gc, "check_compile", lambda s: GateCheck("compile", True))
    monkeypatch.setattr(
        gc,
        "check_backend_conformance",
        lambda **k: GateCheck("backend_conformance", True),
    )
    monkeypatch.setattr(
        gc,
        "check_provisioning_realization",
        lambda **k: ({}, GateCheck("provisioning_realization", True)),
    )
    monkeypatch.setattr(
        _account_parity,
        "check_account_provisioner_parity",
        lambda **k: GateCheck("account_provisioner_parity", True),
    )
    report = validate_scenario(
        tmp_path / "s.sdl.yaml",
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "t"}),
        options=GateOptions(check_imports=True),
    )
    assert report.passed
    assert {c.name for c in report.checks} == {
        "parse",
        "import_lock",
        "compile",
        "backend_conformance",
        "provisioning_realization",
        "account_provisioner_parity",
    }


def test_validate_scenario_short_circuits_on_parse_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        gc, "check_parse", lambda p: (None, GateCheck("parse", False, ("bad",)))
    )
    report = validate_scenario(
        tmp_path / "s.sdl.yaml",
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "t"}),
    )
    assert not report.passed
    assert [c.name for c in report.checks] == ["parse"]


def test_no_start_backend_refuses_everything():
    backend = _NoStartBackend()
    with pytest.raises(RuntimeError):
        backend.start(["p"])
    with pytest.raises(RuntimeError):
        backend.stop()
    with pytest.raises(RuntimeError):
        backend.status()


def _realized_aliases(details):
    aliases = set()
    for node in details.get("nodes", []):
        aliases.update(node.get("aliases", []))
    return aliases
