"""Static validation gate tests (SCN-010E / issue #322).

These exercise the scenario-generic gate composed in
``aptl.validation.techvault_gate``: the TechVault happy path, fail-loud on a
missing ACES corpus, the parity-manifest represented/deferred contract, Phase B
cutover strictness, and the anti-collapse / anti-preset proofs that the
realization is driven by declared content, not by the scenario id.

The gate spawns ``aces`` subprocesses and compiles the full scenario; the
TechVault happy-path report is computed once per module.
"""

import subprocess
from pathlib import Path

import pytest
import yaml
from aces_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RuntimeDomain,
)

from aptl.backends.aces_profiles import (
    public_start_profiles,
    select_backend_profiles,
    steady_state_service_aliases_for_profiles,
)
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig, load_config
from aptl.validation import _gate_checks as gc
from aptl.validation._gate_checks import (
    _NoStartBackend,
    _cli_detail,
    _conformance_cli_diagnostics,
    _contains_key,
    _coverage_set_diagnostics,
    _load_required_surface_coverage,
    _outcome,
    _severity,
    _surface_diagnostics,
    _surface_evidence,
    _target_conformance_diagnostics,
    _verify_imports_diagnostics,
    check_backend_conformance,
    check_compile,
    check_import_lock,
    check_parity_manifest,
    check_parse,
    check_provisioning_realization,
)
from aptl.validation.techvault_gate import (
    PHASE_B,
    REQUIRED_SURFACES,
    GateCheck,
    GateOptions,
    GateReport,
    validate_scenario,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIO = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"
OPERATIONAL_SCENARIO = PROJECT_ROOT / "scenarios" / "techvault-operational.sdl.yaml"


@pytest.fixture(scope="module")
def techvault_report():
    # The fast inner-loop gate: the slow `aces sdl verify-imports` step
    # (~4.5 min on TechVault) is owned by the dedicated CI job / pre-push hook
    # and the integration-marked test below.
    config = AptlConfig(lab={"name": "techvault"})
    return validate_scenario(
        SCENARIO,
        project_dir=PROJECT_ROOT,
        config=config,
        options=GateOptions(check_imports=False),
    )


# --------------------------------------------------------------------------- #
# Full-scenario happy path (integration: parsing TechVault is ~4.5 min, so this
# runs under `pytest -m integration` and the dedicated CI gate job, not the
# fast inner-loop suite — matching test_parity_inventory / composition tests).
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_gate_passes_on_techvault(techvault_report):
    assert techvault_report.passed, techvault_report.render()


@pytest.mark.integration
def test_gate_runs_every_fast_stage(techvault_report):
    assert {check.name for check in techvault_report.checks} == {
        "parse",
        "compile",
        "backend_conformance",
        "provisioning_realization",
        "parity_manifest",
    }


def test_committed_lockfile_exists():
    assert (SCENARIO.with_name("aces.lock.json")).exists()


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
        if not set(aliases) & realized_aliases
    }
    assert missing == {}


@pytest.mark.integration
def test_import_lock_verifies_committed_lockfile():
    # Slow (~4.5 min): re-hashes TechVault's full module tree. Runs under
    # `pytest -m integration` and the dedicated CI / pre-push gate, not the
    # fast inner-loop suite.
    check = check_import_lock(SCENARIO)
    assert check.passed, check.diagnostics


# --------------------------------------------------------------------------- #
# Fail-loud: a missing corpus/profile is a gate failure, never a warning.
# The in-process path (run_target_conformance) stays in the fast suite; the full
# check additionally spawns the `aces conformance backend` CLI, so its test is
# integration-marked (the repo classifies subprocess-spawning tests that way).
# --------------------------------------------------------------------------- #


def test_target_conformance_fails_loudly_on_missing_corpus(tmp_path):
    from aces_conformance.conformance import run_target_conformance

    from aptl.backends.aces import create_aptl_runtime_target
    from aptl.validation._gate_checks import _NoStartBackend

    config = AptlConfig(lab={"name": "techvault"})
    target = create_aptl_runtime_target(
        project_dir=PROJECT_ROOT, config=config, backend=_NoStartBackend()
    )
    report = run_target_conformance(
        target, profile="orchestration-capable", root=tmp_path, profiles_root=tmp_path
    )
    assert not report.passed


@pytest.mark.integration
def test_backend_conformance_fails_loudly_on_missing_corpus(tmp_path):
    # Spawns the `aces conformance backend` CLI subprocess via
    # check_backend_conformance, so it is integration-marked.
    config = AptlConfig(lab={"name": "techvault"})
    check = check_backend_conformance(
        project_dir=PROJECT_ROOT,
        config=config,
        profile="orchestration-capable",
        profiles_root=tmp_path,  # empty corpus root -> profile artifact not found
        fixtures_root=tmp_path,
    )
    assert not check.passed
    assert check.diagnostics


# --------------------------------------------------------------------------- #
# Parity manifest: represented must have evidence; deferred must cite an issue.
# --------------------------------------------------------------------------- #


class _FakeScenario:
    def __init__(self, doc):
        self._doc = doc

    def model_dump(self, **_kwargs):
        return self._doc


def _full_coverage(**overrides):
    coverage = {
        "nodes": {"status": "represented"},
        "services": {"status": "represented"},
        "vulnerabilities": {"status": "represented"},
        "features": {"status": "represented"},
        "kali_apparatus": {"status": "represented"},
        "defensive_stack": {"status": "represented"},
        "health": {"status": "represented"},
        "injects": {"status": "deferred", "blocking_followup": "#312"},
        "workflows": {"status": "deferred", "blocking_followup": "#312"},
        "objectives": {"status": "deferred", "blocking_followup": "#312"},
        "scoring": {"status": "deferred", "blocking_followup": "#312"},
        "run_archive": {"status": "deferred", "blocking_followup": "#312"},
    }
    coverage.update(overrides)
    return coverage


def _represented_doc():
    return {
        "nodes": [{"name": "db", "runtime": {"health": {"status": "healthy"}}}],
        "vulnerabilities": [{"id": "v1"}],
        "features": [{"id": "f1"}],
    }


def _represented_realization():
    return {
        "nodes": [{"name": "db", "services": ["smb"]}],
        "networks": [{"name": "net"}],
        "profiles": ["kali", "soc"],
    }


def _write_inventory(tmp_path, coverage):
    path = tmp_path / "parity-inventory.yaml"
    path.write_text(yaml.safe_dump({"required_surface_coverage": coverage}))
    return path


def _parity(tmp_path, coverage, *, doc=None, realization=None, phase="phase_a"):
    return check_parity_manifest(
        scenario=_FakeScenario(doc or _represented_doc()),
        realization_details=realization or _represented_realization(),
        project_dir=tmp_path,
        parity_inventory_path=_write_inventory(tmp_path, coverage),
        phase=phase,
    )


def test_parity_passes_when_represented_has_evidence_and_deferred_has_issue(tmp_path):
    assert _parity(tmp_path, _full_coverage()).passed


def test_parity_covers_exactly_the_required_surfaces(tmp_path):
    assert set(REQUIRED_SURFACES) == set(_full_coverage())


def test_parity_fails_when_required_surface_missing(tmp_path):
    coverage = _full_coverage()
    del coverage["vulnerabilities"]
    check = _parity(tmp_path, coverage)
    assert not check.passed
    assert any("missing entries" in d for d in check.diagnostics)


def test_parity_fails_when_represented_surface_lacks_evidence(tmp_path):
    # Coverage claims nodes are represented, but the realization has no nodes.
    check = _parity(
        tmp_path,
        _full_coverage(),
        realization={"nodes": [], "networks": [], "profiles": []},
    )
    assert not check.passed
    assert any("no evidence" in d for d in check.diagnostics)


def test_parity_fails_closed_when_surface_entry_is_not_a_mapping(tmp_path):
    # A required surface present with a scalar/list/null value must fail, not
    # silently bypass validation.
    coverage = _full_coverage(nodes="represented")
    check = _parity(tmp_path, coverage)
    assert not check.passed
    assert any("must be a mapping" in d for d in check.diagnostics)


def test_parity_fails_when_deferred_without_issue(tmp_path):
    coverage = _full_coverage(objectives={"status": "deferred", "blocking_followup": "n/a"})
    check = _parity(tmp_path, coverage)
    assert not check.passed
    assert any("without a tracking issue" in d for d in check.diagnostics)


def test_phase_b_cutover_disallows_deferrals(tmp_path):
    check = _parity(tmp_path, _full_coverage(), phase=PHASE_B)
    assert not check.passed
    assert any("Phase B" in d for d in check.diagnostics)


# --------------------------------------------------------------------------- #
# Anti-collapse (#324) and anti-preset: realization is content-driven.
# --------------------------------------------------------------------------- #


def _write_compose(project_dir, services):
    lines = ["services:"]
    for name, profiles in services.items():
        rendered = ", ".join(f'"{profile}"' for profile in profiles)
        lines += [f"  {name}:", f"    profiles: [{rendered}]", "    image: x:latest"]
    (project_dir / "docker-compose.yml").write_text("\n".join(lines))


def _node_plan(node_name, *, node_type="vm", os_family="linux"):
    address = f"provision.node.{node_name}"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload={
            "name": node_name,
            "node_name": node_name,
            "node_type": node_type,
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
        plan=_node_plan("kali"), project_dir=tmp_path, config=config
    )
    second = interpret_provisioning_plan(
        plan=_node_plan("victim"), project_dir=tmp_path, config=config
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
        plan=_node_plan("totally-unknown-node"), project_dir=tmp_path, config=config
    )
    assert [d for d in realization.diagnostics if _is_error(d)]


def _is_error(diagnostic):
    severity = getattr(diagnostic, "severity", None)
    return getattr(severity, "value", str(severity)).lower() == "error"


# --------------------------------------------------------------------------- #
# The APTL-local manifest shim is gone (canonical backend-manifest-v2 only).
# --------------------------------------------------------------------------- #


def test_local_manifest_shim_is_removed():
    from aptl.backends import aces_manifest

    assert not hasattr(aces_manifest, "AptlBackendManifest")
    assert not hasattr(aces_manifest, "AptlProvisionerCapabilities")


# --------------------------------------------------------------------------- #
# Fast unit coverage of the gate helpers, check-function branches, the report
# shape, and the orchestrator. The full happy paths are integration-marked
# above; these cover the logic without parsing the full TechVault tree.
# --------------------------------------------------------------------------- #


def _proc(returncode, stdout="", stderr=""):
    return subprocess.CompletedProcess(["aces"], returncode, stdout, stderr)


def test_gate_report_passed_failures_and_render():
    ok = GateCheck("parse", True)
    bad = GateCheck("compile", False, ("boom",))
    report = GateReport("scn", "provisioning-only", "phase_a", (ok, bad))
    assert report.passed is False
    assert report.failures() == (bad,)
    text = report.render()
    assert "FAIL" in text
    assert "boom" in text
    assert GateReport("scn", "p", "phase_a", (ok,)).passed is True


def test_contains_key_nested():
    assert _contains_key({"a": {"health": 1}}, "health")
    assert _contains_key([{"x": [{"health": 1}]}], "health")
    assert not _contains_key({"a": {"b": 1}}, "health")
    assert not _contains_key("scalar", "health")


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


def test_surface_evidence_detects_each_family():
    doc = {
        "vulnerabilities": [1],
        "features": [1],
        "nodes": [{"runtime": {"health": {}}}],
    }
    realization = {"nodes": [{"services": ["smb"]}], "profiles": ["kali", "soc"]}
    ev = _surface_evidence(doc, realization)
    assert ev["nodes"] and ev["services"] and ev["vulnerabilities"]
    assert ev["features"] and ev["kali_apparatus"] and ev["defensive_stack"]
    assert ev["health"]
    assert not _surface_evidence({}, {})["nodes"]


def test_coverage_set_diagnostics():
    assert _coverage_set_diagnostics(_full_coverage()) == []
    bad = {"nodes": {}, "unknown_surface": {}}
    diags = _coverage_set_diagnostics(bad)
    assert any("missing entries" in d for d in diags)
    assert any("unknown entries" in d for d in diags)


def test_load_required_surface_coverage_paths(tmp_path):
    missing = tmp_path / "nope.yaml"
    cov, err = _load_required_surface_coverage(missing)
    assert cov == {} and "missing" in err

    bad = tmp_path / "bad.yaml"
    bad.write_text("not-a-mapping")
    cov, err = _load_required_surface_coverage(bad)
    assert "required_surface_coverage" in err

    good = _write_inventory(tmp_path, _full_coverage())
    cov, err = _load_required_surface_coverage(good)
    assert err is None and set(cov) == set(REQUIRED_SURFACES)


def test_surface_diagnostics_branches():
    ev = {"nodes": True}
    assert _surface_diagnostics("nodes", {"status": "represented"}, ev, "phase_a") == []
    assert _surface_diagnostics("nodes", {"status": "represented"}, {}, "phase_a")
    assert _surface_diagnostics("nodes", "scalar", ev, "phase_a")
    deferred = {"status": "deferred", "blocking_followup": "#312"}
    assert _surface_diagnostics("injects", deferred, ev, "phase_a") == []
    assert _surface_diagnostics("injects", deferred, ev, PHASE_B)
    assert _surface_diagnostics("injects", {"status": "bogus"}, ev, "phase_a")


def test_verify_imports_diagnostics():
    assert _verify_imports_diagnostics(None)
    assert _verify_imports_diagnostics(_proc(1, stderr="stale"))
    assert _verify_imports_diagnostics(_proc(0)) == []


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
    monkeypatch.setattr(gc, "_run_aces", lambda *a, **k: None)
    assert _conformance_cli_diagnostics("provisioning-only", None, None)
    monkeypatch.setattr(gc, "_run_aces", lambda *a, **k: _proc(1, stderr="x"))
    assert _conformance_cli_diagnostics("provisioning-only", Path("f"), Path("p"))
    monkeypatch.setattr(gc, "_run_aces", lambda *a, **k: _proc(0))
    assert _conformance_cli_diagnostics("provisioning-only", None, None) == []


def test_cli_detail_json_and_plain():
    payload = '{"diagnostics": [{"code": "conformance.profile-load-failed"}]}'
    assert "profile-load-failed" in _cli_detail(_proc(1, stdout=payload))
    assert "exit=2" in _cli_detail(_proc(2, stderr="boom\nlast line"))


def test_check_parse_rejects_missing_file(tmp_path):
    scenario, check = check_parse(tmp_path / "nope.sdl.yaml")
    assert scenario is None
    assert not check.passed


def test_check_import_lock_missing_and_unavailable(tmp_path, monkeypatch):
    scenario = tmp_path / "techvault.sdl.yaml"
    scenario.write_text("name: t\n")
    check = check_import_lock(scenario)
    assert not check.passed and any("missing import lockfile" in d for d in check.diagnostics)

    (tmp_path / "aces.lock.json").write_text("{}")
    monkeypatch.setattr(gc, "_run_aces", lambda *a, **k: None)
    check = check_import_lock(scenario)
    assert not check.passed and any("not found on PATH" in d for d in check.diagnostics)


def test_check_compile_rejects_invalid_scenario():
    check = check_compile(object())
    assert not check.passed


def test_check_provisioning_realization_handles_raise(monkeypatch):
    def _boom(**_kwargs):
        raise RuntimeError("no target")

    monkeypatch.setattr(gc, "create_aptl_runtime_target", _boom)
    details, check = check_provisioning_realization(
        scenario=object(), project_dir=PROJECT_ROOT, config=AptlConfig(lab={"name": "t"})
    )
    assert details is None and not check.passed


def test_check_provisioning_realization_fails_on_profile_mismatch(tmp_path):
    from textwrap import dedent

    from aces_sdl.parser import parse_sdl

    _write_compose(tmp_path, {"kali": ["kali"], "victim": ["victim"]})
    scenario = parse_sdl(
        dedent(
            """
            name: partial-range
            nodes:
              internal-net:
                type: switch
              kali:
                type: vm
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


def test_validate_scenario_composes_checks(monkeypatch, tmp_path):
    monkeypatch.setattr(gc, "check_parse", lambda p: ("scn", GateCheck("parse", True)))
    monkeypatch.setattr(gc, "check_import_lock", lambda p: GateCheck("import_lock", True))
    monkeypatch.setattr(gc, "check_compile", lambda s: GateCheck("compile", True))
    monkeypatch.setattr(
        gc, "check_backend_conformance", lambda **k: GateCheck("backend_conformance", True)
    )
    monkeypatch.setattr(
        gc,
        "check_provisioning_realization",
        lambda **k: ({}, GateCheck("provisioning_realization", True)),
    )
    monkeypatch.setattr(
        gc, "check_parity_manifest", lambda **k: GateCheck("parity_manifest", True)
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
        "parity_manifest",
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
