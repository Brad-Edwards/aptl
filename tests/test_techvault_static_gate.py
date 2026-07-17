"""Static validation gate tests (SCN-010E / issue #322).

These exercise the scenario-generic gate composed in
``aptl.validation.techvault_gate``: the authoritative operational scenario
gate, fail-loud on a missing ACES corpus, and the anti-collapse / anti-preset
proofs that the realization is driven by declared content, not by the
scenario id.

``techvault-operational.sdl.yaml`` is the authoritative driving scenario the
gate validates.
"""

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from aces_runtime.manager import RuntimeManager
from aces_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RuntimeDomain,
)

from aptl.backends.aces_profiles import (
    load_compose_profile_index,
    public_start_profiles,
    select_backend_profiles,
    steady_state_service_aliases_for_profiles,
)
from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig, load_config
from aptl.validation import _account_parity
from aptl.validation import _gate_checks as gc
from aptl.validation._account_parity import check_account_provisioner_parity
from aptl.validation._gate_checks import (
    _NoStartBackend,
    _cli_detail,
    _conformance_cli_diagnostics,
    _outcome,
    _severity,
    _target_conformance_diagnostics,
    _verify_imports_diagnostics,
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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OPERATIONAL_SCENARIO = PROJECT_ROOT / "scenarios" / "techvault-operational.sdl.yaml"
PAPER_SCENARIO = PROJECT_ROOT / "scenarios" / "paper-agent-loop.sdl.yaml"
PROFILE_INFRASTRUCTURE_SERVICES = frozenset({"kali-ssh-proxy"})


# --------------------------------------------------------------------------- #
# Authoritative operational scenario gate (integration: backend_conformance
# spawns the `aces conformance backend` CLI). This is the driving-SDL completion
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
    config = load_config(PROJECT_ROOT / "aptl.json")
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert scenario is not None
    assert parse_check.passed, parse_check.diagnostics

    execution_plan = RuntimeManager(
        create_aptl_runtime_target(
            project_dir=PROJECT_ROOT,
            config=config,
            backend=_NoStartBackend(),
        )
    ).plan(scenario)
    realization = interpret_provisioning_plan(
        plan=execution_plan.provisioning,
        project_dir=PROJECT_ROOT,
        config=config,
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
    assert generators == {"certificate_bundle", "rendered_config"}
    artifacts = {item["name"]: item for item in details["generated_artifacts"]}
    assert {output["path"] for output in artifacts["wazuh-indexer-certs"]["outputs"]} == {
        "root-ca.pem",
        "wazuh.indexer-key.pem",
        "wazuh.indexer.pem",
    }
    assert {output["path"] for output in artifacts["wazuh-manager-certs"]["outputs"]} == {
        "root-ca-manager.pem",
        "wazuh.manager-key.pem",
        "wazuh.manager.pem",
    }
    assert {output["path"] for output in artifacts["wazuh-dashboard-certs"]["outputs"]} == {
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
    assert nodes["wazuh-manager"]["image"]["image_ref"] == (
        "wazuh/wazuh-manager:4.12.0"
    )
    assert nodes["wazuh-indexer"]["image"]["image_ref"] == (
        "wazuh/wazuh-indexer:4.12.0"
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

    execution_plan = RuntimeManager(
        create_aptl_runtime_target(
            project_dir=PROJECT_ROOT,
            config=config,
            backend=_NoStartBackend(),
        )
    ).plan(scenario)
    realization = interpret_provisioning_plan(
        plan=execution_plan.provisioning,
        project_dir=PROJECT_ROOT,
        config=config,
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
        target,
        profile="full-remote-control-plane",
        root=tmp_path,
        profiles_root=tmp_path,
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


def _scenario_with_imports(*imports: object) -> SimpleNamespace:
    """Stand in for a parsed ACES ``Scenario`` carrying (or not) an import set."""
    return SimpleNamespace(imports=list(imports))


def test_check_import_lock_missing_and_unavailable(tmp_path, monkeypatch):
    path = tmp_path / "techvault.sdl.yaml"
    path.write_text("name: t\n")
    scenario = _scenario_with_imports("local:mod.sdl.yaml")

    check = check_import_lock(path, scenario)
    assert not check.passed and any(
        "missing import lockfile" in d for d in check.diagnostics
    )

    (tmp_path / "aces.lock.json").write_text("{}")
    monkeypatch.setattr(gc, "_run_aces", lambda *a, **k: None)
    check = check_import_lock(path, scenario)
    assert not check.passed and any("not found on PATH" in d for d in check.diagnostics)


def test_check_import_lock_passes_when_scenario_declares_no_imports(tmp_path):
    """No imports means nothing to resolve, so no lockfile is required."""
    path = tmp_path / "operational.sdl.yaml"
    path.write_text("name: t\n")

    check = check_import_lock(path, _scenario_with_imports())

    assert check.passed
    assert not (tmp_path / "aces.lock.json").exists()


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
    assert content_placements and all("content" in p for p in content_placements)
    assert account_placements and all("account" in p for p in account_placements)


def test_provisioning_realization_fails_on_unrealizable_content(tmp_path):
    from textwrap import dedent

    from aces_sdl.parser import parse_sdl

    _write_compose(tmp_path, {"fileshare": ["fileshare"]})
    scenario = parse_sdl(
        dedent(
            """
            name: bad-content
            nodes:
              fileshare:
                type: vm
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
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None

    check = check_account_provisioner_parity(
        scenario=scenario, project_dir=PROJECT_ROOT
    )

    assert check.passed, check.diagnostics


def test_account_provisioner_parity_fails_on_phantom_account():
    from aces_sdl.accounts import Account, PasswordStrength

    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    scenario.accounts["phantom-user"] = Account(
        username="not-a-real-provisioner-user",
        node="ad",
        password_strength=PasswordStrength.WEAK,
    )

    check = check_account_provisioner_parity(
        scenario=scenario, project_dir=PROJECT_ROOT
    )

    assert not check.passed
    assert any("not-a-real-provisioner-user" in d for d in check.diagnostics)


def test_account_provisioner_parity_fails_closed_when_script_missing(tmp_path):
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None

    check = check_account_provisioner_parity(scenario=scenario, project_dir=tmp_path)

    assert not check.passed
    assert any("provisioner script missing" in d.lower() for d in check.diagnostics)


def test_account_provisioner_parity_fails_on_undeclared_group():
    """A declared group the provisioner never adds must fail closed."""
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    account = scenario.accounts["ad-jessica-williams"]
    account.groups = [*account.groups, "Finance"]

    check = check_account_provisioner_parity(
        scenario=scenario, project_dir=PROJECT_ROOT
    )

    assert not check.passed
    assert any("Finance" in d and "group" in d.lower() for d in check.diagnostics)


def test_account_provisioner_parity_fails_on_mail_mismatch():
    """A declared mail address that doesn't match the provisioner's --mail must fail closed."""
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    account = scenario.accounts["ad-jessica-williams"]
    account.mail = "jessica.williams@example.com"

    check = check_account_provisioner_parity(
        scenario=scenario, project_dir=PROJECT_ROOT
    )

    assert not check.passed
    assert any("mail" in d.lower() for d in check.diagnostics)


def test_account_provisioner_parity_fails_on_spn_mismatch():
    """A declared SPN the provisioner never sets via `samba-tool spn add` must fail closed."""
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    account = scenario.accounts["ad-svc-sql"]
    account.spn = "HTTP/bogus.techvault.local"

    check = check_account_provisioner_parity(
        scenario=scenario, project_dir=PROJECT_ROOT
    )

    assert not check.passed
    assert any("spn" in d.lower() for d in check.diagnostics)


def test_account_provisioner_parity_fails_on_undisabled_account():
    """A declared disabled=True account the provisioner never disables must fail closed."""
    scenario, parse_check = check_parse(OPERATIONAL_SCENARIO)
    assert parse_check.passed
    assert scenario is not None
    account = scenario.accounts["ad-former-employee"]
    account.disabled = True

    check = check_account_provisioner_parity(
        scenario=scenario, project_dir=PROJECT_ROOT
    )

    assert not check.passed
    assert any("disabled" in d.lower() for d in check.diagnostics)


def test_provisioner_relaxes_password_policy_before_user_creation():
    """Declared weak-password personas must actually provision at boot.

    The Samba domain default password policy (complexity on, min length 7)
    rejects deliberately-weak passwords (e.g. jessica.williams / password123)
    at ``samba-tool user create``; the script's ``|| true`` masks the failure,
    so the account silently never exists — a runtime honesty gap the static
    parity gate cannot see. The provisioner must disable complexity BEFORE it
    creates any user so every declared weak-password account is realized
    (issue #689 account-realization honesty).
    """
    script = (PROJECT_ROOT / "containers" / "ad" / "provision-users.sh").read_text(
        encoding="utf-8"
    )
    lines = script.splitlines()
    complexity_off = next(
        (
            i
            for i, line in enumerate(lines)
            if "passwordsettings set --complexity=off" in line
        ),
        None,
    )
    first_user_create = next(
        (i for i, line in enumerate(lines) if "samba-tool user create " in line),
        None,
    )

    assert complexity_off is not None, (
        "provisioner must disable password complexity so weak-password "
        "personas can be created"
    )
    assert first_user_create is not None
    assert complexity_off < first_user_create, (
        "password complexity must be disabled BEFORE the first user is "
        "created, or weak-password accounts silently fail to provision"
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
