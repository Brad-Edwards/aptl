"""Static validation gate tests (SCN-010E / issue #322).

These exercise the scenario-generic gate composed in
``aptl.validation.techvault_gate``: the TechVault happy path, fail-loud on a
missing ACES corpus, the parity-manifest represented/deferred contract, Phase B
cutover strictness, and the anti-collapse / anti-preset proofs that the
realization is driven by declared content, not by the scenario id.

The gate spawns ``aces`` subprocesses and compiles the full scenario; the
TechVault happy-path report is computed once per module.
"""

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

from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig
from aptl.validation._gate_checks import (
    check_backend_conformance,
    check_import_lock,
    check_parity_manifest,
)
from aptl.validation.techvault_gate import (
    PHASE_B,
    REQUIRED_SURFACES,
    GateOptions,
    validate_scenario,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIO = PROJECT_ROOT / "scenarios" / "techvault.sdl.yaml"


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
        target, profile="provisioning-only", root=tmp_path, profiles_root=tmp_path
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
        profile="provisioning-only",
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
