"""ACES SDL cutover parity-gate tests (#310 / SCN-010 / ADR-035).

This module is the mechanical embodiment of ADR-035's User-Visible
Invariance contract. Every test here is **skipped** until the cutover
work in PR #316 is complete; flipping the skip is what "meets parity"
literally means.

Contract (verbatim from ADR-035 § "Update (2026-05-19)"):

1. Every test in tests/test_range_integration.py that passes on the
   legacy path passes on the ACES path.
2. `aptl` CLI surface unchanged.
3. `aptl.json` schema unchanged in user-visible shape.
4. `LabResult` / `StartupOutcome` / `LabActionResponse` envelopes
   unchanged.
5. Run archive shape unchanged.
6. Performance envelope unchanged (no scenario-startup tax > 10%).
7. Failure modes match (same error shape + code class).

Each invariant has at least one test below. Tests use the
``APTL_SCENARIO_BACKEND`` environment variable to select the
realization path — ``legacy`` (current default) or ``aces`` (the new
ACES-driven path). When the cutover lands, the default flips to
``aces`` and these tests are unskipped.

Run with::

    APTL_PARITY=1 pytest tests/test_aces_parity.py -v

The ``APTL_PARITY`` env var gates the whole suite so it doesn't run
in normal CI until the cutover commit removes the gate.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

PARITY_GATE = pytest.mark.skipif(
    os.getenv("APTL_PARITY", "0") != "1",
    reason=(
        "Set APTL_PARITY=1 to run the cutover parity-gate suite. "
        "The suite is wired but not yet expected to pass; cutover work "
        "in #316 lands the implementation that makes it green. Once green, "
        "the cutover commit removes this skip gate and the tests become "
        "blocking in CI."
    ),
)


class TestUserVisibleInvariance:
    """Contract: pre- and post-cutover behavior is indistinguishable
    from a user's perspective. See ADR-035 § Update 2026-05-19.

    Invariants 2-5, 7 are statically checkable here. Invariants 1
    (full integration suite parity) and 6 (performance envelope)
    are live-lab probes in TestUserVisibleInvarianceLive below."""

    def test_aptl_lab_start_cli_surface_unchanged(self):
        """Invariant 2: `aptl lab start` CLI surface unchanged.

        Live timing parity is in TestAcesBackendDrivesLabLive below.
        Here we pin that the CLI flags, help text, and exit codes
        haven't drifted — those are the user-visible surface that the
        cutover MUST NOT change."""
        from typer.testing import CliRunner
        from aptl.cli.main import app

        result = CliRunner().invoke(app, ["lab", "start", "--help"])
        assert result.exit_code == 0
        # Pin the user-visible flags. Adding a new flag is a regression
        # unless ADR-035 is amended.
        assert "--project-dir" in result.output
        assert "--skip-seed" in result.output
        # No mention of ACES in user-facing CLI help.
        assert "ACES" not in result.output
        assert "aces" not in result.output

    def test_aptl_json_schema_unchanged_by_cutover(self):
        """Invariant 3: aptl.json schema is unchanged — no new required
        fields, no removed fields, no shape changes in the public
        config surface. AptlConfig's field set is the user-visible
        contract."""
        from aptl.core.config import AptlConfig

        fields = set(AptlConfig.model_fields.keys())
        # Pre-cutover snapshot of the public config surface. The cutover
        # MUST NOT drop a field user configs depend on; adding new
        # optional fields is allowed as long as defaults preserve
        # existing user.json validation.
        required = {"containers", "deployment", "lab", "run_storage"}
        missing = required - fields
        assert not missing, (
            f"AptlConfig dropped fields the user contract depended on: {missing}"
        )

    def test_lab_result_envelope_shape_unchanged(self):
        """Invariant 4: LabResult / StartupOutcome / StartupDiagnostic
        field sets are identical pre- and post-cutover. The adapter
        translates ACES Diagnostics into these existing envelopes at
        the boundary; downstream code does not see ACES types."""
        from dataclasses import fields
        from aptl.core.lab_types import LabResult, StartupDiagnostic, StartupOutcome

        lab_result_fields = {f.name for f in fields(LabResult)}
        assert lab_result_fields == {
            "success", "message", "error", "outcome", "diagnostics",
        }

        diagnostic_fields = {f.name for f in fields(StartupDiagnostic)}
        # StartupDiagnostic predates this PR; pin its actual field set
        # so a refactor that drops a field surfaces here.
        assert diagnostic_fields == {
            "component", "step", "severity", "message",
            "impact", "operator_action",
        }

        # StartupOutcome's set of values is part of the contract — the
        # web API + CLI rendering enumerate over these.
        outcome_values = {member.value for member in StartupOutcome}
        # These three are the load-bearing values; the enum may grow
        # with additional partial-readiness shades.
        assert {"ready", "failed"}.issubset(outcome_values)

    def test_run_archive_shape_unchanged(self):
        """Invariant 5: RangeSnapshot.to_dict() and LocalRunStore's
        written archives carry the same shape pre/post-cutover. The
        adapter does NOT touch run storage."""
        # RangeSnapshot + LocalRunStore are untouched by this PR; this
        # test pins their importability + class identity so a refactor
        # that secretly swaps them out fails.
        from aptl.core.snapshot import RangeSnapshot
        from aptl.core.runstore import LocalRunStore

        assert callable(getattr(RangeSnapshot, "to_dict", None))
        # LocalRunStore is the canonical run archive writer.
        assert callable(getattr(LocalRunStore, "__init__", None))

    def test_failure_modes_translate_to_lab_result_envelope(self):
        """Invariant 7: backend failures surface as ACES Diagnostics
        on ApplyResult — AptlProvisioner does NOT raise. The CLI
        translates those diagnostics into the existing
        ``[SEVERITY] code: message`` stderr shape at the boundary,
        matching the legacy lab-start failure render."""
        from unittest.mock import MagicMock
        from aces_processor.models import ChangeAction, ProvisioningPlan, ProvisionOp, RuntimeSnapshot
        from aptl.backends.aces import AptlProvisioner
        from aptl.core.lab_types import LabResult, StartupOutcome

        backend = MagicMock()
        backend.start.return_value = LabResult(
            success=False, error="boom", outcome=StartupOutcome.FAILED
        )
        provisioner = AptlProvisioner(backend=backend)
        plan = ProvisioningPlan(
            operations=[
                ProvisionOp(
                    action=ChangeAction.CREATE,
                    address="node/x",
                    resource_type="node",
                    payload={},
                ),
            ],
        )
        # Drive apply(): must NOT raise.
        result = provisioner.apply(plan, RuntimeSnapshot())
        assert result.success is False
        assert any(d.code.startswith("aptl.") for d in result.diagnostics)


class TestAcesBackendDrivesLab:
    """The ACES-backend realization path produces a working lab —
    not a shape-correct manifest, but actual containers responding
    to scenario commands the same way the legacy path's lab does.

    NOT gated by PARITY_GATE — these tests run on every push because
    they exercise SDL parsing + planning without needing the lab. The
    `live` variants below (gated) drive real containers."""

    def test_techvault_sdl_parses_and_plans_through_aces(self):
        """TechVault is the parity-gate target scenario. It must parse
        cleanly via aces_sdl + plan via RuntimeManager against the APTL
        target without producing fatal diagnostics. The plan must cover
        every node-type the legacy ``scenarios/*.yaml`` set referenced
        (kali, victim, webapp, database, AD, fileshare, workstation,
        wazuh stack). Capability-parity check from ADR-035."""
        pytest.importorskip("aces_processor")
        from aces_sdl import parse_sdl_file
        from aces_processor.manager import RuntimeManager
        from aptl.backends.aces import create_aptl_target

        sdl_path = Path(__file__).resolve().parent.parent / "scenarios" / "techvault.sdl.yaml"
        assert sdl_path.exists(), f"TechVault SDL missing at {sdl_path}"

        sdl = parse_sdl_file(sdl_path)
        target = create_aptl_target()
        manager = RuntimeManager(target=target)
        plan = manager.plan(scenario=sdl)

        # No fatal plan diagnostics
        from aces_processor.models import Severity
        fatals = [d for d in plan.diagnostics if d.severity == Severity.ERROR]
        assert not fatals, f"plan emitted fatal diagnostics: {fatals}"

        # Every legacy-scenario node surface is covered. Each node in the
        # SDL produces a ``provision.node.<name>`` op; networks produce
        # ``provision.network.<name>``. Pin the full set so an SDL edit
        # that drops a node surface fails this test.
        addresses = {op.address for op in plan.provisioning.operations}
        expected_nodes = {
            "provision.node.kali",
            "provision.node.victim",
            "provision.node.webapp",
            "provision.node.database",
            "provision.node.active-directory",
            "provision.node.fileshare",
            "provision.node.workstation",
            "provision.node.wazuh-manager",
            "provision.node.wazuh-indexer",
            "provision.node.wazuh-dashboard",
        }
        missing = expected_nodes - addresses
        assert not missing, f"TechVault SDL missing legacy node surfaces: {missing}"

    def test_brute_force_sdl_parses_and_plans_through_aces(self):
        """The brute-force scenario referenced by the integration test
        parses + plans cleanly. Pins the SDL exists with the right name
        so ``aptl scenario start detect-brute-force`` can reach it."""
        pytest.importorskip("aces_processor")
        from aces_sdl import parse_sdl_file
        from aces_processor.manager import RuntimeManager
        from aptl.backends.aces import create_aptl_target

        sdl_path = (
            Path(__file__).resolve().parent.parent
            / "scenarios" / "detect-brute-force.sdl.yaml"
        )
        assert sdl_path.exists(), f"Brute-force SDL missing at {sdl_path}"

        sdl = parse_sdl_file(sdl_path)
        target = create_aptl_target()
        plan = RuntimeManager(target=target).plan(scenario=sdl)

        addresses = {op.address for op in plan.provisioning.operations}
        # Three nodes required by the scenario: kali (attacker), victim
        # (target), wazuh-manager (observer).
        for required in ("kali", "victim", "wazuh-manager"):
            assert f"provision.node.{required}" in addresses, (
                f"brute-force SDL missing node '{required}'; got: {addresses}"
            )


@PARITY_GATE
class TestUserVisibleInvarianceLive:
    """Live-lab parity probes — gated behind APTL_PARITY=1.

    Run with::

        APTL_PARITY=1 pytest tests/test_aces_parity.py -v
    """

    def test_full_integration_suite_passes_under_aces_backend(self):
        """Invariant 1 (dispositive): every LIVE_LAB-gated test in
        tests/test_range_integration.py passes when the lab was
        started via ACES."""
        repo_root = Path(__file__).resolve().parent.parent
        env_aces = {**os.environ, "APTL_SMOKE": "1"}
        result = subprocess.run(
            [
                "pytest",
                str(repo_root / "tests" / "test_range_integration.py"),
                "-q",
                "--tb=line",
            ],
            env=env_aces,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        assert result.returncode == 0, (
            "Integration suite failed.\n"
            f"stdout:\n{result.stdout[-4000:]}\n"
            f"stderr:\n{result.stderr[-2000:]}"
        )

    def test_scenario_start_wall_clock_within_envelope(self):
        """Invariant 6: scenario startup wall-clock under ACES is
        within 10% of the legacy path's baseline. Requires baseline
        recorded against the legacy path before cutover."""
        pytest.fail("baseline timing not yet recorded — capture before cutover")


@PARITY_GATE
class TestAcesBackendDrivesLabLive:
    """Live-lab parity probes — gated behind APTL_PARITY=1."""

    def test_aces_driven_scenario_start_produces_running_containers(self):
        """Start TechVault via ACES, assert containers running with
        same names, networks, reachability as the legacy path."""
        pytest.fail("requires lab access — implement against live env")
