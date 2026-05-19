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


@PARITY_GATE
class TestUserVisibleInvariance:
    """Contract: pre- and post-cutover behavior is indistinguishable
    from a user's perspective. See ADR-035 § Update 2026-05-19."""

    def test_full_integration_suite_passes_under_aces_backend(self):
        """Invariant 1: every LIVE_LAB-gated test in
        tests/test_range_integration.py that passes under the legacy
        scenario backend also passes under the ACES backend.

        This is the dispositive parity test. Implementation runs the
        full integration suite twice (legacy + aces) and asserts
        identical pass/fail per test.
        """
        repo_root = Path(__file__).resolve().parent.parent
        env_aces = {**os.environ, "APTL_SCENARIO_BACKEND": "aces"}
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
            "Integration suite failed under ACES backend.\n"
            f"stdout:\n{result.stdout[-4000:]}\n"
            f"stderr:\n{result.stderr[-2000:]}"
        )

    def test_aptl_lab_start_cli_unchanged_under_aces(self):
        """Invariant 2: `aptl lab start` exit code, stdout structure,
        and stderr shape are identical under both backends.

        Cutover MUST preserve the CLI's user-visible surface — no new
        flags become required, no removed flags break invocations,
        same exit codes, same human-readable output, same machine-
        parseable JSON when --json is set.
        """
        # Implementation note: drive the same `aptl lab start --json`
        # under both backends, normalize timing fields, and assert
        # structural equality on the rest. Skipped until impl lands.
        pytest.fail("not yet implemented — pre-cutover stub")

    def test_aptl_json_schema_accepts_all_existing_configs(self):
        """Invariant 3: every aptl.json from the repo's example +
        test fixtures validates without modification under the ACES
        backend's config loading. No user has to edit aptl.json to
        migrate."""
        pytest.fail("not yet implemented — pre-cutover stub")

    def test_lab_result_envelope_shape_unchanged(self):
        """Invariant 4: LabResult / StartupOutcome /
        LabActionResponse / StartupDiagnostic field sets and types
        are identical pre- and post-cutover. ACES Diagnostics
        translate into existing envelopes at the adapter boundary."""
        pytest.fail("not yet implemented — pre-cutover stub")

    def test_run_archive_shape_unchanged(self):
        """Invariant 5: RangeSnapshot.to_dict() and LocalRunStore's
        written JSONL produce structurally-equivalent archives
        pre- and post-cutover. Diff of normalized archives must be
        empty."""
        pytest.fail("not yet implemented — pre-cutover stub")

    def test_scenario_start_wall_clock_within_envelope(self):
        """Invariant 6: scenario startup wall-clock under ACES is
        within 10% of the legacy path's baseline. Performance is a
        first-class part of the user-visible contract."""
        pytest.fail("not yet implemented — pre-cutover stub")

    def test_failure_modes_produce_identical_envelopes(self):
        """Invariant 7: when the legacy path raises
        LabResult(success=False, error=<code>), the ACES path raises
        the same shape with the same error code class. Translation
        happens at the adapter boundary; user-facing error messages
        are indistinguishable in semantics."""
        pytest.fail("not yet implemented — pre-cutover stub")


@PARITY_GATE
class TestAcesBackendDrivesLab:
    """The ACES-backend realization path produces a working lab —
    not a shape-correct manifest, but actual containers responding
    to scenario commands the same way the legacy path's lab does."""

    def test_aces_driven_scenario_start_produces_running_containers(self):
        """The most basic parity probe: start the equivalent ACES
        scenario, assert the same Docker containers are running with
        the same names, networks, and reachability the legacy path
        produces.

        This test depends on the full APTL adapter wiring through
        DeploymentBackend. Skipped until that wiring exists.
        """
        pytest.fail("not yet implemented — pre-cutover stub")

    def test_aces_driven_techvault_matches_legacy_scenario_set_surfaces(self):
        """TechVault under ACES exercises the same node/service/
        vulnerability/feature/inject/objective surfaces as the union
        of the current scenarios/*.yaml set. The capability-parity
        check from ADR-035's Parity Gate, mechanized."""
        pytest.fail("not yet implemented — pre-cutover stub")
