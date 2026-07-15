"""Static validation gate for ACES scenarios (SCN-010E / issue #322).

Composes the ACES authorities — the reference parser, import-lock verification,
the runtime compiler/semantic validator, and canonical ``backend-manifest-v2``
conformance — together with APTL's provisioning realization into a single,
scenario-generic gate. It is parameterized by scenario path, backend profile,
corpus roots, and target name: TechVault is the proving input, never a
hardcoded branch, so the next scenario in APTL's expressivity class passes
through by changing inputs rather than editing this module.

The gate is STATIC. It parses, locks, compiles, conformance-checks, and
interprets the provisioning plan, but never starts Docker or touches the lab.
Every failure is a structured, redacted diagnostic; the gate never emits the
full SDL object or a raw exception payload (ADR-029).

A missing ACES contract corpus, profile artifact, or conformance CLI is a gate
*failure* with an actionable diagnostic — never silently downgraded to a
warning, and never a reason to accept an APTL-local manifest approximation.

The check implementations live in ``aptl.validation._gate_checks``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig

DEFAULT_PROFILE = "full-remote-control-plane"
DEFAULT_SCENARIO = Path("scenarios") / "techvault-operational.sdl.yaml"


@dataclass(frozen=True)
class GateCheck(object):
    """One named gate check and its outcome."""

    name: str
    passed: bool
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class GateReport(object):
    """The composed outcome of every gate check for a scenario."""

    scenario: str
    profile: str
    checks: tuple[GateCheck, ...]

    @property
    def passed(self) -> bool:
        """Return whether every gate check passed."""
        return all(check.passed for check in self.checks)

    def failures(self) -> tuple[GateCheck, ...]:
        """Return the checks that failed."""
        return tuple(check for check in self.checks if not check.passed)

    def render(self) -> str:
        """Render a redacted, human/CI-readable summary."""
        lines = [
            f"ACES static validation gate — scenario={self.scenario} "
            f"profile={self.profile}: "
            f"{'PASS' if self.passed else 'FAIL'}"
        ]
        for check in self.checks:
            marker = "ok" if check.passed else "FAIL"
            lines.append(f"  [{marker}] {check.name}")
            for diagnostic in check.diagnostics:
                lines.append(f"        - {diagnostic}")
        return "\n".join(lines)


@dataclass(frozen=True)
class GateOptions(object):
    """Tunable inputs for the static validation gate.

    ``fixtures_root`` / ``profiles_root`` override the ACES corpus roots
    (default: the roots bundled with the installed ``aces-sdl`` wheel).
    ``check_imports`` controls the ``aces sdl verify-imports`` step, whose cost
    scales with the scenario's imported module tree; the fast inner-loop test
    suite sets it False and lets the dedicated CI job / pre-push hook own lock
    verification. A scenario that declares no ``imports:`` passes the step
    without a lockfile, so it costs nothing for the import-free scenarios this
    repo ships today while staying fail-closed for any that import.
    """

    profile: str = DEFAULT_PROFILE
    fixtures_root: Path | None = None
    profiles_root: Path | None = None
    check_imports: bool = True


def validate_scenario(
    scenario_path: Path,
    *,
    project_dir: Path,
    config: AptlConfig,
    options: GateOptions | None = None,
) -> GateReport:
    """Run the full static validation gate for ``scenario_path``."""
    from aptl.validation import _gate_checks as checks

    opts = options or GateOptions()
    results: list[GateCheck] = []

    # 1. Parse — ACES reference parser must accept the scenario.
    scenario, parse_check = checks.check_parse(scenario_path)
    results.append(parse_check)
    if scenario is None:
        return GateReport(str(scenario_path), opts.profile, tuple(results))

    # 2. Import lock — verify the committed lockfile, trust policy, and imports.
    if opts.check_imports:
        results.append(checks.check_import_lock(scenario_path, scenario))

    # 3. Compile / semantic validation.
    results.append(checks.check_compile(scenario))

    # 4. Backend manifest + conformance (API target check + published CLI).
    results.append(
        checks.check_backend_conformance(
            project_dir=project_dir,
            config=config,
            profile=opts.profile,
            fixtures_root=opts.fixtures_root,
            profiles_root=opts.profiles_root,
            reference_scenario=scenario,
        )
    )

    # 5. Provisioning realization — interpret the plan, scenario-generically.
    _realization_details, realization_check = checks.check_provisioning_realization(
        scenario=scenario, project_dir=project_dir, config=config
    )
    results.append(realization_check)

    # 6. Account provisioner parity — every SDL account is a real,
    # clean-start-realized fixture, not a phantom declaration (#689).
    from aptl.validation import _account_parity

    results.append(
        _account_parity.check_account_provisioner_parity(
            scenario=scenario, project_dir=project_dir
        )
    )

    return GateReport(str(scenario_path), opts.profile, tuple(results))
