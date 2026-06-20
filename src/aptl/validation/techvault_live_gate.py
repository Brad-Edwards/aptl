"""Live validation gate for ACES scenarios (SCN-010F / issue #323).

The operational counterpart to the static gate in
``aptl.validation.techvault_gate``. Where the static gate parses, locks,
compiles, conformance-checks, and *interprets* a scenario without ever
starting Docker, this gate boots the full lab through APTL's **public** start
path (``aptl lab stop -v`` cleanup followed by ``orchestrate_lab_start``) and
proves the running range is realized from the interpreted ACES model — not from
a TechVault preset — then captures operational and provenance evidence in a run
archive.

Like the static gate, it is scenario-generic and parameterized by scenario
path, backend profile, and project directory: TechVault is the proving input,
never a hardcoded branch (ADR-035). The next scenario in APTL's
``orchestration-capable`` expressivity class passes through by changing inputs.

The gate is inherently integration / live-run work: it requires Docker, the SOC
stack's resources, real ``.env`` secrets, and minutes-long startup. It is wired
behind an explicit guard (``aptl lab validate-live`` and the
``APTL_LIVE_GATE``-gated integration test), never a fast CI / pre-commit gate,
and its cleanup is **data-destroying** and must run only against an isolated,
project-scoped lab.

Every failure is a structured, redacted diagnostic tagged with a stable failure
*category* (ACES specification, backend interpretation, backend instantiation,
defensive-stack readiness, Kali reachability, evidence/run-archive capture) so
an operator can tell *which* layer broke (ADR-029 / ADR-030). The gate never
emits the full SDL object, a raw exception payload, or control-plane secrets.

The check implementations live in ``aptl.validation._live_gate_checks``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

from aptl.validation.techvault_gate import DEFAULT_SCENARIO

if TYPE_CHECKING:
    from aces_sdl.scenario import Scenario

    from aptl.core.config import AptlConfig
    from aptl.core.runstore import RunStorageBackend

DEFAULT_PROFILE = "orchestration-capable"

# Stable failure categories (issue #323 acceptance: a failure must identify the
# layer that broke). These map onto existing ACES diagnostics and APTL startup
# diagnostics — they are labels for triage, NOT a parallel exception hierarchy.
CATEGORY_ACES_SPECIFICATION = "aces_specification"
CATEGORY_BACKEND_INTERPRETATION = "backend_interpretation"
CATEGORY_BACKEND_INSTANTIATION = "backend_instantiation"
CATEGORY_DEFENSIVE_STACK_READINESS = "defensive_stack_readiness"
CATEGORY_KALI_REACHABILITY = "kali_reachability"
CATEGORY_EVIDENCE_CAPTURE = "evidence_capture"

FAILURE_CATEGORIES: tuple[str, ...] = (
    CATEGORY_ACES_SPECIFICATION,
    CATEGORY_BACKEND_INTERPRETATION,
    CATEGORY_BACKEND_INSTANTIATION,
    CATEGORY_DEFENSIVE_STACK_READINESS,
    CATEGORY_KALI_REACHABILITY,
    CATEGORY_EVIDENCE_CAPTURE,
)

# Each live check's stable failure category. A check name absent from this map
# is a programming error surfaced by ``LiveGateReport.failure_categories``.
CHECK_CATEGORY: dict[str, str] = {
    "static_prerequisite": CATEGORY_ACES_SPECIFICATION,
    "boot_inputs_match_public_path": CATEGORY_BACKEND_INSTANTIATION,
    "aces_driven_boot": CATEGORY_BACKEND_INSTANTIATION,
    "defensive_stack_readiness": CATEGORY_DEFENSIVE_STACK_READINESS,
    "kali_reachability": CATEGORY_KALI_REACHABILITY,
    "telemetry_evidence_path": CATEGORY_EVIDENCE_CAPTURE,
    "run_archive_manifest": CATEGORY_EVIDENCE_CAPTURE,
    "scenario_variation": CATEGORY_BACKEND_INTERPRETATION,
}


@dataclass(frozen=True)
class LiveGateCheck(object):
    """One named live-gate check, its failure category, and outcome.

    Distinct from the static gate's ``GateCheck`` only by the ``category``
    field, which carries the issue-#323 failure taxonomy. ``diagnostics`` are
    already redacted by the check that produced them (ADR-029).
    """

    name: str
    category: str
    passed: bool
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class LiveGateReport(object):
    """The composed outcome of every live-gate check for a scenario."""

    scenario: str
    profile: str
    run_id: str
    checks: tuple[LiveGateCheck, ...]

    @property
    def passed(self) -> bool:
        """Return whether every live-gate check passed."""
        return all(check.passed for check in self.checks)

    def failures(self) -> tuple[LiveGateCheck, ...]:
        """Return the checks that failed."""
        return tuple(check for check in self.checks if not check.passed)

    def failure_categories(self) -> tuple[str, ...]:
        """Return the distinct failure categories, worst-layer order preserved."""
        failed = {check.category for check in self.failures()}
        return tuple(cat for cat in FAILURE_CATEGORIES if cat in failed)

    def render(self) -> str:
        """Render a redacted, human/CI-readable summary."""
        lines = [
            f"ACES live validation gate — scenario={self.scenario} "
            f"profile={self.profile} run_id={self.run_id}: "
            f"{'PASS' if self.passed else 'FAIL'}"
        ]
        for check in self.checks:
            marker = "ok" if check.passed else "FAIL"
            lines.append(f"  [{marker}] {check.name} ({check.category})")
            for diagnostic in check.diagnostics:
                lines.append(f"        - {diagnostic}")
        if not self.passed:
            lines.append(
                "  failing layers: " + ", ".join(self.failure_categories())
            )
        return "\n".join(lines)


@dataclass(frozen=True)
class LiveGateOptions(object):
    """Tunable inputs for the live validation gate.

    ``profile`` selects the backend capability profile (``orchestration-capable``).
    ``clean_volumes`` runs the data-destroying ``stop -v`` cleanup before the
    boot; ``skip_clean_boot`` validates against an already-running lab without
    the destructive cleanup (operator opt-in for a non-destructive check). The
    static prerequisite runs the fast static stages by default
    (``static_check_imports=False``); the slow ``aces sdl verify-imports`` step
    has its own dedicated gate. ``event_window_seconds`` bounds the
    telemetry-evidence collection window.
    """

    profile: str = DEFAULT_PROFILE
    run_id: str | None = None
    clean_volumes: bool = True
    skip_clean_boot: bool = False
    static_check_imports: bool = False
    event_window_seconds: int = 180
    fixtures_root: Path | None = None
    profiles_root: Path | None = None


@dataclass
class LiveGateState(object):
    """Mutable scratchpad threaded through the live-gate checks.

    Analogous to ``aptl.core.lab._LabStartContext``: each check reads what it
    needs and writes outputs later checks depend on, so the orchestrator stays
    a flat sequence and the per-check return contract stays uniform.
    """

    realization_details: dict | None = None
    selected_profiles: list[str] = field(default_factory=list)
    snapshot: dict | None = None
    evidence: dict | None = None
    diagnostics_seen: int = 0


@dataclass(frozen=True)
class _RunContext(object):
    """Immutable run-scoped inputs threaded through the post-boot checks.

    Bundles what every post-boot check needs (scenario path, project dir,
    config, options, run store, run id) so the check runner stays within a
    sane parameter count and the orchestrator threads a single value.
    """

    scenario_path: Path
    project_dir: Path
    config: AptlConfig
    options: LiveGateOptions
    run_store: RunStorageBackend | None
    run_id: str


def validate_live_deployment(
    scenario_path: Path | None = None,
    *,
    project_dir: Path,
    config: "AptlConfig",
    options: LiveGateOptions | None = None,
    run_store: RunStorageBackend | None = None,
) -> LiveGateReport:
    """Run the full live validation gate for ``scenario_path``.

    Boots the lab through the public ACES start path, validates operational
    readiness / reachability / telemetry, and records ACES provenance plus
    validation evidence into the run archive. Returns a structured
    :class:`LiveGateReport`; never raises for an expected failure mode (a
    failed check is reported, not raised).
    """
    from aptl.validation import _live_gate_checks as checks

    opts = options or LiveGateOptions()
    scenario_path = scenario_path or (project_dir / DEFAULT_SCENARIO)
    run_id = opts.run_id or uuid.uuid4().hex
    state = LiveGateState()
    results: list[LiveGateCheck] = []

    # 1. Static prerequisite — parse/compile/conformance/parity must pass; a
    #    static failure blocks the live boot rather than degrading to a warning.
    scenario, static_check = checks.check_static_prerequisite(
        scenario_path, project_dir=project_dir, config=config, options=opts
    )
    results.append(static_check)
    static_passed = scenario is not None and static_check.passed

    # 2a. Input/boot-path agreement — the public start path is hardwired to the
    #     default scenario + orchestration-capable profile, so a scenario/profile
    #     the boot path will not honor must fail loud BEFORE any destructive
    #     boot, not silently validate one model while booting another.
    inputs_passed = False
    if static_passed:
        inputs_check = checks.check_boot_inputs_match_public_path(
            scenario_path, project_dir=project_dir, options=opts
        )
        results.append(inputs_check)
        inputs_passed = inputs_check.passed

    # 2b–7. ACES-driven boot through run-archive manifest. Each early failure
    #       short-circuits the *remaining* checks but always falls through to the
    #       single return below, so the report is composed in one place.
    if inputs_passed:
        ctx = _RunContext(
            scenario_path=scenario_path,
            project_dir=project_dir,
            config=config,
            options=opts,
            run_store=run_store,
            run_id=run_id,
        )
        _run_live_checks(checks, scenario, ctx, state, results)

    return _report(scenario_path, run_id, opts, results)


def _run_live_checks(
    checks: ModuleType,
    scenario: "Scenario",
    ctx: "_RunContext",
    state: LiveGateState,
    results: list[LiveGateCheck],
) -> None:
    """Run the boot-and-beyond checks, appending each outcome to ``results``.

    The lab boot is destructive, so this only runs after the static and
    input/boot-path-agreement guards have passed. A failed boot short-circuits
    the readiness/reachability/telemetry/variation checks (which cannot be
    trusted on a partial boot) but still records the provenance manifest.
    """
    # 2b. ACES-driven boot — clean up, boot via orchestrate_lab_start, and tie
    #    the realization matrix to ACES resource addresses (anti-preset).
    boot_check = checks.check_aces_driven_boot(
        scenario,
        project_dir=ctx.project_dir,
        config=ctx.config,
        options=ctx.options,
        state=state,
    )
    results.append(boot_check)
    if not boot_check.passed:
        # The lab may be partially up; readiness/reachability cannot be trusted
        # on a failed boot. Still record what provenance we have (step 6).
        results.append(_archive_manifest(checks, ctx, state, results))
        return

    # 3. Defensive-stack readiness — every ACES-realized node live + healthy,
    #    plus the SOC readiness probes the issue enumerates.
    results.append(checks.check_defensive_stack_readiness(state=state))

    # 4. Kali reachability — DMZ/internal hosts reachable via declared
    #    DNS/host mappings and network attachments from the realization.
    results.append(
        checks.check_kali_reachability(
            project_dir=ctx.project_dir, config=ctx.config, state=state
        )
    )

    # 5. Telemetry/evidence path — at least one artifact traverses the
    #    defensive stack and is reflected in the run archive.
    results.append(
        checks.check_telemetry_evidence_path(
            project_dir=ctx.project_dir,
            config=ctx.config,
            options=ctx.options,
            state=state,
        )
    )

    # 6. Scenario variation — the same interpreter path realizes distinct
    #    declared content distinctly (#324 / SCN-010G live diagnostic). Run
    #    BEFORE the manifest write so the persisted run archive — the durable
    #    audit artifact — reflects the complete check set and cannot disagree
    #    with the returned report.
    results.append(
        checks.check_scenario_variation(
            project_dir=ctx.project_dir, config=ctx.config, state=state
        )
    )

    # 7. Run-archive manifest — scenario identity + ACES provenance +
    #    validation evidence (all prior checks) + snapshot, written through the
    #    redacting boundary as the final step.
    results.append(_archive_manifest(checks, ctx, state, results))


def _archive_manifest(
    checks: ModuleType,
    ctx: "_RunContext",
    state: LiveGateState,
    prior: list[LiveGateCheck],
) -> LiveGateCheck:
    """Write the run-archive manifest capturing the prior check outcomes."""
    return checks.check_run_archive_manifest(
        ctx.scenario_path,
        project_dir=ctx.project_dir,
        config=ctx.config,
        run_store=ctx.run_store,
        run_id=ctx.run_id,
        state=state,
        prior_checks=tuple(prior),
    )


def _report(
    scenario_path: Path,
    run_id: str,
    opts: LiveGateOptions,
    results: list[LiveGateCheck],
) -> LiveGateReport:
    """Pack accumulated checks into a :class:`LiveGateReport`."""
    return LiveGateReport(str(scenario_path), opts.profile, run_id, tuple(results))
