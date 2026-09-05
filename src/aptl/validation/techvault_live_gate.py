"""Live validation gate for RAES scenarios (SCN-010F / issue #323).

The operational counterpart to the static gate in
``aptl.validation.techvault_gate``. Where the static gate parses, locks,
compiles, conformance-checks, and *interprets* a scenario without ever
starting Docker, this gate boots the full lab through APTL's **public** start
path (``aptl lab stop -v`` cleanup followed by ``orchestrate_lab_start``) and
proves the running range is realized from the interpreted RAES model — not from
a TechVault preset — then captures operational and provenance evidence in a run
archive.

Like the static gate, it is scenario-generic and parameterized by scenario
path, backend profile, and project directory: TechVault is the proving input,
never a hardcoded branch (ADR-035). The next scenario in APTL's
``full-remote-control-plane`` expressivity class passes through by changing inputs.

The gate is inherently integration / live-run work: it requires Docker, the SOC
stack's resources, real ``.env`` secrets, and minutes-long startup. It is wired
behind an explicit guard (``aptl lab validate-live`` and the
``APTL_LIVE_GATE``-gated integration test), never a fast CI / pre-commit gate,
and its cleanup is **data-destroying** and must run only against an isolated,
project-scoped lab.

Every failure is a structured, redacted diagnostic tagged with a stable failure
*category* (RAES specification, backend interpretation, backend instantiation,
defensive-stack readiness, Kali reachability, evidence/run-archive capture) so
an operator can tell *which* layer broke (ADR-029 / ADR-030). The gate never
emits the full SDL object, a raw exception payload, or control-plane secrets.

The check implementations live in ``aptl.validation._live_gate_checks``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from types import ModuleType
from typing import TYPE_CHECKING

from aptl.backends.identity import (
    APTL_RAES_TARGET_NAME,
    APTL_RAES_TARGET_VERSION,
    BackendIdentity,
)
from aptl.backends.raes import DEFAULT_RAES_SCENARIO
from aptl.validation.scenario_verification import (
    ScenarioIdentity,
    VerificationCheck,
    VerificationReport,
    VerificationStatus,
)

if TYPE_CHECKING:
    from raes.scenario import Scenario

    from aptl.core.config import AptlConfig
    from aptl.core.runstore import RunStorageBackend
    from aptl.core.scenario_bundle import ScenarioBundle

DEFAULT_PROFILE = "full-remote-control-plane"

# Stable failure categories (issue #323 acceptance: a failure must identify the
# layer that broke). These map onto existing RAES diagnostics and APTL startup
# diagnostics — they are labels for triage, NOT a parallel exception hierarchy.
CATEGORY_RAES_SPECIFICATION = "raes_specification"
CATEGORY_BACKEND_INTERPRETATION = "backend_interpretation"
CATEGORY_BACKEND_INSTANTIATION = "backend_instantiation"
CATEGORY_DEFENSIVE_STACK_READINESS = "defensive_stack_readiness"
CATEGORY_KALI_REACHABILITY = "kali_reachability"
CATEGORY_EVIDENCE_CAPTURE = "evidence_capture"

FAILURE_CATEGORIES: tuple[str, ...] = (
    CATEGORY_RAES_SPECIFICATION,
    CATEGORY_BACKEND_INTERPRETATION,
    CATEGORY_BACKEND_INSTANTIATION,
    CATEGORY_DEFENSIVE_STACK_READINESS,
    CATEGORY_KALI_REACHABILITY,
    CATEGORY_EVIDENCE_CAPTURE,
)

# Each live check's stable failure category. A check name absent from this map
# is a programming error surfaced by ``LiveGateReport.failure_categories``.
CHECK_CATEGORY: dict[str, str] = {
    "static_prerequisite": CATEGORY_RAES_SPECIFICATION,
    "boot_inputs_match_public_path": CATEGORY_BACKEND_INSTANTIATION,
    "raes_driven_boot": CATEGORY_BACKEND_INSTANTIATION,
    "defensive_stack_readiness": CATEGORY_DEFENSIVE_STACK_READINESS,
    "kali_reachability": CATEGORY_KALI_REACHABILITY,
    "telemetry_evidence_path": CATEGORY_EVIDENCE_CAPTURE,
    "runtime_orchestration_containment": CATEGORY_BACKEND_INSTANTIATION,
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
    status: VerificationStatus | bool
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Normalize compatibility booleans into the shared status vocabulary."""

        if isinstance(self.status, bool):
            object.__setattr__(
                self,
                "status",
                VerificationStatus.PASSED if self.status else VerificationStatus.FAILED,
            )

    @property
    def passed(self) -> bool:
        """Return whether this check reached the sole successful outcome."""

        return self.status is VerificationStatus.PASSED


def _aggregate_status(checks: tuple[LiveGateCheck, ...]) -> VerificationStatus:
    """Return the authoritative aggregate outcome for operational checks."""

    if any(check.status is VerificationStatus.BLOCKED for check in checks):
        return VerificationStatus.BLOCKED
    if any(check.status is VerificationStatus.FAILED for check in checks):
        return VerificationStatus.FAILED
    return VerificationStatus.PASSED


def _canonical_checks(
    checks: tuple[LiveGateCheck, ...],
) -> tuple[VerificationCheck, ...]:
    """Convert legacy operational checks at the shared report boundary."""

    return tuple(
        VerificationCheck(
            check_id=check.name,
            category=check.category,
            status=check.status,
            diagnostic="; ".join(check.diagnostics),
        )
        for check in checks
    )


def make_live_gate_report(
    scenario: str,
    profile: str,
    run_id: str,
    checks: tuple[LiveGateCheck, ...],
) -> VerificationReport:
    """Compatibility constructor for the one shared verification report shape."""

    import hashlib

    return VerificationReport(
        status=_aggregate_status(checks),
        scenario=ScenarioIdentity(
            identity=scenario,
            content_digest="sha256:"
            + hashlib.sha256(scenario.encode("utf-8")).hexdigest(),
            source_kind="project-tree",
            version="project-tree",
        ),
        backend=BackendIdentity(
            target_name=APTL_RAES_TARGET_NAME,
            target_version=APTL_RAES_TARGET_VERSION,
            profile=profile,
            provider="unknown",
            transport="unknown",
        ),
        run_id=run_id,
        attempt_id=run_id,
        checks=_canonical_checks(checks),
    )


# Existing callers import this constructor by its historical name. It returns
# ``VerificationReport`` and therefore does not preserve a second report schema.
LiveGateReport = make_live_gate_report


@dataclass(frozen=True)
class LiveGateOptions(object):
    """Tunable inputs for the live validation gate.

    ``profile`` selects the backend capability profile (``full-remote-control-plane``).
    ``clean_volumes`` runs the data-destroying ``stop -v`` cleanup before the
    boot; ``skip_clean_boot`` validates against an already-running lab without
    the destructive cleanup (operator opt-in for a non-destructive check). The
    static prerequisite runs the fast static stages by default
    (``static_check_imports=False``); the slow ``raes sdl verify-imports`` step
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
    deployment_spec: object | None = None
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
    bundle: ScenarioBundle
    # The selector the boot resolves (``None`` -> configured env-pack). Distinct
    # from ``scenario_path`` (the resolved staged SDL used for parse/digest): the
    # env-pack's content artifacts resolve through the pack resolver, not a
    # project-tree path, so the boot must not be handed the staged path (#875).
    boot_scenario_path: Path | None
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
) -> VerificationReport:
    """Run the full live validation gate for ``scenario_path``.

    Boots the lab through the public RAES start path, validates operational
    readiness / reachability / telemetry, and records RAES provenance plus
    validation evidence into the run archive. Returns a structured
    :class:`VerificationReport`; never raises for an expected failure mode (a
    failed check is reported, not raised).
    """
    from aptl.validation import _live_gate_checks as checks

    opts = options or LiveGateOptions()
    # Resolve the scenario the same env-pack-aware way `aptl lab start` does: an
    # explicit path uses the project tree, otherwise the configured env-pack is
    # staged and its SDL is the scenario. Issue #875 moved TechVault into the
    # `raes-env-packs` pack, so the in-tree DEFAULT_RAES_SCENARIO path no longer
    # exists -- the gate must validate the same scenario the lab actually boots.
    from aptl.backends.raes import resolve_scenario_bundle

    # The parse/compile/matrix/digest layers validate the exact SDL the env-pack
    # stages; the boot instead resolves the env-pack itself (config-driven), so it
    # keeps the original selector.
    boot_scenario_path = scenario_path
    bundle = resolve_scenario_bundle(project_dir, scenario_path, config)
    scenario_path = bundle.sdl_path
    run_id = opts.run_id or uuid.uuid4().hex
    state = LiveGateState()
    results: list[LiveGateCheck] = []

    run_id_check = checks.check_run_id_input(opts)
    results.append(run_id_check)
    if not run_id_check.passed:
        return _report(scenario_path, run_id, opts, results, bundle, config)

    # 1. Static prerequisite — parse/compile/conformance must pass; a
    #    static failure blocks the live boot rather than degrading to a warning.
    scenario, static_check = checks.check_static_prerequisite(
        scenario_path, project_dir=project_dir, config=config, options=opts
    )
    results.append(static_check)
    static_passed = scenario is not None and static_check.passed

    # 2a. Input/boot-path agreement — the public start path honors the selected
    #     scenario, but still uses the default orchestration/evaluation profile.
    #     Reject profile mismatches before any destructive boot.
    inputs_passed = False
    if static_passed:
        inputs_check = checks.check_boot_inputs_match_public_path(
            scenario_path, project_dir=project_dir, options=opts
        )
        results.append(inputs_check)
        inputs_passed = inputs_check.passed

    # 2b–7. RAES-driven boot through run-archive manifest. Each early failure
    #       short-circuits the *remaining* checks but always falls through to the
    #       single return below, so the report is composed in one place.
    if inputs_passed:
        ctx = _RunContext(
            scenario_path=scenario_path,
            bundle=bundle,
            boot_scenario_path=boot_scenario_path,
            project_dir=project_dir,
            config=config,
            options=opts,
            run_store=run_store,
            run_id=run_id,
        )
        _run_live_checks(checks, scenario, ctx, state, results)

    return _report(scenario_path, run_id, opts, results, bundle, config)


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
    # 2b. RAES-driven boot — clean up, boot via orchestrate_lab_start, and tie
    #    the realization matrix to RAES resource addresses (anti-preset).
    # The boot resolves the env-pack itself (config-driven); it must not receive
    # the resolved staged SDL path, or the pack's content artifacts resolve as a
    # project tree and admission fails as unavailable-exact-artifact (#875).
    boot_check = checks.check_raes_driven_boot(
        scenario,
        project_dir=ctx.project_dir,
        config=ctx.config,
        options=ctx.options,
        state=state,
        scenario_path=ctx.boot_scenario_path,
    )
    results.append(boot_check)
    if not boot_check.passed:
        # The lab may be partially up; readiness/reachability cannot be trusted
        # on a failed boot. Still record what provenance we have (step 6).
        results.append(_archive_manifest(checks, ctx, state, results))
        return

    # 3. Defensive-stack readiness — every RAES-realized node live + healthy,
    #    plus the SOC readiness probes the issue enumerates.
    results.append(checks.check_defensive_stack_readiness(state=state))

    # 4–5. Semantic verification — which node is the attacker, what the
    #      defensive stack is, and what proves detection traversed it. That
    #      knowledge lives in an installed verifier plugin, discovered through the
    #      seam (#878/#879); core builds a scenario-neutral context and an
    #      operations surface and maps the plugin's report back. With no plugin
    #      installed the seam returns ``blocked`` and these checks fail, so core
    #      holds no scenario answer key of its own.
    results.extend(_semantic_checks(ctx, state))

    # Re-attest after semantic work, when on-demand orchestration children have
    # existed. Startup-only observation cannot cover workers spawned later by a
    # workflow, so acceptance waits for this second backend-boundary check.
    results.append(
        checks.check_runtime_orchestration_containment(
            project_dir=ctx.project_dir,
            config=ctx.config,
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

    # 7. Run-archive manifest — scenario identity + RAES provenance +
    #    validation evidence (all prior checks) + snapshot, written through the
    #    redacting boundary as the final step.
    results.append(_archive_manifest(checks, ctx, state, results))


def _semantic_checks(
    ctx: "_RunContext",
    state: LiveGateState,
) -> list[LiveGateCheck]:
    """Run scenario-specific verification through the installed-plugin seam (#879).

    Core holds no scenario answer key: it builds a scenario-neutral context and
    an operations surface, discovers the one compatible verifier, and maps its
    report back onto the gate's check taxonomy. With no verifier installed the
    seam returns ``blocked`` and both semantic checks fail with that reason --
    honest, because a range whose semantic verification could not run has not
    been verified.
    """
    from aptl.validation._live_gate_operations import LiveGateOperations
    from aptl.validation.scenario_verification import (
        VerificationContext,
    )
    from aptl.validation.scenario_verification_discovery import verify_scenario

    scenario, backend = _verification_identities(
        ctx.scenario_path,
        ctx.bundle,
        ctx.options.profile,
        ctx.config.deployment.provider,
    )
    containers = [
        str(c.get("name", ""))
        for c in (state.snapshot or {}).get("containers", [])
        if c.get("name")
    ]
    deadline_monotonic = monotonic() + ctx.options.event_window_seconds
    context = VerificationContext(
        run_id=ctx.run_id,
        attempt_id=ctx.run_id,
        scenario=scenario,
        backend=backend,
        deadline_monotonic=deadline_monotonic,
        poll_interval_seconds=min(10.0, float(ctx.options.event_window_seconds)),
        operations=LiveGateOperations(
            project_dir=ctx.project_dir,
            config=ctx.config,
            options=ctx.options,
            state=state,
            deadline_monotonic=deadline_monotonic,
        ),
        observations={"containers": containers},
    )
    return _map_verification_report(verify_scenario(context))


def _map_verification_report(report: object) -> list[LiveGateCheck]:
    """Map a verifier's report onto the live gate's named checks.

    A passed/failed semantic check keeps its natural category. A ``blocked``
    report -- no verifier installed, or a plugin that could not run -- fails both
    semantic checks with the blocking reason, so verification that could not
    happen never reads as verification that passed.
    """
    from aptl.validation.scenario_verification import (
        VerificationReport,
        VerificationStatus,
    )

    if not isinstance(report, VerificationReport):
        return [
            LiveGateCheck(
                "scenario_verification",
                CATEGORY_EVIDENCE_CAPTURE,
                VerificationStatus.BLOCKED,
                ("scenario verification returned no usable report",),
            )
        ]

    if report.status is VerificationStatus.BLOCKED:
        reason = "; ".join(report.diagnostics) or "scenario verification was blocked"
        return [
            LiveGateCheck(
                "scenario_verification",
                CATEGORY_EVIDENCE_CAPTURE,
                VerificationStatus.BLOCKED,
                (f"blocked: {reason}",),
            )
        ]

    results: list[LiveGateCheck] = []
    for check in report.checks:
        category = (
            check.category
            if check.category in FAILURE_CATEGORIES
            else CATEGORY_EVIDENCE_CAPTURE
        )
        diagnostics = (
            ()
            if check.status is VerificationStatus.PASSED
            else (check.diagnostic or "semantic check failed",)
        )
        results.append(
            LiveGateCheck(check.check_id, category, check.status, diagnostics)
        )
    return results


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
    bundle: ScenarioBundle,
    config: AptlConfig,
) -> VerificationReport:
    """Pack accumulated checks into the shared versioned report shape."""

    checks = tuple(results)
    scenario, backend = _verification_identities(
        scenario_path,
        bundle,
        opts.profile,
        config.deployment.provider,
    )
    return VerificationReport(
        status=_aggregate_status(checks),
        scenario=scenario,
        backend=backend,
        run_id=run_id,
        attempt_id=run_id,
        checks=_canonical_checks(checks),
    )


def _verification_identities(
    scenario_path: Path,
    bundle: ScenarioBundle,
    profile: str,
    provider: str,
) -> tuple[ScenarioIdentity, BackendIdentity]:
    """Bind reports and plugin admission to the same canonical identities."""

    import hashlib

    pack = bundle.pack_identity
    content = (
        scenario_path.read_bytes()
        if scenario_path.is_file()
        else f"unavailable:{bundle.identity}".encode()
    )
    digest = (
        pack.set_digest
        if pack is not None
        else "sha256:" + hashlib.sha256(content).hexdigest()
    )
    return (
        ScenarioIdentity(
            identity=bundle.identity,
            content_digest=digest,
            source_kind=bundle.source_kind.value,
            version=pack.pack_version if pack is not None else "project-tree",
        ),
        BackendIdentity(
            target_name=APTL_RAES_TARGET_NAME,
            target_version=APTL_RAES_TARGET_VERSION,
            profile=profile,
            provider=provider,
            transport=provider,
        ),
    )
