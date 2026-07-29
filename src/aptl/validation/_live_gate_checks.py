"""Check implementations for the RAES live validation gate (SCN-010F / #323).

These compose behind ``techvault_live_gate.validate_live_deployment``; see that
module for the public entry point, the ``LiveGateCheck`` / ``LiveGateReport``
shapes, the failure-category taxonomy, and the gate's contract.

Each check returns a :class:`LiveGateCheck` with redacted diagnostics (ADR-029).
Live Docker / log / network inspection goes through ``DeploymentBackend`` and the
existing collectors; SOC HTTP probes go through the collectors' ``curl_safe``
boundary — never raw ``docker`` / ``curl`` in this module. Realization evidence
is tied to RAES resource addresses and realization details, never the scenario
name or a TechVault preset.

The private probe / helper functions live in
``aptl.validation._live_gate_probes`` (split out to keep both modules under the
file-size budget). The module-level imports of the lifecycle / interpretation
entry points used directly by the checks here are deliberate: the fast unit
suite monkeypatches them on this module to drive the orchestrator and every
check branch without a live lab. The boot / telemetry probes that live in
``_live_gate_probes`` are monkeypatched on *that* module.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from raes import SDLError, parse_sdl_file
from raes.scenario import Scenario

from aptl.backends.raes_profiles import select_backend_profiles
from aptl.backends.raes_realization import interpret_provisioning_plan
from aptl.utils.redaction import redact
from aptl.validation._live_gate_probes import (
    _boot_lab,
    _check,
    _check_to_dict,
    _compute_realization,
    _default_run_store,
    _distinct_profile_nodes,
    _missing_manifest_keys,
    _scenario_name,
    _single_node_plan,
    _variation_diagnostics,
)
from aptl.validation._live_gate_readiness import (
    _node_readiness_diagnostics,
    _warn_unhealthy_infra,
)
from aptl.validation.techvault_gate import GateOptions, validate_scenario
from aptl.validation.techvault_live_gate import (
    CATEGORY_RAES_SPECIFICATION,
    CATEGORY_BACKEND_INSTANTIATION,
    CATEGORY_BACKEND_INTERPRETATION,
    CATEGORY_DEFENSIVE_STACK_READINESS,
    CATEGORY_EVIDENCE_CAPTURE,
    DEFAULT_PROFILE,
    LiveGateCheck,
)

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig
    from aptl.core.runstore import RunStorageBackend
    from aptl.validation.techvault_live_gate import LiveGateOptions, LiveGateState


# --------------------------------------------------------------------------- #
# 1. Static prerequisite.
# --------------------------------------------------------------------------- #


def check_static_prerequisite(
    scenario_path: Path,
    *,
    project_dir: Path,
    config: "AptlConfig",
    options: "LiveGateOptions",
) -> tuple[Scenario | None, LiveGateCheck]:
    """Run the static gate; a static failure blocks the live boot.

    Returns the parsed scenario (for the realization matrix) and the check.
    Static parse/compile/conformance failures are hard blocks, never
    downgraded to live-gate warnings.
    """
    report = validate_scenario(
        scenario_path,
        project_dir=project_dir,
        config=config,
        options=GateOptions(
            profile=options.profile,
            fixtures_root=options.fixtures_root,
            profiles_root=options.profiles_root,
            check_imports=options.static_check_imports,
        ),
    )
    if not report.passed:
        diagnostics = [
            f"static gate failed: {check.name} "
            f"({'; '.join(check.diagnostics) or 'no detail'})"
            for check in report.failures()
        ]
        return None, _check(
            "static_prerequisite", CATEGORY_RAES_SPECIFICATION, diagnostics
        )
    try:
        scenario = parse_sdl_file(scenario_path)
    except (SDLError, FileNotFoundError, ValueError, TypeError) as exc:
        return None, _check(
            "static_prerequisite",
            CATEGORY_RAES_SPECIFICATION,
            [redact(f"scenario parse failed after static gate passed: {exc}")],
        )
    return scenario, _check("static_prerequisite", CATEGORY_RAES_SPECIFICATION, [])


# --------------------------------------------------------------------------- #
# 2. RAES-driven boot.
# --------------------------------------------------------------------------- #


def check_run_id_input(options: "LiveGateOptions") -> LiveGateCheck:
    """Reject caller-supplied run ids that could escape the run archive tree."""
    from aptl.core.runstore import _validate_id

    if options.run_id is None:
        return _check("run_id_input", CATEGORY_EVIDENCE_CAPTURE, [])
    try:
        _validate_id(options.run_id, "run_id")
    except ValueError as exc:
        return _check("run_id_input", CATEGORY_EVIDENCE_CAPTURE, [str(exc)])
    return _check("run_id_input", CATEGORY_EVIDENCE_CAPTURE, [])


def check_boot_inputs_match_public_path(
    scenario_path: Path,
    *,
    project_dir: Path,
    options: "LiveGateOptions",
) -> LiveGateCheck:
    """Reject profile inputs the public start path will not honor.

    The public boot path accepts the selected ``scenario_path`` and forwards it
    to ``orchestrate_lab_start``. Profile selection remains fixed to the public
    default, so a mismatched profile still fails before any destructive boot.
    """
    _ = scenario_path, project_dir
    diagnostics: list[str] = []
    if options.profile != DEFAULT_PROFILE:
        diagnostics.append(
            f"profile {options.profile!r} is not the public start path's "
            f"capability profile ({DEFAULT_PROFILE!r}); the gate would validate "
            "a profile the boot path will not realize"
        )
    return _check(
        "boot_inputs_match_public_path",
        CATEGORY_BACKEND_INSTANTIATION,
        diagnostics,
    )


def check_raes_driven_boot(
    scenario: Scenario,
    *,
    project_dir: Path,
    config: "AptlConfig",
    options: "LiveGateOptions",
    state: "LiveGateState",
    scenario_path: Path | None = None,
) -> LiveGateCheck:
    """Clean up and boot through the public RAES start path; tie evidence to RAES.

    Computes the realization matrix (``RuntimeManager.plan`` +
    ``interpret_provisioning_plan`` — the same pure interpretation
    ``AptlProvisioner.apply`` performs) so the expected node/service/network/
    profile surface is keyed by RAES resource addresses, never the scenario
    name. Then runs ``stop_lab(-v)`` cleanup and ``orchestrate_lab_start`` (whose
    only container-start path is the RAES handoff) and records the snapshot.
    """
    realization, interp_errors = _compute_realization(scenario, project_dir, config)
    if realization is None or interp_errors:
        return _check(
            "raes_driven_boot", CATEGORY_BACKEND_INTERPRETATION, interp_errors
        )
    state.realization_details = realization.details()
    state.diagnostics_seen = len(realization.diagnostics)
    state.selected_profiles = select_backend_profiles(config, realization.profiles)

    boot_diagnostics = _boot_lab(
        project_dir,
        config,
        options,
        state,
        scenario_path=scenario_path,
    )
    return _check("raes_driven_boot", CATEGORY_BACKEND_INSTANTIATION, boot_diagnostics)


# --------------------------------------------------------------------------- #
# 3. Defensive-stack readiness.
# --------------------------------------------------------------------------- #


def check_defensive_stack_readiness(
    *,
    state: "LiveGateState",
) -> LiveGateCheck:
    """Assert every RAES-realized node is live + healthy in the booted range.

    Pass/fail is keyed to the realized node surface (anti-preset): each declared
    node must map to a running, non-unhealthy container. Non-node infrastructure
    (e.g. OTEL/Tempo/Grafana observability) that is unhealthy is surfaced as a
    degraded note, not a hard failure of the scenario surface.
    """
    snapshot = state.snapshot or {}
    containers = snapshot.get("containers", [])
    nodes = (state.realization_details or {}).get("nodes", [])
    selected = set(state.selected_profiles or [])
    if not containers:
        return _check(
            "defensive_stack_readiness",
            CATEGORY_DEFENSIVE_STACK_READINESS,
            ["no containers in post-boot snapshot"],
        )

    diagnostics, matched_names = _node_readiness_diagnostics(
        nodes, containers, selected
    )
    _warn_unhealthy_infra(containers, matched_names)
    return _check(
        "defensive_stack_readiness", CATEGORY_DEFENSIVE_STACK_READINESS, diagnostics
    )


# --------------------------------------------------------------------------- #
# 6. Run-archive manifest.
# --------------------------------------------------------------------------- #


def check_run_archive_manifest(
    scenario_path: Path,
    *,
    project_dir: Path,
    config: "AptlConfig",
    run_store: RunStorageBackend | None,
    run_id: str,
    state: "LiveGateState",
    prior_checks: tuple[LiveGateCheck, ...],
) -> LiveGateCheck:
    """Persist scenario identity + RAES provenance + validation evidence.

    Writes through ``LocalRunStore``'s redacting boundary (ADR-029).
    Objective and condition run surfaces are published through the portable
    RAES evaluation contracts at the backend boundary. Live evaluator
    progression is emitted by ``AptlEvaluator`` from observed runtime state.
    """
    realization = state.realization_details or {}
    manifest = {
        "schema": "aptl.live-gate.manifest/v1",
        "scenario": {
            "path": str(scenario_path),
            "name": _scenario_name(scenario_path),
        },
        "run_id": run_id,
        "raes_provenance": {
            "realization": realization,
            "selected_profiles": state.selected_profiles,
            "interpretation_diagnostics": state.diagnostics_seen,
        },
        "validation": {
            "checks": [_check_to_dict(check) for check in prior_checks],
            # Key is "ok", not "passed": the run-archive redaction boundary masks
            # any key containing "pass" (the password heuristic), which would
            # render every check outcome as [REDACTED].
            "ok": all(check.passed for check in prior_checks),
        },
        "snapshot": state.snapshot,
        "evidence": state.evidence,
        "evaluator_surfaces": {
            "profile": "full-remote-control-plane",
            "contracts": [
                "evaluation-result-envelope-v1",
                "evaluation-history-event-stream-v1",
            ],
            "execution_state_integration": "aptl.backends.raes_evaluator.AptlEvaluator",
        },
        "orchestrator_surfaces": {
            "profile": "orchestration-evaluation",
            "contracts": [
                "workflow-result-envelope-v1",
                "workflow-history-event-stream-v1",
            ],
            "execution_state_integration": "aptl.core.runtime.workflow_engine",
        },
        "participant_runtime_surfaces": {
            "profile": "full-remote-control-plane",
            "contracts": [
                "participant-episode-state-envelope-v1",
                "participant-episode-history-event-stream-v1",
                "participant-behavior-history-event-stream-v1",
            ],
            "execution_state_integration": "aptl.backends.raes_participant_runtime",
        },
    }

    diagnostics = _missing_manifest_keys(manifest)
    if diagnostics:
        return _check("run_archive_manifest", CATEGORY_EVIDENCE_CAPTURE, diagnostics)

    store = run_store or _default_run_store(project_dir, config)
    try:
        store.create_run(run_id)
        store.write_json(run_id, "live-gate/manifest.json", manifest)
    # broad-except: persistence failures must surface as an evidence-capture failure.
    except Exception as exc:
        return _check(
            "run_archive_manifest",
            CATEGORY_EVIDENCE_CAPTURE,
            [redact(f"run-archive write failed: {exc}")],
        )
    return _check("run_archive_manifest", CATEGORY_EVIDENCE_CAPTURE, [])


# --------------------------------------------------------------------------- #
# 7. Scenario variation (#324 / SCN-010G live diagnostic).
# --------------------------------------------------------------------------- #


def check_scenario_variation(
    *,
    project_dir: Path,
    config: "AptlConfig",
    state: "LiveGateState",
) -> LiveGateCheck:
    """Prove the same interpreter path realizes distinct declared content distinctly.

    Compares two declared RAES nodes from the booted scenario through the same
    ``interpret_provisioning_plan`` path and asserts distinct realization details
    — the anti-collapse property #324 (SCN-010G) generalized.
    """
    nodes = (state.realization_details or {}).get("nodes", [])
    pair = _distinct_profile_nodes(nodes)
    if pair is None:
        return _check(
            "scenario_variation",
            CATEGORY_BACKEND_INTERPRETATION,
            ["scenario declares fewer than two distinct-profile nodes to vary"],
        )

    first_node, second_node = pair
    first = interpret_provisioning_plan(
        plan=_single_node_plan(first_node), project_dir=project_dir, config=config
    )
    second = interpret_provisioning_plan(
        plan=_single_node_plan(second_node), project_dir=project_dir, config=config
    )
    diagnostics = _variation_diagnostics(first, second)
    return _check("scenario_variation", CATEGORY_BACKEND_INTERPRETATION, diagnostics)
