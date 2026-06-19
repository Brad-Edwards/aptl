"""Check implementations for the ACES live validation gate (SCN-010F / #323).

These compose behind ``techvault_live_gate.validate_live_deployment``; see that
module for the public entry point, the ``LiveGateCheck`` / ``LiveGateReport``
shapes, the failure-category taxonomy, and the gate's contract.

Each check returns a :class:`LiveGateCheck` with redacted diagnostics (ADR-029).
Live Docker / log / network inspection goes through ``DeploymentBackend`` and the
existing collectors; SOC HTTP probes go through the collectors' ``curl_safe``
boundary — never raw ``docker`` / ``curl`` in this module. Realization evidence
is tied to ACES resource addresses and realization details, never the scenario
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

from aces_sdl import SDLError, parse_sdl_file
from aces_sdl.scenario import Scenario

from aptl.backends.aces import DEFAULT_ACES_SCENARIO
from aptl.backends.aces_profiles import select_backend_profiles
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.deployment import get_backend
from aptl.utils.redaction import redact
from aptl.validation._live_gate_probes import (
    _KALI_CONTAINER,
    _boot_lab,
    _check,
    _check_to_dict,
    _collect_until_evidence,
    _compute_realization,
    _default_run_store,
    _distinct_profile_nodes,
    _event_type_tally,
    _find_container,
    _generate_event,
    _is_traffic_event,
    _missing_manifest_keys,
    _node_readiness_diagnostics,
    _now_iso,
    _ping_from_kali,
    _scenario_name,
    _shared_network_targets,
    _single_node_plan,
    _variation_diagnostics,
    _warn_unhealthy_infra,
)
from aptl.validation.techvault_gate import GateOptions, validate_scenario
from aptl.validation.techvault_live_gate import (
    CATEGORY_ACES_SPECIFICATION,
    CATEGORY_BACKEND_INSTANTIATION,
    CATEGORY_BACKEND_INTERPRETATION,
    CATEGORY_DEFENSIVE_STACK_READINESS,
    CATEGORY_EVIDENCE_CAPTURE,
    CATEGORY_KALI_REACHABILITY,
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
    Static parse/compile/conformance/parity failures are hard blocks, never
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
            "static_prerequisite", CATEGORY_ACES_SPECIFICATION, diagnostics
        )
    try:
        scenario = parse_sdl_file(scenario_path)
    except (SDLError, FileNotFoundError, ValueError, TypeError) as exc:
        return None, _check(
            "static_prerequisite",
            CATEGORY_ACES_SPECIFICATION,
            [redact(f"scenario parse failed after static gate passed: {exc}")],
        )
    return scenario, _check("static_prerequisite", CATEGORY_ACES_SPECIFICATION, [])


# --------------------------------------------------------------------------- #
# 2. ACES-driven boot.
# --------------------------------------------------------------------------- #


def check_boot_inputs_match_public_path(
    scenario_path: Path,
    *,
    project_dir: Path,
    options: "LiveGateOptions",
) -> LiveGateCheck:
    """Reject scenario/profile inputs the public start path will not honor.

    The gate computes the expected realization from ``scenario_path`` and
    ``options.profile``, but the public boot path it exercises
    (``orchestrate_lab_start`` → ``start_aces_scenario``) is hardwired to
    ``DEFAULT_ACES_SCENARIO`` and the ``provisioning-only`` capability profile;
    it ignores any caller-supplied scenario/profile. Booting one model while
    validating another would silently produce false pass/fail results, so a
    mismatch is a hard ``backend_instantiation`` failure raised *before* any
    destructive boot — never a degraded warning. This holds for
    ``skip_clean_boot`` too: the already-running lab was itself booted from the
    default scenario, so a mismatched ``--scenario`` would validate the wrong
    model against it.
    """
    expected_scenario = DEFAULT_ACES_SCENARIO
    if not expected_scenario.is_absolute():
        expected_scenario = project_dir / expected_scenario
    diagnostics: list[str] = []
    if scenario_path.resolve() != expected_scenario.resolve():
        diagnostics.append(
            f"scenario {scenario_path.name!r} does not match the scenario the "
            f"public start path boots ({expected_scenario.name!r}); the gate "
            "would validate one model while booting another"
        )
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


def check_aces_driven_boot(
    scenario: Scenario,
    *,
    project_dir: Path,
    config: "AptlConfig",
    options: "LiveGateOptions",
    state: "LiveGateState",
) -> LiveGateCheck:
    """Clean up and boot through the public ACES start path; tie evidence to ACES.

    Computes the realization matrix (``RuntimeManager.plan`` +
    ``interpret_provisioning_plan`` — the same pure interpretation
    ``AptlProvisioner.apply`` performs) so the expected node/service/network/
    profile surface is keyed by ACES resource addresses, never the scenario
    name. Then runs ``stop_lab(-v)`` cleanup and ``orchestrate_lab_start`` (whose
    only container-start path is the ACES handoff) and records the snapshot.
    """
    realization, interp_errors = _compute_realization(scenario, project_dir, config)
    if realization is None or interp_errors:
        return _check(
            "aces_driven_boot", CATEGORY_BACKEND_INTERPRETATION, interp_errors
        )
    state.realization_details = realization.details()
    state.diagnostics_seen = len(realization.diagnostics)
    state.selected_profiles = select_backend_profiles(config, realization.profiles)

    boot_diagnostics = _boot_lab(project_dir, config, options, state)
    return _check(
        "aces_driven_boot", CATEGORY_BACKEND_INSTANTIATION, boot_diagnostics
    )


# --------------------------------------------------------------------------- #
# 3. Defensive-stack readiness.
# --------------------------------------------------------------------------- #


def check_defensive_stack_readiness(
    *,
    state: "LiveGateState",
) -> LiveGateCheck:
    """Assert every ACES-realized node is live + healthy in the booted range.

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
# 4. Kali reachability.
# --------------------------------------------------------------------------- #


def check_kali_reachability(
    *,
    project_dir: Path,
    config: "AptlConfig",
    state: "LiveGateState",
) -> LiveGateCheck:
    """From Kali, reach every lab host it shares a declared network with.

    Reachability targets are derived from network co-membership in the live
    snapshot (the realized network attachments), not a hardcoded host list.
    """
    snapshot = state.snapshot or {}
    containers = snapshot.get("containers", [])
    kali = _find_container(containers, _KALI_CONTAINER)
    if kali is None:
        return _check(
            "kali_reachability",
            CATEGORY_KALI_REACHABILITY,
            ["Kali container not present in the booted range"],
        )

    kali_networks = set((kali.get("networks") or {}).keys())
    targets = _shared_network_targets(kali, containers, kali_networks)
    diagnostics = _reachability_diagnostics(
        kali_networks, targets, config, project_dir, state
    )
    return _check("kali_reachability", CATEGORY_KALI_REACHABILITY, diagnostics)


def _reachability_diagnostics(
    kali_networks: set[str],
    targets: list[tuple[str, str]],
    config: "AptlConfig",
    project_dir: Path,
    state: "LiveGateState",
) -> list[str]:
    """Probe each shared-network target from Kali and record the tested set."""
    if not kali_networks:
        return ["Kali container has no network attachments in the snapshot"]
    if not targets:
        return ["no lab hosts share a network with Kali to test reachability"]

    backend = get_backend(config, project_dir)
    diagnostics: list[str] = []
    for name, ip in targets:
        if not _ping_from_kali(backend, ip):
            diagnostics.append(f"Kali cannot reach {name} ({ip}) on shared network")
    state.evidence = {"kali_reachability_targets": [t[0] for t in targets]}
    return diagnostics


# --------------------------------------------------------------------------- #
# 5. Telemetry / evidence path.
# --------------------------------------------------------------------------- #


def check_telemetry_evidence_path(
    *,
    project_dir: Path,
    config: "AptlConfig",
    options: "LiveGateOptions",
    state: "LiveGateState",
) -> LiveGateCheck:
    """Generate one representative event and confirm it traverses the defensive stack.

    Drives traffic from Kali at a reachable DMZ host, then collects Suricata EVE
    and Wazuh alerts in the bounded window. At least one evidence artifact must
    be captured; the summary is recorded for the run archive.
    """
    snapshot = state.snapshot or {}
    containers = snapshot.get("containers", [])
    kali = _find_container(containers, _KALI_CONTAINER)
    if kali is None:
        return _check(
            "telemetry_evidence_path",
            CATEGORY_EVIDENCE_CAPTURE,
            ["Kali container not present; cannot generate a representative event"],
        )

    kali_networks = set((kali.get("networks") or {}).keys())
    targets = _shared_network_targets(kali, containers, kali_networks)
    if not targets:
        return _check(
            "telemetry_evidence_path",
            CATEGORY_EVIDENCE_CAPTURE,
            ["no reachable target to generate defensive-stack telemetry"],
        )

    diagnostics = _telemetry_diagnostics(targets, config, project_dir, options, state)
    return _check("telemetry_evidence_path", CATEGORY_EVIDENCE_CAPTURE, diagnostics)


def _telemetry_diagnostics(
    targets: list[tuple[str, str]],
    config: "AptlConfig",
    project_dir: Path,
    options: "LiveGateOptions",
    state: "LiveGateState",
) -> list[str]:
    """Generate an event, collect evidence, record the summary, and grade it."""
    backend = get_backend(config, project_dir)
    start_iso = _now_iso()
    _generate_event(backend, targets)
    eve, alerts = _collect_until_evidence(
        backend, start_iso, options.event_window_seconds
    )
    end_iso = _now_iso()

    traffic_eve = [e for e in eve if _is_traffic_event(e)]
    summary = {
        "generator": "kali nmap + failed-ssh-auth against reachable targets",
        "window": [start_iso, end_iso],
        "suricata_event_types": _event_type_tally(eve),
        "suricata_traffic_event_count": len(traffic_eve),
        "wazuh_alert_count": len(alerts),
    }
    state.evidence = {**(state.evidence or {}), "telemetry": summary}

    if (len(traffic_eve) + len(alerts)) < 1:
        return [
            "no traffic-derived alert/log/evidence traversed the defensive "
            "stack in the window (Suricata stats-only events do not count)"
        ]
    return []


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
    """Persist scenario identity + ACES provenance + validation evidence.

    Writes through ``LocalRunStore``'s redacting boundary (ADR-029). Objective /
    scoring run surfaces are the evaluator-profile output deferred to #312; they
    are recorded as deferred, never faked.
    """
    realization = state.realization_details or {}
    manifest = {
        "schema": "aptl.live-gate.manifest/v1",
        "scenario": {
            "path": str(scenario_path),
            "name": _scenario_name(scenario_path),
        },
        "run_id": run_id,
        "aces_provenance": {
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
        "evaluator_surfaces_deferred": {
            "objectives": "#312",
            "scoring": "#312",
            "run_archive_evaluator_output": "#312",
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

    Compares two declared ACES nodes from the booted scenario through the same
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
