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

The module-level imports of the lifecycle / snapshot / collector entry points
are deliberate: the fast unit suite monkeypatches them on this module to drive
the orchestrator and every check branch without a live lab.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aces_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RuntimeDomain,
)
from aces_runtime.manager import RuntimeManager
from aces_sdl import SDLError, parse_sdl_file
from aces_sdl.scenario import Scenario

from aptl.backends.aces import DEFAULT_ACES_SCENARIO, create_aptl_runtime_target
from aptl.backends.aces_profiles import normalize_identifier, select_backend_profiles
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.collectors import collect_suricata_eve, collect_wazuh_alerts
from aptl.core.deployment import get_backend
from aptl.core.lab import orchestrate_lab_start, stop_lab
from aptl.core.lab_types import StartupOutcome
from aptl.core.runstore import LocalRunStore
from aptl.core.snapshot import capture_snapshot
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact
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

log = get_logger("live-gate")

_KALI_CONTAINER = "aptl-kali"
# Poll interval while waiting for generated activity to land as Suricata flow /
# alert events and Wazuh alerts (both have ingest/flush latency).
_POLL_STEP_SECONDS = 10
# Suricata emits periodic ``stats`` events regardless of traffic, so they never
# count as proof that a generated event traversed the defensive stack.
_NON_TRAFFIC_EVENT_TYPES = frozenset({"stats"})
# Reachable targets to drive failed-auth events at (kept small to bound runtime).
_MAX_EVENT_TARGETS = 3


def _check(name: str, category: str, diagnostics: list[str]) -> LiveGateCheck:
    """Pack diagnostics into a :class:`LiveGateCheck` (empty ⇒ passed)."""
    return LiveGateCheck(name, category, not diagnostics, tuple(diagnostics))


def _now_iso() -> str:
    """Return a timezone-aware UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).isoformat()


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


def _compute_realization(scenario, project_dir, config):
    """Interpret the scenario's provisioning plan, returning (realization, diags)."""
    try:
        backend = get_backend(config, project_dir)
        target = create_aptl_runtime_target(
            project_dir=project_dir, config=config, backend=backend
        )
        execution_plan = RuntimeManager(target).plan(scenario)
        realization = interpret_provisioning_plan(
            plan=execution_plan.provisioning, project_dir=project_dir, config=config
        )
    # broad-except: ACES planning/interpretation surfaces diverse error types.
    except Exception as exc:
        return None, [redact(f"realization interpretation raised: {exc}")]

    errors = [
        redact(f"{d.code}: {d.message}")
        for d in realization.diagnostics
        if _severity(d) == "error"
    ]
    if not realization.nodes:
        errors.append("realization produced no ACES nodes (no model to instantiate)")
    return realization, errors


def _boot_lab(project_dir, config, options, state) -> list[str]:
    """Run the destructive cleanup + public boot; return failure diagnostics.

    With ``skip_clean_boot`` the gate neither tears down nor reboots the lab; it
    snapshots the already-running range as-is (a non-destructive validation of
    the current lab against the realized model).
    """
    diagnostics: list[str] = []
    if options.skip_clean_boot:
        state.snapshot = _capture(project_dir, config)
        if state.snapshot is None:
            diagnostics.append("snapshot capture returned no data for running lab")
        return diagnostics

    stop_result = stop_lab(
        remove_volumes=options.clean_volumes, project_dir=project_dir
    )
    if not stop_result.success:
        diagnostics.append(redact(f"pre-boot cleanup failed: {stop_result.error}"))

    start_result = orchestrate_lab_start(project_dir)
    if start_result.outcome is StartupOutcome.FAILED:
        diagnostics.append(
            redact(f"public lab start failed: {start_result.error or 'unknown'}")
        )
        diagnostics.extend(_startup_diag_lines(start_result))
        return diagnostics
    if start_result.outcome is not StartupOutcome.READY:
        # Degraded-but-usable still boots the range; record the degradation but
        # let later readiness checks decide pass/fail on concrete components.
        diagnostics_note = _startup_diag_lines(start_result)
        log.warning("lab booted degraded: %s", "; ".join(diagnostics_note) or "")

    state.snapshot = _capture(project_dir, config)
    if state.snapshot is None:
        diagnostics.append("snapshot capture returned no data after boot")
    return diagnostics


def _capture(project_dir, config) -> dict | None:
    """Capture a redacted range snapshot, returning ``None`` on failure."""
    try:
        backend = get_backend(config, project_dir)
        return capture_snapshot(config_dir=project_dir, backend=backend).to_dict()
    # broad-except: snapshot probes shell through the backend; never fatal here.
    except Exception as exc:
        log.warning("snapshot capture failed: %s", redact(str(exc)))
        return None


def _startup_diag_lines(result) -> list[str]:
    """Render redacted one-line summaries of startup diagnostics."""
    lines: list[str] = []
    for diag in getattr(result, "diagnostics", []) or []:
        label = f"{diag.step}/{diag.component}" if diag.component else diag.step
        lines.append(redact(f"[{diag.impact.value}|{diag.severity.value}] {label}: {diag.message}"))
    return lines


# --------------------------------------------------------------------------- #
# 3. Defensive-stack readiness.
# --------------------------------------------------------------------------- #


def check_defensive_stack_readiness(
    *,
    project_dir: Path,
    config: "AptlConfig",
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

    diagnostics: list[str] = []
    matched_names: set[str] = set()
    for node in nodes:
        # Only nodes whose profile is in the started subset get a container; a
        # declared node in a non-selected profile (e.g. mail/reverse when those
        # profiles are disabled) is correctly absent and not a readiness gap.
        if selected and not (set(node.get("profiles", ())) & selected):
            continue
        container = _live_container_for_node(node, containers)
        if container is None:
            diagnostics.append(f"realized node {node.get('name', '?')!r} has no live container")
            continue
        matched_names.add(container.get("name", ""))
        diagnostics.extend(_container_health_diagnostics(node.get("name", "?"), container))

    # Surface unhealthy infra (non-node) containers as informational notes only.
    for container in containers:
        if container.get("name", "") in matched_names:
            continue
        if container.get("health") == "unhealthy":
            log.warning(
                "non-node infra container unhealthy: %s", container.get("name", "?")
            )
    return _check(
        "defensive_stack_readiness", CATEGORY_DEFENSIVE_STACK_READINESS, diagnostics
    )


def _container_health_diagnostics(node_name: str, container: Mapping[str, Any]) -> list[str]:
    """Return hard-failure diagnostics for one realized node's container."""
    status = str(container.get("status", ""))
    health = str(container.get("health", ""))
    if not status.startswith("Up"):
        return [f"node {node_name!r} container not running (status={status!r})"]
    if health == "unhealthy":
        return [f"node {node_name!r} container unhealthy"]
    return []


def _live_container_for_node(
    node: Mapping[str, Any], containers: Sequence[Mapping[str, Any]]
) -> Mapping[str, Any] | None:
    """Match a realized node to a live container by normalized alias."""
    node_keys: set[str] = set()
    raw_values = [node.get("name", ""), *node.get("aliases", ())]
    for raw in raw_values:
        norm = normalize_identifier(str(raw))
        if norm:
            node_keys.add(norm)
            node_keys.add(norm.removeprefix("aptl-"))
    for container in containers:
        cname = normalize_identifier(str(container.get("name", "")))
        if cname in node_keys or cname.removeprefix("aptl-") in node_keys:
            return container
    return None


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
    if not kali_networks:
        return _check(
            "kali_reachability",
            CATEGORY_KALI_REACHABILITY,
            ["Kali container has no network attachments in the snapshot"],
        )

    targets = _shared_network_targets(kali, containers, kali_networks)
    if not targets:
        return _check(
            "kali_reachability",
            CATEGORY_KALI_REACHABILITY,
            ["no lab hosts share a network with Kali to test reachability"],
        )

    backend = get_backend(config, project_dir)
    diagnostics: list[str] = []
    for name, ip in targets:
        if not _ping_from_kali(backend, ip):
            diagnostics.append(f"Kali cannot reach {name} ({ip}) on shared network")
    state.evidence = {"kali_reachability_targets": [t[0] for t in targets]}
    return _check("kali_reachability", CATEGORY_KALI_REACHABILITY, diagnostics)


def _shared_network_targets(
    kali: Mapping[str, Any],
    containers: Sequence[Mapping[str, Any]],
    kali_networks: set[str],
) -> list[tuple[str, str]]:
    """Return (name, ip) for containers sharing a network with Kali."""
    targets: list[tuple[str, str]] = []
    for container in containers:
        if container.get("name") == kali.get("name"):
            continue
        nets = container.get("networks") or {}
        shared = kali_networks & set(nets.keys())
        for net in sorted(shared):
            ip = nets.get(net)
            if ip:
                targets.append((str(container.get("name", "?")), str(ip)))
                break
    return targets


def _ping_from_kali(backend, ip: str) -> bool:
    """Return whether Kali can ICMP-reach ``ip`` (via the backend, no raw docker)."""
    try:
        result = backend.container_exec(
            _KALI_CONTAINER, ["ping", "-c", "1", "-W", "2", ip], timeout=15
        )
    # broad-except: backend exec surfaces diverse transport errors; treat as unreachable.
    except Exception as exc:
        log.warning("ping exec failed for %s: %s", ip, redact(str(exc)))
        return False
    return result.returncode == 0


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
        return _check(
            "telemetry_evidence_path",
            CATEGORY_EVIDENCE_CAPTURE,
            [
                "no traffic-derived alert/log/evidence traversed the defensive "
                "stack in the window (Suricata stats-only events do not count)"
            ],
        )
    return _check("telemetry_evidence_path", CATEGORY_EVIDENCE_CAPTURE, [])


def _collect_until_evidence(
    backend, start_iso: str, window_seconds: int
) -> tuple[list[dict], list[dict]]:
    """Poll for defensive-stack evidence until found or the window elapses.

    Both Suricata flow flushing and Wazuh ingest have latency, so the gate polls
    rather than sleeping a fixed interval; it returns as soon as a traffic-derived
    Suricata event or a Wazuh alert appears.
    """
    steps = max(1, window_seconds // _POLL_STEP_SECONDS)
    eve: list[dict] = []
    alerts: list[dict] = []
    for _ in range(steps):
        time.sleep(_POLL_STEP_SECONDS)
        now = _now_iso()
        eve = collect_suricata_eve(start_iso, now, backend)
        alerts = collect_wazuh_alerts(start_iso, now)
        if any(_is_traffic_event(e) for e in eve) or alerts:
            break
    return eve, alerts


def _generate_event(backend, targets: list[tuple[str, str]]) -> None:
    """Drive representative Kali activity at reachable targets (best effort).

    An nmap scan exercises the network sensor (Suricata) and failed SSH logins
    exercise host monitoring (Wazuh sshd rules). Both are best effort; the
    collection step decides pass/fail.
    """
    first_ip = targets[0][1]
    _exec_kali(backend, ["nmap", "-Pn", "-T4", "-p", "22,80,443,445", first_ip], 120)
    for _name, ip in targets[:_MAX_EVENT_TARGETS]:
        for _attempt in range(3):
            _exec_kali(
                backend,
                [
                    "ssh",
                    "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=3",
                    "-p", "22",
                    f"aptl-live-gate-invalid@{ip}",
                    "true",
                ],
                15,
            )


def _exec_kali(backend, cmd: list[str], timeout: int) -> None:
    """Run a best-effort command from Kali (failures are expected and ignored)."""
    try:
        backend.container_exec(_KALI_CONTAINER, cmd, timeout=timeout)
    # broad-except: event generation is best effort; collection decides pass/fail.
    except Exception as exc:
        log.warning("event generation step failed: %s", redact(str(exc)))


def _is_traffic_event(entry: object) -> bool:
    """Return whether a Suricata EVE entry reflects real traffic (not stats)."""
    return (
        isinstance(entry, dict)
        and str(entry.get("event_type", "")) not in _NON_TRAFFIC_EVENT_TYPES
        and bool(entry.get("event_type"))
    )


def _event_type_tally(eve: list[dict]) -> dict[str, int]:
    """Tally Suricata EVE entries by event_type (no raw payloads)."""
    tally: dict[str, int] = {}
    for entry in eve:
        etype = str(entry.get("event_type", "unknown")) if isinstance(entry, dict) else "unknown"
        tally[etype] = tally.get(etype, 0) + 1
    return tally


# --------------------------------------------------------------------------- #
# 6. Run-archive manifest.
# --------------------------------------------------------------------------- #


def check_run_archive_manifest(
    scenario_path: Path,
    *,
    project_dir: Path,
    config: "AptlConfig",
    run_store: "RunStorageBackend | None",
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
            "name": _scenario_name(realization, scenario_path),
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


def _missing_manifest_keys(manifest: Mapping[str, Any]) -> list[str]:
    """Confirm the manifest carries the audit-required surfaces."""
    diagnostics: list[str] = []
    provenance = manifest.get("aces_provenance", {})
    realization = provenance.get("realization") or {}
    if not realization.get("nodes"):
        diagnostics.append(
            "manifest carries no ACES realization nodes (cannot audit interpretation)"
        )
    if not provenance.get("selected_profiles"):
        diagnostics.append("manifest carries no ACES-selected profiles")
    if not manifest.get("validation", {}).get("checks"):
        diagnostics.append("manifest carries no validation evidence")
    if not manifest.get("snapshot"):
        diagnostics.append("manifest carries no post-boot snapshot")
    return diagnostics


def _scenario_name(realization: Mapping[str, Any], scenario_path: Path) -> str:
    """Best-effort scenario identity from the path stem."""
    return scenario_path.name.split(".")[0] or scenario_path.name


def _check_to_dict(check: LiveGateCheck) -> dict[str, Any]:
    """Serialize a check record for the manifest.

    Uses ``ok`` rather than ``passed`` because the run-archive redaction boundary
    masks any key containing ``pass`` (the password heuristic).
    """
    return {
        "name": check.name,
        "category": check.category,
        "ok": check.passed,
        "diagnostics": list(check.diagnostics),
    }


def _default_run_store(project_dir: Path, config: "AptlConfig") -> LocalRunStore:
    """Build the project's run store (mirrors cli._common.resolve_run_store).

    Inlined to keep the validation layer from depending on the CLI layer; the
    CLI passes ``resolve_run_store(...)`` explicitly in production.
    """
    local_path = Path(config.run_storage.local_path)
    if not local_path.is_absolute():
        local_path = project_dir / local_path
    return LocalRunStore(local_path)


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


def _distinct_profile_nodes(
    nodes: Sequence[Mapping[str, Any]],
) -> tuple[str, str] | None:
    """Pick two node names whose realized profiles differ."""
    seen: list[tuple[str, frozenset]] = []
    for node in nodes:
        name = _node_primary_name(node)
        profiles = frozenset(node.get("profiles", ()))
        if not name or not profiles:
            continue
        for other_name, other_profiles in seen:
            if other_profiles != profiles:
                return other_name, name
        seen.append((name, profiles))
    return None


def _node_primary_name(node: Mapping[str, Any]) -> str:
    """Return a usable node name from the realization node record."""
    aliases = node.get("aliases") or ()
    return str(aliases[0]) if aliases else str(node.get("name", ""))


def _variation_diagnostics(first, second) -> list[str]:
    """Confirm two interpretations are error-free and distinct."""
    diagnostics: list[str] = []
    for label, realization in (("first", first), ("second", second)):
        errors = [d for d in realization.diagnostics if _severity(d) == "error"]
        if errors:
            diagnostics.append(f"{label} variation node failed to realize")
    if not diagnostics and first.details() == second.details():
        diagnostics.append("distinct declared nodes collapsed to one realization")
    return diagnostics


def _single_node_plan(node_name: str) -> ProvisioningPlan:
    """Build a single-node ACES provisioning plan for ``node_name``."""
    address = f"provision.node.{node_name}"
    resource = PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload={
            "name": node_name,
            "node_name": node_name,
            "node_type": "vm",
            "os_family": "linux",
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


# --------------------------------------------------------------------------- #
# Shared helpers.
# --------------------------------------------------------------------------- #


def _find_container(
    containers: Sequence[Mapping[str, Any]], name: str
) -> Mapping[str, Any] | None:
    """Find a container by exact name in a snapshot container list."""
    for container in containers:
        if container.get("name") == name:
            return container
    return None


def _severity(diagnostic) -> str:
    """Return a diagnostic's severity as a lowercase string."""
    severity = getattr(diagnostic, "severity", None)
    return getattr(severity, "value", str(severity)).lower()
