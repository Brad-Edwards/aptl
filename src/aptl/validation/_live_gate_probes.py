"""Private probe / helper functions for the RAES live validation gate.

These support the check implementations in ``_live_gate_checks`` (SCN-010F /
#323); the split keeps each module under the file-size budget. This module is
the leaf of the live-gate package: it imports the lifecycle / snapshot /
collector / interpretation entry points directly and never imports
``_live_gate_checks``. The fast unit suite monkeypatches the leaf entry points
*on this module* (e.g. ``_live_gate_probes.get_backend``) to drive the boot and
telemetry probes without a live lab.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from raes_runtime.manager import RuntimeManager
from raes.scenario import Scenario

from aptl.backends.raes import create_aptl_runtime_target, resolve_scenario_bundle
from aptl.backends.raes_artifact_availability import artifact_availability_for_scenario
from aptl.backends.raes_realization import interpret_provisioning_plan
from aptl.backends.raes_runtime_orchestration import (
    prepare_runtime_orchestration_for_scenario,
)
from aptl.core.collectors import collect_suricata_eve, collect_wazuh_alerts
from aptl.core.deployment import get_backend
from aptl.core.lab import clean_boot_lab
from aptl.core.lab_types import StartupOutcome
from aptl.core.runstore import LocalRunStore
from aptl.core.snapshot import capture_snapshot
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact
from aptl.validation.techvault_live_gate import LiveGateCheck

if TYPE_CHECKING:
    from raes_contracts.diagnostics import Diagnostic

    from aptl.backends.raes_realization_model import AptlRealization
    from aptl.core.config import AptlConfig
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.lab_types import LabResult
    from aptl.validation.techvault_live_gate import LiveGateOptions, LiveGateState

log = get_logger("live-gate")

_KALI_CONTAINER = "aptl-kali"
# Poll interval while waiting for generated activity to land in Wazuh. Suricata
# traffic remains useful supporting evidence, but cannot complete this gate.
_POLL_STEP_SECONDS = 10
# Suricata emits periodic ``stats`` events regardless of traffic, so they never
# count as proof that a generated event traversed the defensive stack.
_NON_TRAFFIC_EVENT_TYPES = frozenset({"stats"})
# Reachable targets to drive failed-auth events at (kept small to bound runtime).
_MAX_EVENT_TARGETS = 3
_WAZUH_TRIGGER_IDENTITY = "aptl-live-gate-invalid"


def _check(name: str, category: str, diagnostics: list[str]) -> LiveGateCheck:
    """Pack diagnostics into a :class:`LiveGateCheck` (empty ⇒ passed)."""
    return LiveGateCheck(name, category, not diagnostics, tuple(diagnostics))


def _now_iso() -> str:
    """Return a timezone-aware UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _severity(diagnostic: "Diagnostic") -> str:
    """Return a diagnostic's severity as a lowercase string."""
    severity = getattr(diagnostic, "severity", None)
    return getattr(severity, "value", str(severity)).lower()


def _find_container(
    containers: Sequence[Mapping[str, Any]], name: str
) -> Mapping[str, Any] | None:
    """Find a container by exact name in a snapshot container list."""
    for container in containers:
        if container.get("name") == name:
            return container
    return None


def _compute_realization(
    scenario: Scenario, project_dir: Path, config: "AptlConfig"
) -> tuple[AptlRealization | None, list[str]]:
    """Interpret the scenario's provisioning plan, returning (realization, diags)."""
    try:
        backend = get_backend(config, project_dir)
        # Config-driven bundle: the configured env-pack when selected, else the
        # in-tree scenario (issue #875). Scenario content anchors to the bundle
        # root; component build contexts always resolve from the engine checkout
        # (an env-pack ships none), so component_root stays project_dir (ADR-051).
        bundle = resolve_scenario_bundle(project_dir, None, config)
        target = create_aptl_runtime_target(
            project_dir=project_dir, config=config, backend=backend, bundle=bundle
        )
        prepare_runtime_orchestration_for_scenario(scenario, backend)
        # Gather artifact availability at the backend trust boundary before
        # planning, exactly as `aptl lab start` does (`admit_raes_scenario`): the image
        # policy trusts a node's source image only against verified availability,
        # so a real-backend plan without it rejects every imaged node as
        # ``untrusted-image``.
        availability = artifact_availability_for_scenario(
            scenario, backend, scenario_root=bundle.root, component_root=project_dir
        )
        execution_plan = RuntimeManager(target).plan(
            scenario, artifact_availability=availability
        )
        realization = interpret_provisioning_plan(
            plan=execution_plan.provisioning,
            config=config,
            bundle=bundle,
            component_root=project_dir,
        )
    # broad-except: RAES planning/interpretation surfaces diverse error types.
    except Exception as exc:
        return None, [redact(f"realization interpretation raised: {exc}")]

    errors = [
        redact(f"{d.code}: {d.message}")
        for d in realization.diagnostics
        if _severity(d) == "error"
    ]
    if not realization.nodes:
        errors.append("realization produced no RAES nodes (no model to instantiate)")
    return realization, errors


def _boot_lab(
    project_dir: Path,
    config: "AptlConfig",
    options: "LiveGateOptions",
    state: "LiveGateState",
    scenario_path: Path | None = None,
) -> list[str]:
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

    # Reuse the RNG-001 clean-boot lifecycle capability rather than open-coding
    # the destructive stop+start here: the gate is a proof point, not the only
    # implementation home. A failed cleanup is fatal inside ``clean_boot_lab``
    # (a contaminated environment must not be snapshotted as proof), so a
    # ``FAILED`` outcome covers both cleanup and start failures.
    boot_result = clean_boot_lab(
        project_dir,
        remove_volumes=options.clean_volumes,
        scenario_path=scenario_path,
    )
    if boot_result.outcome is StartupOutcome.FAILED:
        diagnostics.append(
            redact(f"public lab start failed: {boot_result.error or 'unknown'}")
        )
        diagnostics.extend(_startup_diag_lines(boot_result))
        return diagnostics
    if boot_result.outcome is not StartupOutcome.READY:
        # Degraded-but-usable still boots the range; record the degradation but
        # let later readiness checks decide pass/fail on concrete components.
        diagnostics_note = _startup_diag_lines(boot_result)
        log.warning("lab booted degraded: %s", "; ".join(diagnostics_note) or "")

    state.snapshot = _capture(project_dir, config)
    if state.snapshot is None:
        diagnostics.append("snapshot capture returned no data after boot")
    return diagnostics


def _capture(project_dir: Path, config: "AptlConfig") -> dict | None:
    """Capture a redacted range snapshot, returning ``None`` on failure."""
    try:
        backend = get_backend(config, project_dir)
        return capture_snapshot(config_dir=project_dir, backend=backend).to_dict()
    # broad-except: snapshot probes shell through the backend; never fatal here.
    except Exception as exc:
        log.warning("snapshot capture failed: %s", redact(str(exc)))
        return None


def _startup_diag_lines(result: "LabResult") -> list[str]:
    """Render redacted one-line summaries of startup diagnostics."""
    lines: list[str] = []
    for diag in getattr(result, "diagnostics", []) or []:
        label = f"{diag.step}/{diag.component}" if diag.component else diag.step
        lines.append(
            redact(
                f"[{diag.impact.value}|{diag.severity.value}] {label}: {diag.message}"
            )
        )
    return lines


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


def _ping_from_kali(backend: "DeploymentBackend", ip: str) -> bool:
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


def _ssh_reachable_from_kali(backend: "DeploymentBackend", ip: str) -> bool:
    """Return whether Kali can open a TCP connection to ``ip`` on port 22."""
    try:
        result = backend.container_exec(
            _KALI_CONTAINER,
            ["nc", "-z", "-w", "3", ip, "22"],
            timeout=15,
        )
    # broad-except: backend exec surfaces diverse transport errors.
    except Exception as exc:
        log.warning("ssh probe failed for %s: %s", ip, redact(str(exc)))
        return False
    return result.returncode == 0


def _prioritise_ssh_targets(
    backend: "DeploymentBackend", targets: list[tuple[str, str]]
) -> list[tuple[str, str]]:
    """Order targets so hosts actually exposing SSH are probed first.

    The generator proves host monitoring through failed SSH authentication, so a
    target with no listener produces no auth event and no alert however many
    times it is tried. Taking an arbitrary slice of reachable containers can
    therefore probe only hosts that cannot answer, which reads as a broken
    detection path when the path is fine.

    This stays scenario-generic: it asks which reachable hosts expose the service
    whose failed auth is being generated, rather than naming any node.
    """

    listening = [target for target in targets if _ssh_reachable_from_kali(backend, target[1])]
    remaining = [target for target in targets if target not in listening]
    return listening + remaining


def _collect_until_evidence(
    backend: "DeploymentBackend",
    start_iso: str,
    window_seconds: int,
    *,
    indexer_url: str,
    indexer_auth: tuple[str, str],
    sleep_fn: Callable[[float], None] = time.sleep,
    regenerate: Callable[[], None] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Poll for a post-trigger Wazuh alert until the window elapses.

    Both Suricata flow flushing and Wazuh ingest have latency, so the gate polls
    rather than sleeping a fixed interval. Suricata evidence is retained in the
    returned summary, but only a Wazuh alert ends the poll: a sensor-only event
    does not prove the realized Wazuh ingestion path. ``sleep_fn`` is injectable
    so tests can skip the real poll wait without patching ``time.sleep``.

    ``regenerate`` re-drives the trigger on each poll. Host monitoring on a
    freshly booted range becomes ready some seconds after the containers report
    healthy, and a trigger fired once before that happens is simply lost: the
    events never reach the SIEM and no amount of later polling can recover them.
    Re-driving makes the check ask whether the path works within the window
    rather than whether it happened to be ready at one instant.
    """
    steps = max(1, window_seconds // _POLL_STEP_SECONDS)
    eve: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    for _ in range(steps):
        sleep_fn(_POLL_STEP_SECONDS)
        if regenerate is not None:
            regenerate()
        now = _now_iso()
        eve = collect_suricata_eve(start_iso, now, backend)
        alerts = collect_wazuh_alerts(
            start_iso,
            now,
            indexer_url=indexer_url,
            auth=indexer_auth,
        )
        if any(_is_correlated_wazuh_alert(alert) for alert in alerts):
            break
    return eve, alerts


def _generate_event(
    backend: "DeploymentBackend", targets: list[tuple[str, str]]
) -> None:
    """Drive representative Kali activity at reachable targets (best effort).

    An nmap scan exercises the network sensor (Suricata) and failed SSH logins
    exercise host monitoring (Wazuh sshd rules). Both are best effort; the
    collection step decides pass/fail.
    """
    first_ip = targets[0][1]
    _exec_kali(backend, ["nmap", "-Pn", "-T4", "-p", "22,80,443,445", first_ip], 120)
    for _name, ip in _prioritise_ssh_targets(backend, targets)[:_MAX_EVENT_TARGETS]:
        for _attempt in range(3):
            _exec_kali(
                backend,
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "ConnectTimeout=3",
                    "-p",
                    "22",
                    f"aptl-live-gate-invalid@{ip}",
                    "true",
                ],
                15,
            )


def _exec_kali(backend: "DeploymentBackend", cmd: list[str], timeout: int) -> None:
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


def _event_type_tally(eve: list[dict[str, Any]]) -> dict[str, int]:
    """Tally Suricata EVE entries by event_type (no raw payloads)."""
    tally: dict[str, int] = {}
    for entry in eve:
        etype = (
            str(entry.get("event_type", "unknown"))
            if isinstance(entry, dict)
            else "unknown"
        )
        tally[etype] = tally.get(etype, 0) + 1
    return tally


def _is_correlated_wazuh_alert(alert: object) -> bool:
    """Match the bounded failed-auth identity emitted by ``_generate_event``."""

    if not isinstance(alert, dict) or not isinstance(alert.get("rule"), dict):
        return False
    return any(_WAZUH_TRIGGER_IDENTITY in value for value in _nested_strings(alert))


def _nested_strings(value: object) -> list[str]:
    """Collect string leaves from a nested JSON-like value."""

    strings: list[str] = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for nested in value.values():
            strings.extend(_nested_strings(nested))
    elif isinstance(value, list):
        for nested in value:
            strings.extend(_nested_strings(nested))
    return strings


def _wazuh_correlation_summary(alert: dict[str, Any]) -> dict[str, str]:
    """Return a bounded, non-secret identity summary for one correlated alert."""

    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    canonical = json.dumps(alert, sort_keys=True, default=str).encode("utf-8")
    return {
        "rule_id": str(rule.get("id", "unknown"))[:64],
        "event_time": str(alert.get("@timestamp", "unknown"))[:64],
        "source_identity": redact(
            str(data.get("srcip") or agent.get("name") or "unknown")
        )[:128],
        "correlation_id": _WAZUH_TRIGGER_IDENTITY,
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _missing_manifest_keys(manifest: Mapping[str, Any]) -> list[str]:
    """Confirm the manifest carries the audit-required surfaces."""
    diagnostics: list[str] = []
    provenance = manifest.get("raes_provenance", {})
    realization = provenance.get("realization") or {}
    if not realization.get("nodes"):
        diagnostics.append(
            "manifest carries no RAES realization nodes (cannot audit interpretation)"
        )
    if not provenance.get("selected_profiles"):
        diagnostics.append("manifest carries no RAES-selected profiles")
    if not manifest.get("validation", {}).get("checks"):
        diagnostics.append("manifest carries no validation evidence")
    if not manifest.get("snapshot"):
        diagnostics.append("manifest carries no post-boot snapshot")
    return diagnostics


def _scenario_name(scenario_path: Path) -> str:
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
