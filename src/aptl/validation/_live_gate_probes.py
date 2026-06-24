"""Private probe / helper functions for the ACES live validation gate.

These support the check implementations in ``_live_gate_checks`` (SCN-010F /
#323); the split keeps each module under the file-size budget. This module is
the leaf of the live-gate package: it imports the lifecycle / snapshot /
collector / interpretation entry points directly and never imports
``_live_gate_checks``. The fast unit suite monkeypatches the leaf entry points
*on this module* (e.g. ``_live_gate_probes.get_backend``) to drive the boot and
telemetry probes without a live lab.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
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
from aces_sdl.scenario import Scenario

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_profiles import normalize_identifier
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.collectors import collect_suricata_eve, collect_wazuh_alerts
from aptl.core.deployment import get_backend
from aptl.core.lab import orchestrate_lab_start, stop_lab
from aptl.core.lab_types import StartupOutcome
from aptl.core.runstore import LocalRunStore
from aptl.core.snapshot import capture_snapshot
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact
from aptl.validation.techvault_live_gate import LiveGateCheck

if TYPE_CHECKING:
    from aces_contracts.diagnostics import Diagnostic

    from aptl.backends.aces_realization_model import AptlRealization
    from aptl.core.config import AptlConfig
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.lab_types import LabResult
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
) -> tuple["AptlRealization | None", list[str]]:
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

    stop_result = stop_lab(
        remove_volumes=options.clean_volumes, project_dir=project_dir
    )
    if not stop_result.success:
        diagnostics.append(redact(f"pre-boot cleanup failed: {stop_result.error}"))

    start_result = orchestrate_lab_start(project_dir, scenario_path=scenario_path)
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


def _node_readiness_diagnostics(
    nodes: Sequence[Mapping[str, Any]],
    containers: Sequence[Mapping[str, Any]],
    selected: set[str],
) -> tuple[list[str], set[str]]:
    """Return (hard-failure diagnostics, matched container names) for realized nodes."""
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
            diagnostics.append(
                f"realized node {node.get('name', '?')!r} has no live container"
            )
            continue
        matched_names.add(container.get("name", ""))
        diagnostics.extend(
            _container_health_diagnostics(
                node.get("name", "?"), container, node.get("declared_health")
            )
        )
    return diagnostics, matched_names


def _warn_unhealthy_infra(
    containers: Sequence[Mapping[str, Any]], matched_names: set[str]
) -> None:
    """Log unhealthy non-node infra containers as informational notes only."""
    for container in containers:
        if container.get("name", "") in matched_names:
            continue
        if container.get("health") == "unhealthy":
            log.warning(
                "non-node infra container unhealthy: %s", container.get("name", "?")
            )


def _container_health_diagnostics(
    node_name: str,
    container: Mapping[str, Any],
    declared_health: str | None = None,
) -> list[str]:
    """Return hard-failure diagnostics for one realized node's container.

    ``declared_health`` is the node's realized ``runtime.health.status``
    expectation (``None`` when the scenario declares no health). When a node
    declares ``healthy``, the running container's health must actually report
    ``healthy`` — an empty/``starting``/``unhealthy`` health is a conformance
    failure, not silently tolerated as it is for nodes with no declaration.
    """
    status = str(container.get("status", ""))
    health = str(container.get("health", ""))
    if not status.startswith("Up"):
        return [f"node {node_name!r} container not running (status={status!r})"]
    if health == "unhealthy":
        return [f"node {node_name!r} container unhealthy"]
    if declared_health == "healthy" and health != "healthy":
        return [
            f"node {node_name!r} declares health {declared_health!r} but container "
            f"health is {health or 'unreported'!r}"
        ]
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


def _collect_until_evidence(
    backend: "DeploymentBackend",
    start_iso: str,
    window_seconds: int,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Poll for defensive-stack evidence until found or the window elapses.

    Both Suricata flow flushing and Wazuh ingest have latency, so the gate polls
    rather than sleeping a fixed interval; it returns as soon as a traffic-derived
    Suricata event or a Wazuh alert appears. ``sleep_fn`` is injectable so tests
    can skip the real poll wait without patching ``time.sleep`` on the module.
    """
    steps = max(1, window_seconds // _POLL_STEP_SECONDS)
    eve: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    for _ in range(steps):
        sleep_fn(_POLL_STEP_SECONDS)
        now = _now_iso()
        eve = collect_suricata_eve(start_iso, now, backend)
        alerts = collect_wazuh_alerts(start_iso, now)
        if any(_is_traffic_event(e) for e in eve) or alerts:
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


def _distinct_profile_nodes(
    nodes: Sequence[Mapping[str, Any]],
) -> tuple[str, str] | None:
    """Pick two node names whose realized profiles differ."""
    seen: list[tuple[str, frozenset[str]]] = []
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


def _variation_diagnostics(
    first: "AptlRealization", second: "AptlRealization"
) -> list[str]:
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
