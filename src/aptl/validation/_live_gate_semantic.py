"""Scenario-specific semantic verification for the live gate (#877).

Everything in this module answers a question that only makes sense once you know
*which scenario* is running: which node is the attacker, what the defensive stack
is, and what evidence proves detection traversed it. That knowledge is
simultaneously about one scenario and one backend, so it belongs in neither the
portable scenario contract nor a backend that must serve any scenario — it is the
plugin quadrant (Shifter #1293).

The checks are gathered here, and only here, so the structural half of the gate in
``_live_gate_checks`` carries no scenario-derived constant. This module is the
extraction unit: #878 defines the installed-plugin seam and #879 moves this
content out of core behind it. Until then it is ordinary core code that happens to
be quarantined, which is honest about the current state — the boundary exists, the
content has not moved yet.

The generic behaviours these checks rely on stay framework and are deliberately
*not* duplicated here: bounded polling windows, re-driving a trigger while its
window is open rather than firing once, and preferring probe targets that actually
expose the service being exercised all live in ``_live_gate_probes`` /
``_live_gate_telemetry`` because they are true of any scenario.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.core.deployment import get_backend
from aptl.validation._live_gate_probes import (
    _KALI_CONTAINER,
    _check,
    _find_container,
    _ping_from_kali,
    _shared_network_targets,
)
from aptl.validation._live_gate_telemetry import telemetry_diagnostics
from aptl.validation.techvault_live_gate import (
    CATEGORY_EVIDENCE_CAPTURE,
    CATEGORY_KALI_REACHABILITY,
    LiveGateCheck,
)

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig
    from aptl.validation.techvault_live_gate import LiveGateOptions, LiveGateState


# --------------------------------------------------------------------------- #
# Attacker reachability.
# --------------------------------------------------------------------------- #


def check_kali_reachability(
    *,
    project_dir: Path,
    config: "AptlConfig",
    state: "LiveGateState",
) -> LiveGateCheck:
    """From Kali, reach every lab host it shares a declared network with.

    Scenario-specific because it names the attacker node. The reachability
    *targets* are still derived from network co-membership in the live snapshot
    rather than a hardcoded host list, so only the starting point is an answer
    key.
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
# Detection traversal.
# --------------------------------------------------------------------------- #


def check_telemetry_evidence_path(
    *,
    project_dir: Path,
    config: "AptlConfig",
    options: "LiveGateOptions",
    state: "LiveGateState",
    env_loader: Callable[[Path], dict[str, str]] | None = None,
) -> LiveGateCheck:
    """Generate one representative event and confirm it traverses the defensive stack.

    Drives traffic from Kali at a reachable DMZ host, then collects Suricata EVE
    and Wazuh alerts in the bounded post-trigger window. A Wazuh alert is
    mandatory; Suricata evidence is recorded as supporting evidence but cannot
    satisfy the realized-Wazuh proof by itself.

    Scenario-specific throughout: it knows the attacker node, that the defensive
    stack is Wazuh plus Suricata, and what an alert traversing it looks like.
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

    diagnostics = telemetry_diagnostics(
        targets,
        config,
        project_dir,
        options,
        state,
        env_loader=env_loader,
    )
    return _check("telemetry_evidence_path", CATEGORY_EVIDENCE_CAPTURE, diagnostics)


#: The scenario-specific checks, in gate order. The orchestrator runs this
#: sequence rather than naming the checks itself, so core's control flow does not
#: enumerate any scenario's answer keys and #879 replaces one binding.
SEMANTIC_CHECKS: tuple[str, ...] = (
    "kali_reachability",
    "telemetry_evidence_path",
)

__all__ = [
    "SEMANTIC_CHECKS",
    "check_kali_reachability",
    "check_telemetry_evidence_path",
]
