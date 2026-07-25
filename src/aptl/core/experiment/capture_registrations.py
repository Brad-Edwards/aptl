"""The trusted built-in collector registrations (EXP-010 / issue #752 PR 2).

Split out of :mod:`aptl.core.experiment.capture_registry` (which imports these
at its foot into :data:`~aptl.core.experiment.capture_registry.
DEFAULT_COLLECTOR_REGISTRY`) so the registration DATA lives apart from the
registry/binding TYPES and matching logic — keeping both files within budget.

Each registration is a static capability declaration only — no factory, import
path, or executable reference. The trusted adapter wiring that maps a
``registration_id`` to a live :class:`~aptl.core.evidence.protocol.Collector`
lives in :mod:`aptl.core.evidence.adapters.wiring`. Turning these on is what
flips ``create_aptl_manifest().observation`` from ``None`` to a real aggregate
projection — done together with the acquisition machinery (the honesty rule).

``channel_kind`` / ``capture_kind`` / sealing use governed ACES
controlled-vocabulary terms (``observation-channel-kinds`` /
``observation-capture-kinds`` / ``observation-sealing-modes``); the observation
projection validates them at manifest build.
"""

from __future__ import annotations

from aptl.core.experiment.capture_registry import (
    CaptureLimits,
    CaptureVisibility,
    CollectorRegistration,
)

#: Shared limits for the built-in windowed sources: 8 MiB / 5 minutes / 4096
#: artifacts per capture. Generous but bounded — the coordinator truncates a
#: source that exceeds the byte quota and discloses it.
_LIMITS = CaptureLimits(max_bytes=8 * 1024 * 1024, max_artifact_count=4096, max_duration_s=300)


def _builtin(
    registration_id: str,
    *,
    capture_kind: str,
    capture_scope: str,
    channel_kind: str,
    visibility_class: CaptureVisibility,
) -> CollectorRegistration:
    """Build one built-in registration from the per-source axes + shared defaults.

    The built-ins all serialize their windowed source's structured records to
    ``application/json``, seal by content-address ``digest`` (not a signed
    attestation), redact structured payloads, honor retention + loss
    disclosure, and support the ``run``/``task``/``interval`` window kinds.
    """
    return CollectorRegistration(
        registration_id=registration_id,
        implementation_version="1.0.0",
        contract_version="experiment-capture-spec/v1",
        channel_kind=channel_kind,
        capture_kind=capture_kind,
        capture_scope=capture_scope,
        window_kinds=frozenset({"run", "task", "interval"}),
        media_types=frozenset({"application/json"}),
        required_artifact_roles=frozenset({"observation"}),
        supported_sensitivities=frozenset({"public", "internal", "restricted"}),
        supports_redaction=True,
        integrity_modes=frozenset({"sha256-digest"}),
        sealing_modes=frozenset({"digest"}),
        supports_chain_of_custody=False,
        supports_retention=True,
        supports_loss_disclosure=True,
        visibility_class=visibility_class,
        limits=_LIMITS,
    )


#: The trusted built-in fleet — one per source owner, covering the acceptance
#: criterion's synchronized red / container / network / defensive evidence.
BUILTIN_REGISTRATIONS: tuple[CollectorRegistration, ...] = (
    # Red-team activity via the MCP result envelope (participant's own action).
    _builtin(
        "aptl.collector.mcp-red",
        capture_kind="observation",
        capture_scope="participant",
        channel_kind="participant-observation",
        visibility_class=CaptureVisibility.PARTICIPANT_VISIBLE,
    ),
    # Container logs via DeploymentBackend.
    _builtin(
        "aptl.collector.container-logs",
        capture_kind="log",
        capture_scope="service",
        channel_kind="backend-log",
        visibility_class=CaptureVisibility.EVALUATOR_ONLY,
    ),
    # Network IDS events (Suricata EVE) — the network-evidence source.
    _builtin(
        "aptl.collector.suricata-eve",
        capture_kind="log",
        capture_scope="network",
        channel_kind="packet-capture",
        visibility_class=CaptureVisibility.EVALUATOR_ONLY,
    ),
    # Defensive SIEM detections (Wazuh alerts).
    _builtin(
        "aptl.collector.wazuh-alerts",
        capture_kind="telemetry",
        capture_scope="service",
        channel_kind="backend-log",
        visibility_class=CaptureVisibility.EVALUATOR_ONLY,
    ),
    # Distributed traces (Tempo) — apparatus-only run trace.
    _builtin(
        "aptl.collector.tempo-traces",
        capture_kind="trace",
        capture_scope="run",
        channel_kind="workflow-history",
        visibility_class=CaptureVisibility.APPARATUS_ONLY,
    ),
)
