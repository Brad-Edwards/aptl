"""The TechVault collector registrations (EXP-010 / issue #980).

These declarations are owned and exported by the installed TechVault adapter.
Core's default registry stays empty; exact adapter discovery supplies this
registry only for an admitted TechVault pack/backend pairing.

Each registration is a static capability declaration only — no factory, import
path, or executable reference. The trusted adapter wiring that maps a
``registration_id`` to a live :class:`~aptl.core.evidence.protocol.Collector`
lives behind the selected adapter's runtime contribution. Passing this registry
to ``create_aptl_manifest`` turns on its real aggregate observation projection.

``channel_kind`` / ``capture_kind`` / sealing use governed RAES
controlled-vocabulary terms (``observation-channel-kinds`` /
``observation-capture-kinds`` / ``observation-sealing-modes``); the observation
projection validates them at manifest build.
"""

from __future__ import annotations

from dataclasses import dataclass

from raes_backend_protocols.capabilities import ObservationCaptureOffer

from aptl.core.experiment.capture_registry import (
    CaptureLimits,
    CaptureVisibility,
    CollectorRegistration,
)

#: Shared limits for the built-in windowed sources: 8 MiB / 5 minutes / 4096
#: artifacts per capture. Generous but bounded — the coordinator truncates a
#: source that exceeds the byte quota and discloses it.
_LIMITS = CaptureLimits(
    max_bytes=8 * 1024 * 1024, max_artifact_count=4096, max_duration_s=300
)
_CAPTURE_SPEC_CONTRACT = "experiment-capture-spec/v1"
_JSON_MEDIA_TYPE = "application/json"

_CORTEX_SCOPE = (
    "Exact analyzer inventory, successful TechVaultScenarioContext_1_0 execution "
    "for 172.20.1.30, and TheHive Cortex connector status OK."
)
_TRANSCRIPT_SCOPE = (
    "Every interactive shell session on the red-team workstation, with the "
    "commands issued and the responses returned, attributable to a session and "
    "ordered in time."
)
_SURICATA_READINESS_SCOPE = (
    "Exact content identities and realized-byte digests, Suricata configuration "
    "result, selected source paths, and active local SIDs and count."
)
_SQLI_SCOPE = (
    "A fresh Kali-to-webapp POST /login containing UNION SELECT must yield "
    "Suricata signature_id 1000010 and Wazuh rule id 303020; unrelated alerts "
    "and aggregate counts do not satisfy this requirement."
)
# The two scope strings below are the released TechVault pack's own
# ``evidence_requirements.<id>.scope`` text. RAES admits a demand only on an
# exact scope match, so these are transcribed verbatim from the pack and must
# be updated with it -- never paraphrased.
_MISP_READINESS_SCOPE = (
    "On a clean realization, record the canonical MISP URL and certificate "
    "verification result, an authenticated API write/read result, the declared "
    "database identity and application-role access result, and authenticated "
    "Redis access with the declared cache policy. Missing, anonymous, "
    "substituted, stale, or contradictory state fails readiness. Report only "
    "bounded statuses, stable identities, and correlation ids; omit backend "
    "choices, credential values, and configuration bodies."
)
_WAZUH_AGENT_READINESS_SCOPE = (
    "For each subject, correlate the declared forwarding agent with exactly one "
    "active manager member by its stable enrollment name and node reference. "
    "Missing, duplicate, stale or disconnected required identities fail readiness. "
    "Confirm readable declared log sources and fresh telemetry attributed to that "
    "identity before and after restart or recreation, preserving compatible "
    "enrollment. PostgreSQL and Suricata retain their own source ownership; "
    "Suricata EVE, generic syslog and manager health do not prove another host's "
    "endpoint-agent readiness. Report bounded identity/status/correlation results "
    "and loss; omit enrollment keys, credentials and raw event bodies."
)


@dataclass(frozen=True)
class _OfferSpec:
    """The varying axes of one exact TechVault observation offer."""

    artifact_role: str
    media_type: str
    capture_kind: str
    source_refs: frozenset[str]
    scope: str
    scope_refs: frozenset[str]
    channel_kind: str
    window_kinds: frozenset[str]
    integrity_mode: str
    redaction_policy: str
    source_class: str = "native"


def _offer(offer_id: str, spec: _OfferSpec) -> ObservationCaptureOffer:
    """Build one exact RAES offer; no wildcard can broaden TechVault admission."""

    return ObservationCaptureOffer(
        offer_id=offer_id,
        offer_version="1.0.0",
        output_contract="experiment-evidence-record-v1",
        field_selectors=("",),
        artifact_roles=frozenset({spec.artifact_role}),
        media_types=frozenset({spec.media_type}),
        capture_kind=spec.capture_kind,
        source_classes=frozenset({spec.source_class}),
        source_refs=spec.source_refs,
        scopes=frozenset({spec.scope}),
        scope_refs=spec.scope_refs,
        channel_kinds=frozenset({spec.channel_kind}),
        channel_refs=frozenset(),
        window_kinds=spec.window_kinds,
        integrity_modes=frozenset({spec.integrity_mode}),
        sensitivity="plain",
        availability="available",
        fidelity="complete",
        disclosure="redacted",
        retention_policy_refs=frozenset({"run_lifetime"}),
        export_policy="not-required",
        redaction_policy=spec.redaction_policy,
    )


_TECHVAULT_LIMITS = {
    "cortex": CaptureLimits(1024 * 1024, 32, 300),
    "readiness": CaptureLimits(256 * 1024, 1, 300),
    "sqli": CaptureLimits(2 * 1024 * 1024, 256, 300),
    "transcript": CaptureLimits(32 * 1024 * 1024, 4096, 24 * 60 * 60),
    # One bounded status document per readiness capture. MISP reports three
    # subjects (application, database, cache); the Wazuh agent capture reports
    # one row per monitored host plus the manager, so it carries a larger byte
    # budget while staying a single artifact.
    "misp-readiness": CaptureLimits(256 * 1024, 1, 300),
    "wazuh-agent-readiness": CaptureLimits(512 * 1024, 1, 300),
}


def _techvault_registration(
    registration_id: str,
    *,
    offer: ObservationCaptureOffer,
    limits: CaptureLimits,
    chain_of_custody: bool = False,
) -> CollectorRegistration:
    """Bind one TechVault offer to its implementation and runtime limits."""

    return CollectorRegistration(
        registration_id=registration_id,
        implementation_version="1.0.0",
        contract_version=_CAPTURE_SPEC_CONTRACT,
        channel_kind=next(iter(offer.channel_kinds)),
        capture_kind=offer.capture_kind,
        capture_scope="scenario",
        window_kinds=offer.window_kinds,
        media_types=offer.media_types,
        required_artifact_roles=offer.artifact_roles,
        supported_sensitivities=frozenset({"plain"}),
        supports_redaction=True,
        integrity_modes=offer.integrity_modes,
        sealing_modes=frozenset({"digest"}),
        supports_chain_of_custody=chain_of_custody,
        supports_retention=True,
        supports_loss_disclosure=True,
        visibility_class=CaptureVisibility.EVALUATOR_ONLY,
        limits=limits,
        redaction_policies=frozenset({offer.redaction_policy or ""}),
        retention_policies=offer.retention_policy_refs,
        capture_offer=offer,
    )


def _builtin(
    registration_id: str,
    *,
    capture_kind: str,
    capture_scope: str,
    channel_kind: str,
    visibility_class: CaptureVisibility,
    supports_loss_disclosure: bool = True,
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
        contract_version=_CAPTURE_SPEC_CONTRACT,
        channel_kind=channel_kind,
        capture_kind=capture_kind,
        capture_scope=capture_scope,
        window_kinds=frozenset({"run", "task", "interval"}),
        media_types=frozenset({_JSON_MEDIA_TYPE}),
        required_artifact_roles=frozenset({"observation"}),
        supported_sensitivities=frozenset({"public", "internal", "restricted"}),
        supports_redaction=True,
        integrity_modes=frozenset({"sha256-digest"}),
        sealing_modes=frozenset({"digest"}),
        supports_chain_of_custody=False,
        supports_retention=True,
        redaction_policies=frozenset({"redact_secrets"}),
        retention_policies=frozenset({"run_lifetime"}),
        supports_loss_disclosure=supports_loss_disclosure,
        visibility_class=visibility_class,
        limits=_LIMITS,
    )


_CORTEX_ENRICHMENT = _techvault_registration(
    "aptl.collector.cortex-enrichment",
    offer=_offer(
        "aptl.collector.cortex-enrichment",
        _OfferSpec(
            artifact_role="service_materialization_readback",
            media_type=_JSON_MEDIA_TYPE,
            capture_kind="observation",
            source_refs=frozenset(
                {
                    "nodes.cortex.runtime.platform_applications.cortex-enrichment",
                    "nodes.thehive.runtime.platform_applications.thehive-case-management",
                }
            ),
            scope=_CORTEX_SCOPE,
            scope_refs=frozenset({"nodes.cortex", "nodes.thehive"}),
            channel_kind="participant-observation",
            window_kinds=frozenset({"system_under_test"}),
            integrity_mode="checksum",
            redaction_policy="redact_secrets",
        ),
    ),
    limits=_TECHVAULT_LIMITS["cortex"],
)

_REDTEAM_SESSION_TRANSCRIPT = _techvault_registration(
    "aptl.collector.redteam-session-transcript",
    offer=_offer(
        "aptl.collector.redteam-session-transcript",
        _OfferSpec(
            artifact_role="participant_session_transcript",
            media_type="text/plain",
            capture_kind="observation",
            source_refs=frozenset(),
            scope=_TRANSCRIPT_SCOPE,
            scope_refs=frozenset({"nodes.kali"}),
            channel_kind="participant-observation",
            window_kinds=frozenset(
                {"the full run, from range readiness through teardown"}
            ),
            integrity_mode="chain_of_custody",
            redaction_policy="redact_secrets",
            source_class="apparatus",
        ),
    ),
    limits=_TECHVAULT_LIMITS["transcript"],
    chain_of_custody=True,
)

_SURICATA_RULE_READINESS = _techvault_registration(
    "aptl.collector.suricata-rule-readiness",
    offer=_offer(
        "aptl.collector.suricata-rule-readiness",
        _OfferSpec(
            artifact_role="network_detection_rule_readiness",
            media_type="text/plain",
            capture_kind="log",
            source_refs=frozenset(
                {
                    "nodes.suricata.runtime.network_detection_engines.suricata-engine.rule_sources.suricata-builtin",
                    "nodes.suricata.runtime.network_detection_engines.suricata-engine.rule_sources.techvault-local",
                }
            ),
            scope=_SURICATA_READINESS_SCOPE,
            scope_refs=frozenset(
                {
                    "nodes.suricata",
                    "content.suricata-config",
                    "content.suricata-local-rules",
                }
            ),
            channel_kind="backend-log",
            window_kinds=frozenset({"system_under_test"}),
            integrity_mode="checksum",
            redaction_policy="redact_sensitive",
        ),
    ),
    limits=_TECHVAULT_LIMITS["readiness"],
)

_SURICATA_WAZUH_SQLI = _techvault_registration(
    "aptl.collector.suricata-wazuh-sqli",
    offer=_offer(
        "aptl.collector.suricata-wazuh-sqli",
        _OfferSpec(
            artifact_role="network_detection_alert",
            media_type="application/x-ndjson",
            capture_kind="log",
            source_refs=frozenset(
                {
                    "nodes.suricata.runtime.network_detection_engines.suricata-engine.output_streams.eve-json",
                    "nodes.wazuh-manager.runtime.security_monitoring_managers."
                    "wazuh-manager.content_sets.suricata-rules",
                }
            ),
            scope=_SQLI_SCOPE,
            scope_refs=frozenset(
                {
                    "nodes.webapp.runtime.applications.techvault-portal",
                    "nodes.suricata.runtime.network_detection_engines.suricata-engine.rule_sources.techvault-local",
                }
            ),
            channel_kind="backend-log",
            window_kinds=frozenset({"event", "participant_equivalent"}),
            integrity_mode="checksum",
            redaction_policy="redact_sensitive",
        ),
    ),
    limits=_TECHVAULT_LIMITS["sqli"],
)

_MISP_AUTHENTICATED_API_READINESS = _techvault_registration(
    "aptl.collector.misp-authenticated-api-readiness",
    offer=_offer(
        "aptl.collector.misp-authenticated-api-readiness",
        _OfferSpec(
            artifact_role="service_materialization_readback",
            media_type=_JSON_MEDIA_TYPE,
            capture_kind="observation",
            source_refs=frozenset(
                {
                    "nodes.misp.runtime.platform_applications.misp-threat-intelligence",
                    "nodes.misp-db.runtime.database_services.misp-db",
                    "nodes.misp-redis.runtime.datastore_services.misp-redis",
                }
            ),
            scope=_MISP_READINESS_SCOPE,
            scope_refs=frozenset({"nodes.misp", "nodes.misp-db", "nodes.misp-redis"}),
            channel_kind="participant-observation",
            window_kinds=frozenset({"system_under_test"}),
            integrity_mode="checksum",
            redaction_policy="redact_secrets",
        ),
    ),
    limits=_TECHVAULT_LIMITS["misp-readiness"],
)

_WAZUH_AGENT_READINESS = _techvault_registration(
    "aptl.collector.wazuh-agent-readiness",
    offer=_offer(
        "aptl.collector.wazuh-agent-readiness",
        _OfferSpec(
            artifact_role="service_materialization_readback",
            media_type=_JSON_MEDIA_TYPE,
            capture_kind="artifact",
            source_refs=frozenset(
                {
                    "nodes.wazuh-manager.runtime.security_monitoring_managers.wazuh-manager",
                    "nodes.webapp.runtime.forwarding_agents.webapp-access-forwarder",
                    "nodes.ad.runtime.forwarding_agents.ad-samba-forwarder",
                    "nodes.dns.runtime.forwarding_agents.dns-query-forwarder",
                    "nodes.fileshare.runtime.forwarding_agents.fileshare-samba-forwarder",
                    "nodes.victim.runtime.forwarding_agents.victim-system-forwarder",
                    "nodes.workstation.runtime.forwarding_agents.workstation-system-forwarder",
                    "nodes.db.runtime.forwarding_agents.db-postgres-forwarder",
                    "nodes.suricata.runtime.forwarding_agents.suricata-eve-forwarder",
                }
            ),
            scope=_WAZUH_AGENT_READINESS_SCOPE,
            scope_refs=frozenset(
                {
                    "nodes.webapp",
                    "nodes.ad",
                    "nodes.dns",
                    "nodes.fileshare",
                    "nodes.victim",
                    "nodes.workstation",
                    "nodes.db",
                    "nodes.suricata",
                    "nodes.wazuh-manager",
                }
            ),
            channel_kind="file-artifact",
            window_kinds=frozenset({"system_under_test"}),
            integrity_mode="checksum",
            redaction_policy="redact_secrets",
        ),
    ),
    limits=_TECHVAULT_LIMITS["wazuh-agent-readiness"],
)

#: The trusted built-in fleet — one per source owner, covering the acceptance
#: criterion's synchronized red / container / network / defensive evidence.
BUILTIN_REGISTRATIONS: tuple[CollectorRegistration, ...] = (
    _CORTEX_ENRICHMENT,
    _MISP_AUTHENTICATED_API_READINESS,
    _REDTEAM_SESSION_TRANSCRIPT,
    _SURICATA_RULE_READINESS,
    _SURICATA_WAZUH_SQLI,
    _WAZUH_AGENT_READINESS,
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
        # A successful Tempo query does not account for SDK sampling, exporter
        # queues, retry exhaustion or ingestion losses upstream of the query.
        supports_loss_disclosure=False,
    ),
)

# The source is the native API projection already observed by provisioning,
# reported through runtime-snapshot concerns, not best-effort OTel delivery.
# It is wired by the scenario provisioner, not the generic query-source fleet.
SERVICE_INDEX_READBACK_REGISTRATION = CollectorRegistration(
    registration_id="aptl.collector.service-index-readback",
    implementation_version="1.0.0",
    contract_version=_CAPTURE_SPEC_CONTRACT,
    channel_kind="runtime-snapshot",
    capture_kind="observation",
    capture_scope="service",
    window_kinds=frozenset({"event"}),
    media_types=frozenset({_JSON_MEDIA_TYPE}),
    required_artifact_roles=frozenset({"service_materialization_readback"}),
    supported_sensitivities=frozenset({"public"}),
    supports_redaction=True,
    redaction_policies=frozenset({"redact_secrets"}),
    integrity_modes=frozenset({"sha256-digest"}),
    sealing_modes=frozenset({"digest"}),
    supports_chain_of_custody=False,
    supports_retention=True,
    retention_policies=frozenset({"run_lifetime"}),
    supports_loss_disclosure=True,
    visibility_class=CaptureVisibility.APPARATUS_ONLY,
    limits=_LIMITS,
)
