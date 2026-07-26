"""Participant-profile qualification report and conformance evaluation (APP-2)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aptl.core.runstore import RunStorageBackend
from aptl.validation.curated_live_proof import compare_to_snapshot
from aptl.validation.participant_profile import ResolvedParticipantProfile
from aptl.validation.participant_qualification_evidence import (
    OfflineEvidence,
    ParticipantQualificationError,
    ParticipantQualificationReport,
    QualificationAttestation,
    QualificationCheckEvidence,
    QualificationHardware,
    QualificationMeasurements,
    QualificationSurface,
    VerifiedParticipantQualification,
    load_participant_qualification_report,
    participant_qualification_attestation_payload,
    verify_participant_qualification_attestation,
)
from aptl.validation.techvault_live_gate import (
    CATEGORY_RAES_SPECIFICATION,
    CATEGORY_BACKEND_INSTANTIATION,
    CATEGORY_BACKEND_INTERPRETATION,
    CATEGORY_DEFENSIVE_STACK_READINESS,
    CATEGORY_EVIDENCE_CAPTURE,
    LiveGateCheck,
)

__all__ = [
    "OfflineEvidence",
    "ParticipantQualificationError",
    "ParticipantQualificationReport",
    "QualificationAttestation",
    "QualificationCheckEvidence",
    "QualificationHardware",
    "QualificationMeasurements",
    "QualificationSurface",
    "VerifiedParticipantQualification",
    "load_participant_qualification_report",
    "participant_qualification_attestation_payload",
    "verify_participant_qualification_attestation",
]


@dataclass(frozen=True)
class ParticipantQualificationEvaluation:
    """Conformance result expressed with the existing live-gate check shape."""

    checks: tuple[LiveGateCheck, ...]

    @property
    def passed(self) -> bool:
        """Return whether every conformance layer passed."""

        return all(check.passed for check in self.checks)

    def to_dict(self) -> dict[str, object]:
        """Serialize the evaluation without changing diagnostic content."""

        return {
            "conforming": self.passed,
            "checks": [
                {
                    "name": check.name,
                    "category": check.category,
                    "outcome": "pass" if check.passed else "fail",
                    "diagnostics": list(check.diagnostics),
                }
                for check in self.checks
            ],
        }


def _check(
    name: str,
    category: str,
    diagnostics: list[str],
) -> LiveGateCheck:
    """Build one existing live-gate check from accumulated diagnostics."""

    return LiveGateCheck(
        name=name,
        category=category,
        passed=not diagnostics,
        diagnostics=tuple(diagnostics),
    )


def _identity_check(
    profile: ResolvedParticipantProfile,
    report: ParticipantQualificationReport,
) -> LiveGateCheck:
    """Bind the report to the exact profile and release asset lock."""

    matches = (
        report.profile_id == profile.manifest.profile_id
        and report.profile_version == profile.manifest.version
        and report.profile_sha256 == profile.manifest_sha256
        and report.asset_lock_digest
        == f"sha256:{profile.manifest.release_evidence.asset_lock_sha256}"
    )
    diagnostics = [] if matches else ["profile identity or digest does not match"]
    return _check("profile_identity", CATEGORY_RAES_SPECIFICATION, diagnostics)


def _hardware_check(
    profile: ResolvedParticipantProfile,
    report: ParticipantQualificationReport,
) -> LiveGateCheck:
    """Require the qualification fixture to meet the declared minimum."""

    minimum = profile.manifest.budgets.minimum_hardware
    actual = report.hardware
    passes = (
        actual.architecture == minimum.architecture
        and actual.vcpus >= minimum.vcpus
        and actual.memory_bytes >= minimum.memory_bytes
        and actual.disk_bytes >= minimum.disk_bytes
    )
    diagnostics = [] if passes else ["qualification hardware is below the minimum"]
    return _check("minimum_hardware", CATEGORY_BACKEND_INSTANTIATION, diagnostics)


def _surface_check(
    profile: ResolvedParticipantProfile,
    report: ParticipantQualificationReport,
    snapshot: dict[str, object],
) -> LiveGateCheck:
    """Compare authenticated runtime evidence to the derived exact surface."""

    _, diagnostics = compare_to_snapshot(profile.expected_matrix, snapshot)
    if set(report.surface.selected_profiles) != set(
        profile.expected_matrix.selected_profiles
    ):
        diagnostics.append(
            "reported selected profiles do not match the admitted profile surface"
        )
    if set(report.surface.expected_services) != set(
        profile.expected_matrix.expected_services
    ):
        diagnostics.append(
            "reported expected services do not match the derived profile surface"
        )
    if set(report.surface.expected_networks) != set(
        profile.expected_matrix.expected_networks
    ):
        diagnostics.append(
            "reported expected networks do not match the derived profile surface"
        )
    actual_services = {
        str(container.get("name"))
        for container in snapshot.get("containers", ())
        if isinstance(container, dict)
        and str(container.get("status", "")).startswith("Up")
    }
    actual_networks = {
        str(network.get("name"))
        for network in snapshot.get("networks", ())
        if isinstance(network, dict)
    }
    if set(report.surface.actual_services) != actual_services:
        diagnostics.append(
            "reported actual services do not match the authenticated snapshot"
        )
    if set(report.surface.actual_networks) != actual_networks:
        diagnostics.append(
            "reported actual networks do not match the authenticated snapshot"
        )
    return _check(
        "runtime_surface",
        CATEGORY_BACKEND_INTERPRETATION,
        diagnostics,
    )


def _semantic_check(
    profile: ResolvedParticipantProfile,
    report: ParticipantQualificationReport,
) -> LiveGateCheck:
    """Require exactly one passing outcome per readiness operation."""

    observed = {check.check_id: check.status for check in report.checks}
    required_ids = {check.check_id for check in profile.readiness.checks}
    if set(observed) != required_ids:
        diagnostics = ["qualification checks do not exactly match the readiness suite"]
    elif any(status != "passed" for status in observed.values()):
        diagnostics = ["required readiness checks did not pass"]
    else:
        diagnostics = []
    return _check(
        "semantic_readiness",
        CATEGORY_DEFENSIVE_STACK_READINESS,
        diagnostics,
    )


def _disabled_surface_check(
    profile: ResolvedParticipantProfile,
    report: ParticipantQualificationReport,
) -> LiveGateCheck:
    """Require the observed participant capabilities to equal the allow-list."""

    surface = report.surface
    allowed_workbenches = {
        profile_id.value
        for profile_id in profile.manifest.capabilities.workbench_profiles
    }
    allowed_mcp = set(profile.mcp_server_ids)
    allowed_browser = set(profile.browser_refs)
    exact_allow_list = (
        set(surface.actual_workbench_profiles) == allowed_workbenches
        and set(surface.actual_mcp_servers) == allowed_mcp
        and set(surface.actual_browser_capabilities) == allowed_browser
    )
    diagnostics: list[str] = []
    if not exact_allow_list:
        diagnostics.append(
            "participant workbench, MCP, or browser surface does not match the allow-list"
        )
    return _check(
        "disabled_capability_absence",
        CATEGORY_DEFENSIVE_STACK_READINESS,
        diagnostics,
    )


def _offline_check(report: ParticipantQualificationReport) -> LiveGateCheck:
    """Require denied egress and zero post-stage network resolution."""

    evidence = report.offline
    attempts = (
        evidence.download_attempts
        + evidence.image_pulls
        + evidence.image_builds
        + evidence.package_resolutions
    )
    passes = evidence.egress_denied and attempts == 0
    diagnostics = (
        []
        if passes
        else ["staged startup attempted a download, pull, build, or package resolution"]
    )
    return _check(
        "staged_offline_start",
        CATEGORY_BACKEND_INSTANTIATION,
        diagnostics,
    )


def _budget_check(
    profile: ResolvedParticipantProfile,
    report: ParticipantQualificationReport,
) -> LiveGateCheck:
    """Require every resource and lifecycle measurement within its ceiling."""

    maximums = profile.manifest.budgets.maximums
    measured = report.measurements
    fields = (
        "peak_cpu_percent",
        "peak_memory_bytes",
        "staged_profile_assets_bytes",
        "unique_image_compressed_bytes",
        "unique_image_expanded_bytes",
        "peak_runtime_disk_bytes",
        "cold_start_seconds",
        "warm_start_seconds",
        "clean_reset_seconds",
    )
    passes = all(
        getattr(measured, field) <= getattr(maximums, field) for field in fields
    )
    diagnostics = [] if passes else ["measured resource or lifecycle budget exceeded"]
    return _check("resource_budgets", CATEGORY_EVIDENCE_CAPTURE, diagnostics)


def evaluate_participant_qualification(
    profile: ResolvedParticipantProfile,
    evidence: VerifiedParticipantQualification,
) -> ParticipantQualificationEvaluation:
    """Evaluate every APP-2 layer from authenticated, correlated evidence."""

    report = evidence.report
    return ParticipantQualificationEvaluation(
        checks=(
            _identity_check(profile, report),
            _hardware_check(profile, report),
            _surface_check(profile, report, evidence.snapshot),
            _semantic_check(profile, report),
            _disabled_surface_check(profile, report),
            _offline_check(report),
            _budget_check(profile, report),
        )
    )


def persist_participant_qualification(
    store: RunStorageBackend,
    run_id: str,
    evidence: VerifiedParticipantQualification,
    evaluation: ParticipantQualificationEvaluation,
) -> Path:
    """Persist structured qualification evidence through run-store redaction."""

    relative_path = "participant-profile/qualification.json"
    store.write_json(
        run_id,
        relative_path,
        {
            "report": evidence.report.model_dump(mode="json"),
            "run_record_sha256": evidence.report.run_record_sha256,
            "snapshot_sha256": evidence.report.snapshot_sha256,
            "evaluation": evaluation.to_dict(),
        },
    )
    return store.get_run_path(run_id) / relative_path
