"""Participant-profile qualification report and conformance evaluation (APP-2)."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aptl.core.runstore import RunStorageBackend
from aptl.utils.pathsafe import PathContainmentError, read_contained_nofollow
from aptl.validation.curated_live_proof import compare_to_snapshot
from aptl.validation.participant_profile import ResolvedParticipantProfile
from aptl.validation.techvault_live_gate import (
    CATEGORY_ACES_SPECIFICATION,
    CATEGORY_BACKEND_INSTANTIATION,
    CATEGORY_BACKEND_INTERPRETATION,
    CATEGORY_DEFENSIVE_STACK_READINESS,
    CATEGORY_EVIDENCE_CAPTURE,
    LiveGateCheck,
)

_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


class ParticipantQualificationError(ValueError):
    """Qualification evidence is invalid or outside the project boundary."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class QualificationHardware(_StrictModel):
    architecture: Literal["x86_64", "aarch64"]
    vcpus: int = Field(ge=1)
    memory_bytes: int = Field(gt=0)
    disk_bytes: int = Field(gt=0)
    hypervisor: str = Field(min_length=1)
    engine: str = Field(min_length=1)


class QualificationSurface(_StrictModel):
    selected_profiles: tuple[str, ...]
    expected_services: tuple[str, ...]
    actual_services: tuple[str, ...]
    expected_networks: tuple[str, ...]
    actual_networks: tuple[str, ...]
    actual_workbench_profiles: tuple[str, ...]
    actual_mcp_servers: tuple[str, ...]
    actual_browser_capabilities: tuple[str, ...]

    @field_validator(
        "selected_profiles",
        "expected_services",
        "actual_services",
        "expected_networks",
        "actual_networks",
        "actual_workbench_profiles",
        "actual_mcp_servers",
        "actual_browser_capabilities",
    )
    @classmethod
    def validate_unique_surface(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("qualification surface entries must be unique")
        return values


class QualificationCheckEvidence(_StrictModel):
    check_id: str = Field(min_length=1)
    status: Literal["passed", "failed"]
    summary: str = Field(min_length=1)


class OfflineEvidence(_StrictModel):
    egress_denied: bool
    download_attempts: int = Field(ge=0)
    image_pulls: int = Field(ge=0)
    image_builds: int = Field(ge=0)
    package_resolutions: int = Field(ge=0)


class QualificationMeasurements(_StrictModel):
    peak_cpu_percent: float = Field(ge=0, le=100)
    peak_memory_bytes: int = Field(ge=0)
    staged_profile_assets_bytes: int = Field(ge=0)
    unique_image_compressed_bytes: int = Field(ge=0)
    unique_image_expanded_bytes: int = Field(ge=0)
    peak_runtime_disk_bytes: int = Field(ge=0)
    cold_start_seconds: float = Field(ge=0)
    warm_start_seconds: float = Field(ge=0)
    clean_reset_seconds: float = Field(ge=0)


class QualificationAttestation(_StrictModel):
    algorithm: Literal["ed25519"]
    key_id: str = Field(min_length=1)
    signature: str = Field(min_length=1)


class ParticipantQualificationReport(_StrictModel):
    """Machine-readable evidence for the bounded inner participant profile."""

    schema_version: Literal["aptl.participant-qualification/v1"]
    profile_id: str
    profile_version: int = Field(ge=1)
    profile_sha256: str
    asset_lock_digest: str
    run_record_ref: str = Field(min_length=1)
    run_record_sha256: str
    snapshot_ref: str = Field(min_length=1)
    snapshot_sha256: str
    hardware: QualificationHardware
    surface: QualificationSurface
    checks: tuple[QualificationCheckEvidence, ...]
    offline: OfflineEvidence
    measurements: QualificationMeasurements
    sample_count: int = Field(ge=1)
    aggregation: Literal["worst-conforming-sample", "maximum"]
    attestation: QualificationAttestation

    @field_validator("profile_sha256", "run_record_sha256", "snapshot_sha256")
    @classmethod
    def validate_profile_digest(cls, value: str) -> str:
        if not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("evidence sha256 must be lowercase hexadecimal")
        return value

    @field_validator("asset_lock_digest")
    @classmethod
    def validate_release_digest(cls, value: str) -> str:
        if not _DIGEST_RE.fullmatch(value):
            raise ValueError("release digest must use sha256:<hex>")
        return value

    @field_validator("run_record_ref", "snapshot_ref")
    @classmethod
    def validate_evidence_ref(cls, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or "." in path.parts or ".." in path.parts:
            raise ValueError("evidence ref must be a safe relative path")
        return value

    @field_validator("checks")
    @classmethod
    def validate_unique_checks(
        cls, checks: tuple[QualificationCheckEvidence, ...]
    ) -> tuple[QualificationCheckEvidence, ...]:
        ids = [check.check_id for check in checks]
        if len(ids) != len(set(ids)):
            raise ValueError("qualification check ids must be unique")
        return checks


@dataclass(frozen=True)
class VerifiedParticipantQualification:
    """Authenticated report plus the content-addressed canonical evidence."""

    report: ParticipantQualificationReport
    run_record: dict[str, object]
    snapshot: dict[str, object]


def participant_qualification_attestation_payload(
    report: ParticipantQualificationReport,
) -> bytes:
    """Return the canonical bytes signed by the qualification pipeline."""

    document = report.model_dump(mode="json", exclude={"attestation"})
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_participant_qualification_attestation(
    report: ParticipantQualificationReport,
    public_key_pem: bytes,
) -> None:
    """Verify the report against a release-pipeline trust anchor."""

    try:
        key = serialization.load_pem_public_key(public_key_pem)
        signature = base64.b64decode(
            report.attestation.signature,
            validate=True,
        )
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("qualification key must be Ed25519")
        key_der = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected_key_id = f"sha256:{hashlib.sha256(key_der).hexdigest()}"
        if report.attestation.key_id != expected_key_id:
            raise ValueError("qualification key id does not match the trust anchor")
        key.verify(
            signature,
            participant_qualification_attestation_payload(report),
        )
    except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError) as exc:
        raise ParticipantQualificationError(
            "participant qualification attestation is invalid"
        ) from exc


def _load_evidence_json(
    project_root: Path,
    reference: str,
    expected_sha256: str,
    *,
    label: str,
) -> dict[str, object]:
    try:
        payload = read_contained_nofollow(project_root, reference)
    except PathContainmentError as exc:
        raise ParticipantQualificationError(
            f"unsafe participant qualification {label} path"
        ) from exc
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ParticipantQualificationError(
            f"participant qualification {label} digest mismatch"
        )
    try:
        document = json.loads(payload)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ParticipantQualificationError(
            f"invalid participant qualification {label}"
        ) from exc
    if not isinstance(document, dict):
        raise ParticipantQualificationError(
            f"invalid participant qualification {label}"
        )
    return document


def _validate_canonical_evidence(
    report: ParticipantQualificationReport,
    run_record: dict[str, object],
    snapshot: dict[str, object],
) -> None:
    backend_evidence = run_record.get("backend_evidence")
    if not isinstance(backend_evidence, dict):
        raise ParticipantQualificationError("invalid participant run record")
    selected_profiles = backend_evidence.get("selected_profiles")
    if not isinstance(selected_profiles, list) or not all(
        isinstance(profile, str) for profile in selected_profiles
    ):
        raise ParticipantQualificationError("invalid participant run record")
    matches = (
        run_record.get("schema_version") == "aptl.run-record/v1"
        and run_record.get("outcome") == "success"
        and set(selected_profiles) == set(report.surface.selected_profiles)
        and backend_evidence.get("range_snapshot") == snapshot
    )
    if not matches:
        raise ParticipantQualificationError(
            "participant qualification evidence is not correlated"
        )


def load_participant_qualification_report(
    project_dir: Path,
    report_path: Path,
    public_key_path: Path,
) -> VerifiedParticipantQualification:
    """Load and authenticate one project-contained qualification bundle."""

    project_root = project_dir.resolve()
    candidate = report_path if report_path.is_absolute() else project_root / report_path
    try:
        relative = candidate.relative_to(project_root)
        payload = read_contained_nofollow(project_root, relative)
    except (ValueError, PathContainmentError) as exc:
        raise ParticipantQualificationError(
            "unsafe participant qualification report path"
        ) from exc
    try:
        report = ParticipantQualificationReport.model_validate_json(payload)
    except (ValidationError, ValueError) as exc:
        raise ParticipantQualificationError(
            "invalid participant qualification report"
        ) from exc
    try:
        key_relative = (
            public_key_path
            if not public_key_path.is_absolute()
            else public_key_path.relative_to(project_root)
        )
        public_key_pem = read_contained_nofollow(project_root, key_relative)
    except (ValueError, PathContainmentError) as exc:
        raise ParticipantQualificationError(
            "unsafe participant qualification public key path"
        ) from exc
    verify_participant_qualification_attestation(report, public_key_pem)
    run_record = _load_evidence_json(
        project_root,
        report.run_record_ref,
        report.run_record_sha256,
        label="run record",
    )
    snapshot = _load_evidence_json(
        project_root,
        report.snapshot_ref,
        report.snapshot_sha256,
        label="snapshot",
    )
    _validate_canonical_evidence(report, run_record, snapshot)
    return VerifiedParticipantQualification(report, run_record, snapshot)


@dataclass(frozen=True)
class ParticipantQualificationEvaluation:
    """Conformance result expressed with the existing live-gate check shape."""

    checks: tuple[LiveGateCheck, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    def to_dict(self) -> dict[str, object]:
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
    matches = (
        report.profile_id == profile.manifest.profile_id
        and report.profile_version == profile.manifest.version
        and report.profile_sha256 == profile.manifest_sha256
        and report.asset_lock_digest
        == f"sha256:{profile.manifest.release_evidence.asset_lock_sha256}"
    )
    diagnostics = [] if matches else ["profile identity or digest does not match"]
    return _check("profile_identity", CATEGORY_ACES_SPECIFICATION, diagnostics)


def _hardware_check(
    profile: ResolvedParticipantProfile,
    report: ParticipantQualificationReport,
) -> LiveGateCheck:
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
