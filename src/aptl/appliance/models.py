"""Strict models for the signed disposable-appliance release envelope."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from aptl.appliance.versioning import is_appliance_version

_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^[a-z0-9][a-z0-9._/:~-]{0,254}@sha256:[a-f0-9]{64}$")
_COMMIT_RE = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")

ArtifactKind = Literal[
    "golden-disk",
    "offline-payload",
    "participant-profile",
    "participant-readiness",
    "participant-asset-lock",
    "participant-qualification",
    "boundary-policy",
    "golden-inventory",
    "machine-drill",
]
_REQUIRED_ARTIFACT_KINDS = frozenset(
    {
        "golden-disk",
        "offline-payload",
        "participant-profile",
        "participant-readiness",
        "participant-asset-lock",
        "participant-qualification",
        "boundary-policy",
        "golden-inventory",
        "machine-drill",
    }
)


class _StrictModel(BaseModel):
    """Immutable closed record used at the release trust boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _validate_digest(value: str) -> str:
    """Validate a canonical lowercase SHA-256 identity."""

    if not _DIGEST_RE.fullmatch(value):
        raise ValueError("digest must be sha256 followed by lowercase hexadecimal")
    return value


def _validate_identifier(value: str) -> str:
    """Validate a bounded lowercase release identifier."""

    if not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError("invalid release identifier")
    return value


def _validate_relative_path(value: str) -> str:
    """Validate a normalized relative POSIX path."""

    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or "//" in value
        or value.startswith("./")
        or path.is_absolute()
        or str(path) != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("artifact path must be a safe relative POSIX path")
    return value


class ArtifactReference(_StrictModel):
    """One content-addressed file contained by the release directory."""

    artifact_id: str
    kind: ArtifactKind
    path: str
    sha256: str
    size_bytes: int = Field(ge=1)

    @field_validator("artifact_id")
    @classmethod
    def validate_artifact_id(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _validate_relative_path(value)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        return _validate_digest(value)


class ReleaseSource(_StrictModel):
    """Immutable source identity resolved by the release pipeline."""

    aptl_version: str
    source_tag: str
    source_commit: str

    @field_validator("aptl_version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if not is_appliance_version(value):
            raise ValueError("invalid APTL release version")
        return value

    @field_validator("source_commit")
    @classmethod
    def validate_commit(cls, value: str) -> str:
        if not _COMMIT_RE.fullmatch(value):
            raise ValueError("source commit must be a full hexadecimal object id")
        return value

    @model_validator(mode="after")
    def validate_tag(self) -> ReleaseSource:
        if self.source_tag != f"v{self.aptl_version}":
            raise ValueError("source tag must exactly match the APTL version")
        return self


class ApplianceGuest(_StrictModel):
    """Immutable guest and disposable-overlay contract."""

    os_id: Literal["ubuntu"]
    os_version: str = Field(min_length=1, max_length=32)
    architecture: Literal["x86_64", "aarch64"]
    disk_format: Literal["qcow2"]
    base_image_digest: str
    immutable: Literal[True]
    overlay_strategy: Literal["qcow2-backing-file"]

    @field_validator("base_image_digest")
    @classmethod
    def validate_base_image_digest(cls, value: str) -> str:
        return _validate_digest(value)


class ParticipantReleaseBinding(_StrictModel):
    """References to the existing APP-2 participant release contracts."""

    profile_id: str
    profile_version: int = Field(ge=1)
    profile_manifest_digest: str
    readiness_suite_digest: str
    asset_lock_digest: str
    qualification_report_digest: str

    @field_validator("profile_id")
    @classmethod
    def validate_profile_id(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator(
        "profile_manifest_digest",
        "readiness_suite_digest",
        "asset_lock_digest",
        "qualification_report_digest",
    )
    @classmethod
    def validate_digests(cls, value: str) -> str:
        return _validate_digest(value)


class ApplianceBoundaryReleaseBinding(_StrictModel):
    """References to the existing APP-1 platform-boundary contracts."""

    policy_digest: str
    boundary_helper_image: str
    egress_proxy_image: str

    @field_validator("policy_digest")
    @classmethod
    def validate_policy_digest(cls, value: str) -> str:
        return _validate_digest(value)

    @field_validator("boundary_helper_image", "egress_proxy_image")
    @classmethod
    def validate_image_digest(cls, value: str) -> str:
        if not _IMAGE_DIGEST_RE.fullmatch(value):
            raise ValueError("release helper images must use immutable digests")
        return value


class HostPrerequisites(_StrictModel):
    """Minimum physical-host resources for the bounded participant profile."""

    architecture: Literal["x86_64", "aarch64"]
    vcpus: int = Field(ge=8)
    memory_bytes: int = Field(ge=16 * 1024**3)
    disk_bytes: int = Field(ge=100 * 1024**3)
    hardware_virtualization: Literal[True]
    local_adapter: Literal["qemu-kvm"]
    supported_hypervisors: tuple[str, ...] = Field(min_length=1)

    @field_validator("supported_hypervisors")
    @classmethod
    def validate_hypervisors(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(
            not value.strip() for value in values
        ):
            raise ValueError("supported hypervisors must be non-empty and unique")
        return values


class DeliveryAdapter(_StrictModel):
    """One outer delivery form for the exact same guest payload."""

    adapter_id: str
    kind: Literal["local-kvm", "hosted"]
    payload_unchanged: bool

    @field_validator("adapter_id")
    @classmethod
    def validate_adapter_id(cls, value: str) -> str:
        return _validate_identifier(value)


class DeliveryParity(_StrictModel):
    """Participant UX and payload identity shared by local and hosted forms."""

    participant_ui_digest: str
    participant_routes_digest: str
    adapters: tuple[DeliveryAdapter, ...]

    @field_validator("participant_ui_digest", "participant_routes_digest")
    @classmethod
    def validate_digests(cls, value: str) -> str:
        return _validate_digest(value)

    @model_validator(mode="after")
    def validate_adapter_parity(self) -> DeliveryParity:
        ids = [adapter.adapter_id for adapter in self.adapters]
        kinds = {adapter.kind for adapter in self.adapters}
        if len(ids) != len(set(ids)):
            raise ValueError("delivery adapter ids must be unique")
        if kinds != {"local-kvm", "hosted"}:
            raise ValueError("local and hosted delivery adapters are required")
        if any(not adapter.payload_unchanged for adapter in self.adapters):
            raise ValueError("delivery adapters must use the same payload")
        return self


class MachineDrill(_StrictModel):
    """Bounded result from one independent supported build/rollback host."""

    machine_id: str
    architecture: Literal["x86_64", "aarch64"]
    vcpus: int = Field(ge=1)
    memory_bytes: int = Field(gt=0)
    disk_bytes: int = Field(gt=0)
    build_passed: bool
    offline_boot_passed: bool
    participant_smoke_passed: bool
    rollback_passed: bool
    overlay_destroy_passed: bool

    @field_validator("machine_id")
    @classmethod
    def validate_machine_id(cls, value: str) -> str:
        return _validate_digest(value)

    @property
    def passed(self) -> bool:
        return all(
            (
                self.build_passed,
                self.offline_boot_passed,
                self.participant_smoke_passed,
                self.rollback_passed,
                self.overlay_destroy_passed,
            )
        )


class ApplianceDrillReport(_StrictModel):
    """Outer release qualification without duplicating APP-2 readiness data."""

    schema_version: Literal["aptl.appliance-drill/v1"]
    machines: tuple[MachineDrill, ...]
    golden_secret_scan_passed: bool
    golden_read_only_passed: bool
    distinct_overlay_identities_passed: bool
    failed_candidate_preserved_active_passed: bool

    @model_validator(mode="after")
    def validate_release_drills(self) -> ApplianceDrillReport:
        if len(self.machines) < 2:
            raise ValueError("two independent machine drills are required")
        machine_ids = [machine.machine_id for machine in self.machines]
        if len(machine_ids) != len(set(machine_ids)):
            raise ValueError("machine drill identities must be unique")
        if any(not machine.passed for machine in self.machines):
            raise ValueError("every machine drill must pass")
        release_checks = (
            self.golden_secret_scan_passed,
            self.golden_read_only_passed,
            self.distinct_overlay_identities_passed,
            self.failed_candidate_preserved_active_passed,
        )
        if not all(release_checks):
            raise ValueError("every appliance release drill must pass")
        return self


class GoldenImageInventory(_StrictModel):
    """Scanner result proving the immutable base carries no per-seat state."""

    schema_version: Literal["aptl.golden-inventory/v1"]
    scan_complete: Literal[True]
    populated_sensitive_paths: tuple[str, ...]
    writable_runtime_paths: tuple[str, ...]

    @field_validator("populated_sensitive_paths", "writable_runtime_paths")
    @classmethod
    def validate_inventory_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _validate_relative_path(value)
        if len(values) != len(set(values)):
            raise ValueError("golden inventory paths must be unique")
        return values

    @model_validator(mode="after")
    def validate_clean_golden_image(self) -> GoldenImageInventory:
        if self.populated_sensitive_paths or self.writable_runtime_paths:
            raise ValueError("golden image contains per-instance state")
        return self


class ApplianceReleaseManifest(_StrictModel):
    """Canonical signed manifest for one immutable appliance release."""

    schema_version: Literal["aptl.appliance-release/v1"]
    release_id: str
    source: ReleaseSource
    guest: ApplianceGuest
    artifacts: tuple[ArtifactReference, ...]
    payload_digest: str
    participant: ParticipantReleaseBinding
    boundary: ApplianceBoundaryReleaseBinding
    host_prerequisites: HostPrerequisites
    delivery: DeliveryParity
    qualification: ApplianceDrillReport
    upgrade_strategy: Literal["replace-golden-create-overlay"]

    @field_validator("release_id")
    @classmethod
    def validate_release_id(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("payload_digest")
    @classmethod
    def validate_payload_digest(cls, value: str) -> str:
        return _validate_digest(value)

    @model_validator(mode="after")
    def validate_release_bindings(self) -> ApplianceReleaseManifest:
        ids = [artifact.artifact_id for artifact in self.artifacts]
        paths = [artifact.path for artifact in self.artifacts]
        kinds = [artifact.kind for artifact in self.artifacts]
        if len(ids) != len(set(ids)):
            raise ValueError("artifact ids must be unique")
        if len(paths) != len(set(paths)):
            raise ValueError("artifact paths must be unique")
        if set(kinds) != _REQUIRED_ARTIFACT_KINDS or len(kinds) != len(
            _REQUIRED_ARTIFACT_KINDS
        ):
            raise ValueError("manifest does not contain the required artifact kinds")
        by_kind = {artifact.kind: artifact for artifact in self.artifacts}
        comparisons = (
            (
                by_kind["participant-profile"].sha256,
                self.participant.profile_manifest_digest,
            ),
            (
                by_kind["participant-readiness"].sha256,
                self.participant.readiness_suite_digest,
            ),
            (
                by_kind["participant-asset-lock"].sha256,
                self.participant.asset_lock_digest,
            ),
            (
                by_kind["participant-qualification"].sha256,
                self.participant.qualification_report_digest,
            ),
            (by_kind["boundary-policy"].sha256, self.boundary.policy_digest),
        )
        if any(actual != bound for actual, bound in comparisons):
            raise ValueError("release artifact digest does not match its binding")
        if self.guest.architecture != self.host_prerequisites.architecture:
            raise ValueError("guest and host architecture must match")
        return self


class ApplianceManifestSignature(_StrictModel):
    """Detached release signature stored next to the canonical manifest."""

    schema_version: Literal["aptl.appliance-signature/v1"]
    algorithm: Literal["ed25519"]
    key_id: str
    manifest_digest: str
    signature: str = Field(min_length=1)

    @field_validator("key_id", "manifest_digest")
    @classmethod
    def validate_digests(cls, value: str) -> str:
        return _validate_digest(value)
