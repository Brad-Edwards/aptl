"""Strict data models for the versioned participant profile contract."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aptl.core.config import AptlConfig
from aptl.validation.curated_live_proof import ExpectedMatrix
from aptl.workbench.profiles import ProfileId, WorkbenchProfile

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")


class _StrictModel(BaseModel):
    """Immutable profile model that rejects undeclared input fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ArtifactReference(_StrictModel):
    """One project-contained immutable profile input."""

    path: str
    sha256: str

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        """Require a non-empty project-relative artifact path."""

        if not value or Path(value).is_absolute():
            raise ValueError("artifact path must be project-relative")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        """Require a lowercase SHA-256 content digest."""

        if not _SHA256_RE.fullmatch(value):
            raise ValueError("sha256 must be lowercase hexadecimal")
        return value


class ScenarioReference(ArtifactReference):
    """Catalog identity plus the exact SDL bytes admitted for the profile."""

    catalog_id: str

    @field_validator("catalog_id")
    @classmethod
    def validate_catalog_id(cls, value: str) -> str:
        """Require the canonical lowercase catalog identifier shape."""

        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("invalid scenario catalog id")
        return value


class ParticipantCapabilities(_StrictModel):
    """Workbench compartments admitted in sequence by the guided workflow."""

    workbench_profiles: tuple[ProfileId, ...]

    @field_validator("workbench_profiles")
    @classmethod
    def validate_unique_identifiers(
        cls, values: tuple[ProfileId, ...]
    ) -> tuple[ProfileId, ...]:
        """Require a non-empty sequence without repeated compartments."""

        if not values or len(set(values)) != len(values):
            raise ValueError("capability ids must be non-empty and unique")
        return values


class MinimumHardware(_StrictModel):
    """Minimum supported participant qualification fixture."""

    architecture: Literal["x86_64", "aarch64"]
    vcpus: int = Field(ge=1)
    memory_bytes: int = Field(gt=0)
    disk_bytes: int = Field(gt=0)


class ProfileMaximums(_StrictModel):
    """Resource and lifecycle ceilings for a conforming profile run."""

    peak_cpu_percent: float = Field(gt=0, le=100)
    peak_memory_bytes: int = Field(gt=0)
    staged_profile_assets_bytes: int = Field(gt=0)
    unique_image_compressed_bytes: int = Field(gt=0)
    unique_image_expanded_bytes: int = Field(gt=0)
    peak_runtime_disk_bytes: int = Field(gt=0)
    cold_start_seconds: float = Field(gt=0)
    warm_start_seconds: float = Field(gt=0)
    clean_reset_seconds: float = Field(gt=0)


class ProfileBudgets(_StrictModel):
    """Minimum fixture and maximum measured values for the release."""

    minimum_hardware: MinimumHardware
    maximums: ProfileMaximums


class ReleaseEvidenceContract(_StrictModel):
    """Profile evidence that the appliance release in issue 823 consumes."""

    asset_lock_schema: Literal["aptl.participant-asset-lock/v1"]
    qualification_report_schema: Literal["aptl.participant-qualification/v1"]
    asset_lock_ref: str
    asset_lock_sha256: str
    qualification_report_ref: str

    @field_validator("asset_lock_ref", "qualification_report_ref")
    @classmethod
    def validate_release_ref(cls, value: str) -> str:
        """Keep release evidence references inside the project."""

        path = Path(value)
        if not value or path.is_absolute() or "." in path.parts or ".." in path.parts:
            raise ValueError("release evidence ref must be a safe relative path")
        return value

    @field_validator("asset_lock_sha256")
    @classmethod
    def validate_asset_lock_digest(cls, value: str) -> str:
        """Require the exact lowercase asset-lock digest."""

        if not _SHA256_RE.fullmatch(value):
            raise ValueError("asset lock sha256 must be lowercase hexadecimal")
        return value


class AssetLockEntry(_StrictModel):
    """One staged input identity required by the participant profile."""

    asset_id: str
    kind: Literal["project-file", "mcp-artifact", "oci-image"]
    source: str = Field(min_length=1)
    sha256: str
    services: tuple[str, ...] = ()

    @field_validator("asset_id")
    @classmethod
    def validate_asset_id(cls, value: str) -> str:
        """Require a stable lowercase asset identifier."""

        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("invalid asset id")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        """Require a lowercase SHA-256 asset digest."""

        if not _SHA256_RE.fullmatch(value):
            raise ValueError("asset sha256 must be lowercase hexadecimal")
        return value

    @field_validator("services")
    @classmethod
    def validate_unique_services(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Reject duplicate Compose service bindings."""

        if len(values) != len(set(values)):
            raise ValueError("asset service ids must be unique")
        return values


class ParticipantAssetLock(_StrictModel):
    """Content-addressed closure staged before participant delivery."""

    schema_version: Literal["aptl.participant-asset-lock/v1"]
    profile_id: str
    profile_version: int = Field(ge=1)
    assets: tuple[AssetLockEntry, ...]

    @field_validator("assets")
    @classmethod
    def validate_unique_assets(
        cls, assets: tuple[AssetLockEntry, ...]
    ) -> tuple[AssetLockEntry, ...]:
        """Require a non-empty asset closure with unique identifiers."""

        ids = [asset.asset_id for asset in assets]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("asset lock ids must be non-empty and unique")
        return assets


class ParticipantProfileManifest(_StrictModel):
    """The immutable release-level profile binding."""

    schema_version: Literal["aptl.participant-profile/v1"]
    profile_id: str
    version: int = Field(ge=1)
    narrative: ArtifactReference
    scenario: ScenarioReference
    config: ArtifactReference
    readiness: ArtifactReference
    capabilities: ParticipantCapabilities
    release_evidence: ReleaseEvidenceContract
    budgets: ProfileBudgets

    @field_validator("profile_id")
    @classmethod
    def validate_profile_id(cls, value: str) -> str:
        """Require a stable lowercase profile identifier."""

        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("invalid profile id")
        return value


class NarrativeOperation(_StrictModel):
    """One participant, optional, or facilitator workflow operation."""

    operation_id: str
    classification: Literal["required", "optional", "facilitator-only"]
    capability_id: str
    channel: Literal["mcp", "browser", "workflow"]
    expected_result: str = Field(min_length=1)


class ParticipantNarrative(_StrictModel):
    """Versioned sequence of admitted guided-workflow operations."""

    schema_version: Literal["aptl.participant-narrative/v1"]
    narrative_id: str
    version: int = Field(ge=1)
    operations: tuple[NarrativeOperation, ...]

    @field_validator("operations")
    @classmethod
    def validate_unique_operations(
        cls, operations: tuple[NarrativeOperation, ...]
    ) -> tuple[NarrativeOperation, ...]:
        """Require a non-empty narrative without repeated operation ids."""

        operation_ids = [operation.operation_id for operation in operations]
        if not operation_ids or len(operation_ids) != len(set(operation_ids)):
            raise ValueError("narrative operation ids must be non-empty and unique")
        return operations


class ReadinessCheck(_StrictModel):
    """One bounded semantic readiness operation for an admitted capability."""

    check_id: str
    capability_id: str
    kind: Literal[
        "runtime-surface",
        "mcp-tool",
        "browser-operation",
        "evidence",
        "offline-assets",
        "resource-budget",
    ]
    subject_id: str
    operation_id: str
    timeout_seconds: int = Field(gt=0, le=3600)


class ParticipantReadinessSuite(_StrictModel):
    """Versioned exact semantic checks for the guided workflow."""

    schema_version: Literal["aptl.participant-readiness/v1"]
    suite_id: str
    version: int = Field(ge=1)
    checks: tuple[ReadinessCheck, ...]

    @field_validator("checks")
    @classmethod
    def validate_unique_checks(
        cls, checks: tuple[ReadinessCheck, ...]
    ) -> tuple[ReadinessCheck, ...]:
        """Require a non-empty readiness suite without repeated ids."""

        check_ids = [check.check_id for check in checks]
        if not check_ids or len(check_ids) != len(set(check_ids)):
            raise ValueError("readiness check ids must be non-empty and unique")
        return checks


@dataclass(frozen=True)
class ResolvedParticipantProfile:
    """Validated profile plus its canonical resolved runtime inputs."""

    manifest: ParticipantProfileManifest
    manifest_sha256: str
    config: AptlConfig
    scenario_path: Path
    narrative: ParticipantNarrative
    readiness: ParticipantReadinessSuite
    asset_lock: ParticipantAssetLock
    workbench_profiles: tuple[WorkbenchProfile, ...]
    expected_matrix: ExpectedMatrix

    @property
    def mcp_server_ids(self) -> tuple[str, ...]:
        """Return the ordered unique MCP surface of all compartments."""

        return tuple(
            dict.fromkeys(
                server_id
                for workbench in self.workbench_profiles
                for server_id in workbench.server_ids
            )
        )

    @property
    def browser_refs(self) -> tuple[str, ...]:
        """Return the ordered unique browser surface of all compartments."""

        return tuple(
            dict.fromkeys(
                bookmark
                for workbench in self.workbench_profiles
                for bookmark in workbench.bookmark_refs
            )
        )
