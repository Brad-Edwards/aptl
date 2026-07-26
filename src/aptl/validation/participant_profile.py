"""Strict versioned participant-profile binding and resolution (APP-2).

The profile is release/conformance data.  It references the canonical ACES
scenario, first-party config, narrative, and readiness suite by contained path
and digest, then derives the expected runtime surface through the same ACES and
Compose authorities used by the public start path.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aptl.core.config import AptlConfig, load_config
from aptl.core.scenario_catalog import load_scenario_catalog
from aptl.utils.pathsafe import PathContainmentError, read_contained_nofollow
from aptl.validation.curated_live_proof import (
    ExpectedMatrix,
    expected_reduced_matrix,
)
from aptl.workbench.profiles import (
    ProfileId,
    WorkbenchConfigurationError,
    WorkbenchProfile,
    profile_for,
)

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")


class ParticipantProfileError(ValueError):
    """A participant profile cannot be validated or safely resolved."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


_ModelT = TypeVar("_ModelT", bound=BaseModel)


class ArtifactReference(_StrictModel):
    """One project-contained immutable profile input."""

    path: str
    sha256: str

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value or Path(value).is_absolute():
            raise ValueError("artifact path must be project-relative")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("sha256 must be lowercase hexadecimal")
        return value


class ScenarioReference(ArtifactReference):
    """Catalog identity plus the exact SDL bytes admitted for the profile."""

    catalog_id: str

    @field_validator("catalog_id")
    @classmethod
    def validate_catalog_id(cls, value: str) -> str:
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
        if not values or len(set(values)) != len(values):
            raise ValueError("capability ids must be non-empty and unique")
        return values


class MinimumHardware(_StrictModel):
    architecture: Literal["x86_64", "aarch64"]
    vcpus: int = Field(ge=1)
    memory_bytes: int = Field(gt=0)
    disk_bytes: int = Field(gt=0)


class ProfileMaximums(_StrictModel):
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
        path = Path(value)
        if not value or path.is_absolute() or "." in path.parts or ".." in path.parts:
            raise ValueError("release evidence ref must be a safe relative path")
        return value

    @field_validator("asset_lock_sha256")
    @classmethod
    def validate_asset_lock_digest(cls, value: str) -> str:
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
        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("invalid asset id")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("asset sha256 must be lowercase hexadecimal")
        return value

    @field_validator("services")
    @classmethod
    def validate_unique_services(cls, values: tuple[str, ...]) -> tuple[str, ...]:
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
        if not _IDENTIFIER_RE.fullmatch(value):
            raise ValueError("invalid profile id")
        return value


class NarrativeOperation(_StrictModel):
    operation_id: str
    classification: Literal["required", "optional", "facilitator-only"]
    capability_id: str
    channel: Literal["mcp", "browser", "workflow"]
    expected_result: str = Field(min_length=1)


class ParticipantNarrative(_StrictModel):
    schema_version: Literal["aptl.participant-narrative/v1"]
    narrative_id: str
    version: int = Field(ge=1)
    operations: tuple[NarrativeOperation, ...]

    @field_validator("operations")
    @classmethod
    def validate_unique_operations(
        cls, operations: tuple[NarrativeOperation, ...]
    ) -> tuple[NarrativeOperation, ...]:
        operation_ids = [operation.operation_id for operation in operations]
        if not operation_ids or len(operation_ids) != len(set(operation_ids)):
            raise ValueError("narrative operation ids must be non-empty and unique")
        return operations


class ReadinessCheck(_StrictModel):
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
    schema_version: Literal["aptl.participant-readiness/v1"]
    suite_id: str
    version: int = Field(ge=1)
    checks: tuple[ReadinessCheck, ...]

    @field_validator("checks")
    @classmethod
    def validate_unique_checks(
        cls, checks: tuple[ReadinessCheck, ...]
    ) -> tuple[ReadinessCheck, ...]:
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
        return tuple(
            dict.fromkeys(
                server_id
                for workbench in self.workbench_profiles
                for server_id in workbench.server_ids
            )
        )

    @property
    def browser_refs(self) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                bookmark
                for workbench in self.workbench_profiles
                for bookmark in workbench.bookmark_refs
            )
        )


def _relative_path(project_root: Path, path: Path) -> Path:
    try:
        return path.relative_to(project_root)
    except ValueError as exc:
        raise ParticipantProfileError("unsafe participant profile path") from exc


def _read_reference(
    project_root: Path,
    reference: ArtifactReference,
) -> bytes:
    try:
        payload = read_contained_nofollow(project_root, reference.path)
    except PathContainmentError as exc:
        raise ParticipantProfileError("unsafe profile reference") from exc
    if hashlib.sha256(payload).hexdigest() != reference.sha256:
        raise ParticipantProfileError(
            f"profile reference digest mismatch: {reference.path}"
        )
    return payload


def _load_model(
    model_type: type[_ModelT],
    payload: bytes,
    *,
    label: str,
) -> _ModelT:
    try:
        value = json.loads(payload)
        return model_type.model_validate(value)
    except (json.JSONDecodeError, ValidationError, TypeError) as exc:
        raise ParticipantProfileError(f"invalid participant {label}") from exc


def _validate_profile_links(
    project_root: Path,
    manifest: ParticipantProfileManifest,
) -> tuple[AptlConfig, Path, ParticipantNarrative, ParticipantReadinessSuite]:
    narrative = _load_model(
        ParticipantNarrative,
        _read_reference(project_root, manifest.narrative),
        label="narrative",
    )
    readiness = _load_model(
        ParticipantReadinessSuite,
        _read_reference(project_root, manifest.readiness),
        label="readiness suite",
    )
    _read_reference(project_root, manifest.config)
    scenario_bytes = _read_reference(project_root, manifest.scenario)

    config_path = project_root / manifest.config.path
    try:
        config = load_config(config_path)
        catalog = load_scenario_catalog(project_root)
    except ValueError as exc:
        raise ParticipantProfileError("invalid participant profile reference") from exc

    entry = catalog.get(manifest.scenario.catalog_id)
    if entry is None or entry.path != manifest.scenario.path:
        raise ParticipantProfileError("participant scenario catalog reference mismatch")
    scenario_path = project_root / manifest.scenario.path
    # Keep the exact no-follow bytes alive through the catalog check above.  The
    # planner reopens the canonical contained path through the ACES authority.
    if not scenario_bytes:
        raise ParticipantProfileError("participant scenario is empty")
    if (
        narrative.narrative_id != manifest.profile_id
        or narrative.version != manifest.version
        or readiness.suite_id != manifest.profile_id
        or readiness.version != manifest.version
    ):
        raise ParticipantProfileError("participant profile input identity mismatch")
    return (
        config,
        scenario_path,
        narrative,
        readiness,
    )


def _validate_narrative_readiness(
    narrative: ParticipantNarrative,
    readiness: ParticipantReadinessSuite,
) -> None:
    required = {
        operation.capability_id
        for operation in narrative.operations
        if operation.classification == "required"
    }
    checked = {check.capability_id for check in readiness.checks}
    if not required <= checked:
        raise ParticipantProfileError(
            "required narrative operation lacks a readiness check"
        )


def _load_asset_lock(
    project_root: Path,
    manifest: ParticipantProfileManifest,
) -> ParticipantAssetLock:
    reference = ArtifactReference(
        path=manifest.release_evidence.asset_lock_ref,
        sha256=manifest.release_evidence.asset_lock_sha256,
    )
    lock = _load_model(
        ParticipantAssetLock,
        _read_reference(project_root, reference),
        label="asset lock",
    )
    if (
        lock.profile_id != manifest.profile_id
        or lock.profile_version != manifest.version
    ):
        raise ParticipantProfileError("participant asset lock identity mismatch")
    for asset in lock.assets:
        if asset.kind == "project-file":
            _read_reference(
                project_root,
                ArtifactReference(path=asset.source, sha256=asset.sha256),
            )
        elif asset.kind == "mcp-artifact":
            _read_reference(
                project_root,
                ArtifactReference(path=asset.source, sha256=asset.sha256),
            )
        elif not asset.source.endswith(f"@sha256:{asset.sha256}"):
            raise ParticipantProfileError("participant OCI asset identity mismatch")
    return lock


def _validate_asset_lock_coverage(
    manifest: ParticipantProfileManifest,
    lock: ParticipantAssetLock,
    workbench_profiles: tuple[WorkbenchProfile, ...],
    expected_matrix: ExpectedMatrix,
) -> None:
    locked_files = {
        asset.source: asset.sha256
        for asset in lock.assets
        if asset.kind == "project-file"
    }
    required_references = (
        manifest.narrative,
        manifest.scenario,
        manifest.config,
        manifest.readiness,
    )
    if any(
        locked_files.get(reference.path) != reference.sha256
        for reference in required_references
    ):
        raise ParticipantProfileError("participant asset lock misses a profile input")
    workbench_artifacts = {
        server.artifact_ref
        for workbench in workbench_profiles
        for server in workbench.servers
    }
    locked_mcp_artifacts = {
        asset.source for asset in lock.assets if asset.kind == "mcp-artifact"
    }
    if not workbench_artifacts <= locked_mcp_artifacts:
        raise ParticipantProfileError("participant asset lock misses an MCP artifact")
    image_services = [
        service
        for asset in lock.assets
        if asset.kind == "oci-image"
        for service in asset.services
    ]
    if (
        len(image_services) != len(set(image_services))
        or set(image_services) != set(expected_matrix.expected_services)
    ):
        raise ParticipantProfileError(
            "participant asset lock does not match the derived service surface"
        )
    if any(
        bool(asset.services) != (asset.kind == "oci-image") for asset in lock.assets
    ):
        raise ParticipantProfileError("participant asset service binding is invalid")


def _validate_workbench_readiness(
    readiness: ParticipantReadinessSuite,
    workbench_profiles: tuple[WorkbenchProfile, ...],
) -> None:
    expected_browser = {
        bookmark
        for workbench in workbench_profiles
        for bookmark in workbench.bookmark_refs
    }
    checked_browser = {
        check.subject_id
        for check in readiness.checks
        if check.kind == "browser-operation"
    }
    if checked_browser != expected_browser:
        raise ParticipantProfileError(
            "participant browser readiness does not match the workbench surface"
        )


def load_participant_profile(
    project_dir: Path,
    manifest_path: Path,
) -> ResolvedParticipantProfile:
    """Load and resolve one strict project-contained participant profile."""

    project_root = project_dir.resolve()
    manifest_candidate = (
        manifest_path if manifest_path.is_absolute() else project_root / manifest_path
    )
    relative_manifest = _relative_path(project_root, manifest_candidate)
    try:
        manifest_bytes = read_contained_nofollow(project_root, relative_manifest)
    except PathContainmentError as exc:
        raise ParticipantProfileError("unsafe participant profile path") from exc
    manifest = _load_model(
        ParticipantProfileManifest,
        manifest_bytes,
        label="profile",
    )
    assert isinstance(manifest, ParticipantProfileManifest)
    config, scenario_path, narrative, readiness = _validate_profile_links(
        project_root, manifest
    )
    _validate_narrative_readiness(narrative, readiness)
    try:
        workbench_profiles = tuple(
            profile_for(profile_id)
            for profile_id in manifest.capabilities.workbench_profiles
        )
    except WorkbenchConfigurationError as exc:
        raise ParticipantProfileError("participant workbench profile is invalid") from exc
    _validate_workbench_readiness(readiness, workbench_profiles)
    asset_lock = _load_asset_lock(project_root, manifest)
    try:
        expected_matrix = expected_reduced_matrix(
            project_root,
            config,
            scenario_path,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ParticipantProfileError(
            "participant profile runtime surface is invalid"
        ) from exc
    _validate_asset_lock_coverage(
        manifest,
        asset_lock,
        workbench_profiles,
        expected_matrix,
    )
    return ResolvedParticipantProfile(
        manifest=manifest,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        config=config,
        scenario_path=scenario_path,
        narrative=narrative,
        readiness=readiness,
        asset_lock=asset_lock,
        workbench_profiles=workbench_profiles,
        expected_matrix=expected_matrix,
    )
