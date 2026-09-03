"""Strict versioned participant-profile binding and resolution (APP-2).

The profile is release/conformance data.  It references the canonical RAES
scenario, first-party config, narrative, and readiness suite by contained path
and digest, then derives the expected runtime surface through the same RAES and
Compose authorities used by the public start path.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ValidationError

from aptl.core.config import AptlConfig, load_config
from aptl.core.scenario_catalog import load_scenario_catalog
from aptl.utils.pathsafe import PathContainmentError, read_contained_nofollow
from aptl.validation.curated_live_proof import (
    ExpectedMatrix,
    expected_reduced_matrix,
)
from aptl.validation.participant_profile_models import (
    ArtifactReference,
    ParticipantAssetLock,
    ParticipantNarrative,
    ParticipantProfileManifest,
    ParticipantReadinessSuite,
    ResolvedParticipantProfile,
)
from aptl.workbench.profiles import (
    WorkbenchConfigurationError,
    WorkbenchProfile,
    profile_for,
)


class ParticipantProfileError(ValueError):
    """A participant profile cannot be validated or safely resolved."""


def _relative_path(project_root: Path, path: Path) -> Path:
    """Return a contained project-relative path or reject the candidate."""

    try:
        return path.relative_to(project_root)
    except ValueError as exc:
        raise ParticipantProfileError("unsafe participant profile path") from exc


def _read_reference(
    project_root: Path,
    reference: ArtifactReference,
) -> bytes:
    """Read one contained no-follow reference and verify its exact digest."""

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
    model_type: type[BaseModel],
    payload: bytes,
    *,
    label: str,
) -> BaseModel:
    """Decode strict JSON into the requested participant profile model."""

    try:
        value = json.loads(payload)
        return model_type.model_validate(value)
    except (json.JSONDecodeError, ValidationError, TypeError) as exc:
        raise ParticipantProfileError(f"invalid participant {label}") from exc


def _validate_profile_links(
    project_root: Path,
    manifest: ParticipantProfileManifest,
) -> tuple[AptlConfig, Path, ParticipantNarrative, ParticipantReadinessSuite]:
    """Resolve and cross-bind all immutable profile input references."""

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
    assert isinstance(narrative, ParticipantNarrative)
    assert isinstance(readiness, ParticipantReadinessSuite)
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
    # planner reopens the canonical contained path through the RAES authority.
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
    """Require each mandatory narrative capability to have a readiness check."""

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
    """Load and byte-verify the staged asset closure."""

    reference = ArtifactReference(
        path=manifest.release_evidence.asset_lock_ref,
        sha256=manifest.release_evidence.asset_lock_sha256,
    )
    lock = _load_model(
        ParticipantAssetLock,
        _read_reference(project_root, reference),
        label="asset lock",
    )
    assert isinstance(lock, ParticipantAssetLock)
    if (
        lock.profile_id != manifest.profile_id
        or lock.profile_version != manifest.version
    ):
        raise ParticipantProfileError("participant asset lock identity mismatch")
    for asset in lock.assets:
        if asset.kind in {"project-file", "mcp-artifact"}:
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
    """Require the asset lock to cover every derived release input exactly."""

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
    if len(image_services) != len(set(image_services)) or set(image_services) != set(
        expected_matrix.expected_services
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
    """Require browser readiness checks to equal the workbench bookmarks."""

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
        raise ParticipantProfileError(
            "participant workbench profile is invalid"
        ) from exc
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
