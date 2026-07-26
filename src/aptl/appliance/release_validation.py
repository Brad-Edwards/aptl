"""Artifact and evidence verification for signed appliance releases."""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import rfc8785

from aptl.appliance.errors import ApplianceManifestError
from aptl.appliance.models import (
    ApplianceDrillReport,
    ApplianceReleaseManifest,
    ArtifactKind,
    ArtifactReference,
    GoldenImageInventory,
)
from aptl.appliance.versioning import aptl_wheel_version
from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
from aptl.utils.pathsafe import PathContainmentError, read_contained_nofollow
from aptl.validation.participant_profile_models import (
    ParticipantAssetLock,
    ParticipantProfileManifest,
    ParticipantReadinessSuite,
)
from aptl.validation.participant_qualification_evidence import (
    ParticipantQualificationReport,
)

_PAYLOAD_KINDS = frozenset(
    {
        "golden-disk",
        "offline-payload",
        "participant-profile",
        "participant-readiness",
        "participant-asset-lock",
        "participant-qualification",
        "boundary-policy",
    }
)


def read_release_artifact(root: Path, relative_path: str) -> bytes:
    """Read one contained release file without following symlinks."""

    try:
        return read_contained_nofollow(root, relative_path)
    except (OSError, PathContainmentError, ValueError) as exc:
        raise ApplianceManifestError(
            f"unsafe release artifact: {relative_path}"
        ) from exc


def compute_payload_digest(artifacts: tuple[ArtifactReference, ...]) -> str:
    """Bind guest bytes and reused APP-1/APP-2 identities into one digest."""

    projection = [
        {
            "artifact_id": artifact.artifact_id,
            "kind": artifact.kind,
            "path": artifact.path,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
        }
        for artifact in sorted(artifacts, key=lambda item: item.artifact_id)
        if artifact.kind in _PAYLOAD_KINDS
    ]
    if {item["kind"] for item in projection} != _PAYLOAD_KINDS:
        raise ApplianceManifestError("payload artifact set is incomplete")
    return f"sha256:{hashlib.sha256(rfc8785.dumps(projection)).hexdigest()}"


def verify_artifacts(
    release_root: Path,
    manifest: ApplianceReleaseManifest,
) -> dict[ArtifactKind, bytes]:
    """Verify every declared artifact and return payloads keyed by kind."""

    payloads: dict[ArtifactKind, bytes] = {}
    for artifact in manifest.artifacts:
        payload = read_release_artifact(release_root, artifact.path)
        actual_digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        if actual_digest != artifact.sha256 or len(payload) != artifact.size_bytes:
            raise ApplianceManifestError(
                f"release artifact digest mismatch: {artifact.artifact_id}"
            )
        payloads[artifact.kind] = payload
    if compute_payload_digest(manifest.artifacts) != manifest.payload_digest:
        raise ApplianceManifestError("release payload digest mismatch")
    return payloads


def _parse_evidence(
    payloads: dict[ArtifactKind, bytes],
) -> tuple[
    ParticipantProfileManifest,
    ParticipantReadinessSuite,
    ParticipantAssetLock,
    ParticipantQualificationReport,
    ApplianceDrillReport,
]:
    """Parse every release evidence record through its closed schema."""

    try:
        profile = ParticipantProfileManifest.model_validate_json(
            payloads["participant-profile"]
        )
        readiness = ParticipantReadinessSuite.model_validate_json(
            payloads["participant-readiness"]
        )
        asset_lock = ParticipantAssetLock.model_validate_json(
            payloads["participant-asset-lock"]
        )
        qualification = ParticipantQualificationReport.model_validate_json(
            payloads["participant-qualification"]
        )
        ApplianceBoundaryPolicy.model_validate_json(payloads["boundary-policy"])
        GoldenImageInventory.model_validate_json(payloads["golden-inventory"])
        drill = ApplianceDrillReport.model_validate_json(payloads["machine-drill"])
    except ValueError as exc:
        raise ApplianceManifestError("invalid appliance release evidence") from exc
    return profile, readiness, asset_lock, qualification, drill


def _participant_binding_matches(
    manifest: ApplianceReleaseManifest,
    payloads: dict[ArtifactKind, bytes],
    profile: ParticipantProfileManifest,
    asset_lock: ParticipantAssetLock,
    qualification: ParticipantQualificationReport,
) -> bool:
    """Check the exact APP-2 profile, readiness, lock, and report identities."""

    profile_digest = hashlib.sha256(payloads["participant-profile"]).hexdigest()
    readiness_digest = hashlib.sha256(payloads["participant-readiness"]).hexdigest()
    asset_lock_digest = hashlib.sha256(payloads["participant-asset-lock"]).hexdigest()
    actual = (
        profile.profile_id,
        profile.version,
        profile.readiness.sha256,
        manifest.participant.readiness_suite_digest,
        asset_lock.profile_id,
        asset_lock.profile_version,
        profile.release_evidence.asset_lock_sha256,
        qualification.profile_id,
        qualification.profile_version,
        qualification.profile_sha256,
        qualification.asset_lock_digest,
    )
    expected = (
        manifest.participant.profile_id,
        manifest.participant.profile_version,
        readiness_digest,
        f"sha256:{readiness_digest}",
        profile.profile_id,
        profile.version,
        asset_lock_digest,
        profile.profile_id,
        profile.version,
        profile_digest,
        f"sha256:{asset_lock_digest}",
    )
    return actual == expected


def _qualification_surface_matches(
    profile: ParticipantProfileManifest,
    readiness: ParticipantReadinessSuite,
    qualification: ParticipantQualificationReport,
) -> bool:
    """Check all required readiness checks and realized participant surfaces."""

    required_checks = {check.check_id for check in readiness.checks}
    expected_workbenches = {
        profile_id.value for profile_id in profile.capabilities.workbench_profiles
    }
    expected_mcp = {
        check.subject_id for check in readiness.checks if check.kind == "mcp-tool"
    }
    expected_browser = {
        check.subject_id
        for check in readiness.checks
        if check.kind == "browser-operation"
    }
    surface = qualification.surface
    actual = (
        {check.check_id for check in qualification.checks},
        all(check.status == "passed" for check in qualification.checks),
        set(surface.actual_workbench_profiles),
        set(surface.actual_mcp_servers),
        set(surface.actual_browser_capabilities),
        set(surface.actual_services),
        set(surface.actual_networks),
    )
    expected = (
        required_checks,
        True,
        expected_workbenches,
        expected_mcp,
        expected_browser,
        set(surface.expected_services),
        set(surface.expected_networks),
    )
    return actual == expected


def _offline_evidence_passed(qualification: ParticipantQualificationReport) -> bool:
    """Require the qualification run to prove a closed offline execution."""

    offline = qualification.offline
    return (
        offline.egress_denied,
        offline.download_attempts,
        offline.image_pulls,
        offline.image_builds,
        offline.package_resolutions,
    ) == (
        True,
        0,
        0,
        0,
        0,
    )


def verify_release_evidence(
    manifest: ApplianceReleaseManifest,
    payloads: dict[ArtifactKind, bytes],
) -> None:
    """Verify APP-1, APP-2, golden-state, and machine-drill evidence."""

    profile, readiness, asset_lock, qualification, drill = _parse_evidence(payloads)
    passed = (
        _participant_binding_matches(
            manifest,
            payloads,
            profile,
            asset_lock,
            qualification,
        )
        and _qualification_surface_matches(profile, readiness, qualification)
        and _offline_evidence_passed(qualification)
    )
    if not passed:
        raise ApplianceManifestError(
            "participant qualification evidence does not match the release"
        )
    if drill != manifest.qualification:
        raise ApplianceManifestError("machine drill evidence does not match manifest")


def verify_offline_aptl_version(payload: bytes, expected_version: str) -> None:
    """Bind the one staged APTL wheel and release env to the signed version."""

    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            wheels = [
                version
                for member in archive.getmembers()
                if (version := aptl_wheel_version(member.name)) is not None
                and member.isfile()
            ]
            env_member = archive.getmember("appliance-release.env")
            env_file = archive.extractfile(env_member)
            if env_file is None:
                raise KeyError("appliance-release.env")
            env_text = env_file.read().decode("utf-8")
    except (KeyError, OSError, UnicodeDecodeError, tarfile.TarError) as exc:
        raise ApplianceManifestError(
            "offline payload release identity is invalid"
        ) from exc
    version_line = f"APTL_APPLIANCE_VERSION={expected_version}\n"
    if wheels != [expected_version] or version_line not in env_text.splitlines(
        keepends=True
    ):
        raise ApplianceManifestError(
            "offline payload APTL version does not match the release"
        )
