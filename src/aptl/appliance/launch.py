"""Verified create-once launch projection for appliance first boot."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import rfc8785
from pydantic import ValidationError

from aptl.appliance.manifest import (
    ApplianceManifestError,
    ApplianceReleaseInspection,
    _inspection,
    _load_release_documents,
    _read_external_file,
    _read_release_artifact,
    _write_create_once,
    verify_release_directory,
    verify_release_metadata,
)
from aptl.appliance.models import ApplianceReleaseManifest
from aptl.appliance.release_models import ApplianceLaunchDescriptor
from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
from aptl.utils.strict_json import model_validate_json_strict
from aptl.validation.participant_qualification_evidence import (
    ParticipantQualificationReport,
    verify_participant_qualification_attestation,
)


@dataclass(frozen=True)
class VerifiedApplianceLaunch:
    """Authenticated runtime inputs consumed before scenario realization."""

    descriptor: ApplianceLaunchDescriptor
    release_root: Path
    boundary_policy: ApplianceBoundaryPolicy


def canonical_launch_bytes(descriptor: ApplianceLaunchDescriptor) -> bytes:
    """Return deterministic bytes for one verified launch projection."""

    return rfc8785.dumps(descriptor.model_dump(mode="json"))


def _derive_descriptor(
    manifest: ApplianceReleaseManifest,
    inspection: ApplianceReleaseInspection,
    *,
    release_dir: str,
    host_observation_id: str,
) -> ApplianceLaunchDescriptor:
    """Project signed release and host identities into a launch descriptor."""

    by_kind = {artifact.kind: artifact for artifact in manifest.artifacts}
    return ApplianceLaunchDescriptor(
        schema_version="aptl.appliance-launch/v1",
        release_dir=release_dir,
        release_id=manifest.release_id,
        aptl_version=manifest.source.aptl_version,
        manifest_digest=inspection.manifest_digest,
        payload_digest=manifest.payload_digest,
        golden_image_digest=by_kind["golden-disk"].sha256,
        boundary_policy_path=by_kind["boundary-policy"].path,
        boundary_policy_digest=manifest.boundary.policy_digest,
        boundary_helper_image=manifest.boundary.boundary_helper_image,
        egress_proxy_image=manifest.boundary.egress_proxy_image,
        participant_routes_digest=manifest.delivery.participant_routes_digest,
        canonical_inputs_digest=manifest.delivery.canonical_inputs_digest,
        host_mcp_contract=manifest.delivery.host_mcp_contract,
        host_observation_id=host_observation_id,
    )


def prepare_launch_descriptor(
    release_dir: Path,
    release_public_key_path: Path,
    qualification_public_key_path: Path,
    output_path: Path,
    *,
    host_observation_id: str,
) -> ApplianceLaunchDescriptor:
    """Verify a release and atomically publish its runtime launch projection."""

    inspection = verify_release_directory(
        release_dir,
        release_public_key_path,
        qualification_public_key_path=qualification_public_key_path,
    )
    manifest, _ = _load_release_documents(release_dir.resolve())
    return _prepare_verified_launch_descriptor(
        release_dir,
        output_path,
        manifest,
        inspection,
        host_observation_id=host_observation_id,
    )


def _prepare_verified_launch_descriptor(
    release_dir: Path,
    output_path: Path,
    manifest: ApplianceReleaseManifest,
    inspection: ApplianceReleaseInspection,
    *,
    host_observation_id: str,
) -> ApplianceLaunchDescriptor:
    """Project a release fully verified by the current host staging operation."""

    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_parent = output_path.parent.resolve()
    release_root = release_dir.resolve()
    try:
        release_relative = release_root.relative_to(output_parent).as_posix()
    except ValueError as exc:
        raise ApplianceManifestError(
            "launch release directory must be beneath the descriptor directory"
        ) from exc
    descriptor = _derive_descriptor(
        manifest,
        inspection,
        release_dir=release_relative,
        host_observation_id=host_observation_id,
    )
    _write_create_once(output_path, canonical_launch_bytes(descriptor), mode=0o444)
    return descriptor


def verify_launch_descriptor(
    descriptor_path: Path,
    release_public_key_path: Path,
    qualification_public_key_path: Path,
) -> VerifiedApplianceLaunch:
    """Authenticate the guest launch after full release admission on the host.

    The host verifies every artifact before VM launch. The guest checks the
    signed metadata, qualification attestation, and consumed boundary policy
    without re-extracting the large payload over the read-only 9p share.
    """

    try:
        descriptor = model_validate_json_strict(
            ApplianceLaunchDescriptor,
            _read_external_file(descriptor_path, label="appliance launch descriptor"),
        )
    except (ValidationError, ValueError) as exc:
        raise ApplianceManifestError("invalid appliance launch descriptor") from exc
    launch_root = descriptor_path.parent.resolve()
    release_root = (launch_root / descriptor.release_dir).resolve()
    if not release_root.is_relative_to(launch_root):
        raise ApplianceManifestError("appliance launch release path is unsafe")
    manifest = verify_release_metadata(release_root, release_public_key_path)
    inspection = _inspection(manifest)
    qualification_artifact = next(
        artifact
        for artifact in manifest.artifacts
        if artifact.kind == "participant-qualification"
    )
    qualification_payload = _read_release_artifact(
        release_root, qualification_artifact.path
    )
    if (
        len(qualification_payload) != qualification_artifact.size_bytes
        or f"sha256:{hashlib.sha256(qualification_payload).hexdigest()}"
        != qualification_artifact.sha256
    ):
        raise ApplianceManifestError("launch qualification artifact differs")
    try:
        qualification = model_validate_json_strict(
            ParticipantQualificationReport, qualification_payload
        )
        verify_participant_qualification_attestation(
            qualification,
            _read_external_file(
                qualification_public_key_path,
                label="participant qualification trust anchor",
            ),
        )
    except ValueError as exc:
        raise ApplianceManifestError(
            "launch qualification attestation is invalid"
        ) from exc
    expected = _derive_descriptor(
        manifest,
        inspection,
        release_dir=descriptor.release_dir,
        host_observation_id=descriptor.host_observation_id,
    )
    if descriptor != expected:
        raise ApplianceManifestError(
            "appliance launch descriptor does not match the verified release"
        )
    policy_payload = _read_release_artifact(
        release_root,
        descriptor.boundary_policy_path,
    )
    if (
        f"sha256:{hashlib.sha256(policy_payload).hexdigest()}"
        != descriptor.boundary_policy_digest
    ):
        raise ApplianceManifestError(
            "appliance launch boundary policy does not match the release"
        )
    try:
        policy = model_validate_json_strict(ApplianceBoundaryPolicy, policy_payload)
    except ValueError as exc:
        raise ApplianceManifestError(
            "appliance launch boundary policy is invalid"
        ) from exc
    if policy.host_mcp_contract != descriptor.host_mcp_contract:
        raise ApplianceManifestError(
            "launch transport policy differs from signed release"
        )
    return VerifiedApplianceLaunch(descriptor, release_root, policy)
