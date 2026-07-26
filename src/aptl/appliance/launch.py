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
    _load_release_documents,
    _read_external_file,
    _read_release_artifact,
    _write_create_once,
    verify_release_directory,
)
from aptl.appliance.models import (
    ApplianceLaunchDescriptor,
    ApplianceReleaseManifest,
)
from aptl.core.appliance_boundary import ApplianceBoundaryPolicy


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

    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_parent = output_path.parent.resolve()
    release_root = release_dir.resolve()
    try:
        release_relative = release_root.relative_to(output_parent).as_posix()
    except ValueError as exc:
        raise ApplianceManifestError(
            "launch release directory must be beneath the descriptor directory"
        ) from exc
    inspection = verify_release_directory(
        release_root,
        release_public_key_path,
        qualification_public_key_path=qualification_public_key_path,
    )
    manifest, _ = _load_release_documents(release_root)
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
    """Reverify the attached release and exact launch projection in the guest."""

    try:
        descriptor = ApplianceLaunchDescriptor.model_validate_json(
            _read_external_file(descriptor_path, label="appliance launch descriptor")
        )
    except (ValidationError, ValueError) as exc:
        raise ApplianceManifestError("invalid appliance launch descriptor") from exc
    launch_root = descriptor_path.parent.resolve()
    release_root = (launch_root / descriptor.release_dir).resolve()
    if not release_root.is_relative_to(launch_root):
        raise ApplianceManifestError("appliance launch release path is unsafe")
    inspection = verify_release_directory(
        release_root,
        release_public_key_path,
        qualification_public_key_path=qualification_public_key_path,
    )
    manifest, _ = _load_release_documents(release_root)
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
        policy = ApplianceBoundaryPolicy.model_validate_json(policy_payload)
    except ValueError as exc:
        raise ApplianceManifestError(
            "appliance launch boundary policy is invalid"
        ) from exc
    return VerifiedApplianceLaunch(descriptor, release_root, policy)
