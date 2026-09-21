"""Development-only signed candidate trust path for real KVM qualification."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import Field, model_validator

from aptl.appliance.build import GoldenImageBuildRequest
from aptl.appliance.errors import ApplianceManifestError
from aptl.appliance.manifest import (
    ApplianceReleaseInspection,
    _public_key_id,
    _read_external_file,
    _read_release_artifact,
    _write_create_once,
    describe_artifact,
)
from aptl.appliance.models import (
    ApplianceBoundaryReleaseBinding,
    CandidateSource,
    ApplianceGuest,
    ApplianceManifestSignature,
    ArtifactReference,
    DeliveryParity,
    GoldenImageInventory,
    HostPrerequisites,
    ReleaseSource,
    _StrictModel,
)
from aptl.appliance.release_models import (
    ApplianceLaunchDescriptor,
    BoundaryTemplateBinding,
    ParticipantTemplateBinding,
    StagedArtifact,
)
from aptl.appliance.release_validation import (
    StreamedArtifact,
    read_release_artifact,
    release_artifact_identity,
    validate_canonical_payload,
    verify_offline_aptl_version,
)
from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
from aptl.utils.strict_json import model_validate_json_strict

CANDIDATE_MANIFEST = "candidate-manifest.json"
CANDIDATE_SIGNATURE = "candidate-manifest.sig.json"
_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_CANDIDATE_KINDS = frozenset(
    {
        "canonical-inputs",
        "golden-build-request",
        "golden-provisioner",
        "golden-scanner",
        "golden-disk",
        "offline-payload",
        "participant-profile",
        "participant-readiness",
        "participant-asset-lock",
        "boundary-policy",
        "golden-inventory",
    }
)


class ApplianceCandidateTemplate(_StrictModel):
    """Human-authored inputs for a candidate that cannot be published."""

    schema_version: Literal["aptl.appliance-candidate-template/v1"]
    candidate_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    source: ReleaseSource | CandidateSource
    guest: ApplianceGuest
    artifacts: tuple[StagedArtifact, ...]
    participant: ParticipantTemplateBinding
    boundary: BoundaryTemplateBinding
    host_prerequisites: HostPrerequisites
    delivery: DeliveryParity
    build_request_digest: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def complete_candidate(self) -> Self:
        kinds = [item.kind for item in self.artifacts]
        paths = [item.path for item in self.artifacts]
        if (
            set(kinds) != _CANDIDATE_KINDS
            or len(kinds) != len(set(kinds))
            or len(paths) != len(set(paths))
        ):
            raise ValueError("candidate artifact set is incomplete or ambiguous")
        if self.delivery.canonical_inputs_digest is None:
            raise ValueError("candidate requires canonical full-TechVault inputs")
        return self


class ApplianceCandidateManifest(_StrictModel):
    """Signed exact bytes admitted only by the qualification launcher."""

    schema_version: Literal["aptl.appliance-candidate/v1"]
    candidate_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    source: ReleaseSource | CandidateSource
    guest: ApplianceGuest
    artifacts: tuple[ArtifactReference, ...]
    payload_digest: str = Field(pattern=_SHA256_PATTERN)
    participant: ParticipantTemplateBinding
    boundary: ApplianceBoundaryReleaseBinding
    host_prerequisites: HostPrerequisites
    delivery: DeliveryParity
    build_request_digest: str = Field(pattern=_SHA256_PATTERN)
    trust_mode: Literal["qualification-only"]

    @model_validator(mode="after")
    def never_release_shaped(self) -> Self:
        kinds = [item.kind for item in self.artifacts]
        if set(kinds) != _CANDIDATE_KINDS or len(kinds) != len(set(kinds)):
            raise ValueError("candidate artifact set is invalid")
        return self


@dataclass(frozen=True)
class VerifiedCandidateLaunch:
    """Verified qualification-only launch material and its signed policy."""

    descriptor: ApplianceLaunchDescriptor
    release_root: Path
    boundary_policy: ApplianceBoundaryPolicy


def _candidate_payload_digest(artifacts: tuple[ArtifactReference, ...]) -> str:
    """Digest the canonical ordered candidate artifact projection."""

    projection = [
        item.model_dump(mode="json")
        for item in sorted(artifacts, key=lambda value: value.artifact_id)
    ]
    return f"sha256:{hashlib.sha256(rfc8785.dumps(projection)).hexdigest()}"


def _canonical_candidate_bytes(manifest: ApplianceCandidateManifest) -> bytes:
    """Serialize a candidate manifest to its signed canonical bytes."""

    return rfc8785.dumps(manifest.model_dump(mode="json"))


def prepare_candidate_manifest(
    candidate_dir: Path, template_path: Path
) -> ApplianceCandidateManifest:
    """Derive a candidate manifest without accepting qualification evidence."""

    root = candidate_dir.resolve(strict=True)
    try:
        template = model_validate_json_strict(
            ApplianceCandidateTemplate,
            _read_external_file(template_path, label="candidate template"),
        )
    except ValueError as exc:
        raise ApplianceManifestError("invalid appliance candidate template") from exc
    artifacts = tuple(
        describe_artifact(
            root,
            artifact_id=item.artifact_id,
            kind=item.kind,
            path=item.path,
        )
        for item in template.artifacts
    )
    by_kind = {item.kind: item for item in artifacts}
    if by_kind["canonical-inputs"].sha256 != template.delivery.canonical_inputs_digest:
        raise ApplianceManifestError("candidate canonical input digest mismatch")
    manifest = ApplianceCandidateManifest(
        schema_version="aptl.appliance-candidate/v1",
        candidate_id=template.candidate_id,
        source=template.source,
        guest=template.guest,
        artifacts=artifacts,
        payload_digest=_candidate_payload_digest(artifacts),
        participant=template.participant,
        boundary=ApplianceBoundaryReleaseBinding(
            policy_digest=by_kind["boundary-policy"].sha256,
            boundary_helper_image=template.boundary.boundary_helper_image,
            egress_proxy_image=template.boundary.egress_proxy_image,
        ),
        host_prerequisites=template.host_prerequisites,
        delivery=template.delivery,
        build_request_digest=template.build_request_digest,
        trust_mode="qualification-only",
    )
    _validate_candidate(root, manifest)
    _write_create_once(
        root / CANDIDATE_MANIFEST,
        _canonical_candidate_bytes(manifest),
        mode=0o444,
    )
    return manifest


def _validate_candidate(root: Path, manifest: ApplianceCandidateManifest) -> None:
    """Validate candidate bytes, build provenance, policy, and offline closure."""

    payloads: dict[str, bytes] = {}
    for artifact in manifest.artifacts:
        digest, size, pinned = release_artifact_identity(root, artifact.path)
        if digest != artifact.sha256 or size != artifact.size_bytes:
            raise ApplianceManifestError("candidate artifact digest mismatch")
        if artifact.kind not in {"golden-disk", "offline-payload"}:
            with pinned.open() as handle:
                payloads[artifact.kind] = handle.read()
    if _candidate_payload_digest(manifest.artifacts) != manifest.payload_digest:
        raise ApplianceManifestError("candidate payload digest mismatch")
    try:
        policy = model_validate_json_strict(
            ApplianceBoundaryPolicy, payloads["boundary-policy"]
        )
        inventory = model_validate_json_strict(
            GoldenImageInventory, payloads["golden-inventory"]
        )
        build_request = model_validate_json_strict(
            GoldenImageBuildRequest, payloads["golden-build-request"]
        )
    except ValueError as exc:
        raise ApplianceManifestError("candidate evidence is invalid") from exc
    if (
        policy.host_mcp_contract != manifest.delivery.host_mcp_contract
        or inventory.populated_sensitive_paths
        or inventory.writable_runtime_paths
    ):
        raise ApplianceManifestError("candidate boundary or golden state is invalid")
    by_kind = {item.kind: item for item in manifest.artifacts}
    if (
        by_kind["golden-build-request"].sha256 != manifest.build_request_digest
        or build_request.base_image_digest != manifest.guest.base_image_digest
        or build_request.offline_payload_digest != by_kind["offline-payload"].sha256
        or build_request.provisioner_digest != by_kind["golden-provisioner"].sha256
        or build_request.scanner_digest != by_kind["golden-scanner"].sha256
        or Path(build_request.output_image_path).name
        != Path(by_kind["golden-disk"].path).name
        or Path(build_request.inventory_output_path).name
        != Path(by_kind["golden-inventory"].path).name
    ):
        raise ApplianceManifestError("candidate build provenance is inconsistent")
    verify_offline_aptl_version(
        _streamed(root, manifest, "offline-payload"),
        manifest.source.aptl_version,
    )
    validate_canonical_payload(
        _streamed(root, manifest, "offline-payload"),
        payloads["canonical-inputs"],
    )


def _streamed(
    root: Path, manifest: ApplianceCandidateManifest, kind: str
) -> StreamedArtifact:
    """Return a pinned streamed candidate artifact by kind."""

    artifact = next(item for item in manifest.artifacts if item.kind == kind)
    return release_artifact_identity(root, artifact.path)[2]


def seal_candidate(
    candidate_dir: Path, private_key_path: Path
) -> ApplianceManifestSignature:
    """Sign a validated candidate with a development-only external key."""

    root = candidate_dir.resolve(strict=True)
    manifest = model_validate_json_strict(
        ApplianceCandidateManifest,
        read_release_artifact(root, CANDIDATE_MANIFEST),
    )
    _validate_candidate(root, manifest)
    try:
        key = serialization.load_pem_private_key(
            _read_external_file(private_key_path, label="candidate signing key"),
            password=None,
        )
    except (TypeError, ValueError) as exc:
        raise ApplianceManifestError("candidate signing key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ApplianceManifestError("candidate signing key must be Ed25519")
    payload = _canonical_candidate_bytes(manifest)
    signature = ApplianceManifestSignature(
        schema_version="aptl.appliance-signature/v1",
        algorithm="ed25519",
        key_id=_public_key_id(key.public_key()),
        manifest_digest=f"sha256:{hashlib.sha256(payload).hexdigest()}",
        signature=base64.b64encode(key.sign(payload)).decode("ascii"),
    )
    _write_create_once(
        root / CANDIDATE_SIGNATURE,
        rfc8785.dumps(signature.model_dump(mode="json")),
        mode=0o444,
    )
    return signature


def verify_candidate_directory(
    candidate_dir: Path, public_key_path: Path
) -> tuple[ApplianceCandidateManifest, ApplianceReleaseInspection]:
    """Verify the complete candidate, including the offline payload closure."""

    root = candidate_dir.resolve(strict=True)
    manifest, inspection = _verify_candidate_metadata(root, public_key_path)
    _validate_candidate(root, manifest)
    return manifest, inspection


def _verify_candidate_metadata(
    root: Path, public_key_path: Path
) -> tuple[ApplianceCandidateManifest, ApplianceReleaseInspection]:
    """Authenticate the signed candidate identity without reading large artifacts."""

    manifest = model_validate_json_strict(
        ApplianceCandidateManifest,
        read_release_artifact(root, CANDIDATE_MANIFEST),
    )
    signature = model_validate_json_strict(
        ApplianceManifestSignature,
        read_release_artifact(root, CANDIDATE_SIGNATURE),
    )
    try:
        key = serialization.load_pem_public_key(
            _read_external_file(public_key_path, label="candidate trust anchor")
        )
    except (TypeError, ValueError) as exc:
        raise ApplianceManifestError("candidate trust anchor is invalid") from exc
    if not isinstance(key, Ed25519PublicKey) or signature.key_id != _public_key_id(key):
        raise ApplianceManifestError("candidate trust anchor is invalid")
    payload = _canonical_candidate_bytes(manifest)
    if signature.manifest_digest != f"sha256:{hashlib.sha256(payload).hexdigest()}":
        raise ApplianceManifestError("candidate signature digest mismatch")
    try:
        key.verify(base64.b64decode(signature.signature, validate=True), payload)
    except (InvalidSignature, ValueError) as exc:
        raise ApplianceManifestError("candidate signature is invalid") from exc
    return manifest, ApplianceReleaseInspection(
        release_id=manifest.candidate_id,
        aptl_version=manifest.source.aptl_version,
        source_commit=manifest.source.source_commit,
        manifest_digest=signature.manifest_digest,
        payload_digest=manifest.payload_digest,
        artifact_count=len(manifest.artifacts),
        architecture=manifest.guest.architecture,
        minimum_host_vcpus=manifest.host_prerequisites.vcpus,
        minimum_host_memory_bytes=manifest.host_prerequisites.memory_bytes,
        minimum_host_disk_bytes=manifest.host_prerequisites.disk_bytes,
    )


def prepare_candidate_launch_descriptor(
    candidate_dir: Path,
    public_key_path: Path,
    output_path: Path,
    *,
    host_observation_id: str,
) -> ApplianceLaunchDescriptor:
    """Create a launch projection visibly tied to candidate trust."""

    manifest, inspection = verify_candidate_directory(candidate_dir, public_key_path)
    return _prepare_verified_candidate_launch_descriptor(
        candidate_dir,
        output_path,
        manifest,
        inspection,
        host_observation_id=host_observation_id,
    )


def _prepare_verified_candidate_launch_descriptor(
    candidate_dir: Path,
    output_path: Path,
    manifest: ApplianceCandidateManifest,
    inspection: ApplianceReleaseInspection,
    *,
    host_observation_id: str,
) -> ApplianceLaunchDescriptor:
    """Project a candidate fully verified by the current host staging operation."""

    root = candidate_dir.resolve()
    output_parent = output_path.parent.resolve()
    try:
        relative = root.relative_to(output_parent).as_posix()
    except ValueError as exc:
        raise ApplianceManifestError(
            "candidate must be beneath launch directory"
        ) from exc
    by_kind = {item.kind: item for item in manifest.artifacts}
    descriptor = ApplianceLaunchDescriptor(
        schema_version="aptl.appliance-launch/v1",
        release_dir=relative,
        release_id=manifest.candidate_id,
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
    _write_create_once(
        output_path, rfc8785.dumps(descriptor.model_dump(mode="json")), mode=0o444
    )
    return descriptor


def verify_candidate_launch_descriptor(
    descriptor_path: Path, public_key_path: Path
) -> VerifiedCandidateLaunch:
    """Verify the signed guest launch projection after full host admission.

    The host already verified every large artifact before starting this VM.
    The guest authenticates the manifest and its consumed boundary policy; it
    does not re-extract the offline payload over the read-only 9p share.
    """

    descriptor = model_validate_json_strict(
        ApplianceLaunchDescriptor,
        _read_external_file(descriptor_path, label="candidate launch descriptor"),
    )
    root = (descriptor_path.parent.resolve() / descriptor.release_dir).resolve()
    if not root.is_relative_to(descriptor_path.parent.resolve()):
        raise ApplianceManifestError("candidate launch path is unsafe")
    manifest, inspection = _verify_candidate_metadata(root, public_key_path)
    by_kind = {item.kind: item for item in manifest.artifacts}
    expected = descriptor.model_copy(
        update={
            "release_id": manifest.candidate_id,
            "aptl_version": manifest.source.aptl_version,
            "manifest_digest": inspection.manifest_digest,
            "payload_digest": manifest.payload_digest,
            "golden_image_digest": by_kind["golden-disk"].sha256,
            "boundary_policy_path": by_kind["boundary-policy"].path,
            "boundary_policy_digest": manifest.boundary.policy_digest,
            "boundary_helper_image": manifest.boundary.boundary_helper_image,
            "egress_proxy_image": manifest.boundary.egress_proxy_image,
            "participant_routes_digest": manifest.delivery.participant_routes_digest,
            "canonical_inputs_digest": manifest.delivery.canonical_inputs_digest,
            "host_mcp_contract": manifest.delivery.host_mcp_contract,
        }
    )
    if descriptor != expected:
        raise ApplianceManifestError(
            "candidate launch descriptor differs from manifest"
        )
    policy_payload = _read_release_artifact(root, descriptor.boundary_policy_path)
    if (
        f"sha256:{hashlib.sha256(policy_payload).hexdigest()}"
        != manifest.boundary.policy_digest
    ):
        raise ApplianceManifestError("candidate launch boundary policy differs")
    policy = model_validate_json_strict(ApplianceBoundaryPolicy, policy_payload)
    if policy.host_mcp_contract != descriptor.host_mcp_contract:
        raise ApplianceManifestError("candidate launch transport policy differs")
    return VerifiedCandidateLaunch(descriptor, root, policy)
