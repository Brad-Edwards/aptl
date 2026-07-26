"""Canonical serialization and Ed25519 verification for appliance releases."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

import rfc8785
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aptl.appliance.errors import ApplianceManifestError
from aptl.appliance.models import (
    ApplianceBoundaryReleaseBinding,
    ApplianceDrillReport,
    ApplianceManifestSignature,
    ApplianceReleaseManifest,
    ApplianceReleaseTemplate,
    ArtifactKind,
    ArtifactReference,
    ParticipantReleaseBinding,
)
from aptl.appliance.release_validation import (
    compute_payload_digest,
    read_release_artifact as _read_release_artifact,
    verify_artifacts as _verify_artifacts,
    verify_offline_aptl_version as _verify_offline_aptl_version,
    verify_release_evidence as _verify_release_evidence,
)
from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
from aptl.validation.participant_qualification_evidence import (
    ParticipantQualificationReport,
    verify_participant_qualification_attestation,
)

_MANIFEST_NAME = "manifest.json"
_SIGNATURE_NAME = "manifest.sig.json"
_MISSING_RELEASE = "appliance release directory is missing"


@dataclass(frozen=True)
class ApplianceReleaseInspection:
    """Safe host/readiness projection from a fully verified release."""

    release_id: str
    aptl_version: str
    source_commit: str
    manifest_digest: str
    payload_digest: str
    artifact_count: int
    architecture: str
    minimum_host_vcpus: int
    minimum_host_memory_bytes: int
    minimum_host_disk_bytes: int


def canonical_manifest_bytes(manifest: ApplianceReleaseManifest) -> bytes:
    """Return RFC 8785 bytes for the closed release manifest."""

    return rfc8785.dumps(manifest.model_dump(mode="json"))


def describe_artifact(
    root: Path,
    *,
    artifact_id: str,
    kind: ArtifactKind,
    path: str,
) -> ArtifactReference:
    """Read one contained input once and return its exact release identity."""

    payload = _read_release_artifact(root.resolve(), path)
    if not payload:
        raise ApplianceManifestError(f"release artifact is empty: {path}")
    return ArtifactReference(
        artifact_id=artifact_id,
        kind=kind,
        path=path,
        sha256=f"sha256:{hashlib.sha256(payload).hexdigest()}",
        size_bytes=len(payload),
    )


def _read_external_file(path: Path, *, label: str) -> bytes:
    """Read an external trust input without following its final symlink."""

    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise ApplianceManifestError(f"{label} is unavailable") from exc


def _public_key_id(key: Ed25519PublicKey) -> str:
    """Return the stable SHA-256 identity of an Ed25519 public key."""

    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"sha256:{hashlib.sha256(der).hexdigest()}"


def sign_manifest(
    manifest: ApplianceReleaseManifest,
    private_key_pem: bytes,
) -> ApplianceManifestSignature:
    """Sign canonical manifest bytes without persisting private key material."""

    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ApplianceManifestError("release signing key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ApplianceManifestError("release signing key must be Ed25519")
    payload = canonical_manifest_bytes(manifest)
    return ApplianceManifestSignature(
        schema_version="aptl.appliance-signature/v1",
        algorithm="ed25519",
        key_id=_public_key_id(key.public_key()),
        manifest_digest=f"sha256:{hashlib.sha256(payload).hexdigest()}",
        signature=base64.b64encode(key.sign(payload)).decode("ascii"),
    )


def verify_manifest_signature(
    manifest: ApplianceReleaseManifest,
    signature: ApplianceManifestSignature,
    public_key_pem: bytes,
) -> None:
    """Verify the manifest against a separately configured trust anchor."""

    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ApplianceManifestError("release trust anchor is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ApplianceManifestError("release trust anchor must be Ed25519")
    if signature.key_id != _public_key_id(key):
        raise ApplianceManifestError(
            "release signature does not match the trust anchor"
        )
    payload = canonical_manifest_bytes(manifest)
    digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
    if signature.manifest_digest != digest:
        raise ApplianceManifestError("release manifest signature digest mismatch")
    try:
        raw_signature = base64.b64decode(signature.signature, validate=True)
        key.verify(raw_signature, payload)
    except (InvalidSignature, ValueError) as exc:
        raise ApplianceManifestError("release manifest signature is invalid") from exc


def _load_release_documents(
    release_root: Path,
) -> tuple[ApplianceReleaseManifest, ApplianceManifestSignature]:
    """Parse the canonical manifest and detached signature documents."""

    manifest_bytes = _read_release_artifact(release_root, _MANIFEST_NAME)
    signature_bytes = _read_release_artifact(release_root, _SIGNATURE_NAME)
    try:
        manifest = ApplianceReleaseManifest.model_validate_json(manifest_bytes)
        signature = ApplianceManifestSignature.model_validate_json(signature_bytes)
    except ValueError as exc:
        raise ApplianceManifestError("invalid appliance release document") from exc
    return manifest, signature


def prepare_release_manifest(
    release_dir: Path,
    template_path: Path,
) -> ApplianceReleaseManifest:
    """Derive every content identity from staged bytes and write canonically."""

    release_root = release_dir.resolve()
    if not release_root.is_dir():
        raise ApplianceManifestError(_MISSING_RELEASE)
    try:
        resolved_template = template_path.resolve(strict=True)
    except OSError as exc:
        raise ApplianceManifestError("release template is unavailable") from exc
    if resolved_template.is_relative_to(release_root):
        raise ApplianceManifestError(
            "release template must remain outside the release directory"
        )
    try:
        template = ApplianceReleaseTemplate.model_validate_json(
            _read_external_file(resolved_template, label="release template")
        )
    except ValueError as exc:
        raise ApplianceManifestError("invalid appliance release template") from exc
    artifacts = tuple(
        describe_artifact(
            release_root,
            artifact_id=staged.artifact_id,
            kind=staged.kind,
            path=staged.path,
        )
        for staged in template.artifacts
    )
    by_kind = {artifact.kind: artifact for artifact in artifacts}
    try:
        qualification = ApplianceDrillReport.model_validate_json(
            _read_release_artifact(
                release_root,
                by_kind["machine-drill"].path,
            )
        )
    except ValueError as exc:
        raise ApplianceManifestError("invalid appliance release evidence") from exc
    manifest = ApplianceReleaseManifest(
        schema_version="aptl.appliance-release/v1",
        release_id=template.release_id,
        source=template.source,
        guest=template.guest,
        artifacts=artifacts,
        payload_digest=compute_payload_digest(artifacts),
        participant=ParticipantReleaseBinding(
            profile_id=template.participant.profile_id,
            profile_version=template.participant.profile_version,
            profile_manifest_digest=by_kind["participant-profile"].sha256,
            readiness_suite_digest=by_kind["participant-readiness"].sha256,
            asset_lock_digest=by_kind["participant-asset-lock"].sha256,
            qualification_report_digest=by_kind["participant-qualification"].sha256,
        ),
        boundary=ApplianceBoundaryReleaseBinding(
            policy_digest=by_kind["boundary-policy"].sha256,
            boundary_helper_image=template.boundary.boundary_helper_image,
            egress_proxy_image=template.boundary.egress_proxy_image,
        ),
        host_prerequisites=template.host_prerequisites,
        delivery=template.delivery,
        qualification=qualification,
        upgrade_strategy=template.upgrade_strategy,
    )
    payloads = _verify_artifacts(release_root, manifest)
    _verify_offline_aptl_version(
        payloads["offline-payload"],
        manifest.source.aptl_version,
    )
    _verify_release_evidence(manifest, payloads)
    manifest_bytes = canonical_manifest_bytes(manifest)
    manifest_path = release_root / _MANIFEST_NAME
    if manifest_path.exists() or manifest_path.is_symlink():
        existing = _read_release_artifact(release_root, _MANIFEST_NAME)
        if existing != manifest_bytes:
            raise ApplianceManifestError(
                "release manifest already exists with different content"
            )
    else:
        _write_create_once(manifest_path, manifest_bytes, mode=0o644)
    return manifest


def _release_checksum_payload(
    release_root: Path,
    manifest: ApplianceReleaseManifest,
    *,
    signature_bytes: bytes | None = None,
) -> bytes:
    """Render the deterministic checksum file, optionally before sealing."""

    paths = [_MANIFEST_NAME, _SIGNATURE_NAME] + [
        artifact.path for artifact in manifest.artifacts
    ]
    lines: list[str] = []
    for relative_path in sorted(paths):
        if relative_path == _SIGNATURE_NAME and signature_bytes is not None:
            payload = signature_bytes
        else:
            payload = _read_release_artifact(release_root, relative_path)
        lines.append(f"{hashlib.sha256(payload).hexdigest()}  {relative_path}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _write_create_once(path: Path, payload: bytes, *, mode: int) -> None:
    """Persist immutable release bytes without replacing an existing path."""

    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(temporary, flags, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode, follow_symlinks=False)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            existing = _read_release_artifact(path.parent, path.name)
            if existing != payload:
                raise ApplianceManifestError(
                    f"release seal artifact already exists: {path.name}"
                ) from exc
    except ApplianceManifestError:
        raise
    except OSError as exc:
        raise ApplianceManifestError("release seal could not be persisted") from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _inspection(manifest: ApplianceReleaseManifest) -> ApplianceReleaseInspection:
    """Project a verified manifest into its safe operator-facing identity."""

    canonical = canonical_manifest_bytes(manifest)
    prerequisites = manifest.host_prerequisites
    return ApplianceReleaseInspection(
        release_id=manifest.release_id,
        aptl_version=manifest.source.aptl_version,
        source_commit=manifest.source.source_commit,
        manifest_digest=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        payload_digest=manifest.payload_digest,
        artifact_count=len(manifest.artifacts),
        architecture=manifest.guest.architecture,
        minimum_host_vcpus=prerequisites.vcpus,
        minimum_host_memory_bytes=prerequisites.memory_bytes,
        minimum_host_disk_bytes=prerequisites.disk_bytes,
    )


def seal_release_directory(
    release_dir: Path,
    private_key_path: Path,
    *,
    qualification_public_key_path: Path,
) -> ApplianceReleaseInspection:
    """Validate and atomically seal a staged release with an external key."""

    release_root = release_dir.resolve()
    if not release_root.is_dir():
        raise ApplianceManifestError(_MISSING_RELEASE)
    try:
        key_path = private_key_path.resolve(strict=True)
    except OSError as exc:
        raise ApplianceManifestError("release signing key is unavailable") from exc
    if key_path.is_relative_to(release_root):
        raise ApplianceManifestError(
            "release signing key must remain outside the release directory"
        )
    try:
        qualification_key_path = qualification_public_key_path.resolve(strict=True)
    except OSError as exc:
        raise ApplianceManifestError(
            "participant qualification trust anchor is unavailable"
        ) from exc
    if qualification_key_path.is_relative_to(release_root):
        raise ApplianceManifestError(
            "participant qualification trust anchor must remain outside the release"
        )
    signature_path = release_root / _SIGNATURE_NAME
    if signature_path.exists() or signature_path.is_symlink():
        raise ApplianceManifestError("appliance release is already sealed")
    manifest_bytes = _read_release_artifact(release_root, _MANIFEST_NAME)
    try:
        manifest = ApplianceReleaseManifest.model_validate_json(manifest_bytes)
    except ValueError as exc:
        raise ApplianceManifestError("invalid appliance release document") from exc
    if manifest_bytes != canonical_manifest_bytes(manifest):
        raise ApplianceManifestError("appliance release manifest is not canonical")
    payloads = _verify_artifacts(release_root, manifest)
    _verify_offline_aptl_version(
        payloads["offline-payload"],
        manifest.source.aptl_version,
    )
    _verify_release_evidence(manifest, payloads)
    try:
        qualification = ParticipantQualificationReport.model_validate_json(
            payloads["participant-qualification"]
        )
        verify_participant_qualification_attestation(
            qualification,
            _read_external_file(
                qualification_key_path,
                label="participant qualification trust anchor",
            ),
        )
    except (OSError, ValueError) as exc:
        raise ApplianceManifestError(
            "participant qualification attestation is invalid"
        ) from exc
    private_key_pem = _read_external_file(key_path, label="release signing key")
    signature = sign_manifest(manifest, private_key_pem)
    signature_bytes = rfc8785.dumps(signature.model_dump(mode="json"))
    checksums = _release_checksum_payload(
        release_root,
        manifest,
        signature_bytes=signature_bytes,
    )
    _write_create_once(release_root / "SHA256SUMS", checksums, mode=0o644)
    _write_create_once(signature_path, signature_bytes, mode=0o644)
    return _inspection(manifest)


def _verify_checksum_file(
    release_root: Path,
    manifest: ApplianceReleaseManifest,
) -> None:
    """Require SHA256SUMS to match the exact sealed release bytes."""

    actual = _read_release_artifact(release_root, "SHA256SUMS")
    expected = _release_checksum_payload(release_root, manifest)
    if actual != expected:
        raise ApplianceManifestError("release checksum file does not match artifacts")


def verify_release_directory(
    release_dir: Path,
    public_key_path: Path,
    *,
    qualification_public_key_path: Path,
) -> ApplianceReleaseInspection:
    """Verify signature, payload, every artifact, and clean-base evidence."""

    release_root = release_dir.resolve()
    if not release_root.is_dir():
        raise ApplianceManifestError(_MISSING_RELEASE)
    public_key_pem = _read_external_file(
        public_key_path,
        label="release trust anchor",
    )
    manifest, signature = _load_release_documents(release_root)
    verify_manifest_signature(manifest, signature, public_key_pem)
    payloads = _verify_artifacts(release_root, manifest)
    _verify_offline_aptl_version(
        payloads["offline-payload"],
        manifest.source.aptl_version,
    )
    _verify_release_evidence(manifest, payloads)
    try:
        qualification = ParticipantQualificationReport.model_validate_json(
            payloads["participant-qualification"]
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
            "participant qualification attestation is invalid"
        ) from exc
    _verify_checksum_file(release_root, manifest)
    return _inspection(manifest)
