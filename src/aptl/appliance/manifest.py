"""Canonical serialization and Ed25519 verification for appliance releases."""

from __future__ import annotations

import base64
import hashlib
import io
import os
import re
import secrets
import tarfile
from dataclasses import dataclass
from pathlib import Path

import rfc8785
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aptl.appliance.models import (
    ApplianceBoundaryReleaseBinding,
    ApplianceDrillReport,
    ApplianceManifestSignature,
    ApplianceReleaseManifest,
    ApplianceReleaseTemplate,
    ArtifactKind,
    ArtifactReference,
    GoldenImageInventory,
    ParticipantReleaseBinding,
)
from aptl.core.appliance_boundary import ApplianceBoundaryPolicy
from aptl.utils.pathsafe import PathContainmentError, read_contained_nofollow
from aptl.validation.participant_profile_models import (
    ParticipantAssetLock,
    ParticipantProfileManifest,
    ParticipantReadinessSuite,
)
from aptl.validation.participant_qualification_evidence import (
    ParticipantQualificationError,
    ParticipantQualificationReport,
    verify_participant_qualification_attestation,
)


class ApplianceManifestError(ValueError):
    """The appliance manifest or its release signature is invalid."""


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


def _read_release_artifact(root: Path, relative_path: str) -> bytes:
    try:
        return read_contained_nofollow(root, relative_path)
    except (OSError, PathContainmentError, ValueError) as exc:
        raise ApplianceManifestError(
            f"unsafe release artifact: {relative_path}"
        ) from exc


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
    manifest_bytes = _read_release_artifact(release_root, "manifest.json")
    signature_bytes = _read_release_artifact(release_root, "manifest.sig.json")
    try:
        manifest = ApplianceReleaseManifest.model_validate_json(manifest_bytes)
        signature = ApplianceManifestSignature.model_validate_json(signature_bytes)
    except ValueError as exc:
        raise ApplianceManifestError("invalid appliance release document") from exc
    return manifest, signature


def _verify_artifacts(
    release_root: Path,
    manifest: ApplianceReleaseManifest,
) -> dict[ArtifactKind, bytes]:
    payloads: dict[ArtifactKind, bytes] = {}
    for artifact in manifest.artifacts:
        payload = _read_release_artifact(release_root, artifact.path)
        actual_digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
        if actual_digest != artifact.sha256 or len(payload) != artifact.size_bytes:
            raise ApplianceManifestError(
                f"release artifact digest mismatch: {artifact.artifact_id}"
            )
        payloads[artifact.kind] = payload
    if compute_payload_digest(manifest.artifacts) != manifest.payload_digest:
        raise ApplianceManifestError("release payload digest mismatch")
    return payloads


def _verify_release_evidence(
    manifest: ApplianceReleaseManifest,
    payloads: dict[ArtifactKind, bytes],
) -> None:
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
    profile_digest = hashlib.sha256(payloads["participant-profile"]).hexdigest()
    readiness_digest = hashlib.sha256(payloads["participant-readiness"]).hexdigest()
    asset_lock_digest = hashlib.sha256(payloads["participant-asset-lock"]).hexdigest()
    participant_matches = (
        profile.profile_id == manifest.participant.profile_id
        and profile.version == manifest.participant.profile_version
        and profile.readiness.sha256 == readiness_digest
        and manifest.participant.readiness_suite_digest == f"sha256:{readiness_digest}"
        and asset_lock.profile_id == profile.profile_id
        and asset_lock.profile_version == profile.version
        and profile.release_evidence.asset_lock_sha256 == asset_lock_digest
        and qualification.profile_id == profile.profile_id
        and qualification.profile_version == profile.version
        and qualification.profile_sha256 == profile_digest
        and qualification.asset_lock_digest == f"sha256:{asset_lock_digest}"
    )
    offline = qualification.offline
    required_checks = {check.check_id for check in readiness.checks}
    observed_checks = {check.check_id for check in qualification.checks}
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
    qualification_passed = (
        participant_matches
        and observed_checks == required_checks
        and all(check.status == "passed" for check in qualification.checks)
        and set(surface.actual_workbench_profiles) == expected_workbenches
        and set(surface.actual_mcp_servers) == expected_mcp
        and set(surface.actual_browser_capabilities) == expected_browser
        and set(surface.actual_services) == set(surface.expected_services)
        and set(surface.actual_networks) == set(surface.expected_networks)
        and offline.egress_denied
        and offline.download_attempts == 0
        and offline.image_pulls == 0
        and offline.image_builds == 0
        and offline.package_resolutions == 0
    )
    if not qualification_passed:
        raise ApplianceManifestError(
            "participant qualification evidence does not match the release"
        )
    if drill != manifest.qualification:
        raise ApplianceManifestError("machine drill evidence does not match manifest")


_APTL_WHEEL_RE = re.compile(
    r"^wheelhouse/aptl_labs-([0-9]+(?:\.[0-9]+){2}(?:[a-z0-9.+_]*)?)"
    r"-[^/]+\.whl$"
)


def _verify_offline_aptl_version(
    payload: bytes,
    expected_version: str,
) -> None:
    """Bind the one staged APTL wheel and release env to the signed version."""

    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            wheels = [
                match.group(1).replace("_", "-")
                for member in archive.getmembers()
                if (match := _APTL_WHEEL_RE.fullmatch(member.name)) is not None
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


def prepare_release_manifest(
    release_dir: Path,
    template_path: Path,
) -> ApplianceReleaseManifest:
    """Derive every content identity from staged bytes and write canonically."""

    release_root = release_dir.resolve()
    if not release_root.is_dir():
        raise ApplianceManifestError("appliance release directory is missing")
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
    manifest_path = release_root / "manifest.json"
    if manifest_path.exists() or manifest_path.is_symlink():
        existing = _read_release_artifact(release_root, "manifest.json")
        if existing == manifest_bytes:
            return manifest
        raise ApplianceManifestError(
            "release manifest already exists with different content"
        )
    _write_create_once(manifest_path, manifest_bytes, mode=0o644)
    return manifest


def _release_checksum_payload(
    release_root: Path,
    manifest: ApplianceReleaseManifest,
    *,
    signature_bytes: bytes | None = None,
) -> bytes:
    paths = ["manifest.json", "manifest.sig.json"] + [
        artifact.path for artifact in manifest.artifacts
    ]
    lines: list[str] = []
    for relative_path in sorted(paths):
        if relative_path == "manifest.sig.json" and signature_bytes is not None:
            payload = signature_bytes
        else:
            payload = _read_release_artifact(release_root, relative_path)
        lines.append(f"{hashlib.sha256(payload).hexdigest()}  {relative_path}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _write_create_once(path: Path, payload: bytes, *, mode: int) -> None:
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
        raise ApplianceManifestError("appliance release directory is missing")
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
    signature_path = release_root / "manifest.sig.json"
    if signature_path.exists() or signature_path.is_symlink():
        raise ApplianceManifestError("appliance release is already sealed")
    manifest_bytes = _read_release_artifact(release_root, "manifest.json")
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
    except (
        OSError,
        ParticipantQualificationError,
        ValueError,
    ) as exc:
        raise ApplianceManifestError(
            "participant qualification attestation is invalid"
        ) from exc
    try:
        private_key_pem = _read_external_file(key_path, label="release signing key")
    except ApplianceManifestError:
        raise
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
        raise ApplianceManifestError("appliance release directory is missing")
    try:
        public_key_pem = _read_external_file(
            public_key_path,
            label="release trust anchor",
        )
    except ApplianceManifestError:
        raise
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
    except (ParticipantQualificationError, ValueError) as exc:
        raise ApplianceManifestError(
            "participant qualification attestation is invalid"
        ) from exc
    _verify_checksum_file(release_root, manifest)
    return _inspection(manifest)
