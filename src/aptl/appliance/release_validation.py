"""Artifact and evidence verification for signed appliance releases."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import stat
import tarfile
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

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
from aptl.utils.pathsafe import (
    PathContainmentError,
    open_contained_nofollow,
    read_contained_nofollow,
)
from aptl.validation.participant_profile_models import (
    ParticipantAssetLock,
    ParticipantProfileManifest,
    ParticipantReadinessSuite,
)
from aptl.validation.participant_qualification_evidence import (
    ParticipantQualificationReport,
)
from aptl.utils.strict_json import loads_strict, model_validate_json_strict

_PAYLOAD_KINDS = frozenset(
    {
        "golden-disk",
        "offline-payload",
        "participant-profile",
        "participant-readiness",
        "participant-asset-lock",
        "participant-qualification",
        "participant-run-record",
        "participant-snapshot",
        "boundary-policy",
    }
)
_STREAMED_KINDS = frozenset({"golden-disk", "offline-payload"})


@dataclass(frozen=True)
class StreamedArtifact:
    """A large artifact pinned to the filesystem identity that was hashed."""

    root: Path
    relative_path: str
    device: int
    inode: int
    mtime_ns: int
    size_bytes: int

    @contextmanager
    def open(self) -> Iterator[BinaryIO]:
        """Reopen the contained file only if its hashed identity is unchanged."""

        with open_contained_nofollow(self.root, self.relative_path) as handle:
            info = os.fstat(handle.fileno())
            actual = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size)
            expected = (self.device, self.inode, self.mtime_ns, self.size_bytes)
            if actual != expected or not stat.S_ISREG(info.st_mode):
                raise ApplianceManifestError(
                    f"release artifact changed during verification: {self.relative_path}"
                )
            yield handle


ArtifactPayload = bytes | StreamedArtifact


def read_release_artifact(root: Path, relative_path: str) -> bytes:
    """Read one contained release file without following symlinks."""

    try:
        return read_contained_nofollow(root, relative_path)
    except (OSError, PathContainmentError, ValueError) as exc:
        raise ApplianceManifestError(
            f"unsafe release artifact: {relative_path}"
        ) from exc


def release_artifact_identity(
    root: Path, relative_path: str
) -> tuple[str, int, StreamedArtifact]:
    """Stream one contained artifact and pin the exact inode that was hashed."""

    try:
        with open_contained_nofollow(root, relative_path) as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise OSError("artifact is not a regular file")
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
    except (OSError, PathContainmentError, ValueError) as exc:
        raise ApplianceManifestError(
            f"unsafe release artifact: {relative_path}"
        ) from exc
    pinned = StreamedArtifact(
        root=root,
        relative_path=relative_path,
        device=info.st_dev,
        inode=info.st_ino,
        mtime_ns=info.st_mtime_ns,
        size_bytes=size,
    )
    return f"sha256:{digest.hexdigest()}", size, pinned


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
        if artifact.kind
        in _PAYLOAD_KINDS | {"canonical-inputs", "redistribution-review"}
    ]
    if not _PAYLOAD_KINDS <= {item["kind"] for item in projection}:
        raise ApplianceManifestError("payload artifact set is incomplete")
    return f"sha256:{hashlib.sha256(rfc8785.dumps(projection)).hexdigest()}"


def verify_artifacts(
    release_root: Path,
    manifest: ApplianceReleaseManifest,
) -> dict[ArtifactKind, ArtifactPayload]:
    """Verify every declared artifact and return payloads keyed by kind."""

    payloads: dict[ArtifactKind, ArtifactPayload] = {}
    for artifact in manifest.artifacts:
        if artifact.kind in _STREAMED_KINDS:
            actual_digest, size, payload = release_artifact_identity(
                release_root, artifact.path
            )
        else:
            payload = read_release_artifact(release_root, artifact.path)
            actual_digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
            size = len(payload)
        if actual_digest != artifact.sha256 or size != artifact.size_bytes:
            raise ApplianceManifestError(
                f"release artifact digest mismatch: {artifact.artifact_id}"
            )
        payloads[artifact.kind] = payload
    if compute_payload_digest(manifest.artifacts) != manifest.payload_digest:
        raise ApplianceManifestError("release payload digest mismatch")
    return payloads


def _payload_bytes(payload: ArtifactPayload, *, label: str) -> bytes:
    """Return a bounded evidence payload, never a streamed disk or archive."""

    if not isinstance(payload, bytes):
        raise ApplianceManifestError(f"{label} must be a bounded evidence artifact")
    return payload


@contextmanager
def _open_tar_payload(payload: ArtifactPayload) -> Iterator[tarfile.TarFile]:
    """Open a verified offline payload without retaining it in memory."""

    if isinstance(payload, bytes):
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            yield archive
        return
    with payload.open() as handle, tarfile.open(fileobj=handle, mode="r:") as archive:
        yield archive


def _parse_evidence(
    payloads: dict[ArtifactKind, ArtifactPayload],
) -> tuple[
    ParticipantProfileManifest,
    ParticipantReadinessSuite,
    ParticipantAssetLock,
    ParticipantQualificationReport,
    ApplianceDrillReport,
]:
    """Parse every release evidence record through its closed schema."""

    try:
        profile = model_validate_json_strict(
            ParticipantProfileManifest,
            _payload_bytes(
                payloads["participant-profile"], label="participant profile"
            ),
        )
        readiness = model_validate_json_strict(
            ParticipantReadinessSuite,
            _payload_bytes(
                payloads["participant-readiness"], label="participant readiness"
            ),
        )
        asset_lock = model_validate_json_strict(
            ParticipantAssetLock,
            _payload_bytes(
                payloads["participant-asset-lock"], label="participant asset lock"
            ),
        )
        qualification = model_validate_json_strict(
            ParticipantQualificationReport,
            _payload_bytes(
                payloads["participant-qualification"], label="participant qualification"
            ),
        )
        model_validate_json_strict(
            ApplianceBoundaryPolicy,
            _payload_bytes(payloads["boundary-policy"], label="boundary policy"),
        )
        model_validate_json_strict(
            GoldenImageInventory,
            _payload_bytes(payloads["golden-inventory"], label="golden inventory"),
        )
        drill = model_validate_json_strict(
            ApplianceDrillReport,
            _payload_bytes(payloads["machine-drill"], label="machine drill"),
        )
    except ValueError as exc:
        raise ApplianceManifestError("invalid appliance release evidence") from exc
    return profile, readiness, asset_lock, qualification, drill


def _participant_binding_matches(
    manifest: ApplianceReleaseManifest,
    payloads: dict[ArtifactKind, ArtifactPayload],
    profile: ParticipantProfileManifest,
    asset_lock: ParticipantAssetLock,
    qualification: ParticipantQualificationReport,
) -> bool:
    """Check the exact APP-2 profile, readiness, lock, and report identities."""

    profile_digest = hashlib.sha256(
        _payload_bytes(payloads["participant-profile"], label="participant profile")
    ).hexdigest()
    readiness_digest = hashlib.sha256(
        _payload_bytes(payloads["participant-readiness"], label="participant readiness")
    ).hexdigest()
    asset_lock_digest = hashlib.sha256(
        _payload_bytes(
            payloads["participant-asset-lock"], label="participant asset lock"
        )
    ).hexdigest()
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


def _qualification_budget_matches(
    manifest: ApplianceReleaseManifest,
    profile: ParticipantProfileManifest,
    qualification: ParticipantQualificationReport,
) -> bool:
    """Require measured values and actual qualification hardware to fit APP-2."""

    measured = qualification.measurements
    maximums = profile.budgets.maximums
    fields = (
        "peak_cpu_percent",
        "peak_memory_bytes",
        "staged_profile_assets_bytes",
        "unique_image_compressed_bytes",
        "unique_image_expanded_bytes",
        "peak_runtime_disk_bytes",
        "cold_start_seconds",
        "warm_start_seconds",
        "clean_reset_seconds",
    )
    minimum = profile.budgets.minimum_hardware
    hardware = qualification.hardware
    return (
        all(getattr(measured, field) <= getattr(maximums, field) for field in fields)
        and hardware.architecture == manifest.guest.architecture
        and hardware.vcpus >= minimum.vcpus
        and hardware.memory_bytes >= minimum.memory_bytes
        and hardware.disk_bytes >= minimum.disk_bytes
        and manifest.host_prerequisites.vcpus == minimum.vcpus
        and manifest.host_prerequisites.memory_bytes == minimum.memory_bytes
        and manifest.host_prerequisites.disk_bytes == minimum.disk_bytes
    )


def _qualification_runtime_matches(
    payloads: dict[ArtifactKind, ArtifactPayload],
    qualification: ParticipantQualificationReport,
) -> bool:
    """Bind the successful run record and exact range snapshot into the release."""

    run_payload = _payload_bytes(
        payloads["participant-run-record"], label="participant run record"
    )
    snapshot_payload = _payload_bytes(
        payloads["participant-snapshot"], label="participant snapshot"
    )
    try:
        run_record = loads_strict(run_payload)
        snapshot = loads_strict(snapshot_payload)
        if not isinstance(run_record, dict) or not isinstance(snapshot, dict):
            raise ValueError("runtime evidence must contain JSON objects")
    except ValueError as exc:
        raise ApplianceManifestError(
            "invalid participant qualification runtime evidence"
        ) from exc
    backend = run_record.get("backend_evidence")
    selected = backend.get("selected_profiles") if isinstance(backend, dict) else None
    return (
        qualification.run_record_ref == "evidence/run-record.json"
        and qualification.snapshot_ref == "evidence/snapshot.json"
        and qualification.run_record_sha256 == hashlib.sha256(run_payload).hexdigest()
        and qualification.snapshot_sha256
        == hashlib.sha256(snapshot_payload).hexdigest()
        and run_record.get("schema_version") == "aptl.run-record/v1"
        and run_record.get("outcome") == "success"
        and isinstance(selected, list)
        and all(isinstance(item, str) for item in selected)
        and set(selected) == set(qualification.surface.selected_profiles)
        and isinstance(backend, dict)
        and backend.get("range_snapshot") == snapshot
    )


def verify_release_evidence(
    manifest: ApplianceReleaseManifest,
    payloads: dict[ArtifactKind, ArtifactPayload],
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
        and _qualification_budget_matches(manifest, profile, qualification)
        and _qualification_runtime_matches(payloads, qualification)
    )
    if not passed:
        raise ApplianceManifestError(
            "participant qualification evidence does not match the release"
        )
    _verify_canonical_delivery(manifest, payloads, profile, readiness)
    if drill != manifest.qualification:
        raise ApplianceManifestError("machine drill evidence does not match manifest")


def verify_offline_aptl_version(
    payload: ArtifactPayload, expected_version: str
) -> None:
    """Bind the one staged APTL wheel and release env to the signed version."""

    try:
        with _open_tar_payload(payload) as archive:
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


def _verify_canonical_delivery(
    manifest: ApplianceReleaseManifest,
    payloads: dict[str, ArtifactPayload],
    profile: ParticipantProfileManifest,
    readiness: ParticipantReadinessSuite,
) -> None:
    """Bind the optional host transport to full packaged inputs in the payload."""
    _verify_transport_readiness(manifest, payloads, readiness)
    canonical = payloads.get("canonical-inputs")
    if canonical is None:
        return
    canonical_bytes = _payload_bytes(canonical, label="canonical inputs")
    from aptl.appliance.inputs import CanonicalInputs
    from aptl.validation.participant_profile_models import EnvPackScenarioReference

    try:
        inputs = model_validate_json_strict(CanonicalInputs, canonical_bytes)
        if (
            inputs.aptl_version != manifest.source.aptl_version
            or not isinstance(profile.scenario, EnvPackScenarioReference)
            or profile.scenario.identity != inputs.scenario_pack
            or set(profile.capabilities.workbench_profiles) != {"red", "blue"}
        ):
            raise ValueError("canonical delivery identity differs")
        _verify_embedded_inputs(payloads["offline-payload"], canonical_bytes)
        validate_canonical_payload(payloads["offline-payload"], canonical_bytes)
        from aptl.appliance.redistribution import (
            RedistributionReview,
            validate_redistribution_review,
        )

        review = model_validate_json_strict(
            RedistributionReview,
            _payload_bytes(
                payloads["redistribution-review"], label="redistribution review"
            ),
        )
        validate_redistribution_review(review, manifest, inputs)
    except (ValueError, KeyError, tarfile.TarError) as exc:
        raise ApplianceManifestError("canonical release evidence mismatch") from exc


def _verify_transport_readiness(
    manifest: ApplianceReleaseManifest,
    payloads: dict[str, ArtifactPayload],
    readiness: ParticipantReadinessSuite,
) -> None:
    """Require policy agreement and real-client qualification for host MCP."""
    policy = model_validate_json_strict(
        ApplianceBoundaryPolicy,
        _payload_bytes(payloads["boundary-policy"], label="boundary policy"),
    )
    if policy.host_mcp_contract != manifest.delivery.host_mcp_contract:
        raise ApplianceManifestError("host MCP policy differs from the signed delivery")
    if manifest.delivery.host_mcp_contract:
        clients = {
            check.subject_id
            for check in readiness.checks
            if check.kind == "client-transport"
            and check.operation_id == "authenticated-client-tool-call-and-revocation"
        }
        if clients != {"claude", "codex"}:
            raise ApplianceManifestError(
                "host MCP qualification requires both real clients"
            )


def _verify_embedded_inputs(payload: ArtifactPayload, canonical: bytes) -> None:
    """Require one byte-identical canonical record in the signed payload."""
    with _open_tar_payload(payload) as archive:
        members = [member for member in archive if member.name == "inputs.json"]
        if (
            len(members) != 1
            or not members[0].isfile()
            or members[0].size != len(canonical)
        ):
            raise ValueError("canonical payload input record is missing or ambiguous")
        if archive.extractfile(members[0]).read() != canonical:
            raise ValueError("canonical payload input record differs")


def validate_canonical_payload(
    payload: ArtifactPayload,
    canonical: bytes,
) -> None:
    """Materialize and fully validate the canonical payload closure.

    The outer archive is admitted while it is extracted into a private,
    newly-created directory. Nested project, wheel and OCI archives are then
    checked by ``validate_canonical_inputs`` exactly as they were before the
    payload was assembled.
    """

    from aptl.appliance.inputs import validate_canonical_inputs
    from aptl.appliance.payload_content import safe_member

    with tempfile.TemporaryDirectory(prefix="aptl-release-inputs-") as temporary:
        staging = Path(temporary)
        seen: set[str] = set()
        total = 0
        try:
            with _open_tar_payload(payload) as archive:
                for member in archive:
                    name = safe_member(member.name)
                    if (
                        name in seen
                        or not (member.isfile() or member.isdir())
                        or member.size < 0
                    ):
                        raise ValueError("invalid canonical payload member")
                    seen.add(name)
                    total += member.size
                    if len(seen) > 500_000 or total > 500 * 1024**3:
                        raise ValueError("canonical payload limits exceeded")
                    target = staging / name
                    if not target.resolve().is_relative_to(staging.resolve()):
                        raise ValueError("canonical payload member escapes staging")
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=False)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError("canonical payload file is unreadable")
                    descriptor = os.open(
                        target,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                    )
                    with os.fdopen(descriptor, "wb") as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
            if (staging / "inputs.json").read_bytes() != canonical:
                raise ValueError("canonical payload input record differs")
            validate_canonical_inputs(staging, enforce_runtime_target=False)
        except (OSError, tarfile.TarError, ValueError) as exc:
            raise ApplianceManifestError(
                "canonical payload closure validation failed"
            ) from exc
