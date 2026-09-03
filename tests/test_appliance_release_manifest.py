"""Behavioral tests for the signed appliance release envelope (APP-3)."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from aptl.appliance.manifest import (
    ApplianceManifestError,
    canonical_manifest_bytes,
    compute_payload_digest,
    describe_artifact,
    prepare_release_manifest,
    seal_release_directory,
    sign_manifest,
    verify_release_directory,
    verify_manifest_signature,
)
from aptl.appliance.launch import (
    prepare_launch_descriptor,
    verify_launch_descriptor,
)
from aptl.appliance.models import (
    ApplianceBoundaryReleaseBinding,
    ApplianceDrillReport,
    ApplianceGuest,
    ApplianceReleaseManifest,
    ArtifactReference,
    DeliveryAdapter,
    DeliveryParity,
    HostPrerequisites,
    GoldenImageInventory,
    MachineDrill,
    ParticipantReleaseBinding,
    ReleaseSource,
)
from aptl.appliance.release_models import (
    ApplianceReleaseTemplate,
    BoundaryTemplateBinding,
    ParticipantTemplateBinding,
    StagedArtifact,
)
from aptl.validation.participant_qualification_evidence import (
    ParticipantQualificationReport,
    participant_qualification_attestation_payload,
)

_HEX_A = "a" * 64
_HEX_B = "b" * 64
_HEX_C = "c" * 64
_HEX_D = "d" * 64
_HEX_E = "e" * 64
_HEX_F = "f" * 64


def _artifact(
    artifact_id: str,
    kind: str,
    path: str,
    digest: str = _HEX_A,
) -> ArtifactReference:
    return ArtifactReference(
        artifact_id=artifact_id,
        kind=kind,
        path=path,
        sha256=f"sha256:{digest}",
        size_bytes=1024,
    )


def _machine(machine_id: str) -> MachineDrill:
    return MachineDrill(
        machine_id=f"sha256:{hashlib.sha256(machine_id.encode()).hexdigest()}",
        architecture="x86_64",
        vcpus=8,
        memory_bytes=16 * 1024**3,
        disk_bytes=100 * 1024**3,
        build_passed=True,
        offline_boot_passed=True,
        participant_smoke_passed=True,
        rollback_passed=True,
        overlay_destroy_passed=True,
    )


def _manifest() -> ApplianceReleaseManifest:
    artifacts = (
        _artifact("golden-disk", "golden-disk", "artifacts/golden.qcow2", _HEX_A),
        _artifact(
            "offline-payload",
            "offline-payload",
            "artifacts/offline-payload.tar",
            _HEX_B,
        ),
        _artifact(
            "profile-manifest",
            "participant-profile",
            "evidence/profile.json",
            _HEX_C,
        ),
        _artifact(
            "readiness-suite",
            "participant-readiness",
            "evidence/readiness.json",
            _HEX_A,
        ),
        _artifact(
            "asset-lock",
            "participant-asset-lock",
            "evidence/asset-lock.json",
            _HEX_D,
        ),
        _artifact(
            "qualification",
            "participant-qualification",
            "evidence/qualification.json",
            _HEX_E,
        ),
        _artifact(
            "boundary-policy",
            "boundary-policy",
            "evidence/boundary-policy.json",
            _HEX_F,
        ),
        _artifact(
            "golden-inventory",
            "golden-inventory",
            "evidence/golden-inventory.json",
            _HEX_A,
        ),
        _artifact(
            "machine-drill",
            "machine-drill",
            "evidence/machine-drill.json",
            _HEX_B,
        ),
    )
    return ApplianceReleaseManifest(
        schema_version="aptl.appliance-release/v1",
        release_id="aptl-v5.1.1-x86_64",
        source=ReleaseSource(
            aptl_version="5.1.1",
            source_tag="v5.1.1",
            source_commit="1" * 40,
        ),
        guest=ApplianceGuest(
            os_id="ubuntu",
            os_version="24.04",
            architecture="x86_64",
            disk_format="qcow2",
            base_image_digest=f"sha256:{_HEX_C}",
            immutable=True,
            overlay_strategy="qcow2-backing-file",
        ),
        artifacts=artifacts,
        payload_digest=f"sha256:{_HEX_D}",
        participant=ParticipantReleaseBinding(
            profile_id="guided-purple",
            profile_version=1,
            profile_manifest_digest=f"sha256:{_HEX_C}",
            readiness_suite_digest=f"sha256:{_HEX_A}",
            asset_lock_digest=f"sha256:{_HEX_D}",
            qualification_report_digest=f"sha256:{_HEX_E}",
        ),
        boundary=ApplianceBoundaryReleaseBinding(
            policy_digest=f"sha256:{_HEX_F}",
            boundary_helper_image=f"example/helper@sha256:{_HEX_A}",
            egress_proxy_image=f"example/proxy@sha256:{_HEX_B}",
        ),
        host_prerequisites=HostPrerequisites(
            architecture="x86_64",
            vcpus=8,
            memory_bytes=16 * 1024**3,
            disk_bytes=100 * 1024**3,
            hardware_virtualization=True,
            local_adapter="qemu-kvm",
            supported_hypervisors=("qemu>=8.2", "libvirt>=10.0"),
        ),
        delivery=DeliveryParity(
            participant_ui_digest=f"sha256:{_HEX_A}",
            participant_routes_digest=f"sha256:{_HEX_B}",
            adapters=(
                DeliveryAdapter(
                    adapter_id="local-kvm",
                    kind="local-kvm",
                    payload_unchanged=True,
                ),
                DeliveryAdapter(
                    adapter_id="hosted-seat",
                    kind="hosted",
                    payload_unchanged=True,
                ),
            ),
        ),
        qualification=ApplianceDrillReport(
            schema_version="aptl.appliance-drill/v1",
            machines=(_machine("host-a"), _machine("host-b")),
            golden_secret_scan_passed=True,
            golden_read_only_passed=True,
            distinct_overlay_identities_passed=True,
            failed_candidate_preserved_active_passed=True,
        ),
        upgrade_strategy="replace-golden-create-overlay",
    )


def _key_pair() -> tuple[bytes, bytes]:
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _offline_payload(version: str) -> bytes:
    output = io.BytesIO()
    env = (
        "APTL_APPLIANCE_SCENARIO=techvault-attacker-target\n"
        f"APTL_APPLIANCE_VERSION={version}\n"
    ).encode()
    wheel = b"wheel"
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in (
            ("appliance-release.env", env),
            (f"wheelhouse/aptl_labs-{version}-py3-none-any.whl", wheel),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def test_manifest_is_canonical_and_signed_by_external_trust_anchor() -> None:
    manifest = _manifest()
    private_pem, public_pem = _key_pair()

    first = canonical_manifest_bytes(manifest)
    second = canonical_manifest_bytes(
        ApplianceReleaseManifest.model_validate_json(first)
    )
    signature = sign_manifest(manifest, private_pem)

    assert first == second
    assert signature.manifest_digest == (f"sha256:{hashlib.sha256(first).hexdigest()}")
    assert signature.key_id.startswith("sha256:")
    assert base64.b64decode(signature.signature, validate=True)
    verify_manifest_signature(manifest, signature, public_pem)


def test_manifest_signature_rejects_tampering_and_wrong_key() -> None:
    manifest = _manifest()
    private_pem, public_pem = _key_pair()
    signature = sign_manifest(manifest, private_pem)
    tampered = manifest.model_copy(
        update={
            "source": manifest.source.model_copy(update={"source_commit": "2" * 40})
        }
    )

    with pytest.raises(ApplianceManifestError, match="signature"):
        verify_manifest_signature(tampered, signature, public_pem)

    _, wrong_public = _key_pair()
    with pytest.raises(ApplianceManifestError, match="trust anchor"):
        verify_manifest_signature(manifest, signature, wrong_public)


@pytest.mark.parametrize(
    "path",
    (
        "/tmp/golden.qcow2",
        "../golden.qcow2",
        "artifacts/../golden.qcow2",
        "./artifacts/golden.qcow2",
        "artifacts//golden.qcow2",
        "artifacts\\golden.qcow2",
    ),
)
def test_artifact_reference_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(ValidationError, match="safe relative"):
        _artifact("golden-disk", "golden-disk", path)


def test_manifest_rejects_duplicate_and_missing_release_artifacts() -> None:
    manifest = _manifest()
    duplicate = manifest.artifacts + (manifest.artifacts[0],)
    duplicate_payload = {**manifest.model_dump(), "artifacts": duplicate}
    with pytest.raises(ValidationError, match="artifact ids"):
        ApplianceReleaseManifest.model_validate(duplicate_payload)

    missing = tuple(
        item for item in manifest.artifacts if item.kind != "golden-inventory"
    )
    missing_payload = {**manifest.model_dump(), "artifacts": missing}
    with pytest.raises(ValidationError, match="required artifact kinds"):
        ApplianceReleaseManifest.model_validate(missing_payload)


def test_manifest_requires_two_distinct_successful_machine_drills() -> None:
    manifest = _manifest()
    one_machine = manifest.qualification.model_copy(
        update={"machines": (_machine("host-a"),)}
    )
    one_machine_payload = {**manifest.model_dump(), "qualification": one_machine}
    with pytest.raises(ValidationError, match="two independent"):
        ApplianceReleaseManifest.model_validate(one_machine_payload)

    duplicate = manifest.qualification.model_copy(
        update={"machines": (_machine("host-a"), _machine("host-a"))}
    )
    duplicate_payload = {**manifest.model_dump(), "qualification": duplicate}
    with pytest.raises(ValidationError, match="unique"):
        ApplianceReleaseManifest.model_validate(duplicate_payload)


def test_manifest_requires_payload_parity_and_immutable_upgrade() -> None:
    manifest = _manifest()
    mismatched = manifest.delivery.model_copy(
        update={
            "adapters": (
                manifest.delivery.adapters[0],
                manifest.delivery.adapters[1].model_copy(
                    update={"payload_unchanged": False}
                ),
            )
        }
    )
    mismatched_payload = {**manifest.model_dump(), "delivery": mismatched}
    with pytest.raises(ValidationError, match="same payload"):
        ApplianceReleaseManifest.model_validate(mismatched_payload)

    in_place_payload = {**manifest.model_dump(), "upgrade_strategy": "in-place"}
    with pytest.raises(ValidationError):
        ApplianceReleaseManifest.model_validate(in_place_payload)


def _write_signed_release(root: Path) -> tuple[ApplianceReleaseManifest, bytes]:
    root.mkdir()
    base = _manifest()
    project_root = Path(__file__).resolve().parents[1]
    profile_payload = (
        project_root / "participant-profiles/guided-purple-v1/profile.json"
    ).read_bytes()
    readiness_payload = (
        project_root / "participant-profiles/guided-purple-v1/readiness.json"
    ).read_bytes()
    readiness_document = json.loads(readiness_payload)
    asset_lock_payload = (
        project_root / "participant-profiles/guided-purple-v1/asset-lock.json"
    ).read_bytes()
    qualification_private = Ed25519PrivateKey.generate()
    qualification_public = qualification_private.public_key()
    qualification_public_pem = qualification_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    qualification_key_der = qualification_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    qualification_document = {
        "schema_version": "aptl.participant-qualification/v1",
        "profile_id": "guided-purple",
        "profile_version": 1,
        "profile_sha256": hashlib.sha256(profile_payload).hexdigest(),
        "asset_lock_digest": (
            f"sha256:{hashlib.sha256(asset_lock_payload).hexdigest()}"
        ),
        "run_record_ref": "evidence/run-record.json",
        "run_record_sha256": "1" * 64,
        "snapshot_ref": "evidence/snapshot.json",
        "snapshot_sha256": "2" * 64,
        "hardware": {
            "architecture": "x86_64",
            "vcpus": 8,
            "memory_bytes": 16 * 1024**3,
            "disk_bytes": 100 * 1024**3,
            "hypervisor": "qemu-kvm",
            "engine": "docker",
        },
        "surface": {
            "selected_profiles": [],
            "expected_services": [],
            "actual_services": [],
            "expected_networks": [],
            "actual_networks": [],
            "actual_workbench_profiles": ["red", "guided-blue"],
            "actual_mcp_servers": sorted(
                {
                    check["subject_id"]
                    for check in readiness_document["checks"]
                    if check["kind"] == "mcp-tool"
                }
            ),
            "actual_browser_capabilities": sorted(
                {
                    check["subject_id"]
                    for check in readiness_document["checks"]
                    if check["kind"] == "browser-operation"
                }
            ),
        },
        "checks": [
            {
                "check_id": check["check_id"],
                "status": "passed",
                "summary": "passed",
            }
            for check in readiness_document["checks"]
        ],
        "offline": {
            "egress_denied": True,
            "download_attempts": 0,
            "image_pulls": 0,
            "image_builds": 0,
            "package_resolutions": 0,
        },
        "measurements": {
            "peak_cpu_percent": 0,
            "peak_memory_bytes": 0,
            "staged_profile_assets_bytes": 0,
            "unique_image_compressed_bytes": 0,
            "unique_image_expanded_bytes": 0,
            "peak_runtime_disk_bytes": 0,
            "cold_start_seconds": 0,
            "warm_start_seconds": 0,
            "clean_reset_seconds": 0,
        },
        "sample_count": 2,
        "aggregation": "worst-conforming-sample",
        "attestation": {
            "algorithm": "ed25519",
            "key_id": (f"sha256:{hashlib.sha256(qualification_key_der).hexdigest()}"),
            "signature": "AA==",
        },
    }
    unsigned_qualification = ParticipantQualificationReport.model_validate(
        qualification_document
    )
    qualification_signature = qualification_private.sign(
        participant_qualification_attestation_payload(unsigned_qualification)
    )
    qualification_document["attestation"]["signature"] = base64.b64encode(
        qualification_signature
    ).decode("ascii")
    qualification_payload = json.dumps(
        qualification_document,
        separators=(",", ":"),
    ).encode()
    (root.parent / "qualification-public.pem").write_bytes(qualification_public_pem)
    boundary_payload = json.dumps(
        {
            "schema_version": "aptl.appliance-boundary/v1",
            "policy_id": "participant-default",
            "generation": 1,
            "workbench_policy_version": "participant-workbench-profile/v1",
            "default_deny": True,
            "platform_networks": {
                "participant": "org.aptl.network=participant",
                "management": "org.aptl.network=management",
                "egress": "org.aptl.network=egress",
            },
            "platform_anchors": {
                "participant": "org.aptl.zone=participant",
                "management": "org.aptl.zone=management",
                "egress": "org.aptl.zone=egress",
            },
            "fixed_crossings": [],
            "egress_authorities": [],
            "egress_proxy_limits": {
                "max_connections": 16,
                "max_header_bytes": 4096,
                "header_timeout_seconds": 5,
                "connect_timeout_seconds": 10,
                "idle_timeout_seconds": 30,
            },
            "guest_publications": [],
            "docker_authority": {
                "allowed_holder_labels": [],
                "require_guest_daemon": True,
            },
        },
        separators=(",", ":"),
    ).encode()
    artifacts = []
    for artifact in base.artifacts:
        path = root / artifact.path
        path.parent.mkdir(parents=True, exist_ok=True)
        if artifact.kind == "golden-inventory":
            payload = (
                GoldenImageInventory(
                    schema_version="aptl.golden-inventory/v1",
                    scan_complete=True,
                    populated_sensitive_paths=(),
                    writable_runtime_paths=(),
                )
                .model_dump_json()
                .encode()
            )
        elif artifact.kind == "machine-drill":
            payload = base.qualification.model_dump_json().encode()
        elif artifact.kind == "participant-profile":
            payload = profile_payload
        elif artifact.kind == "participant-readiness":
            payload = readiness_payload
        elif artifact.kind == "participant-asset-lock":
            payload = asset_lock_payload
        elif artifact.kind == "participant-qualification":
            payload = qualification_payload
        elif artifact.kind == "boundary-policy":
            payload = boundary_payload
        elif artifact.kind == "offline-payload":
            payload = _offline_payload(base.source.aptl_version)
        else:
            payload = f"{artifact.kind}\n".encode()
        path.write_bytes(payload)
        artifacts.append(
            describe_artifact(
                root,
                artifact_id=artifact.artifact_id,
                kind=artifact.kind,
                path=artifact.path,
            )
        )
    by_kind = {artifact.kind: artifact for artifact in artifacts}
    manifest = base.model_copy(
        update={
            "artifacts": tuple(artifacts),
            "payload_digest": compute_payload_digest(tuple(artifacts)),
            "participant": base.participant.model_copy(
                update={
                    "profile_manifest_digest": by_kind["participant-profile"].sha256,
                    "readiness_suite_digest": by_kind["participant-readiness"].sha256,
                    "asset_lock_digest": by_kind["participant-asset-lock"].sha256,
                    "qualification_report_digest": by_kind[
                        "participant-qualification"
                    ].sha256,
                }
            ),
            "boundary": base.boundary.model_copy(
                update={"policy_digest": by_kind["boundary-policy"].sha256}
            ),
        }
    )
    private_pem, public_pem = _key_pair()
    signature = sign_manifest(manifest, private_pem)
    (root / "manifest.json").write_bytes(canonical_manifest_bytes(manifest))
    (root / "manifest.sig.json").write_text(signature.model_dump_json())
    checksum_paths = sorted(
        ["manifest.json", "manifest.sig.json"]
        + [artifact.path for artifact in manifest.artifacts]
    )
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((root / path).read_bytes()).hexdigest()}  {path}\n"
            for path in checksum_paths
        )
    )
    return manifest, public_pem


def _resign_release(
    root: Path,
    manifest: ApplianceReleaseManifest,
) -> tuple[ApplianceReleaseManifest, bytes]:
    artifacts = tuple(
        describe_artifact(
            root,
            artifact_id=artifact.artifact_id,
            kind=artifact.kind,
            path=artifact.path,
        )
        for artifact in manifest.artifacts
    )
    by_kind = {artifact.kind: artifact for artifact in artifacts}
    updated = manifest.model_copy(
        update={
            "artifacts": artifacts,
            "payload_digest": compute_payload_digest(artifacts),
            "participant": manifest.participant.model_copy(
                update={
                    "profile_manifest_digest": by_kind["participant-profile"].sha256,
                    "readiness_suite_digest": by_kind["participant-readiness"].sha256,
                    "asset_lock_digest": by_kind["participant-asset-lock"].sha256,
                    "qualification_report_digest": by_kind[
                        "participant-qualification"
                    ].sha256,
                }
            ),
            "boundary": manifest.boundary.model_copy(
                update={"policy_digest": by_kind["boundary-policy"].sha256}
            ),
        }
    )
    private_pem, public_pem = _key_pair()
    signature = sign_manifest(updated, private_pem)
    (root / "manifest.json").write_bytes(canonical_manifest_bytes(updated))
    (root / "manifest.sig.json").write_text(signature.model_dump_json())
    checksum_paths = sorted(
        ["manifest.json", "manifest.sig.json"]
        + [artifact.path for artifact in updated.artifacts]
    )
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((root / path).read_bytes()).hexdigest()}  {path}\n"
            for path in checksum_paths
        )
    )
    return updated, public_pem


def test_release_directory_verifies_every_artifact_and_safe_projection(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    manifest, public_pem = _write_signed_release(release)
    public_key = tmp_path / "release-public.pem"
    public_key.write_bytes(public_pem)

    inspection = verify_release_directory(
        release,
        public_key,
        qualification_public_key_path=tmp_path / "qualification-public.pem",
    )

    assert inspection.release_id == manifest.release_id
    assert inspection.aptl_version == "5.1.1"
    assert inspection.payload_digest == manifest.payload_digest
    assert inspection.manifest_digest.startswith("sha256:")
    assert inspection.artifact_count == len(manifest.artifacts)
    assert inspection.minimum_host_memory_bytes == 16 * 1024**3


def test_release_directory_rejects_artifact_tampering_and_symlinks(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    _, public_pem = _write_signed_release(release)
    public_key = tmp_path / "release-public.pem"
    public_key.write_bytes(public_pem)
    golden = release / "artifacts/golden.qcow2"
    golden.write_bytes(b"tampered")

    with pytest.raises(ApplianceManifestError, match="digest mismatch"):
        verify_release_directory(
            release,
            public_key,
            qualification_public_key_path=tmp_path / "qualification-public.pem",
        )

    golden.unlink()
    golden.symlink_to("/dev/null")
    with pytest.raises(ApplianceManifestError, match="unsafe release artifact"):
        verify_release_directory(
            release,
            public_key,
            qualification_public_key_path=tmp_path / "qualification-public.pem",
        )


def test_release_directory_rejects_golden_state_contamination(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    _, public_pem = _write_signed_release(release)
    public_key = tmp_path / "release-public.pem"
    public_key.write_bytes(public_pem)
    inventory = release / "evidence/golden-inventory.json"
    inventory.write_text(
        GoldenImageInventory.model_construct(
            schema_version="aptl.golden-inventory/v1",
            scan_complete=True,
            populated_sensitive_paths=("etc/ssh/ssh_host_ed25519_key",),
            writable_runtime_paths=(),
        ).model_dump_json()
    )

    with pytest.raises(ApplianceManifestError, match="digest mismatch"):
        verify_release_directory(
            release,
            public_key,
            qualification_public_key_path=tmp_path / "qualification-public.pem",
        )

    with pytest.raises(ValidationError, match="per-instance state"):
        GoldenImageInventory(
            schema_version="aptl.golden-inventory/v1",
            scan_complete=True,
            populated_sensitive_paths=("etc/ssh/ssh_host_ed25519_key",),
            writable_runtime_paths=(),
        )


def test_release_directory_rejects_invalid_reused_contracts(tmp_path: Path) -> None:
    release = tmp_path / "release"
    manifest, _ = _write_signed_release(release)
    (release / "evidence/boundary-policy.json").write_text("{}")
    _, public_pem = _resign_release(release, manifest)
    public_key = tmp_path / "release-public.pem"
    public_key.write_bytes(public_pem)

    with pytest.raises(ApplianceManifestError, match="release evidence"):
        verify_release_directory(
            release,
            public_key,
            qualification_public_key_path=tmp_path / "qualification-public.pem",
        )


def test_release_verification_requires_independent_qualification_trust(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    _, release_public_pem = _write_signed_release(release)
    release_public = tmp_path / "release-public.pem"
    release_public.write_bytes(release_public_pem)
    _, wrong_qualification_public_pem = _key_pair()
    wrong_qualification_public = tmp_path / "wrong-qualification-public.pem"
    wrong_qualification_public.write_bytes(wrong_qualification_public_pem)

    with pytest.raises(ApplianceManifestError, match="qualification"):
        verify_release_directory(
            release,
            release_public,
            qualification_public_key_path=wrong_qualification_public,
        )


def test_release_rejects_missing_readiness_checks_and_wrong_wheel_version(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    manifest, _ = _write_signed_release(release)
    qualification_path = release / "evidence/qualification.json"
    qualification = json.loads(qualification_path.read_text())
    qualification["checks"] = []
    qualification_path.write_text(json.dumps(qualification))
    manifest, public_pem = _resign_release(release, manifest)
    public_key = tmp_path / "release-public.pem"
    public_key.write_bytes(public_pem)

    with pytest.raises(ApplianceManifestError, match="qualification evidence"):
        verify_release_directory(
            release,
            public_key,
            qualification_public_key_path=tmp_path / "qualification-public.pem",
        )

    second = tmp_path / "second-release"
    second_manifest, _ = _write_signed_release(second)
    (second / "artifacts/offline-payload.tar").write_bytes(_offline_payload("5.2.0"))
    _, second_public_pem = _resign_release(second, second_manifest)
    second_public = tmp_path / "second-release-public.pem"
    second_public.write_bytes(second_public_pem)

    with pytest.raises(ApplianceManifestError, match="version"):
        verify_release_directory(
            second,
            second_public,
            qualification_public_key_path=tmp_path / "qualification-public.pem",
        )


def test_release_sealing_is_atomic_and_emits_complete_checksums(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    manifest, _ = _write_signed_release(release)
    (release / "manifest.sig.json").unlink()
    (release / "SHA256SUMS").unlink()
    private_pem, public_pem = _key_pair()
    private_key = tmp_path / "release-private.pem"
    public_key = tmp_path / "release-public.pem"
    private_key.write_bytes(private_pem)
    public_key.write_bytes(public_pem)

    result = seal_release_directory(
        release,
        private_key,
        qualification_public_key_path=tmp_path / "qualification-public.pem",
    )

    assert result.release_id == manifest.release_id
    assert (release / "manifest.sig.json").stat().st_mode & 0o777 == 0o644
    checksums = (release / "SHA256SUMS").read_text().splitlines()
    assert len(checksums) == len(manifest.artifacts) + 2
    assert checksums == sorted(checksums, key=lambda line: line.split("  ", 1)[1])
    verify_release_directory(
        release,
        public_key,
        qualification_public_key_path=tmp_path / "qualification-public.pem",
    )

    with pytest.raises(ApplianceManifestError, match="already sealed"):
        seal_release_directory(
            release,
            private_key,
            qualification_public_key_path=tmp_path / "qualification-public.pem",
        )


def test_release_sealing_refuses_a_private_key_inside_the_release(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    _write_signed_release(release)
    (release / "manifest.sig.json").unlink()
    (release / "SHA256SUMS").unlink()
    private_pem, _ = _key_pair()
    private_key = release / "private-key.pem"
    private_key.write_bytes(private_pem)

    with pytest.raises(ApplianceManifestError, match="outside"):
        seal_release_directory(
            release,
            private_key,
            qualification_public_key_path=tmp_path / "qualification-public.pem",
        )
    assert not (release / "manifest.sig.json").exists()


def test_release_sealing_rejects_untrusted_participant_qualification(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    _write_signed_release(release)
    (release / "manifest.sig.json").unlink()
    (release / "SHA256SUMS").unlink()
    private_pem, _ = _key_pair()
    _, wrong_qualification_public = _key_pair()
    private_key = tmp_path / "release-private.pem"
    qualification_key = tmp_path / "wrong-qualification-public.pem"
    private_key.write_bytes(private_pem)
    qualification_key.write_bytes(wrong_qualification_public)

    with pytest.raises(ApplianceManifestError, match="qualification"):
        seal_release_directory(
            release,
            private_key,
            qualification_public_key_path=qualification_key,
        )
    assert not (release / "manifest.sig.json").exists()
    assert not (release / "SHA256SUMS").exists()


def test_release_manifest_is_prepared_from_staged_artifacts_not_handwritten(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    expected, _ = _write_signed_release(release)
    (release / "manifest.json").unlink()
    (release / "manifest.sig.json").unlink()
    (release / "SHA256SUMS").unlink()
    template = ApplianceReleaseTemplate(
        schema_version="aptl.appliance-release-template/v1",
        release_id=expected.release_id,
        source=expected.source,
        guest=expected.guest,
        artifacts=tuple(
            StagedArtifact(
                artifact_id=artifact.artifact_id,
                kind=artifact.kind,
                path=artifact.path,
            )
            for artifact in expected.artifacts
        ),
        participant=ParticipantTemplateBinding(
            profile_id=expected.participant.profile_id,
            profile_version=expected.participant.profile_version,
        ),
        boundary=BoundaryTemplateBinding(
            boundary_helper_image=expected.boundary.boundary_helper_image,
            egress_proxy_image=expected.boundary.egress_proxy_image,
        ),
        host_prerequisites=expected.host_prerequisites,
        delivery=expected.delivery,
        upgrade_strategy="replace-golden-create-overlay",
    )
    template_path = tmp_path / "release-template.json"
    template_path.write_text(template.model_dump_json())

    prepared = prepare_release_manifest(release, template_path)

    assert prepared == expected
    assert (release / "manifest.json").read_bytes() == canonical_manifest_bytes(
        prepared
    )
    changed_template = template.model_copy(update={"release_id": "different"})
    template_path.write_text(changed_template.model_dump_json())
    with pytest.raises(ApplianceManifestError, match="already exists"):
        prepare_release_manifest(release, template_path)


def test_launch_descriptor_is_create_once_and_reverified_before_runtime(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    _, release_public_pem = _write_signed_release(release)
    release_public = tmp_path / "release-public.pem"
    release_public.write_bytes(release_public_pem)
    qualification_public = tmp_path / "qualification-public.pem"
    output = tmp_path / "appliance-launch.json"

    descriptor = prepare_launch_descriptor(
        release,
        release_public,
        qualification_public,
        output,
        host_observation_id="sha256:" + "9" * 64,
    )
    verified = verify_launch_descriptor(
        output,
        release_public,
        qualification_public,
    )

    assert verified.descriptor == descriptor
    assert verified.boundary_policy.default_deny is True
    assert output.stat().st_mode & 0o777 == 0o444

    output.chmod(0o644)
    document = json.loads(output.read_text())
    document["payload_digest"] = "sha256:" + "0" * 64
    output.write_text(json.dumps(document))
    output.chmod(0o444)
    with pytest.raises(ApplianceManifestError, match="does not match"):
        verify_launch_descriptor(
            output,
            release_public,
            qualification_public,
        )
