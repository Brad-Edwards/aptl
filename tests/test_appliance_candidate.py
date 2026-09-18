"""Qualification candidates remain authenticated and production-inadmissible."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aptl.appliance.build import GoldenImageBuildRequest
from aptl.appliance.candidate import (
    ApplianceCandidateTemplate,
    prepare_candidate_launch_descriptor,
    prepare_candidate_manifest,
    seal_candidate,
    verify_candidate_directory,
    verify_candidate_launch_descriptor,
)
from aptl.appliance.errors import ApplianceManifestError
from aptl.appliance.manifest import verify_release_directory
from aptl.appliance.models import (
    ApplianceGuest,
    CandidateSource,
    DeliveryAdapter,
    DeliveryParity,
    HostPrerequisites,
    ReleaseSource,
)
from aptl.appliance.policy import full_techvault_boundary_policy
from aptl.appliance.release_models import (
    BoundaryTemplateBinding,
    ParticipantTemplateBinding,
    StagedArtifact,
)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _offline(version: str) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, payload in (
            (
                "appliance-release.env",
                f"APTL_APPLIANCE_SCENARIO=techvault\nAPTL_APPLIANCE_VERSION={version}\n".encode(),
            ),
            (f"wheelhouse/aptl_labs-{version}-py3-none-any.whl", b"wheel"),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def _key_pair(tmp_path: Path) -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    private = tmp_path / "candidate-private.pem"
    public = tmp_path / "candidate-public.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private, public


def _candidate(
    tmp_path: Path, *, development_source: bool = False
) -> tuple[Path, Path, Path, Path]:
    candidate = tmp_path / "launch" / "candidate"
    candidate.mkdir(parents=True)
    version = "5.1.1"
    offline = _offline(version)
    provisioner = b"#!/bin/sh\n"
    scanner = b"#!/bin/sh\n"
    golden = b"QFI\xfb" + b"golden"
    canonical = b"{}"
    inventory = json.dumps(
        {
            "schema_version": "aptl.golden-inventory/v1",
            "scan_complete": True,
            "populated_sensitive_paths": [],
            "writable_runtime_paths": [],
        }
    ).encode()
    policy = full_techvault_boundary_policy().model_dump_json().encode()
    request = (
        GoldenImageBuildRequest(
            schema_version="aptl.golden-image-build/v1",
            base_image_path="input/base.qcow2",
            base_image_digest="sha256:" + "a" * 64,
            offline_payload_path="input/offline-payload.tar",
            offline_payload_digest=_digest(offline),
            provisioner_path="input/provision-offline.sh",
            provisioner_digest=_digest(provisioner),
            scanner_path="input/scan-golden.sh",
            scanner_digest=_digest(scanner),
            output_image_path="candidate/aptl-golden.qcow2",
            inventory_output_path="candidate/golden-inventory.json",
            virtual_size_bytes=120 * 1024**3,
        )
        .model_dump_json()
        .encode()
    )
    payloads = {
        "inputs.json": canonical,
        "golden-build.json": request,
        "provision-offline.sh": provisioner,
        "scan-golden.sh": scanner,
        "aptl-golden.qcow2": golden,
        "offline-payload.tar": offline,
        "participant-profile.json": b"{}",
        "participant-readiness.json": b"{}",
        "participant-asset-lock.json": b"{}",
        "boundary-policy.json": policy,
        "golden-inventory.json": inventory,
    }
    for name, payload in payloads.items():
        (candidate / name).write_bytes(payload)
    artifacts = tuple(
        StagedArtifact(artifact_id=artifact_id, kind=kind, path=path)
        for artifact_id, kind, path in (
            ("canonical-inputs", "canonical-inputs", "inputs.json"),
            ("golden-build-request", "golden-build-request", "golden-build.json"),
            ("golden-provisioner", "golden-provisioner", "provision-offline.sh"),
            ("golden-scanner", "golden-scanner", "scan-golden.sh"),
            ("golden-disk", "golden-disk", "aptl-golden.qcow2"),
            ("offline-payload", "offline-payload", "offline-payload.tar"),
            ("participant-profile", "participant-profile", "participant-profile.json"),
            (
                "participant-readiness",
                "participant-readiness",
                "participant-readiness.json",
            ),
            (
                "participant-asset-lock",
                "participant-asset-lock",
                "participant-asset-lock.json",
            ),
            ("boundary-policy", "boundary-policy", "boundary-policy.json"),
            ("golden-inventory", "golden-inventory", "golden-inventory.json"),
        )
    )
    template = ApplianceCandidateTemplate(
        schema_version="aptl.appliance-candidate-template/v1",
        candidate_id="aptl-5.1.1-candidate-x86_64",
        source=(
            CandidateSource(
                aptl_version=version,
                source_revision="commit:" + "1" * 40,
                source_commit="1" * 40,
            )
            if development_source
            else ReleaseSource(
                aptl_version=version,
                source_tag="v5.1.1",
                source_commit="1" * 40,
            )
        ),
        guest=ApplianceGuest(
            os_id="ubuntu",
            os_version="26.04",
            architecture="x86_64",
            disk_format="qcow2",
            base_image_digest="sha256:" + "a" * 64,
            immutable=True,
            overlay_strategy="qcow2-backing-file",
        ),
        artifacts=artifacts,
        participant=ParticipantTemplateBinding(
            profile_id="techvault-full", profile_version=1
        ),
        boundary=BoundaryTemplateBinding(
            boundary_helper_image="example/helper@sha256:" + "b" * 64,
            egress_proxy_image="example/proxy@sha256:" + "c" * 64,
        ),
        host_prerequisites=HostPrerequisites(
            architecture="x86_64",
            vcpus=8,
            memory_bytes=32 * 1024**3,
            disk_bytes=250 * 1024**3,
            hardware_virtualization=True,
            local_adapter="qemu-kvm",
            supported_hypervisors=("qemu-kvm",),
        ),
        delivery=DeliveryParity(
            participant_ui_digest=_digest(payloads["participant-profile.json"]),
            participant_routes_digest=_digest(payloads["participant-readiness.json"]),
            canonical_inputs_digest=_digest(canonical),
            host_mcp_contract="aptl.restricted-ssh-mcp/v1",
            adapters=(
                DeliveryAdapter(
                    adapter_id="local-kvm", kind="local-kvm", payload_unchanged=True
                ),
                DeliveryAdapter(
                    adapter_id="hosted", kind="hosted", payload_unchanged=True
                ),
            ),
        ),
        build_request_digest=_digest(request),
    )
    template_path = tmp_path / "candidate-template.json"
    template_path.write_text(template.model_dump_json())
    private, public = _key_pair(tmp_path)
    return candidate, template_path, private, public


def test_candidate_is_signed_launchable_and_never_production_shaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "aptl.appliance.candidate.validate_canonical_payload", lambda *_: None
    )
    candidate, template, private, public = _candidate(tmp_path)
    manifest = prepare_candidate_manifest(candidate, template)
    seal_candidate(candidate, private)

    verified, _inspection = verify_candidate_directory(candidate, public)
    assert verified.trust_mode == "qualification-only"
    descriptor = tmp_path / "launch" / "appliance-launch.json"
    prepare_candidate_launch_descriptor(
        candidate,
        public,
        descriptor,
        host_observation_id="sha256:" + "d" * 64,
    )
    assert (
        verify_candidate_launch_descriptor(descriptor, public).release_root == candidate
    )
    assert not (candidate / "manifest.json").exists()
    with pytest.raises(ApplianceManifestError):
        verify_release_directory(
            candidate,
            public,
            qualification_public_key_path=public,
        )


def test_candidate_can_bind_an_untagged_exact_source_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "aptl.appliance.candidate.validate_canonical_payload", lambda *_: None
    )
    candidate, template, private, public = _candidate(tmp_path, development_source=True)

    manifest = prepare_candidate_manifest(candidate, template)
    seal_candidate(candidate, private)
    verified, _inspection = verify_candidate_directory(candidate, public)

    assert manifest.source == CandidateSource(
        aptl_version="5.1.1",
        source_revision="commit:" + "1" * 40,
        source_commit="1" * 40,
    )
    assert verified.source == manifest.source


def test_candidate_tampering_and_build_provenance_mismatch_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "aptl.appliance.candidate.validate_canonical_payload", lambda *_: None
    )
    candidate, template, private, public = _candidate(tmp_path)
    prepare_candidate_manifest(candidate, template)
    seal_candidate(candidate, private)
    (candidate / "scan-golden.sh").write_bytes(b"changed")

    with pytest.raises(ApplianceManifestError, match="digest mismatch"):
        verify_candidate_directory(candidate, public)
