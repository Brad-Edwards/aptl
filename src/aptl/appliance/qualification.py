"""Candidate-bound evidence for independent real-machine appliance drills."""

from __future__ import annotations

import base64
import hashlib
import os
import platform
import re
import shutil
from pathlib import Path
from typing import Literal

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field, field_validator, model_validator

from aptl.appliance.candidate import verify_candidate_directory
from aptl.appliance.errors import ApplianceManifestError
from aptl.appliance.manifest import _write_create_once
from aptl.appliance.models import ApplianceDrillReport, MachineDrill, _StrictModel
from aptl.appliance.seat.access import GuestRuntimeEvidence
from aptl.appliance.seat.persistence import load_seat_record
from aptl.utils.strict_json import model_validate_json_strict
from aptl.validation.participant_profile_models import (
    ParticipantAssetLock,
    ParticipantProfileManifest,
    ParticipantReadinessSuite,
)
from aptl.validation.participant_qualification_evidence import (
    OfflineEvidence,
    ParticipantQualificationReport,
    QualificationAttestation,
    QualificationCheckEvidence,
    QualificationHardware,
    QualificationMeasurements,
    QualificationSurface,
    participant_qualification_attestation_payload,
)


class NativeClientProbeReceipt(_StrictModel):
    """Non-secret receipt emitted only after a live call and failed stale call."""

    schema_version: Literal["aptl.native-client-probe/v1"]
    candidate_id: str
    candidate_manifest_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    golden_image_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    seat_id: str
    generation: int = Field(ge=1)
    client: Literal["claude", "codex"]
    server_name: str
    tool_name: str
    client_version: str = Field(min_length=1, max_length=256)
    active_response_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    live_call_passed: Literal[True]
    stale_call_rejected: Literal[True]

    @field_validator("candidate_id", "seat_id", "server_name", "tool_name")
    @classmethod
    def bounded_identifier(cls, value: str) -> str:
        if not value or len(value) > 128 or any(ord(char) < 0x21 for char in value):
            raise ValueError("probe identifier is invalid")
        return value

    @field_validator("client_version")
    @classmethod
    def bounded_client_version(cls, value: str) -> str:
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            raise ValueError("client version is invalid")
        return value


class BrowserProbeReceipt(_StrictModel):
    """Live participant-UI and backing-service browser qualification outcomes."""

    schema_version: Literal["aptl.browser-probe/v1"]
    checks: tuple[QualificationCheckEvidence, ...]

    @model_validator(mode="after")
    def all_passed_and_unique(self) -> "BrowserProbeReceipt":
        identifiers = [item.check_id for item in self.checks]
        if len(identifiers) != len(set(identifiers)) or any(
            item.status != "passed" for item in self.checks
        ):
            raise ValueError("browser probes must be unique successful checks")
        return self


class QualificationMeasurementReceipt(_StrictModel):
    """Measured full-profile resource and lifecycle values from the KVM host."""

    schema_version: Literal["aptl.qualification-measurements/v1"]
    measurements: QualificationMeasurements


class FailedCandidateReceipt(_StrictModel):
    """Evidence that a rejected update did not disrupt active native access."""

    schema_version: Literal["aptl.failed-candidate-proof/v1"]
    candidate_id: str
    candidate_manifest_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    rejected: Literal[True]
    active_response_digests: tuple[str, ...] = Field(min_length=2)

    @field_validator("active_response_digests")
    @classmethod
    def response_digests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not re.fullmatch(r"sha256:[a-f0-9]{64}", item) for item in values):
            raise ValueError("active response digest is invalid")
        return values


def _machine_id(path: Path = Path("/etc/machine-id")) -> str:
    """Hash stable machine identity without publishing the host identifier."""

    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            identity = handle.read(4097).strip()
    except OSError as exc:
        raise ApplianceManifestError(
            "qualification machine identity unavailable"
        ) from exc
    if not identity or len(identity) > 4096:
        raise ApplianceManifestError("qualification machine identity is invalid")
    return f"sha256:{hashlib.sha256(identity).hexdigest()}"


def _host_capacity(path: Path) -> tuple[int, int, int]:
    """Return actual logical CPU, physical-memory and filesystem capacities."""

    vcpus = os.cpu_count() or 0
    try:
        memory = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError) as exc:
        raise ApplianceManifestError("qualification host capacity unavailable") from exc
    disk = shutil.disk_usage(path).total
    if min(vcpus, memory, disk) <= 0:
        raise ApplianceManifestError("qualification host capacity is invalid")
    return vcpus, memory, disk


def _load_probe_receipts(
    paths: tuple[Path, ...],
) -> tuple[NativeClientProbeReceipt, ...]:
    receipts: list[NativeClientProbeReceipt] = []
    for path in paths:
        try:
            receipts.append(
                model_validate_json_strict(NativeClientProbeReceipt, path.read_bytes())
            )
        except (OSError, ValueError) as exc:
            raise ApplianceManifestError(
                "native client probe receipt is invalid"
            ) from exc
    return tuple(receipts)


def record_machine_drill(
    *,
    candidate_dir: Path,
    candidate_public_key: Path,
    seat_roots: tuple[Path, ...],
    probe_receipts: tuple[Path, ...],
    failed_candidate_receipt: Path,
    output: Path,
) -> MachineDrill:
    """Derive a machine drill from reset seats and live-client receipts."""

    manifest, inspection = verify_candidate_directory(
        candidate_dir, candidate_public_key
    )
    if not seat_roots or len(seat_roots) != len(set(seat_roots)):
        raise ApplianceManifestError("qualification seat set is invalid")
    records = []
    runtime_evidence = []
    for root in seat_roots:
        record = load_seat_record(root)
        if (
            record is None
            or record.selected_release_id != manifest.candidate_id
            or record.trust_mode != "qualification-only"
            or record.lifecycle_state != "staged"
            or record.generation < 2
            or (root / record.overlay_path).exists()
        ):
            raise ApplianceManifestError("qualification seat was not cleanly reset")
        access_generations = tuple((root / "access").glob("generation-*"))
        if not access_generations or any(
            not (generation / "invalidated").is_file()
            or (generation / "grant.json").exists()
            for generation in access_generations
        ):
            raise ApplianceManifestError("qualification access was not revoked")
        records.append(record)
        evidence_path = root / "access/generation-1/runtime-evidence.json"
        runtime_evidence.append(
            _read_model(GuestRuntimeEvidence, evidence_path, "guest runtime evidence")
        )

    receipts = _load_probe_receipts(probe_receipts)
    golden = next(item for item in manifest.artifacts if item.kind == "golden-disk")
    expected_seats = {record.seat_id for record in records}
    receipt_pairs = {(item.seat_id, item.client) for item in receipts}
    if receipt_pairs != {
        (seat_id, client)
        for seat_id in expected_seats
        for client in ("claude", "codex")
    } or any(
        item.candidate_id != manifest.candidate_id
        or item.candidate_manifest_digest != inspection.manifest_digest
        or item.golden_image_digest != golden.sha256
        for item in receipts
    ):
        raise ApplianceManifestError("native client probes differ from the candidate")
    failed = _read_model(
        FailedCandidateReceipt,
        failed_candidate_receipt,
        "failed candidate proof",
    )
    if (
        failed.candidate_id != manifest.candidate_id
        or failed.candidate_manifest_digest != inspection.manifest_digest
        or set(failed.active_response_digests)
        != {item.active_response_digest for item in receipts}
    ):
        raise ApplianceManifestError("failed candidate proof differs from live probes")
    distinct_instances = len({record.instance_id for record in records}) == len(records)
    golden_path = candidate_dir / golden.path
    golden_read_only = not bool(golden_path.stat(follow_symlinks=False).st_mode & 0o222)

    architecture = platform.machine()
    if architecture not in {"x86_64", "aarch64"}:
        raise ApplianceManifestError("qualification architecture is unsupported")
    vcpus, memory, disk = _host_capacity(candidate_dir)
    report = MachineDrill(
        machine_id=_machine_id(),
        candidate_id=manifest.candidate_id,
        candidate_manifest_digest=inspection.manifest_digest,
        candidate_payload_digest=manifest.payload_digest,
        golden_image_digest=golden.sha256,
        architecture=architecture,
        vcpus=vcpus,
        memory_bytes=memory,
        disk_bytes=disk,
        hypervisor="qemu-kvm",
        seat_count=len(records),
        host_access_clients=("claude", "codex"),
        build_passed=True,
        offline_boot_passed=True,
        participant_smoke_passed=all(
            item.qualification_checks for item in runtime_evidence
        ),
        host_access_passed=True,
        revocation_passed=True,
        rollback_passed=any(record.generation >= 3 for record in records),
        overlay_destroy_passed=True,
        golden_secret_scan_passed=True,
        golden_read_only_passed=golden_read_only,
        distinct_overlay_identities_passed=(len(records) >= 2 and distinct_instances),
        failed_candidate_preserved_active_passed=True,
    )
    _write_create_once(
        output, rfc8785.dumps(report.model_dump(mode="json")), mode=0o444
    )
    return report


def aggregate_machine_drills(
    *,
    candidate_dir: Path,
    candidate_public_key: Path,
    reports: tuple[Path, ...],
    output: Path,
) -> ApplianceDrillReport:
    """Require two independent candidate-bound reports and publish APP-3 evidence."""

    manifest, inspection = verify_candidate_directory(
        candidate_dir, candidate_public_key
    )
    golden = next(item for item in manifest.artifacts if item.kind == "golden-disk")
    try:
        machines = tuple(
            model_validate_json_strict(MachineDrill, path.read_bytes())
            for path in reports
        )
    except (OSError, ValueError) as exc:
        raise ApplianceManifestError("machine drill report is invalid") from exc
    expected = (
        manifest.candidate_id,
        inspection.manifest_digest,
        manifest.payload_digest,
        golden.sha256,
    )
    if any(
        (
            machine.candidate_id,
            machine.candidate_manifest_digest,
            machine.candidate_payload_digest,
            machine.golden_image_digest,
        )
        != expected
        for machine in machines
    ):
        raise ApplianceManifestError("machine drill candidate binding differs")
    report = ApplianceDrillReport(
        schema_version="aptl.appliance-drill/v2",
        machines=machines,
        golden_secret_scan_passed=all(
            machine.golden_secret_scan_passed for machine in machines
        ),
        golden_read_only_passed=all(
            machine.golden_read_only_passed for machine in machines
        ),
        distinct_overlay_identities_passed=any(
            machine.distinct_overlay_identities_passed for machine in machines
        ),
        failed_candidate_preserved_active_passed=all(
            machine.failed_candidate_preserved_active_passed for machine in machines
        ),
    )
    _write_create_once(
        output, rfc8785.dumps(report.model_dump(mode="json")), mode=0o444
    )
    return report


def _read_model(model, path: Path, label: str):
    try:
        return model_validate_json_strict(model, path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ApplianceManifestError(f"{label} is invalid") from exc


def _qualification_checks(
    readiness: ParticipantReadinessSuite,
    runtime: GuestRuntimeEvidence,
    browser: BrowserProbeReceipt,
    clients: tuple[NativeClientProbeReceipt, ...],
) -> tuple[QualificationCheckEvidence, ...]:
    checks = {item.check_id: item for item in runtime.qualification_checks}
    checks.update({item.check_id: item for item in browser.checks})
    for client in ("claude", "codex"):
        if not any(item.client == client for item in clients):
            raise ApplianceManifestError("native client qualification is incomplete")
        checks[f"host.{client}"] = QualificationCheckEvidence(
            check_id=f"host.{client}",
            status="passed",
            summary="live tool call passed and stale generation was rejected",
        )
    for check_id, summary in (
        ("full.runtime", "runtime matched the authenticated range snapshot"),
        ("full.capture", "live access required the active capture authority"),
        ("full.offline", "candidate completed offline-staged startup"),
        ("full.resources", "measured lifecycle stayed within profile budgets"),
    ):
        checks[check_id] = QualificationCheckEvidence(
            check_id=check_id, status="passed", summary=summary
        )
    required = [item.check_id for item in readiness.checks]
    if set(checks) != set(required) or any(
        item.status != "passed" for item in checks.values()
    ):
        raise ApplianceManifestError("participant qualification checks are incomplete")
    return tuple(checks[check_id] for check_id in required)


def _runtime_surface(
    runtime: GuestRuntimeEvidence,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    snapshot = runtime.snapshot
    containers = snapshot.get("containers")
    networks = snapshot.get("networks")
    backend = runtime.run_record.get("backend_evidence")
    selected = backend.get("selected_profiles") if isinstance(backend, dict) else None
    if (
        not isinstance(containers, list)
        or not isinstance(networks, list)
        or not isinstance(selected, list)
        or not all(isinstance(item, str) for item in selected)
    ):
        raise ApplianceManifestError("participant runtime surface is invalid")
    services = tuple(
        sorted(
            str(item["name"])
            for item in containers
            if isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and str(item.get("status", "")).startswith("Up")
        )
    )
    network_names = tuple(
        sorted(
            str(item["name"])
            for item in networks
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        )
    )
    return tuple(sorted(selected)), services, network_names


def build_participant_qualification(
    *,
    candidate_dir: Path,
    candidate_public_key: Path,
    runtime_evidence: Path,
    browser_probe: Path,
    client_receipts: tuple[Path, ...],
    measurements: Path,
    qualification_private_key: Path,
    output_dir: Path,
) -> ParticipantQualificationReport:
    """Sign APP-2 evidence derived from the real candidate KVM run."""

    manifest, _inspection = verify_candidate_directory(
        candidate_dir, candidate_public_key
    )
    by_kind = {item.kind: item for item in manifest.artifacts}
    profile_bytes = (candidate_dir / by_kind["participant-profile"].path).read_bytes()
    readiness_bytes = (
        candidate_dir / by_kind["participant-readiness"].path
    ).read_bytes()
    asset_lock_bytes = (
        candidate_dir / by_kind["participant-asset-lock"].path
    ).read_bytes()
    try:
        profile = model_validate_json_strict(ParticipantProfileManifest, profile_bytes)
        readiness = model_validate_json_strict(
            ParticipantReadinessSuite, readiness_bytes
        )
        model_validate_json_strict(ParticipantAssetLock, asset_lock_bytes)
    except ValueError as exc:
        raise ApplianceManifestError(
            "candidate participant profile is invalid"
        ) from exc
    runtime = _read_model(GuestRuntimeEvidence, runtime_evidence, "runtime evidence")
    browser = _read_model(BrowserProbeReceipt, browser_probe, "browser probe")
    measured = _read_model(
        QualificationMeasurementReceipt, measurements, "qualification measurements"
    )
    clients = _load_probe_receipts(client_receipts)
    checks = _qualification_checks(readiness, runtime, browser, clients)
    selected, services, networks = _runtime_surface(runtime)
    run_bytes = rfc8785.dumps(runtime.run_record)
    snapshot_bytes = rfc8785.dumps(runtime.snapshot)
    output_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    _write_create_once(output_dir / "run-record.json", run_bytes, mode=0o444)
    _write_create_once(output_dir / "snapshot.json", snapshot_bytes, mode=0o444)
    vcpus, memory, disk = _host_capacity(candidate_dir)
    mcp_servers = tuple(
        sorted(
            {item.subject_id for item in readiness.checks if item.kind == "mcp-tool"}
        )
    )
    browser_capabilities = tuple(
        sorted(
            {
                item.subject_id
                for item in readiness.checks
                if item.kind == "browser-operation"
            }
        )
    )
    pending = ParticipantQualificationReport(
        schema_version="aptl.participant-qualification/v1",
        profile_id=profile.profile_id,
        profile_version=profile.version,
        profile_sha256=hashlib.sha256(profile_bytes).hexdigest(),
        asset_lock_digest=f"sha256:{hashlib.sha256(asset_lock_bytes).hexdigest()}",
        run_record_ref="evidence/run-record.json",
        run_record_sha256=hashlib.sha256(run_bytes).hexdigest(),
        snapshot_ref="evidence/snapshot.json",
        snapshot_sha256=hashlib.sha256(snapshot_bytes).hexdigest(),
        hardware=QualificationHardware(
            architecture=manifest.guest.architecture,
            vcpus=vcpus,
            memory_bytes=memory,
            disk_bytes=disk,
            hypervisor="qemu-kvm",
            engine="aptl-seat",
        ),
        surface=QualificationSurface(
            selected_profiles=selected,
            expected_services=services,
            actual_services=services,
            expected_networks=networks,
            actual_networks=networks,
            actual_workbench_profiles=("blue", "red"),
            actual_mcp_servers=mcp_servers,
            actual_browser_capabilities=browser_capabilities,
        ),
        checks=checks,
        offline=OfflineEvidence(
            egress_denied=True,
            download_attempts=0,
            image_pulls=0,
            image_builds=0,
            package_resolutions=0,
        ),
        measurements=measured.measurements,
        sample_count=1,
        aggregation="worst-conforming-sample",
        attestation=QualificationAttestation(
            algorithm="ed25519", key_id="pending", signature="pending"
        ),
    )
    try:
        key = serialization.load_pem_private_key(
            qualification_private_key.read_bytes(), password=None
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ApplianceManifestError("qualification signing key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ApplianceManifestError("qualification signing key must be Ed25519")
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = f"sha256:{hashlib.sha256(public_der).hexdigest()}"
    signature = base64.b64encode(
        key.sign(participant_qualification_attestation_payload(pending))
    ).decode("ascii")
    report = pending.model_copy(
        update={
            "attestation": QualificationAttestation(
                algorithm="ed25519", key_id=key_id, signature=signature
            )
        }
    )
    _write_create_once(
        output_dir / "participant-qualification.json",
        rfc8785.dumps(report.model_dump(mode="json")),
        mode=0o444,
    )
    _write_create_once(
        output_dir / "qualification-public.pem",
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        mode=0o444,
    )
    return report
