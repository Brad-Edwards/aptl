"""CLI boundary for signed disposable-appliance release operations."""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict
from pathlib import Path

import typer
from pydantic import ValidationError

from aptl.appliance.bootstrap import (
    ApplianceBootstrapError,
    initialize_overlay_state,
)
from aptl.appliance.build import (
    ApplianceBuildError,
    GoldenImageBuildRequest,
    OverlayCreateRequest,
    build_golden_image,
    create_disposable_overlay,
    prepare_golden_image_request,
)
from aptl.appliance.build_host import check_build_host
from aptl.appliance.distribution import (
    ApplianceDistributionError,
    fetch_distribution_artifact,
    github_distribution_urls,
    reconstruct_distribution,
    split_distribution_artifact,
)
from aptl.appliance.download import ApplianceDownloadError, stage_https_artifact
from aptl.appliance.launch import prepare_launch_descriptor, verify_launch_descriptor
from aptl.appliance.loopback_proxy import build_proxy_bindings, serve_proxy_bindings
from aptl.appliance.manifest import (
    ApplianceManifestError,
    ApplianceReleaseInspection,
    prepare_release_manifest,
    seal_release_directory,
    verify_release_directory,
)
from aptl.appliance.offline import OfflinePayloadError, build_offline_payload
from aptl.utils.strict_json import loads_strict, model_validate_json_strict

app = typer.Typer(help="Build and verify signed disposable appliance releases.")


def _emit(payload: dict[str, object]) -> None:
    """Emit one stable machine-readable success record."""

    typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def _fail(message: str, exc: Exception) -> None:
    """Emit one bounded error and terminate the command."""

    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code=2) from exc


@app.command("proxy-loopback", hidden=True)
def proxy_loopback(
    launch_descriptor: Path = typer.Option(..., "--launch-descriptor"),
    release_public_key: Path = typer.Option(..., "--release-public-key"),
    qualification_public_key: Path = typer.Option(..., "--qualification-public-key"),
    adapter_address: str = typer.Option("10.0.2.15", "--adapter-address"),
) -> None:
    """Expose verified guest loopback publications on the private VM adapter."""

    try:
        launch = verify_launch_descriptor(
            launch_descriptor,
            release_public_key,
            qualification_public_key,
        )
        bindings = build_proxy_bindings(
            launch.boundary_policy,
            adapter_address=adapter_address,
        )
        serve_proxy_bindings(bindings)
    except (ApplianceManifestError, OSError, ValueError) as exc:
        _fail("guest publication proxy failed", exc)


@app.command("doctor")
def doctor(
    build_root: Path = typer.Option(Path("."), "--build-root"),
) -> None:
    """Report image-build prerequisites without changing the host."""

    report = check_build_host(build_root=build_root)
    _emit(
        {
            "passed": report.passed,
            "findings": [
                {"code": finding.code, "passed": finding.passed}
                for finding in report.findings
            ],
        }
    )


@app.command("write-boundary-policy")
def write_boundary_policy(output: Path = typer.Option(..., "--output")) -> None:
    """Write the canonical full-TechVault appliance boundary policy once."""

    from aptl.appliance.policy import write_full_techvault_boundary_policy

    try:
        policy = write_full_techvault_boundary_policy(output)
    except (OSError, ValueError) as exc:
        _fail("boundary policy creation failed", exc)
    _emit({"created": True, "policy_id": policy.policy_id})


@app.command("stage-download")
def stage_download(
    url: str = typer.Option(..., "--url"),
    cache_dir: Path = typer.Option(..., "--cache-dir"),
    filename: str = typer.Option(..., "--filename"),
    sha256: str = typer.Option(..., "--sha256"),
    size_bytes: int = typer.Option(..., "--size-bytes"),
) -> None:
    """Resume and verify one HTTPS artifact into the immutable local cache."""

    try:
        result = stage_https_artifact(
            url=url,
            cache_dir=cache_dir,
            filename=filename,
            sha256=sha256,
            size_bytes=size_bytes,
        )
    except ApplianceDownloadError as exc:
        _fail(str(exc), exc)
    _emit(
        {
            "path": str(result.path),
            "reused": result.reused,
            "sha256": result.sha256,
            "size_bytes": result.size_bytes,
        }
    )


@app.command("split-distribution")
def split_distribution(
    source: Path = typer.Option(..., "--source"),
    output_dir: Path = typer.Option(..., "--output-dir"),
    release_id: str = typer.Option(..., "--release-id"),
    manifest_digest: str = typer.Option(..., "--manifest-digest"),
    private_key: Path = typer.Option(..., "--private-key"),
    chunk_size: int = typer.Option(1900 * 1024**2, "--chunk-size"),
) -> None:
    """Create signed, ordered transport chunks for canonical artifact bytes."""

    try:
        result = split_distribution_artifact(
            source=source,
            output_dir=output_dir,
            release_id=release_id,
            manifest_digest=manifest_digest,
            private_key=private_key,
            chunk_size=chunk_size,
        )
    except ApplianceDistributionError as exc:
        _fail(str(exc), exc)
    _emit(
        {
            "created": True,
            "artifact_sha256": result.index.artifact_sha256,
            "chunks": len(result.index.chunks),
            "index": result.index_path.name,
            "signature": result.signature_path.name,
        }
    )


@app.command("reconstruct-distribution")
def reconstruct_distribution_command(
    index: Path = typer.Option(..., "--index"),
    signature: Path = typer.Option(..., "--signature"),
    chunks_dir: Path = typer.Option(..., "--chunks-dir"),
    public_key: Path = typer.Option(..., "--public-key"),
    output: Path = typer.Option(..., "--output"),
) -> None:
    """Authenticate chunks and atomically reconstruct canonical artifact bytes."""

    try:
        reconstructed = reconstruct_distribution(
            index_path=index,
            signature_path=signature,
            chunks_dir=chunks_dir,
            public_key=public_key,
            output=output,
        )
    except ApplianceDistributionError as exc:
        _fail(str(exc), exc)
    _emit({"reconstructed": True, "output": reconstructed.name})


@app.command("fetch-distribution")
def fetch_distribution_command(
    repository: str = typer.Option(..., "--repository"),
    tag: str = typer.Option(..., "--tag"),
    release_id: str = typer.Option(..., "--release-id"),
    artifact_name: str = typer.Option(..., "--artifact-name"),
    public_key: Path = typer.Option(..., "--public-key"),
    cache_dir: Path = typer.Option(..., "--cache-dir"),
    output: Path = typer.Option(..., "--output"),
) -> None:
    """Fetch and automatically reconstruct a public GitHub Release artifact."""

    try:
        index_url, signature_url, chunks_base_url = github_distribution_urls(
            repository=repository,
            tag=tag,
            artifact_name=artifact_name,
        )
        reconstructed = fetch_distribution_artifact(
            index_url=index_url,
            signature_url=signature_url,
            chunks_base_url=chunks_base_url,
            expected_release_id=release_id,
            cache_dir=cache_dir,
            public_key=public_key,
            output=output,
        )
    except ApplianceDistributionError as exc:
        _fail(str(exc), exc)
    _emit({"reconstructed": True, "output": str(reconstructed)})


@app.command("build")
def build(
    request: Path = typer.Option(
        ...,
        "--request",
        help="Strict checksum-pinned golden-image build request.",
    ),
    build_root: Path = typer.Option(
        Path("."),
        "--build-root",
        help="Contained directory holding build inputs and output.",
    ),
) -> None:
    """Build a new read-only golden image using offline fixed-argv tooling."""

    try:
        build_request = model_validate_json_strict(
            GoldenImageBuildRequest,
            request.read_bytes(),
        )
    except (OSError, ValidationError, ValueError) as exc:
        _fail("invalid appliance build request", exc)
    try:
        result = build_golden_image(build_root, build_request)
    except ApplianceBuildError as exc:
        _fail(str(exc), exc)
    _emit(
        {
            "built": True,
            "sha256": result.sha256,
            "size_bytes": result.size_bytes,
        }
    )


@app.command("plan-build")
def plan_build(
    build_root: Path = typer.Option(..., "--build-root"),
    base_image: str = typer.Option(..., "--base-image"),
    offline_payload: str = typer.Option(..., "--offline-payload"),
    provisioner: str = typer.Option(..., "--provisioner"),
    scanner: str = typer.Option(..., "--scanner"),
    output_image: str = typer.Option(..., "--output-image"),
    inventory_output: str = typer.Option(..., "--inventory-output"),
    request: str = typer.Option(..., "--request"),
    virtual_size_bytes: int = typer.Option(250 * 1024**3, "--virtual-size-bytes"),
) -> None:
    """Derive a checksum-pinned build request from staged exact inputs."""

    try:
        planned = prepare_golden_image_request(
            build_root,
            base_image_path=base_image,
            offline_payload_path=offline_payload,
            provisioner_path=provisioner,
            scanner_path=scanner,
            output_image_path=output_image,
            inventory_output_path=inventory_output,
            virtual_size_bytes=virtual_size_bytes,
            request_path=request,
        )
    except (ApplianceBuildError, OSError, ValueError) as exc:
        _fail("golden image build planning failed", exc)
    _emit({"planned": True, "request": request, "base": planned.base_image_digest})


@app.command("bundle")
def bundle(
    staging_dir: Path = typer.Option(
        ...,
        "--staging-dir",
        help="Closed directory of already-resolved wheels, images, and assets.",
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        help="New offline-payload tar path.",
    ),
) -> None:
    """Assemble a byte-reproducible first-boot payload without network access."""

    try:
        result = build_offline_payload(staging_dir, output)
    except OfflinePayloadError as exc:
        _fail(str(exc), exc)
    _emit(
        {
            "built": True,
            "sha256": result.sha256,
            "size_bytes": result.size_bytes,
        }
    )


@app.command("create-overlay")
def create_overlay(
    request: Path = typer.Option(
        ...,
        "--request",
        help="Strict content-pinned disposable-overlay request.",
    ),
    appliance_root: Path = typer.Option(
        Path("."),
        "--appliance-root",
        help="Contained directory holding the golden image and instances.",
    ),
) -> None:
    """Create a mutable qcow2 overlay backed by a verified read-only golden."""

    try:
        overlay_request = model_validate_json_strict(
            OverlayCreateRequest, request.read_bytes()
        )
    except (OSError, ValidationError, ValueError) as exc:
        _fail("invalid disposable overlay request", exc)
    try:
        result = create_disposable_overlay(appliance_root, overlay_request)
    except ApplianceBuildError as exc:
        _fail(str(exc), exc)
    _emit(
        {
            "created": True,
            "golden_image_digest": result.golden_image_digest,
        }
    )


@app.command("prepare-launch")
def prepare_launch(
    release_dir: Path = typer.Option(..., "--release-dir"),
    public_key: Path = typer.Option(..., "--public-key"),
    qualification_public_key: Path = typer.Option(
        ...,
        "--qualification-public-key",
    ),
    output: Path = typer.Option(..., "--output"),
    host_observation_id: str = typer.Option(..., "--host-observation-id"),
) -> None:
    """Verify a release and create its immutable first-boot descriptor."""

    try:
        descriptor = prepare_launch_descriptor(
            release_dir,
            public_key,
            qualification_public_key,
            output,
            host_observation_id=host_observation_id,
        )
    except ApplianceManifestError as exc:
        _fail(str(exc), exc)
    _emit(
        {
            "prepared": True,
            "release_id": descriptor.release_id,
            "manifest_digest": descriptor.manifest_digest,
            "payload_digest": descriptor.payload_digest,
        }
    )


@app.command("prepare-candidate")
def prepare_candidate(
    candidate_dir: Path = typer.Option(..., "--candidate-dir"),
    template: Path = typer.Option(..., "--template"),
) -> None:
    """Prepare a qualification-only candidate that production rejects."""

    from aptl.appliance.candidate import prepare_candidate_manifest

    try:
        manifest = prepare_candidate_manifest(candidate_dir, template)
    except (ApplianceManifestError, OSError, ValueError) as exc:
        _fail("candidate preparation failed", exc)
    _emit({"prepared": True, "candidate_id": manifest.candidate_id})


@app.command("seal-candidate")
def seal_candidate_command(
    candidate_dir: Path = typer.Option(..., "--candidate-dir"),
    private_key: Path = typer.Option(..., "--private-key"),
) -> None:
    """Sign a candidate with an explicitly non-production trust anchor."""

    from aptl.appliance.candidate import seal_candidate

    try:
        signature = seal_candidate(candidate_dir, private_key)
    except (ApplianceManifestError, OSError, ValueError) as exc:
        _fail("candidate sealing failed", exc)
    _emit({"sealed": True, "manifest_digest": signature.manifest_digest})


@app.command("verify-candidate")
def verify_candidate_command(
    candidate_dir: Path = typer.Option(..., "--candidate-dir"),
    public_key: Path = typer.Option(..., "--public-key"),
) -> None:
    """Verify the complete qualification-only candidate without launching it."""

    from aptl.appliance.candidate import verify_candidate_directory

    try:
        manifest, inspection = verify_candidate_directory(candidate_dir, public_key)
    except (ApplianceManifestError, OSError, ValueError) as exc:
        _fail("candidate verification failed", exc)
    _emit(
        {
            "verified": True,
            "candidate_id": manifest.candidate_id,
            "manifest_digest": inspection.manifest_digest,
            "payload_digest": inspection.payload_digest,
        }
    )


@app.command("prepare-candidate-launch", hidden=True)
def prepare_candidate_launch(
    candidate_dir: Path = typer.Option(..., "--candidate-dir"),
    public_key: Path = typer.Option(..., "--public-key"),
    output: Path = typer.Option(..., "--output"),
    host_observation_id: str = typer.Option(..., "--host-observation-id"),
) -> None:
    """Create a development-only candidate launch projection."""

    from aptl.appliance.candidate import prepare_candidate_launch_descriptor

    try:
        descriptor = prepare_candidate_launch_descriptor(
            candidate_dir,
            public_key,
            output,
            host_observation_id=host_observation_id,
        )
    except (ApplianceManifestError, OSError, ValueError) as exc:
        _fail("candidate launch preparation failed", exc)
    _emit({"prepared": True, "candidate_id": descriptor.release_id})


@app.command("record-machine-drill")
def record_machine_drill_command(
    candidate_dir: Path = typer.Option(..., "--candidate-dir"),
    candidate_public_key: Path = typer.Option(..., "--candidate-public-key"),
    seat_root: list[Path] = typer.Option(..., "--seat-root"),
    probe_receipt: list[Path] = typer.Option(..., "--probe-receipt"),
    failed_candidate_receipt: Path = typer.Option(..., "--failed-candidate-receipt"),
    output: Path = typer.Option(..., "--output"),
) -> None:
    """Record reset/revocation evidence from one real qualification machine."""

    from aptl.appliance.qualification import record_machine_drill

    try:
        report = record_machine_drill(
            candidate_dir=candidate_dir,
            candidate_public_key=candidate_public_key,
            seat_roots=tuple(seat_root),
            probe_receipts=tuple(probe_receipt),
            failed_candidate_receipt=failed_candidate_receipt,
            output=output,
        )
    except (ApplianceManifestError, OSError, ValueError) as exc:
        _fail("machine drill recording failed", exc)
    _emit({"recorded": True, "machine_id": report.machine_id})


@app.command("aggregate-machine-drills")
def aggregate_machine_drills_command(
    candidate_dir: Path = typer.Option(..., "--candidate-dir"),
    candidate_public_key: Path = typer.Option(..., "--candidate-public-key"),
    report: list[Path] = typer.Option(..., "--report"),
    output: Path = typer.Option(..., "--output"),
) -> None:
    """Aggregate two independently produced reports for production sealing."""

    from aptl.appliance.qualification import aggregate_machine_drills

    try:
        drill = aggregate_machine_drills(
            candidate_dir=candidate_dir,
            candidate_public_key=candidate_public_key,
            reports=tuple(report),
            output=output,
        )
    except (ApplianceManifestError, OSError, ValueError) as exc:
        _fail("machine drill aggregation failed", exc)
    _emit({"aggregated": True, "machines": len(drill.machines)})


@app.command("build-participant-qualification")
def build_participant_qualification_command(
    candidate_dir: Path = typer.Option(..., "--candidate-dir"),
    candidate_public_key: Path = typer.Option(..., "--candidate-public-key"),
    runtime_evidence: Path = typer.Option(..., "--runtime-evidence"),
    browser_probe: Path = typer.Option(..., "--browser-probe"),
    client_receipt: list[Path] = typer.Option(..., "--client-receipt"),
    measurements: Path = typer.Option(..., "--measurements"),
    qualification_private_key: Path = typer.Option(..., "--qualification-private-key"),
    output_dir: Path = typer.Option(..., "--output-dir"),
) -> None:
    """Sign a participant report from observed real-candidate evidence."""

    from aptl.appliance.qualification import build_participant_qualification

    try:
        report = build_participant_qualification(
            candidate_dir=candidate_dir,
            candidate_public_key=candidate_public_key,
            runtime_evidence=runtime_evidence,
            browser_probe=browser_probe,
            client_receipts=tuple(client_receipt),
            measurements=measurements,
            qualification_private_key=qualification_private_key,
            output_dir=output_dir,
        )
    except (ApplianceManifestError, OSError, ValueError) as exc:
        _fail("participant qualification failed", exc)
    _emit({"qualified": True, "profile_id": report.profile_id})


@app.command("seal")
def seal(
    release_dir: Path = typer.Option(
        ...,
        "--release-dir",
        help="Staged release directory containing a canonical manifest.",
    ),
    private_key: Path = typer.Option(
        ...,
        "--private-key",
        help="External Ed25519 release signing key; never copied into the release.",
    ),
    qualification_public_key: Path = typer.Option(
        ...,
        "--qualification-public-key",
        help="External Ed25519 trust anchor for APP-2 qualification evidence.",
    ),
) -> None:
    """Validate and seal a staged appliance release."""

    try:
        inspection = seal_release_directory(
            release_dir,
            private_key,
            qualification_public_key_path=qualification_public_key,
        )
    except ApplianceManifestError as exc:
        _fail(str(exc), exc)
    _emit(
        {
            "sealed": True,
            "release_id": inspection.release_id,
            "manifest_digest": inspection.manifest_digest,
            "payload_digest": inspection.payload_digest,
        }
    )


@app.command("prepare")
def prepare(
    release_dir: Path = typer.Option(
        ...,
        "--release-dir",
        help="Directory containing all staged release artifacts.",
    ),
    template: Path = typer.Option(
        ...,
        "--template",
        help="External strict metadata template; artifact identities are derived.",
    ),
) -> None:
    """Derive and write the canonical unsigned manifest from staged bytes."""

    try:
        manifest = prepare_release_manifest(release_dir, template)
    except ApplianceManifestError as exc:
        _fail(str(exc), exc)
    _emit(
        {
            "prepared": True,
            "release_id": manifest.release_id,
            "payload_digest": manifest.payload_digest,
            "artifact_count": len(manifest.artifacts),
        }
    )


def _verified_inspection(
    release_dir: Path,
    public_key: Path,
    qualification_public_key: Path,
) -> ApplianceReleaseInspection:
    """Verify a release or translate its bounded error to the CLI."""

    try:
        return verify_release_directory(
            release_dir,
            public_key,
            qualification_public_key_path=qualification_public_key,
        )
    except ApplianceManifestError as exc:
        _fail(str(exc), exc)


@app.command("verify")
def verify(
    release_dir: Path = typer.Option(..., "--release-dir"),
    public_key: Path = typer.Option(
        ...,
        "--public-key",
        help="Configured Ed25519 release trust anchor.",
    ),
    qualification_public_key: Path = typer.Option(
        ...,
        "--qualification-public-key",
        help="Independent Ed25519 trust anchor for APP-2 qualification.",
    ),
) -> None:
    """Fail closed unless the complete release and evidence verify."""

    inspection = _verified_inspection(
        release_dir,
        public_key,
        qualification_public_key,
    )
    _emit(
        {
            "passed": True,
            "release_id": inspection.release_id,
            "aptl_version": inspection.aptl_version,
            "manifest_digest": inspection.manifest_digest,
            "payload_digest": inspection.payload_digest,
        }
    )


@app.command("inspect")
def inspect(
    release_dir: Path = typer.Option(..., "--release-dir"),
    public_key: Path = typer.Option(
        ...,
        "--public-key",
        help="Configured Ed25519 release trust anchor.",
    ),
    qualification_public_key: Path = typer.Option(
        ...,
        "--qualification-public-key",
        help="Independent Ed25519 trust anchor for APP-2 qualification.",
    ),
) -> None:
    """Print the bounded host/readiness projection of a verified release."""

    inspection = _verified_inspection(
        release_dir,
        public_key,
        qualification_public_key,
    )
    _emit(asdict(inspection))


@app.command("bootstrap-overlay", hidden=True)
def bootstrap_overlay(
    state_dir: Path = typer.Option(
        Path("/var/lib/aptl/overlay"),
        "--state-dir",
        help="Guest-only mutable state directory on the disposable overlay.",
    ),
) -> None:
    """Create per-overlay identity once without exposing its credential."""

    try:
        identity = initialize_overlay_state(state_dir)
    except ApplianceBootstrapError as exc:
        _fail(str(exc), exc)
    _emit({"initialized": True, "instance_id": identity.instance_id})


@app.command("assemble-inputs")
def assemble_inputs(
    staging_dir: Path = typer.Option(...),
    wheelhouse: Path = typer.Option(...),
    image_archive: Path = typer.Option(...),
    image_roles: Path = typer.Option(...),
    target_python_version: str | None = typer.Option(None, "--target-python-version"),
    target_architecture: str | None = typer.Option(None, "--target-architecture"),
) -> None:
    """Build canonical package inputs for an image builder, without a VM."""
    from aptl.appliance.inputs import stage_canonical_inputs
    from aptl.utils.deterministic_archive import hash_file_nofollow

    try:
        inputs = stage_canonical_inputs(
            staging=staging_dir,
            wheelhouse=wheelhouse,
            image_archive=image_archive,
            image_roles=loads_strict(image_roles.read_bytes()),
            target_python_version=target_python_version,
            target_architecture=target_architecture,
        )
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        _fail("canonical input assembly failed", exc)
    _emit(
        {
            "schema_version": inputs.schema_version,
            "qualification": "inputs-only",
            "sha256": hash_file_nofollow(staging_dir / "inputs.json")[0],
        }
    )


@app.command("acquire-images")
def acquire_images(
    image_archive: Path = typer.Option(..., "--image-archive"),
    image_roles: Path = typer.Option(..., "--image-roles"),
) -> None:
    """Acquire and content-pin the full canonical TechVault image closure."""

    from aptl.appliance.inputs import acquire_canonical_images

    try:
        roles = acquire_canonical_images(
            image_archive=image_archive,
            image_roles=image_roles,
        )
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        _fail("canonical image acquisition failed", exc)
    _emit({"acquired": True, "roles": len(roles)})


@app.command("validate-inputs")
def validate_inputs(staging_dir: Path = typer.Option(...)) -> None:
    """Verify nested content, locked wheels and built outputs on the target."""
    from aptl.appliance.inputs import validate_canonical_inputs

    try:
        inputs = validate_canonical_inputs(staging_dir)
    except (ValueError, OSError, KeyError) as exc:
        _fail("canonical input validation failed", exc)
    _emit(
        {
            "valid": True,
            "qualification": inputs.qualification,
            "scenario_pack": inputs.scenario_pack.pack_id,
        }
    )


@app.command("verify-redistribution-review")
def verify_redistribution_review(
    release_dir: Path = typer.Option(..., "--release-dir"),
    notices_output: Path = typer.Option(..., "--notices-output"),
) -> None:
    """Require exact redistribution approval and render its public notices."""
    from aptl.appliance.inputs import CanonicalInputs
    from aptl.appliance.manifest import _write_create_once
    from aptl.appliance.models import ApplianceReleaseManifest
    from aptl.appliance.redistribution import (
        RedistributionReview,
        render_third_party_notices,
        validate_redistribution_review,
    )
    from aptl.appliance.release_validation import read_release_artifact
    from aptl.utils.strict_json import model_validate_json_strict

    try:
        manifest = model_validate_json_strict(
            ApplianceReleaseManifest,
            read_release_artifact(release_dir, "manifest.json"),
        )
        artifacts = {artifact.kind: artifact for artifact in manifest.artifacts}
        inputs = model_validate_json_strict(
            CanonicalInputs,
            read_release_artifact(release_dir, artifacts["canonical-inputs"].path),
        )
        review = model_validate_json_strict(
            RedistributionReview,
            read_release_artifact(release_dir, artifacts["redistribution-review"].path),
        )
        validate_redistribution_review(review, manifest, inputs)
        _write_create_once(
            notices_output,
            render_third_party_notices(review).encode(),
            mode=0o444,
        )
    except (
        ApplianceManifestError,
        KeyError,
        OSError,
        ValueError,
        ValidationError,
    ) as exc:
        _fail("redistribution review failed", exc)
    _emit({"approved": True, "notices": str(notices_output)})
