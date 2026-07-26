"""CLI boundary for signed disposable-appliance release operations."""

from __future__ import annotations

import json
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
)
from aptl.appliance.manifest import (
    ApplianceManifestError,
    ApplianceReleaseInspection,
    prepare_release_manifest,
    seal_release_directory,
    verify_release_directory,
)
from aptl.appliance.launch import prepare_launch_descriptor
from aptl.appliance.offline import OfflinePayloadError, build_offline_payload

app = typer.Typer(help="Build and verify signed disposable appliance releases.")


def _emit(payload: dict[str, object]) -> None:
    typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def _fail(message: str, exc: Exception) -> None:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code=2) from exc


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
        build_request = GoldenImageBuildRequest.model_validate_json(
            request.read_bytes()
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
        overlay_request = OverlayCreateRequest.model_validate_json(request.read_bytes())
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
