"""Run export to local archive and S3.

Packages experiment run directories into tar.gz archives with
SHA-256 checksums, and optionally uploads to S3.

Export is read-only over the run archive (ADR-050 "Export and projections are
read-only after sealing"): the checksum manifest travels *inside* the archive as
a synthetic member and is never written back into the source run directory,
which for a sealed attempt is immutable.
"""

import hashlib
import io
import json
import tarfile
from pathlib import Path

from aptl.core.archival.legacy_manifest import summarize_manifest
from aptl.utils.logging import get_logger

log = get_logger("exporter")

try:
    import boto3 as boto3
except ImportError:
    boto3 = None  # type: ignore[assignment]


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest for a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _sealed_members(store: "LocalRunStore", run_id: str) -> list[str] | None:
    """Return the verified run-relative members to export for a sealed run.

    ``None`` means the run is unsealed (legacy) and is packaged whole. For a
    sealed run this verifies the archive and returns exactly the seal marker, the
    manifest, and every verified inventory path.
    """
    from aptl.core.archival.layout import RUN_MANIFEST_RELPATH, SEAL_MARKER_RELPATH
    from aptl.core.archival.verify import verify_sealed_archive

    # ``verify_sealed_archive`` returns ``None`` for an unsealed run (no seal
    # marker) and raises when a present marker is malformed or its bytes drifted.
    verified = verify_sealed_archive(store.base_dir, run_id)
    if verified is None:
        return None
    return sorted({RUN_MANIFEST_RELPATH, SEAL_MARKER_RELPATH, *verified.inventory_paths})


def _member_checksums(run_path: Path, members: list[str] | None) -> dict[str, str]:
    """Compute SHA-256 checksums over the exported members (no source mutation)."""
    if members is None:
        return {
            str(item.relative_to(run_path)): _sha256_file(item)
            for item in sorted(run_path.rglob("*"))
            if item.is_file()
        }
    return {member: _sha256_file(run_path / member) for member in members}


def export_local(
    store: "LocalRunStore",
    run_id: str,
    output_dir: Path,
) -> Path:
    """Export a run as a tar.gz archive with SHA-256 checksums.

    Args:
        store: The run store containing the run data.
        run_id: The run identifier.
        output_dir: Directory to write the archive to.

    Returns:
        Path to the created tar.gz archive.

    Raises:
        FileNotFoundError: If the run directory does not exist.
    """
    from aptl.core.runstore import LocalRunStore

    run_path = store.get_run_path(run_id)
    if not run_path.exists():
        raise FileNotFoundError(f"Run directory not found: {run_path}")

    output_dir.mkdir(parents=True, exist_ok=True)

    # A sealed run is packaged as EXACTLY its verified seal inventory: the seal is
    # verified (marker shape/identity, manifest digest, and every inventory
    # artifact's size/checksum) and only those bytes travel, so tampered or
    # non-inventory files cannot leave the system under an apparently sealed
    # archive (ADR-050). An unsealed (legacy) run keeps whole-directory packaging.
    members = _sealed_members(store, run_id)
    checksums = _member_checksums(run_path, members)

    checksums_bytes = "".join(
        f"{digest}  {name}\n" for name, digest in sorted(checksums.items())
    ).encode("utf-8")

    # Create tar.gz archive; the checksum manifest is a synthetic member added to
    # the archive only, never written back into the run directory.
    archive_name = f"{run_id}.tar.gz"
    archive_path = output_dir / archive_name

    with tarfile.open(archive_path, "w:gz") as tar:
        if members is None:
            tar.add(run_path, arcname=run_id)
        else:
            for member in members:
                tar.add(run_path / member, arcname=f"{run_id}/{member}")
        info = tarfile.TarInfo(name=f"{run_id}/checksums.sha256")
        info.size = len(checksums_bytes)
        info.mode = 0o600
        tar.addfile(info, io.BytesIO(checksums_bytes))

    log.info("Exported run %s to %s (%d files)", run_id, archive_path, len(checksums))
    return archive_path


def export_s3(
    store: "LocalRunStore",
    run_id: str,
    bucket: str,
    prefix: str,
    output_dir: Path,
) -> str:
    """Export a run to S3.

    Creates a local archive first, then uploads both the archive and
    the manifest.json to S3.

    Args:
        store: The run store containing the run data.
        run_id: The run identifier.
        bucket: S3 bucket name.
        prefix: S3 key prefix (e.g. "runs/").
        output_dir: Local directory for the intermediate archive.

    Returns:
        S3 URI of the uploaded archive (s3://bucket/prefix/run_id.tar.gz).

    Raises:
        ImportError: If boto3 is not installed.
        FileNotFoundError: If the run directory does not exist.
    """
    if boto3 is None:
        raise ImportError(
            "boto3 is required for S3 export. "
            "Install it with: pip install aptl[s3]"
        )

    # Create local archive first
    archive_path = export_local(store, run_id, output_dir)

    # Read manifest for S3 metadata tags through the version-dispatching adapter
    # so both the RAES record and legacy shapes yield consistent tags.
    run_path = store.get_run_path(run_id)
    manifest_path = run_path / "manifest.json"
    manifest = {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    summary = summarize_manifest(manifest)

    s3 = boto3.client("s3")

    # Build S3 keys
    if prefix and not prefix.endswith("/"):
        prefix = prefix + "/"
    archive_key = f"{prefix}{run_id}.tar.gz"
    manifest_key = f"{prefix}{run_id}/manifest.json"

    # Build metadata tags from the normalized summary. ``?`` (unknown) is
    # dropped so a tag never carries a placeholder.
    tags = {
        "run_id": run_id,
        "scenario_id": summary.scenario_id,
        "scenario_name": summary.scenario_name,
    }
    tagging = "&".join(f"{k}={v}" for k, v in tags.items() if v and v != "?")

    # Upload archive
    log.info("Uploading %s to s3://%s/%s", archive_path, bucket, archive_key)
    extra_args = {}
    if tagging:
        extra_args["Tagging"] = tagging
    s3.upload_file(str(archive_path), bucket, archive_key, ExtraArgs=extra_args)

    # Upload manifest
    if manifest_path.exists():
        log.info("Uploading manifest to s3://%s/%s", bucket, manifest_key)
        s3.upload_file(str(manifest_path), bucket, manifest_key)

    s3_uri = f"s3://{bucket}/{archive_key}"
    log.info("S3 export complete: %s", s3_uri)
    return s3_uri
