"""Experiment data export: local tar.gz and S3 upload.

Packages an experiment directory into a portable archive with integrity
checksums, and optionally uploads to an S3 bucket with metadata tags.
"""

from __future__ import annotations

import hashlib
import json
import os
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aptl.utils.logging import get_logger

log = get_logger("exporter")


@dataclass
class ExportResult:
    """Result of an export operation."""

    success: bool
    path: str = ""
    size_bytes: int = 0
    checksum_sha256: str = ""
    s3_uri: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Checksums
# ---------------------------------------------------------------------------


def compute_dir_checksums(directory: Path) -> dict[str, str]:
    """Compute SHA-256 checksums for all files in a directory tree.

    Args:
        directory: Root directory to traverse.

    Returns:
        Dict mapping relative file paths to their hex SHA-256 digests.
    """
    checksums: dict[str, str] = {}
    for filepath in sorted(directory.rglob("*")):
        if filepath.is_file():
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            rel = str(filepath.relative_to(directory))
            checksums[rel] = h.hexdigest()
    return checksums


def _file_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a single file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Local tar.gz export
# ---------------------------------------------------------------------------


def export_local(
    exp_dir: Path,
    output_dir: Path | None = None,
    run_id: str = "",
) -> ExportResult:
    """Package an experiment directory into a local tar.gz archive.

    The archive is named ``aptl-experiment-<run_id>.tar.gz`` and placed
    in ``output_dir`` (defaults to the parent of exp_dir).

    The manifest.json is updated with artefact checksums before packaging.

    Args:
        exp_dir: Experiment directory to package.
        output_dir: Where to write the archive. Defaults to exp_dir's parent.
        run_id: Run ID for the filename. Derived from exp_dir.name if empty.

    Returns:
        ExportResult with archive path and checksum.
    """
    if not exp_dir.exists():
        return ExportResult(
            success=False,
            error=f"Experiment directory not found: {exp_dir}",
        )

    if not run_id:
        run_id = exp_dir.name

    if output_dir is None:
        output_dir = exp_dir.parent

    output_dir.mkdir(parents=True, exist_ok=True)

    # Compute checksums for all artefacts
    checksums = compute_dir_checksums(exp_dir)

    # Update manifest with checksums
    manifest_path = exp_dir / "manifest.json"
    if manifest_path.exists():
        try:
            manifest_data = json.loads(manifest_path.read_text())
            manifest_data["artefact_checksums"] = checksums
            manifest_data["exported_at"] = datetime.now(timezone.utc).isoformat()
            manifest_path.write_text(
                json.dumps(manifest_data, indent=2) + "\n",
                encoding="utf-8",
            )
        except json.JSONDecodeError:
            log.warning("Could not update manifest with checksums")

    # Create tar.gz
    archive_name = f"aptl-experiment-{run_id}.tar.gz"
    archive_path = output_dir / archive_name

    log.info("Creating archive: %s", archive_path)

    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(exp_dir, arcname=run_id)

    size = archive_path.stat().st_size
    checksum = _file_sha256(archive_path)

    log.info(
        "Export complete: %s (%d bytes, sha256=%s)",
        archive_path, size, checksum[:16],
    )

    return ExportResult(
        success=True,
        path=str(archive_path),
        size_bytes=size,
        checksum_sha256=checksum,
    )


# ---------------------------------------------------------------------------
# S3 export
# ---------------------------------------------------------------------------


def export_s3(
    exp_dir: Path,
    bucket: str,
    prefix: str = "aptl-experiments",
    run_id: str = "",
    tags: dict[str, str] | None = None,
) -> ExportResult:
    """Export an experiment directory to an S3 bucket.

    First creates a local tar.gz archive, then uploads it to S3 with
    metadata tags. Requires boto3 to be installed.

    The S3 key is: ``<prefix>/<run_id>/aptl-experiment-<run_id>.tar.gz``

    Also uploads the manifest.json separately for easy querying.

    Args:
        exp_dir: Experiment directory to export.
        bucket: S3 bucket name.
        prefix: Key prefix within the bucket.
        run_id: Run ID. Derived from exp_dir.name if empty.
        tags: Additional S3 object tags.

    Returns:
        ExportResult with S3 URI and checksum.
    """
    try:
        import boto3
    except ImportError:
        return ExportResult(
            success=False,
            error=(
                "boto3 is required for S3 export. "
                "Install with: pip install aptl[s3]"
            ),
        )

    if not run_id:
        run_id = exp_dir.name

    # First create local archive
    local_result = export_local(exp_dir, run_id=run_id)
    if not local_result.success:
        return local_result

    archive_path = Path(local_result.path)
    s3_key = f"{prefix.strip('/')}/{run_id}/{archive_path.name}"
    manifest_key = f"{prefix.strip('/')}/{run_id}/manifest.json"

    # Build S3 tags
    all_tags: dict[str, str] = {
        "aptl:run_id": run_id,
        "aptl:checksum_sha256": local_result.checksum_sha256,
        "aptl:exported_at": datetime.now(timezone.utc).isoformat(),
    }
    if tags:
        all_tags.update(tags)

    tag_string = "&".join(f"{k}={v}" for k, v in all_tags.items())

    try:
        s3 = boto3.client("s3")

        # Upload archive
        log.info("Uploading %s to s3://%s/%s", archive_path.name, bucket, s3_key)
        extra_args: dict[str, Any] = {
            "Metadata": {
                "aptl-run-id": run_id,
                "aptl-checksum": local_result.checksum_sha256,
            },
        }
        if tag_string:
            extra_args["Tagging"] = tag_string

        s3.upload_file(
            str(archive_path),
            bucket,
            s3_key,
            ExtraArgs=extra_args,
        )

        # Upload manifest separately for easy querying
        manifest_path = exp_dir / "manifest.json"
        if manifest_path.exists():
            s3.upload_file(
                str(manifest_path),
                bucket,
                manifest_key,
                ExtraArgs={"ContentType": "application/json"},
            )

        s3_uri = f"s3://{bucket}/{s3_key}"
        log.info("Upload complete: %s", s3_uri)

        # Clean up local archive after successful upload
        archive_path.unlink(missing_ok=True)

        return ExportResult(
            success=True,
            path=str(archive_path),
            size_bytes=local_result.size_bytes,
            checksum_sha256=local_result.checksum_sha256,
            s3_uri=s3_uri,
        )

    except Exception as e:
        log.error("S3 upload failed: %s", e)
        return ExportResult(
            success=False,
            path=str(archive_path),
            size_bytes=local_result.size_bytes,
            checksum_sha256=local_result.checksum_sha256,
            error=f"S3 upload failed: {e}",
        )
