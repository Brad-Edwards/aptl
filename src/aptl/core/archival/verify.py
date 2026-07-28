"""The one canonical sealed-archive verifier (EXP-009 / ADR-050).

Marker presence plus a matching manifest digest is NOT proof the archive is
intact: an attacker who can write run files after the marker is published could
replace a sealed evidence blob while leaving the manifest and marker untouched.
:func:`verify_sealed_archive` closes that gap — it validates the marker's shape
and identity and reads every inventory entry no-follow, verifying its size and
checksum against what the marker committed. Discovery and export both call it, so
neither returns nor packages an archive whose sealed bytes have drifted.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from aptl.core.archival.layout import (
    RUN_MANIFEST_RELPATH,
    SEAL_MARKER_DIGEST_FIELD,
    SEAL_MARKER_RELPATH,
    SEAL_MARKER_SCHEMA_VERSION,
)
from aptl.core.runstore import _validate_id, _validate_relative_path
from aptl.utils.pathsafe import PathContainmentError, read_contained_nofollow

_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UNSEALED_REASONS = frozenset({"not_found", "base_dir_unavailable"})


class SealVerificationError(RuntimeError):
    """Raised when a present seal marker is malformed or its inventory drifted."""


@dataclass(frozen=True)
class VerifiedArchive:
    """The verified identity + closed path set of a sealed archive."""

    run_id: str
    run_version: str
    run_record_digest: str
    inventory_paths: tuple[str, ...]


def verify_sealed_archive(base_dir: Path, run_id: str) -> VerifiedArchive | None:
    """Verify the sealed archive for ``run_id`` under ``base_dir``.

    Returns ``None`` when the run has no seal marker (an unsealed recovery
    candidate). Raises :class:`SealVerificationError` when a present marker is
    malformed, its digest does not match the sealed ``manifest.json``, or any
    inventory entry's bytes do not match the committed size/checksum.
    """
    safe_run_id = _validate_id(run_id, "run_id")
    marker = _read_json(base_dir, f"{safe_run_id}/{SEAL_MARKER_RELPATH}")
    if marker is None:
        return None
    _require_marker_shape(safe_run_id, marker)

    digest = marker[SEAL_MARKER_DIGEST_FIELD]
    manifest = _read_bytes(base_dir, f"{safe_run_id}/{RUN_MANIFEST_RELPATH}")
    if manifest is None:
        raise SealVerificationError(f"sealed run {run_id!r} has no manifest")
    if "sha256:" + hashlib.sha256(manifest).hexdigest() != digest:
        raise SealVerificationError(
            f"sealed run {run_id!r} manifest does not match the marker digest"
        )

    paths = _verify_inventory(base_dir, safe_run_id, marker["inventory"])
    return VerifiedArchive(
        run_id=safe_run_id,
        run_version=str(marker.get("run_version", "")),
        run_record_digest=digest,
        inventory_paths=tuple(paths),
    )


def _require_marker_shape(run_id: str, marker: object) -> None:
    if not isinstance(marker, dict):
        raise SealVerificationError(f"seal marker for {run_id!r} is not an object")
    if marker.get("schema_version") != SEAL_MARKER_SCHEMA_VERSION:
        raise SealVerificationError(f"seal marker for {run_id!r} has an unexpected schema")
    if marker.get("run_id") != run_id:
        raise SealVerificationError(f"seal marker for {run_id!r} binds a different run id")
    if marker.get("seal_state") != "sealed":
        raise SealVerificationError(f"seal marker for {run_id!r} is not in the sealed state")
    if not isinstance(marker.get("inventory"), list) or "completeness" not in marker:
        raise SealVerificationError(f"seal marker for {run_id!r} is missing its inventory")
    digest = marker.get(SEAL_MARKER_DIGEST_FIELD)
    if not isinstance(digest, str) or not _PREFIXED_SHA256_RE.fullmatch(digest):
        raise SealVerificationError(f"seal marker for {run_id!r} has no valid run-record digest")


def _verify_inventory(base_dir: Path, run_id: str, inventory: list) -> list[str]:
    paths: list[str] = []
    for entry in inventory:
        if not isinstance(entry, dict):
            raise SealVerificationError(f"sealed run {run_id!r} has a malformed inventory entry")
        path = entry.get("path")
        checksum = entry.get("checksum") if isinstance(entry.get("checksum"), dict) else {}
        expected_size = entry.get("size_bytes")
        expected_hex = checksum.get("value")
        try:
            safe_rel = _validate_relative_path(str(path))
        except ValueError as exc:
            raise SealVerificationError(
                f"sealed run {run_id!r} inventory path is unsafe: {path!r}"
            ) from exc
        raw = _read_bytes(base_dir, f"{run_id}/{safe_rel}")
        if raw is None:
            raise SealVerificationError(
                f"sealed run {run_id!r} inventory artifact is absent: {safe_rel}"
            )
        if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_hex:
            raise SealVerificationError(
                f"sealed run {run_id!r} inventory artifact {safe_rel} does not match its checksum"
            )
        paths.append(safe_rel)
    return paths


def _read_bytes(base_dir: Path, relative_path: str) -> bytes | None:
    try:
        return read_contained_nofollow(base_dir, relative_path)
    except PathContainmentError as exc:
        if exc.reason in _UNSEALED_REASONS:
            return None
        raise


def _read_json(base_dir: Path, relative_path: str) -> object | None:
    raw = _read_bytes(base_dir, relative_path)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SealVerificationError(f"seal marker at {relative_path} is malformed: {exc}") from exc
