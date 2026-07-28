"""The atomic seal marker and its bounded inventory (EXP-009 / ADR-050 "A seal
marker is the atomic commit point").

A run is discoverable as sealed only after a store-owned commit marker has been
atomically published. The marker binds the canonical run-record digest and
version, every included artifact's relative path / media type / size / checksum,
the applicable contract versions, and an explicit completeness/limitation
statement. Directory enumeration is never the authority for membership; this
closed inventory is.

This module builds the marker payload and inventory (reading and checksumming
bytes through the store's descriptor-relative no-follow boundary). The store
publishes it create-once/no-replace and durably (:meth:`LocalRunStore.commit_seal_marker`);
the coordinator sequences prepare -> commit -> index.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from aptl.core.archival.layout import (
    SEAL_MARKER_DIGEST_FIELD,
    SEAL_MARKER_SCHEMA_VERSION,
)
from aptl.core.runstore import LocalRunStore, _validate_id, _validate_relative_path
from aptl.utils.pathsafe import read_contained_nofollow

__all__ = [
    "SEAL_MARKER_SCHEMA_VERSION",
    "SEAL_STATE_SEALED",
    "SealInventoryEntry",
    "SealLimitation",
    "SealMarkerInputs",
    "SealedArtifactSpec",
    "SealIntegrityError",
    "build_inventory_entry",
    "build_seal_marker",
]

#: The seal-state a committed marker asserts. Distinct from
#: ``ExperimentRunModel.run_status`` — the record keeps its real terminal
#: outcome; only the marker asserts the archive is sealed (ADR-050).
SEAL_STATE_SEALED = "sealed"

_MAX_MEDIA_TYPE = 128
_MAX_ROLE = 64


class SealIntegrityError(RuntimeError):
    """Raised when a sealed artifact's bytes disagree with its claimed identity.

    ADR-050: the sealer verifies bytes and digests before commit. A
    ``SealedArtifactSpec`` may carry the checksum/size an owner-native RAES
    artifact reference claims; if the on-disk bytes do not match, the archive
    is inconsistent and must not be sealed — a conformant manifest claiming one
    digest while the marker commits different bytes is exactly the failure this
    check exists to catch.
    """


@dataclass(frozen=True)
class SealedArtifactSpec:
    """One already-written run-relative artifact the seal binds.

    ``path`` is the run-relative POSIX path; ``role`` is a logical role
    (``evidence-record``, ``evidence-blob``, ``provenance``, ``correlation``,
    ``evaluator``, ``lifecycle``); ``media_type`` is its content type. The bytes
    are read and checksummed as-is — the sealer never mutates a source artifact.

    ``expected_sha256`` / ``expected_size_bytes`` are the identity an owner-native
    RAES artifact reference (or acquisition receipt) claims for these bytes. When
    supplied, :func:`build_inventory_entry` joins them against the on-disk bytes
    and refuses to seal on any discrepancy.
    """

    path: str
    media_type: str
    role: str
    expected_sha256: str | None = None
    expected_size_bytes: int | None = None

    @classmethod
    def from_artifact_ref(
        cls, *, run_relative_path: str, artifact_ref: object, role: str
    ) -> "SealedArtifactSpec":
        """Build a spec whose claimed identity comes from a RAES artifact ref.

        ``artifact_ref`` is an ``ExperimentArtifactRefModel`` (media type,
        checksum, size); binding the seal inventory to it makes the RAES record
        the authority for what the sealed bytes must be, so a divergent archive
        is rejected rather than sealed.
        """
        return cls(
            path=run_relative_path,
            media_type=artifact_ref.media_type,
            role=role,
            expected_sha256=artifact_ref.checksum.value,
            expected_size_bytes=artifact_ref.size_bytes,
        )


@dataclass(frozen=True)
class SealInventoryEntry:
    """A closed, bounded seal-inventory entry over one sealed artifact."""

    path: str
    media_type: str
    size_bytes: int
    checksum_algorithm: str
    checksum_value: str
    role: str

    def projection(self) -> dict[str, object]:
        return {
            "path": self.path,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
            "checksum": {
                "algorithm": self.checksum_algorithm,
                "value": self.checksum_value,
            },
            "role": self.role,
        }


@dataclass(frozen=True)
class SealLimitation:
    """One accepted limitation disclosed in the completeness statement."""

    code: str
    detail: str

    def projection(self) -> dict[str, str]:
        return {"code": self.code, "detail": self.detail}


def build_inventory_entry(
    store: LocalRunStore, run_id: str, spec: SealedArtifactSpec
) -> SealInventoryEntry:
    """Read ``spec``'s bytes no-follow, verify presence, and checksum them.

    Raises :class:`~aptl.utils.pathsafe.PathContainmentError` if the artifact is
    absent or escapes the run directory — a seal never lists bytes it could not
    read (ADR-050 "verifies bytes and digests ... before commit").
    """
    safe_run_id = _validate_id(run_id, "run_id")
    safe_rel = _validate_relative_path(spec.path)
    if not isinstance(spec.media_type, str) or not 0 < len(spec.media_type) <= _MAX_MEDIA_TYPE:
        raise ValueError(f"invalid sealed-artifact media_type: {spec.media_type!r}")
    if not isinstance(spec.role, str) or not 0 < len(spec.role) <= _MAX_ROLE:
        raise ValueError(f"invalid sealed-artifact role: {spec.role!r}")
    raw = read_contained_nofollow(store.base_dir, f"{safe_run_id}/{safe_rel}")
    size_bytes = len(raw)
    checksum_value = hashlib.sha256(raw).hexdigest()
    _join_claimed_identity(safe_rel, checksum_value, size_bytes, spec)
    return SealInventoryEntry(
        path=safe_rel,
        media_type=spec.media_type,
        size_bytes=size_bytes,
        checksum_algorithm="sha256",
        checksum_value=checksum_value,
        role=spec.role,
    )


def _join_claimed_identity(
    path: str, actual_sha256: str, actual_size: int, spec: SealedArtifactSpec
) -> None:
    """Refuse to seal when on-disk bytes disagree with the claimed identity.

    ``expected_sha256`` accepts a bare hex digest or a ``sha256:``-prefixed one
    so a caller can pass a RAES ``ExperimentChecksumModel.value`` or a prefixed
    digest interchangeably.
    """
    if spec.expected_sha256 is not None:
        expected = spec.expected_sha256.split(":", 1)[-1].lower()
        if expected != actual_sha256:
            raise SealIntegrityError(
                f"sealed artifact {path!r} bytes (sha256:{actual_sha256}) do not "
                f"match the claimed checksum (sha256:{expected})"
            )
    if spec.expected_size_bytes is not None and spec.expected_size_bytes != actual_size:
        raise SealIntegrityError(
            f"sealed artifact {path!r} size ({actual_size}) does not match the "
            f"claimed size ({spec.expected_size_bytes})"
        )


@dataclass(frozen=True)
class SealMarkerInputs:
    """The bundled inputs :func:`build_seal_marker` composes into a marker.

    ``run_id`` / ``run_version`` / ``run_status`` / ``outcome_status`` /
    ``run_record_digest`` carry the sealed record's identity and its real
    terminal outcome; ``inventory`` / ``contract_versions`` / ``limitations`` /
    ``completeness_statement`` describe the closed sealed byte graph.
    """

    run_id: str
    run_version: str
    run_status: str
    outcome_status: str
    run_record_digest: str
    inventory: list[SealInventoryEntry]
    contract_versions: list[str]
    limitations: list[SealLimitation]
    completeness_statement: str


def build_seal_marker(inputs: SealMarkerInputs) -> dict[str, object]:
    """Return the canonical seal-marker payload.

    ``complete`` is ``True`` iff there are no accepted limitations; the marker
    always records the *real* ``run_status``/``outcome_status`` and never claims
    ``run_status="sealed"`` (that erases the execution outcome — ADR-050).
    """
    return {
        "schema_version": SEAL_MARKER_SCHEMA_VERSION,
        "run_id": inputs.run_id,
        "run_version": inputs.run_version,
        "seal_state": SEAL_STATE_SEALED,
        "run_status": inputs.run_status,
        "outcome_status": inputs.outcome_status,
        SEAL_MARKER_DIGEST_FIELD: inputs.run_record_digest,
        "sealed_contract_versions": sorted(set(inputs.contract_versions)),
        "inventory": [entry.projection() for entry in inputs.inventory],
        "completeness": {
            "complete": not inputs.limitations,
            "statement": inputs.completeness_statement,
            "limitations": [limitation.projection() for limitation in inputs.limitations],
        },
    }
