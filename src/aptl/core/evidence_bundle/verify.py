"""Standalone, streaming, resource-bounded evidence-bundle verifier.

A third party validates a bundle with THIS module and nothing else from APTL:
it imports only the standard library plus ``rfc8785`` and never ``import
aptl`` (asserted by test), so it can be lifted out of the tree and run
anywhere. It streams the archive (never ``extractall``), enforces its OWN
conservative safety bounds (a verifier must not trust limits declared inside the
artifact it is verifying), recomputes every member digest/size against the
inventory, recomputes the reproducible bundle root identity, and rejects a
malformed envelope or a self-declared verified seal.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

import rfc8785

# Self-contained safety bounds. Deliberately independent of the producer's
# declared profile: a hostile bundle cannot raise its own ceiling.
_MAX_MEMBERS = 200_000
_MAX_MEMBER_BYTES = 1024 * 1024 * 1024
_MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
_MAX_PATH_LENGTH = 255
_MAX_PATH_DEPTH = 16
_MAX_ENVELOPE_BYTES = 8 * 1024 * 1024
_READ_CHUNK = 1024 * 1024
_ENVELOPE_NAME = "bundle.json"
_SCHEMA_VERSION = "aptl-evidence-bundle/v1"
_SEAL_SCOPES = frozenset({"unsealed", "verified"})
_REQUIRED_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "bundle_profile",
        "limits_profile",
        "run_id",
        "seal",
        "inventory",
        "data_dictionary",
        "limitations",
        "validation_disclosures",
    }
)
_ALLOWED_TOP_LEVEL = _REQUIRED_TOP_LEVEL | {"created_at"}
_INVENTORY_REQUIRED = frozenset(
    {
        "bundle_path",
        "logical_role",
        "classification",
        "source_ref",
        "digest",
        "size",
        "media_type",
    }
)


@dataclass
class VerificationReport:
    """The outcome of verifying one bundle archive."""

    ok: bool
    root_identity: str | None
    member_count: int
    seal_scope: str | None
    issues: list[str] = field(default_factory=list)


class _Fatal(Exception):
    """Internal signal that verification cannot continue; carries the report."""

    def __init__(self, member_count: int, issues: list[str]) -> None:
        super().__init__("fatal verification failure")
        self.member_count = member_count
        self.issues = issues


def _sha256_hex(data: bytes) -> str:
    """Return the ``sha256:<hex>`` digest of ``data``."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _name_problem(name: object) -> str | None:
    """Return a safe message if ``name`` is an unsafe archive/inventory path.

    Messages use ``repr`` so a hostile name cannot inject control or terminal
    sequences into operator diagnostics. Returns ``None`` when the path is safe.
    """
    if not isinstance(name, str) or not name or name.startswith("/") or "\\" in name:
        return f"unsafe path: {name!r}"
    parts = name.split("/")
    violations = (
        ("control character in path", _has_control_char(name)),
        ("path too long", len(name) > _MAX_PATH_LENGTH),
        (
            "path has an unsafe component",
            any(part in ("", ".", "..") for part in parts),
        ),
        ("path too deep", len(parts) > _MAX_PATH_DEPTH),
    )
    for label, failed in violations:
        if failed:
            return f"{label}: {name!r}"
    return None


def _has_control_char(name: str) -> bool:
    """Return True if ``name`` contains a NUL, C0, or DEL control character."""
    return "\x00" in name or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name)


def _member_problem(member: tarfile.TarInfo) -> str | None:
    """Return a safe message if ``member`` is not a safe regular archive member."""
    if member.issym() or member.islnk():
        return f"link member rejected: {member.name!r}"
    if not member.isreg():
        return f"non-regular member rejected: {member.name!r}"
    problem = _name_problem(member.name)
    return f"member {problem}" if problem else None


def _read_member(tar: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    """Stream one member's bytes, raising ``_Fatal`` past the member byte bound."""
    handle = tar.extractfile(member)
    if handle is None:
        return b""
    data = bytearray()
    while True:
        chunk = handle.read(_READ_CHUNK)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > _MAX_MEMBER_BYTES:
            raise _Fatal(0, ["member exceeds byte limit while streaming"])
    return bytes(data)


def _root_identity(envelope: dict[str, object]) -> str:
    """Recompute the reproducible content root, excluding ``created_at`` + ``seal``.

    A verified seal is an attestation OVER this root, never part of the document
    it binds, so both it and the human-facing ``created_at`` are excluded.
    """
    document = {
        key: value
        for key, value in envelope.items()
        if key not in ("created_at", "seal")
    }
    return _sha256_hex(rfc8785.dumps(document))


def _validate_inventory_rows(inventory: list[object], issues: list[str]) -> None:
    """Append an issue for each inventory row that is malformed or unsafe."""
    seen: set[str] = set()
    for row in inventory:
        if not isinstance(row, dict):
            issues.append("inventory row must be an object")
            continue
        missing = _INVENTORY_REQUIRED - set(row)
        if missing:
            issues.append(f"inventory row missing fields: {sorted(missing)}")
            continue
        path = row["bundle_path"]
        problem = _name_problem(path)
        if problem:
            issues.append(f"inventory {problem}")
            continue
        if not isinstance(row["digest"], str) or not isinstance(row["size"], int):
            issues.append(f"inventory row {path!r} has an invalid digest or size")
        if path in seen:
            issues.append(f"duplicate inventory bundle_path: {path!r}")
        seen.add(path)


def _validate_seal(seal: object, issues: list[str]) -> None:
    """Append an issue for a malformed seal object."""
    if not isinstance(seal, dict):
        issues.append("envelope seal must be an object")
        return
    if seal.get("scope") not in _SEAL_SCOPES:
        issues.append("envelope seal.scope is missing or unrecognized")
    root_id = seal.get("root_identity")
    if root_id is not None and not isinstance(root_id, str):
        issues.append("envelope seal.root_identity must be a string or null")


def _validate_envelope_structure(envelope: object) -> list[str]:
    """Reject a malformed or unknown-shaped envelope before trusting any field.

    A verifier must not coerce an attacker-supplied ``bundle.json`` into
    permissive empty defaults: an empty ``{}`` object is NOT a valid bundle.
    """
    if not isinstance(envelope, dict):
        return ["envelope is not a JSON object"]
    issues: list[str] = []
    if envelope.get("schema_version") != _SCHEMA_VERSION:
        issues.append("envelope schema_version is missing or unrecognized")
    missing = _REQUIRED_TOP_LEVEL - set(envelope)
    if missing:
        issues.append(f"envelope missing required fields: {sorted(missing)}")
    unknown = set(envelope) - _ALLOWED_TOP_LEVEL
    if unknown:
        issues.append(f"envelope has unknown fields: {sorted(unknown)}")
    for name in ("bundle_profile", "limits_profile", "run_id"):
        if not isinstance(envelope.get(name), str) or not envelope.get(name):
            issues.append(f"envelope {name} must be a non-empty string")
    _validate_seal(envelope.get("seal"), issues)
    inventory = envelope.get("inventory")
    if not isinstance(inventory, list):
        issues.append("envelope inventory must be a list")
    else:
        _validate_inventory_rows(inventory, issues)
    _validate_collections(envelope, issues)
    return issues


def _validate_collections(envelope: dict[str, object], issues: list[str]) -> None:
    """Append an issue for a malformed data dictionary, limitations, or disclosures."""
    data_dictionary = envelope.get("data_dictionary")
    if (
        not isinstance(data_dictionary, dict)
        or not isinstance(data_dictionary.get("schemas"), list)
        or not isinstance(data_dictionary.get("projections"), list)
    ):
        issues.append(
            "envelope data_dictionary must have schemas and projections lists"
        )
    if not isinstance(envelope.get("limitations"), list):
        issues.append("envelope limitations must be a list")
    if not isinstance(envelope.get("validation_disclosures"), list):
        issues.append("envelope validation_disclosures must be a list")


def _scan_members(
    tar: tarfile.TarFile, members: list[tarfile.TarInfo], issues: list[str]
) -> tuple[set[str], dict[str, str], dict[str, int]]:
    """Validate and hash every member, returning names, digests, and sizes."""
    digests: dict[str, str] = {}
    sizes: dict[str, int] = {}
    names: set[str] = set()
    total = 0
    for member in members:
        problem = _member_problem(member)
        if problem:
            issues.append(problem)
            continue
        if member.name in names:
            issues.append(f"duplicate member: {member.name!r}")
            continue
        if member.size > _MAX_MEMBER_BYTES:
            issues.append(f"member exceeds byte limit: {member.name!r}")
            continue
        total += member.size
        if total > _MAX_TOTAL_BYTES:
            issues.append("total bytes exceed limit")
            break
        names.add(member.name)
        digests[member.name] = _sha256_hex(_read_member(tar, member))
        sizes[member.name] = member.size
    return names, digests, sizes


def _check_inventory(
    envelope: dict[str, object],
    names: set[str],
    digests: dict[str, str],
    sizes: dict[str, int],
    issues: list[str],
) -> None:
    """Append an issue for any inventory/archive digest, size, or coverage mismatch."""
    inventory = envelope.get("inventory", [])
    inventory_paths: set[str] = set()
    for row in inventory:
        path = row.get("bundle_path")
        inventory_paths.add(path)
        if path == _ENVELOPE_NAME:
            issues.append("envelope must not appear in its own inventory")
            continue
        if path not in digests:
            issues.append(f"inventory member missing from archive: {path!r}")
            continue
        if digests[path] != row.get("digest"):
            issues.append(f"digest mismatch for {path!r}")
        if sizes[path] != row.get("size"):
            issues.append(f"size mismatch for {path!r}")
    for extra in sorted(names - inventory_paths - {_ENVELOPE_NAME}):
        issues.append(f"archive member not in inventory: {extra!r}")


def _load_envelope(
    tar: tarfile.TarFile, names: set[str], member_count: int, issues: list[str]
) -> dict[str, object]:
    """Read, size-bound, parse, and structurally validate the envelope.

    Raises ``_Fatal`` when the envelope is absent, oversized, unparseable, or
    structurally invalid; otherwise returns the parsed envelope object.
    """
    if _ENVELOPE_NAME not in names:
        raise _Fatal(member_count, issues + ["missing bundle.json envelope"])
    env_bytes = _read_member(tar, tar.getmember(_ENVELOPE_NAME))
    if len(env_bytes) > _MAX_ENVELOPE_BYTES:
        raise _Fatal(member_count, issues + ["envelope exceeds metadata size limit"])
    try:
        envelope = json.loads(env_bytes)
    except ValueError as exc:
        raise _Fatal(
            member_count, issues + [f"envelope is not valid JSON: {exc}"]
        ) from exc
    structure_issues = _validate_envelope_structure(envelope)
    if structure_issues:
        raise _Fatal(member_count, issues + structure_issues)
    return envelope


def _verify_archive(tar: tarfile.TarFile) -> VerificationReport:
    """Verify an opened archive, accumulating issues into one final report."""
    issues: list[str] = []
    members = tar.getmembers()
    try:
        if len(members) > _MAX_MEMBERS:
            raise _Fatal(len(members), ["member count exceeds limit"])
        names, digests, sizes = _scan_members(tar, members, issues)
        envelope = _load_envelope(tar, names, len(members), issues)
        root_identity = _root_identity(envelope)
        seal_scope = envelope["seal"].get("scope")
        _check_inventory(envelope, names, digests, sizes, issues)
        if seal_scope == "verified":
            # A "verified" claim requires portable #444 attestation material a
            # third party can authenticate against a trust anchor. That contract
            # does not exist yet, and a self-declared root identity is not
            # evidence, so a verified seal cannot be confirmed. Producers only
            # ever emit "unsealed" today.
            issues.append(
                "seal claims 'verified' but carries no verifiable attestation material"
            )
        return VerificationReport(
            not issues, root_identity, len(members), seal_scope, issues
        )
    except _Fatal as fatal:
        return VerificationReport(False, None, fatal.member_count, None, fatal.issues)


def verify_stream(fileobj: BinaryIO) -> VerificationReport:
    """Verify a bundle from an open binary stream."""
    try:
        tar = tarfile.open(fileobj=fileobj, mode="r:")
    except tarfile.TarError as exc:
        return VerificationReport(
            False, None, 0, None, [f"not an uncompressed USTAR bundle: {exc}"]
        )
    with tar:
        return _verify_archive(tar)


def verify_bundle(path: str | Path) -> VerificationReport:
    """Verify a bundle archive at ``path``."""
    with open(path, "rb") as fileobj:
        return verify_stream(fileobj)


__all__ = ["VerificationReport", "verify_bundle", "verify_stream"]
