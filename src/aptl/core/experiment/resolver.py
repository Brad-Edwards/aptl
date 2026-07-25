"""The offline, project-contained authorized artifact resolver.

ADR-047 "Authorized artifact resolution": experiment references are
capabilities, not paths or commands. The default resolver is offline and
project-contained; it accepts only explicitly supported locator forms and
returns one bounded byte stream plus normalized locator metadata — never an
executable object or a path to reopen.

Two layers, tested independently:

* :func:`parse_locator` is pure string classification of an untrusted
  locator string into a normalized :class:`ProjectFileLocator`. It never
  touches the filesystem, so a hostile locator can be rejected before any
  I/O happens.
* :class:`ProjectContainedResolver` actually resolves bytes. It opens the
  target exactly once via
  :func:`aptl.utils.pathsafe.open_contained_nofollow` (descriptor-relative,
  no-follow — a symlinked path component anywhere, including the leaf, is
  rejected rather than silently followed), verifies declared size/digest
  from that single handle, and tracks aggregate bytes/reference count
  across its own lifetime so a caller can fail an entire admission closed
  once either limit is exceeded.

SDL import graphs are explicitly OUT of scope for this resolver: ADR-047
"Authorized artifact resolution" requires a future staged-import resolver
to materialize a digest-pinned, size-bounded transitive graph into private
staging before ACES ever parses an import-declaring scenario. This module
does not attempt that; ``spec_loading.parse_scenario_bytes`` rejects any
scenario that declares imports instead. A remote/staged-import resolver
implementing the same :class:`ArtifactResolver` protocol is the documented
extension seam — it must not fall back to ambient filesystem/PATH/env/
package-import lookup on failure.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.parse import parse_qsl, urlsplit

import blake3

from aptl.core.experiment.errors import AdmissionRejection, diagnostic
from aptl.core.experiment.policy import AdmissionPolicy
from aptl.utils.pathsafe import PathContainmentError, open_contained_nofollow
from aptl.utils.redaction import is_secret_shaped_value, is_sensitive_key

# Same four algorithms as the ACES `PrefixedDigestString` pattern
# (`^(?:sha256:[A-Fa-f0-9]{64}|sha384:[A-Fa-f0-9]{96}|sha512:[A-Fa-f0-9]{128}|
# blake3:[A-Fa-f0-9]{64})$`) — kept in lockstep so a locator this resolver
# accepts is always a digest ACES itself would also accept.
_DIGEST_PATTERN = re.compile(
    r"^(?:sha256:[A-Fa-f0-9]{64}|sha384:[A-Fa-f0-9]{96}|"
    r"sha512:[A-Fa-f0-9]{128}|blake3:[A-Fa-f0-9]{64})$"
)
_HASHLIB_ALGORITHMS: frozenset[str] = frozenset({"sha256", "sha384", "sha512"})

# Locators are treated as opaque project-relative paths by default (no
# scheme), or explicitly `file:...` — never `http(s)`, `oci`, `registry`,
# or any other transport (ADR-047: "Network, OCI, or registry fetching is
# disabled by default").
_ALLOWED_SCHEMES = frozenset({"", "file"})
_RECOGNIZED_QUERY_KEYS = frozenset({"size", "digest", "media_type"})


@dataclass(frozen=True)
class ResolvedArtifact:
    """One bounded, verified byte stream plus normalized locator metadata.

    Never a path to reopen and never executable: ``data`` is the exact
    bytes read from the single open handle, ``locator`` is a normalized
    PORTABLE (project-relative, never host-absolute) reference, and
    ``digest`` is the sha256 of ``data`` computed by the resolver itself
    (not merely echoed from a caller-declared value).
    """

    data: bytes
    locator: str
    digest: str
    media_type: str | None


@dataclass(frozen=True)
class ProjectFileLocator:
    """A normalized, validated project-file locator.

    Produced by :func:`parse_locator` from an untrusted raw string, or
    constructed directly by a caller that already has a trusted relative
    path. ``resolve()`` re-validates every field regardless of origin —
    it never assumes a ``ProjectFileLocator`` was necessarily built by
    :func:`parse_locator`.
    """

    relative_path: str
    declared_size: int | None = None
    declared_digest: str | None = None
    media_type: str | None = None


class ArtifactResolver(Protocol):
    """The narrow resolver contract admission depends on.

    A future remote/staged-import resolver (ADR-047's documented
    extension seam) implements this same protocol, parameterized by
    allowed scheme/authority, offline mode, limits, and digest policy,
    while always returning the same bounded immutable byte binding.
    """

    def resolve(self, locator: ProjectFileLocator, *, policy: AdmissionPolicy) -> ResolvedArtifact: ...


def _reject(code: str, address: str, message: str) -> AdmissionRejection:
    """Build a one-diagnostic AdmissionRejection for a locator/resolver failure."""
    return AdmissionRejection((diagnostic(code, address, message),))


def parse_locator(raw: str, *, address: str = "artifact-locator") -> ProjectFileLocator:
    """Parse and validate an untrusted locator string.

    Pure string classification — never touches the filesystem. Rejects
    every locator shape ADR-047 "Authorized artifact resolution"
    disallows: credential userinfo (``user:pass@``), a secret-shaped or
    unrecognized query field, any scheme other than the implicit/`file:`
    project-relative form (so ``http(s)``, ``oci``, ``registry``, ``urn``,
    etc. are all rejected), an absolute path, and any ``..``/``.``/empty
    path component. ``size``/``digest``/``media_type`` query fields
    populate the corresponding :class:`ProjectFileLocator` fields; every
    other query key is rejected closed rather than silently ignored.
    """
    if not raw:
        raise _reject(
            "aptl.experiment-admission.locator-empty", address, "artifact locator must not be empty"
        )
    if "\x00" in raw:
        raise _reject(
            "aptl.experiment-admission.locator-nul-byte",
            address,
            "artifact locator must not contain a NUL byte",
        )

    parts = urlsplit(raw)
    if parts.scheme not in _ALLOWED_SCHEMES:
        raise _reject(
            "aptl.experiment-admission.locator-unsupported-scheme",
            address,
            "artifact locator scheme is not supported; only project-relative file "
            "locators are permitted",
        )
    if parts.username is not None or parts.password is not None:
        raise _reject(
            "aptl.experiment-admission.locator-credential-userinfo",
            address,
            "artifact locator must not carry credential userinfo",
        )
    if parts.netloc and parts.scheme == "":
        # A bare "host/path"-shaped string with no scheme is ambiguous
        # (urlsplit only populates netloc for a `scheme://...`-style
        # input); reject rather than guess at intent.
        raise _reject(
            "aptl.experiment-admission.locator-unsupported-scheme",
            address,
            "artifact locator must be a project-relative path",
        )

    declared_size, declared_digest, media_type = _parse_query(parts.query, address=address)
    _validate_relative_path(parts.path, address=address)

    return ProjectFileLocator(
        relative_path=parts.path,
        declared_size=declared_size,
        declared_digest=declared_digest,
        media_type=media_type,
    )


def _validate_query_key(key: str, value: str, *, address: str) -> None:
    """Reject an unrecognized or secret-shaped locator query key/value before it is interpreted."""
    if key not in _RECOGNIZED_QUERY_KEYS:
        raise _reject(
            "aptl.experiment-admission.locator-unrecognized-query-field",
            address,
            "artifact locator query field is not recognized",
        )
    if is_sensitive_key(key) or is_secret_shaped_value(value):
        raise _reject(
            "aptl.experiment-admission.locator-secret-bearing-query",
            address,
            "artifact locator query field looks secret-shaped",
        )


def _parse_size_field(value: str, *, address: str) -> int:
    """Validate and parse the locator query's ``size`` field into a non-negative int."""
    if not value.isdigit():
        raise _reject(
            "aptl.experiment-admission.locator-invalid-size",
            address,
            "artifact locator size field must be a non-negative integer",
        )
    return int(value)


def _parse_digest_field(value: str, *, address: str) -> str:
    """Validate the locator query's ``digest`` field against the supported prefixed-digest pattern."""
    if not _DIGEST_PATTERN.match(value):
        raise _reject(
            "aptl.experiment-admission.locator-invalid-digest",
            address,
            "artifact locator digest field is not a supported prefixed digest",
        )
    return value


def _parse_query(
    query: str, *, address: str
) -> tuple[int | None, str | None, str | None]:
    """Parse and validate the locator's query string into (declared_size, declared_digest, media_type)."""
    declared_size: int | None = None
    declared_digest: str | None = None
    media_type: str | None = None
    for key, value in parse_qsl(query, keep_blank_values=True):
        _validate_query_key(key, value, address=address)
        if key == "size":
            declared_size = _parse_size_field(value, address=address)
        elif key == "digest":
            declared_digest = _parse_digest_field(value, address=address)
        elif key == "media_type":
            media_type = value
    return declared_size, declared_digest, media_type


def _validate_relative_path(path: str, *, address: str) -> None:
    """Reject an empty, absolute, or '.'/'..'/empty-component-bearing relative path."""
    if not path:
        raise _reject(
            "aptl.experiment-admission.locator-empty-path",
            address,
            "artifact locator path must not be empty",
        )
    if path.startswith("/"):
        raise _reject(
            "aptl.experiment-admission.locator-absolute-path",
            address,
            "artifact locator path must be project-relative, not absolute",
        )
    for component in path.split("/"):
        if component in ("", ".", ".."):
            raise _reject(
                "aptl.experiment-admission.locator-invalid-path-component",
                address,
                "artifact locator path must not contain empty, '.', or '..' components",
            )


def _digest_hex(data: bytes, algorithm: str) -> str:
    """Return the lowercase hex digest of data under the named algorithm (blake3 or a hashlib algorithm)."""
    if algorithm == "blake3":
        return blake3.blake3(data).hexdigest()
    hasher = hashlib.new(algorithm)
    hasher.update(data)
    return hasher.hexdigest()


@dataclass
class _ResolverAccumulator:
    """Mutable per-resolver-instance counters (one instance = one session)."""

    total_bytes: int = 0
    reference_count: int = 0


@dataclass
class ProjectContainedResolver:
    """Offline, project-contained :class:`ArtifactResolver`.

    Every ``resolve()`` call opens its target exactly once via
    :func:`aptl.utils.pathsafe.open_contained_nofollow` under ``base_dir``
    — no fallback to CWD, ``PATH``, environment, or package import on any
    failure. Aggregate bytes and reference count are tracked across the
    resolver instance's own lifetime (one instance is one resolve
    session); construct a fresh instance per admission attempt.
    """

    base_dir: Path
    _accumulator: _ResolverAccumulator = field(default_factory=_ResolverAccumulator, init=False)

    def resolve(self, locator: ProjectFileLocator, *, policy: AdmissionPolicy) -> ResolvedArtifact:
        address = locator.relative_path

        if locator.declared_digest is not None and not _DIGEST_PATTERN.match(locator.declared_digest):
            raise _reject(
                "aptl.experiment-admission.artifact-unsupported-digest-algorithm",
                address,
                "artifact declared digest algorithm is not supported",
            )
        if self._accumulator.reference_count >= policy.max_reference_count:
            raise _reject(
                "aptl.experiment-admission.reference-count-exceeded",
                address,
                "artifact reference count exceeds the admission policy limit",
            )

        data = self._open_and_read(locator, policy=policy)

        if locator.declared_size is not None and locator.declared_size != len(data):
            raise _reject(
                "aptl.experiment-admission.artifact-size-mismatch",
                address,
                "artifact declared size does not match the resolved bytes",
            )

        if locator.declared_digest is not None:
            algorithm, _, expected_hex = locator.declared_digest.partition(":")
            actual_hex = _digest_hex(data, algorithm)
            if actual_hex.lower() != expected_hex.lower():
                raise _reject(
                    "aptl.experiment-admission.artifact-digest-mismatch",
                    address,
                    "artifact declared digest does not match the resolved bytes",
                )

        new_total = self._accumulator.total_bytes + len(data)
        if new_total > policy.max_aggregate_bytes:
            raise _reject(
                "aptl.experiment-admission.aggregate-bytes-exceeded",
                address,
                "aggregate resolved bytes exceed the admission policy limit",
            )

        self._accumulator.total_bytes = new_total
        self._accumulator.reference_count += 1

        return ResolvedArtifact(
            data=data,
            locator=locator.relative_path,
            digest=f"sha256:{_digest_hex(data, 'sha256')}",
            media_type=locator.media_type,
        )

    def _open_and_read(self, locator: ProjectFileLocator, *, policy: AdmissionPolicy) -> bytes:
        address = locator.relative_path
        try:
            handle = open_contained_nofollow(self.base_dir, locator.relative_path)
        except PathContainmentError as exc:
            raise _reject(
                f"aptl.experiment-admission.artifact-{exc.reason}",
                address,
                "artifact locator could not be safely opened under the project root",
            ) from exc
        try:
            # fstat the already-open handle (not a second path lookup) so
            # an oversized file is rejected before it is fully read into
            # memory.
            size = os.fstat(handle.fileno()).st_size
            if size > policy.max_artifact_bytes:
                raise _reject(
                    "aptl.experiment-admission.artifact-too-large",
                    address,
                    "artifact exceeds the per-artifact byte limit",
                )
            return handle.read()
        finally:
            handle.close()
