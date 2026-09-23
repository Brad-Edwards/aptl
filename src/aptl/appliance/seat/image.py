"""Resolve one seat VM disk from an OCI registry reference.

The seat boundary is a VM; the disk that VM boots is ordinary published
content, not a bespoke release artifact.  This module turns a registry
reference into a local, digest-verified qcow2 that
:func:`aptl.appliance.build.create_disposable_overlay` can back an overlay
with.

The pull is plain HTTPS against the registry API so that a seat host needs
QEMU and nothing else; there is no host Docker dependency.  Integrity is the
registry's own content addressing: every blob is fetched by digest and the
staged file is rejected unless its bytes hash to that digest.
"""

from __future__ import annotations

import json
import re
import stat
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from aptl.appliance.download import (
    ApplianceDownloadError,
    fetch_https_metadata,
    stage_https_artifact,
)
from aptl.appliance.seat.image_config import (
    SEAT_IMAGE_CONFIG_MEDIA_TYPE,
    SeatImageConfig,
    SeatImageConfigError,
    parse_seat_image_config,
)

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_REPOSITORY = re.compile(
    r"^[a-z0-9]+(?:(?:[._-]|__)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._-]|__)[a-z0-9]+)*)*$"
)
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
_REGISTRY = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$")

# One seat disk is a single blob in an OCI artifact. Accepting the index as
# well lets a published reference point at a multi-architecture entry.
_MANIFEST_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
)
_INDEX_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
DISK_MEDIA_TYPE = "application/vnd.aptl.seat.disk.v1+qcow2"

# A manifest or token document is small; a disk is not. Bounding the metadata
# fetch keeps an unexpected response from being read into memory at all.
_MAX_METADATA_BYTES = 256 * 1024
_MAX_DISK_BYTES = 512 * 1024 * 1024 * 1024


class SeatImageError(RuntimeError):
    """One seat VM disk could not be resolved from its registry reference."""


@dataclass(frozen=True)
class SeatImageReference:
    """One parsed registry reference for a seat VM disk."""

    registry: str
    repository: str
    tag: str | None
    digest: str | None

    @property
    def target(self) -> str:
        """Return the digest when pinned, else the tag."""

        return self.digest or self.tag or "latest"

    def __str__(self) -> str:
        separator = "@" if self.digest else ":"
        return f"{self.registry}/{self.repository}{separator}{self.target}"


@dataclass(frozen=True)
class StagedSeatImage:
    """One local, digest-verified seat VM disk."""

    path: Path
    digest: str
    size_bytes: int
    reference: SeatImageReference
    manifest_digest: str
    reused: bool


def parse_seat_image_reference(reference: str) -> SeatImageReference:
    """Parse ``registry/repository[:tag|@sha256:...]`` fail-closed.

    A reference selects what a seat will boot, so an ambiguous one is refused
    rather than normalized into something the operator did not write.
    """

    remainder = reference.strip()
    if not remainder or any(character.isspace() for character in remainder):
        raise SeatImageError("seat image reference is empty or malformed")

    registry, separator, rest = remainder.partition("/")
    if not separator or not _REGISTRY.fullmatch(registry.lower()):
        raise SeatImageError(
            "seat image reference must name a registry host and repository"
        )
    registry = registry.lower()

    digest: str | None = None
    tag: str | None = None
    if "@" in rest:
        rest, _, digest = rest.partition("@")
        if not _DIGEST.fullmatch(digest):
            raise SeatImageError("seat image digest must be a lowercase sha256 digest")
    elif ":" in rest:
        rest, _, tag = rest.rpartition(":")
        if not _TAG.fullmatch(tag):
            raise SeatImageError("seat image tag is not a valid registry tag")
    else:
        tag = "latest"

    if not _REPOSITORY.fullmatch(rest):
        raise SeatImageError("seat image repository is not a valid registry path")
    return SeatImageReference(
        registry=registry, repository=rest, tag=tag, digest=digest
    )


def _cache_entry(cache_dir: Path, digest: str) -> Path:
    """Return the cache path for one digest, refusing anything else.

    The digest reaches here from a registry manifest, so it is remote input
    that becomes a filesystem path. Validating it at every path construction
    is what keeps it from being one.
    """

    if not _DIGEST.fullmatch(digest):
        raise SeatImageError("seat image digest is not a lowercase sha256 digest")
    entry = cache_dir / digest.removeprefix("sha256:") / "seat-disk.qcow2"
    if not entry.is_relative_to(cache_dir):
        raise SeatImageError("seat image cache entry escapes the cache")
    return entry


def _stamp_path(disk: Path) -> Path:
    """Return the verification stamp beside one cached disk."""

    return disk.with_suffix(".verified.json")


def write_verification_stamp(disk: Path, *, digest: str, size_bytes: int) -> None:
    """Record the identity a full hash verification just established.

    Hashing a multi-gigabyte disk is affordable once, when it is downloaded.
    Repeating it on every seat start is not, so the result is recorded and
    later starts re-check only what is cheap.
    """

    status = disk.stat(follow_symlinks=False)
    _stamp_path(disk).write_text(
        json.dumps(
            {
                "schema_version": "aptl.seat-disk-verification/v1",
                "digest": digest,
                "size_bytes": size_bytes,
                "inode": status.st_ino,
                "mtime_ns": status.st_mtime_ns,
                "mode": status.st_mode & 0o7777,
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def verified_cached_disk(
    cache_dir: Path, *, digest: str, size_bytes: int | None = None
) -> Path | None:
    """Return the cached disk for ``digest`` when it is cheaply provable.

    The disk is a read-only qcow2 backing file that the VM never writes, so
    these checks are looking for tampering or corruption, not for ordinary
    mutation.  Anything that disagrees returns ``None`` and the caller falls
    back to the full hash.
    """

    disk = _cache_entry(cache_dir, digest)
    try:
        status = disk.stat(follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(status.st_mode):
        return None
    try:
        stamp = json.loads(_stamp_path(disk).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(stamp, dict):
        return None
    expected = {
        "digest": digest,
        "inode": status.st_ino,
        "mtime_ns": status.st_mtime_ns,
        "mode": status.st_mode & 0o7777,
        "size_bytes": status.st_size,
    }
    if any(stamp.get(key) != value for key, value in expected.items()):
        return None
    if size_bytes is not None and status.st_size != size_bytes:
        return None
    return disk


def _anonymous_token(reference: SeatImageReference) -> str | None:
    """Obtain a pull token, returning ``None`` when the registry needs none."""

    query = urllib.parse.urlencode(
        {
            "service": reference.registry,
            "scope": f"repository:{reference.repository}:pull",
        }
    )
    url = f"https://{reference.registry}/token?{query}"
    try:
        payload = fetch_https_metadata(url, max_bytes=_MAX_METADATA_BYTES)
    except ApplianceDownloadError:
        return None
    try:
        document = json.loads(payload)
    except ValueError:
        return None
    token = document.get("token") or document.get("access_token")
    return token if isinstance(token, str) and token else None


def _registry_headers(token: str | None, accept: str) -> dict[str, str]:
    """Build the pull headers for one registry request."""

    headers = {"Accept": accept}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_manifest(
    reference: SeatImageReference, target: str, token: str | None
) -> tuple[dict[str, object], str]:
    """Fetch and parse one manifest document by tag or digest."""

    url = (
        f"https://{reference.registry}/v2/{reference.repository}"
        f"/manifests/{urllib.parse.quote(target, safe=':')}"
    )
    try:
        payload = fetch_https_metadata(
            url,
            max_bytes=_MAX_METADATA_BYTES,
            headers=_registry_headers(token, ",".join(_MANIFEST_TYPES)),
        )
    except ApplianceDownloadError as exc:
        raise SeatImageError(
            f"seat image manifest is unavailable: {reference}"
        ) from exc
    try:
        document = json.loads(payload)
    except ValueError as exc:
        raise SeatImageError("seat image manifest is not valid JSON") from exc
    if not isinstance(document, dict):
        raise SeatImageError("seat image manifest is not a JSON object")
    return document, _sha256_of(payload)


def _sha256_of(payload: bytes) -> str:
    """Return the sha256 digest of one fetched document."""

    import hashlib

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _select_disk_layer(manifest: dict[str, object]) -> dict[str, object]:
    """Return the single disk descriptor this manifest publishes."""

    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise SeatImageError("seat image manifest declares no layers")
    disks = [
        layer
        for layer in layers
        if isinstance(layer, dict) and layer.get("mediaType") == DISK_MEDIA_TYPE
    ]
    if not disks:
        # A published reference that is an ordinary container image, not a seat
        # disk artifact, fails here rather than booting something unexpected.
        raise SeatImageError(
            f"seat image publishes no {DISK_MEDIA_TYPE} layer; "
            "the reference is not a seat VM disk"
        )
    if len(disks) > 1:
        raise SeatImageError("seat image publishes more than one disk layer")
    return disks[0]


def _resolve_index(
    reference: SeatImageReference, manifest: dict[str, object], token: str | None
) -> tuple[dict[str, object], str]:
    """Follow a single-entry index to the manifest it selects."""

    entries = manifest.get("manifests")
    if not isinstance(entries, list) or not entries:
        raise SeatImageError("seat image index declares no manifests")
    candidates = [
        entry
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("digest"), str)
        and (
            not isinstance(entry.get("platform"), dict)
            or entry["platform"].get("architecture") in (None, "amd64", "x86_64")
        )
    ]
    if len(candidates) != 1:
        raise SeatImageError(
            "seat image index does not select exactly one x86_64 manifest"
        )
    digest = candidates[0]["digest"]
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise SeatImageError("seat image index entry has no usable digest")
    return _fetch_manifest(reference, digest, token)


@dataclass(frozen=True)
class SeatDiskDescriptor:
    """What a reference currently resolves to, before any disk is fetched."""

    reference: SeatImageReference
    digest: str
    size_bytes: int
    manifest_digest: str
    token: str | None
    config_digest: str | None = None
    config_size_bytes: int | None = None


def resolve_disk_descriptor(
    reference: str | SeatImageReference,
) -> SeatDiskDescriptor:
    """Resolve a reference to its disk descriptor without downloading it.

    This is the cheap half of resolution: a token and one manifest, a few
    kilobytes.  Checking whether a newer image exists uses only this.
    """

    parsed = (
        reference
        if isinstance(reference, SeatImageReference)
        else parse_seat_image_reference(reference)
    )
    token = _anonymous_token(parsed)
    manifest, manifest_digest = _fetch_manifest(parsed, parsed.target, token)
    if manifest.get("mediaType") in _INDEX_TYPES or "manifests" in manifest:
        manifest, manifest_digest = _resolve_index(parsed, manifest, token)

    descriptor = _select_disk_layer(manifest)
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise SeatImageError("seat image disk layer has no usable digest")
    if not isinstance(size, int) or not 0 < size <= _MAX_DISK_BYTES:
        raise SeatImageError("seat image disk layer declares no usable size")
    config = manifest.get("config")
    config_digest: str | None = None
    config_size: int | None = None
    if isinstance(config, dict) and config.get("mediaType") == (
        SEAT_IMAGE_CONFIG_MEDIA_TYPE
    ):
        candidate_digest = config.get("digest")
        candidate_size = config.get("size")
        if not isinstance(candidate_digest, str) or not _DIGEST.fullmatch(
            candidate_digest
        ):
            raise SeatImageError("seat image config descriptor has no usable digest")
        if not isinstance(candidate_size, int) or not 0 < candidate_size <= (
            _MAX_METADATA_BYTES
        ):
            raise SeatImageError("seat image config descriptor has no usable size")
        config_digest = candidate_digest
        config_size = candidate_size

    return SeatDiskDescriptor(
        reference=parsed,
        digest=digest,
        size_bytes=size,
        manifest_digest=manifest_digest,
        token=token,
        config_digest=config_digest,
        config_size_bytes=config_size,
    )


def fetch_seat_image_config(descriptor: SeatDiskDescriptor) -> SeatImageConfig:
    """Fetch and validate the self-description this image publishes.

    The config blob is small and is fetched by digest, so its identity is the
    registry's content addressing exactly as the disk's is.
    """

    if descriptor.config_digest is None:
        raise SeatImageError(
            f"seat image publishes no {SEAT_IMAGE_CONFIG_MEDIA_TYPE} config; "
            "the reference does not describe a launchable seat"
        )
    quoted = urllib.parse.quote(descriptor.config_digest, safe=":")
    reference = descriptor.reference
    url = f"https://{reference.registry}/v2/{reference.repository}/blobs/{quoted}"
    try:
        payload = fetch_https_metadata(
            url,
            max_bytes=descriptor.config_size_bytes or _MAX_METADATA_BYTES,
            headers=_registry_headers(descriptor.token, "*/*"),
        )
    except ApplianceDownloadError as exc:
        raise SeatImageError(f"seat image config is unavailable: {reference}") from exc
    actual = _sha256_of(payload)
    if actual != descriptor.config_digest:
        raise SeatImageError("seat image config does not match its declared digest")
    try:
        return parse_seat_image_config(payload)
    except SeatImageConfigError as exc:
        raise SeatImageError(str(exc)) from exc


def resolve_seat_image(
    reference: str | SeatImageReference, *, cache_dir: Path
) -> StagedSeatImage:
    """Pull, verify and cache the VM disk one seat reference names.

    The returned disk is immutable and shared by digest, so a second seat on
    the same reference reuses the cached bytes instead of pulling again.
    """

    descriptor = resolve_disk_descriptor(reference)
    reused = (
        verified_cached_disk(
            cache_dir, digest=descriptor.digest, size_bytes=descriptor.size_bytes
        )
        is not None
    )
    return StagedSeatImage(
        path=fetch_seat_disk(
            descriptor.reference,
            digest=descriptor.digest,
            size_bytes=descriptor.size_bytes,
            cache_dir=cache_dir,
            token=descriptor.token,
        ),
        digest=descriptor.digest,
        size_bytes=descriptor.size_bytes,
        reference=descriptor.reference,
        manifest_digest=descriptor.manifest_digest,
        reused=reused,
    )


def fetch_seat_disk(
    reference: SeatImageReference,
    *,
    digest: str,
    size_bytes: int,
    cache_dir: Path,
    token: str | None = None,
) -> Path:
    """Return the cached disk for ``digest``, downloading it when absent.

    A cached disk that its stamp still proves is returned without reading the
    file, so a warm start does not pay for a full hash of the disk it is about
    to boot.
    """

    cached = verified_cached_disk(cache_dir, digest=digest, size_bytes=size_bytes)
    if cached is not None:
        return cached

    quoted = urllib.parse.quote(digest, safe=":")
    blob_url = f"https://{reference.registry}/v2/{reference.repository}/blobs/{quoted}"
    try:
        staged = stage_https_artifact(
            url=blob_url,
            cache_dir=cache_dir,
            filename="seat-disk.qcow2",
            sha256=digest,
            size_bytes=size_bytes,
            headers=_registry_headers(
                token if token is not None else _anonymous_token(reference), "*/*"
            ),
        )
    except ApplianceDownloadError as exc:
        raise SeatImageError(f"seat image disk download failed: {reference}") from exc
    # stage_https_artifact has just proven the digest by reading every byte.
    write_verification_stamp(staged.path, digest=digest, size_bytes=size_bytes)
    return staged.path
