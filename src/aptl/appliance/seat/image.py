"""Resolve one seat VM disk from an OCI registry reference.

The seat boundary is a VM; the disk that VM boots is ordinary published
content, not a bespoke release artifact.  This module turns a registry
reference into a local, digest-verified qcow2 that the seat launcher uses as
the backing disk for a disposable overlay.

The pull is plain HTTPS against the registry API so that a seat host needs
QEMU and nothing else; there is no host Docker dependency.  Integrity is the
registry's own content addressing: every blob is fetched by digest and the
staged file is rejected unless its bytes hash to that digest.
"""

from __future__ import annotations

import json
import os
import re
import secrets
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
from aptl.appliance.seat.image_disk_cache import (
    DISK_FILENAME,
    SeatImageError,
    _DIGEST,
    _cache_entry,
    _sha256_of,
    cached_seat_image_config,
    verified_cached_disk,
    write_verification_stamp,
)

_REPOSITORY_COMPONENT = r"[a-z0-9]+(?:(?:[._-]|__)[a-z0-9]+)*"
_REPOSITORY = re.compile(rf"^{_REPOSITORY_COMPONENT}(?:/{_REPOSITORY_COMPONENT})*$")
_TAG = re.compile(r"^\w[\w.-]{0,127}$", re.ASCII)
_REGISTRY = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?$", re.ASCII)

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
    if not isinstance(document, dict):
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
    digest = _sha256_of(payload)
    if target.startswith("sha256:") and digest != target:
        raise SeatImageError("seat image manifest does not match the requested digest")
    return document, digest


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


def _config_descriptor(manifest: dict[str, object]) -> tuple[str | None, int | None]:
    """Validate the optional seat config blob advertised by one manifest."""

    config = manifest.get("config")
    if not isinstance(config, dict) or config.get("mediaType") != (
        SEAT_IMAGE_CONFIG_MEDIA_TYPE
    ):
        return None, None
    digest = config.get("digest")
    size = config.get("size")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise SeatImageError("seat image config descriptor has no usable digest")
    if not isinstance(size, int) or not 0 < size <= _MAX_METADATA_BYTES:
        raise SeatImageError("seat image config descriptor has no usable size")
    return digest, size


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
    if parsed.digest is not None and manifest_digest != parsed.digest:
        raise SeatImageError("seat image manifest does not match the pinned digest")
    if manifest.get("mediaType") in _INDEX_TYPES or "manifests" in manifest:
        manifest, manifest_digest = _resolve_index(parsed, manifest, token)

    descriptor = _select_disk_layer(manifest)
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise SeatImageError("seat image disk layer has no usable digest")
    if not isinstance(size, int) or not 0 < size <= _MAX_DISK_BYTES:
        raise SeatImageError("seat image disk layer declares no usable size")
    config_digest, config_size = _config_descriptor(manifest)

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


def cache_seat_image_config(
    descriptor: SeatDiskDescriptor, cache_dir: Path
) -> tuple[SeatImageConfig, str]:
    """Fetch a config and keep its exact bytes bound to the selected disk."""

    if descriptor.config_digest is None:
        raise SeatImageError("seat image has no launch config")
    reference = descriptor.reference
    quoted = urllib.parse.quote(descriptor.config_digest, safe=":")
    url = f"https://{reference.registry}/v2/{reference.repository}/blobs/{quoted}"
    try:
        payload = fetch_https_metadata(
            url,
            max_bytes=descriptor.config_size_bytes or _MAX_METADATA_BYTES,
            headers=_registry_headers(descriptor.token, "*/*"),
        )
    except ApplianceDownloadError as exc:
        raise SeatImageError(f"seat image config is unavailable: {reference}") from exc
    if _sha256_of(payload) != descriptor.config_digest:
        raise SeatImageError("seat image config does not match its declared digest")
    try:
        config = parse_seat_image_config(payload)
    except SeatImageConfigError as exc:
        raise SeatImageError(str(exc)) from exc
    existing = cached_seat_image_config(cache_dir, disk_digest=descriptor.digest)
    if existing is not None and existing[1] != descriptor.config_digest:
        raise SeatImageError("one seat disk cannot be rebound to a different config")
    entry = _cache_entry(cache_dir, descriptor.digest).parent
    entry.mkdir(parents=True, exist_ok=True, mode=0o700)
    binding = json.dumps(
        {
            "schema_version": "aptl.seat-config-binding/v1",
            "disk_digest": descriptor.digest,
            "manifest_digest": descriptor.manifest_digest,
            "config_digest": descriptor.config_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    for name, contents in (
        ("seat-config.json", payload),
        ("seat-config-binding.json", binding),
    ):
        target = entry / name
        temporary = entry / f".{name}.{secrets.token_hex(8)}"
        try:
            with temporary.open("xb") as handle:
                handle.write(contents)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    return config, descriptor.config_digest


def resolve_seat_image(
    reference: str | SeatImageReference, *, cache_dir: Path, require_config: bool = False
) -> StagedSeatImage:
    """Pull, verify and cache the VM disk one seat reference names.

    The returned disk is immutable and shared by digest, so a second seat on
    the same reference reuses the cached bytes instead of pulling again.
    """

    descriptor = resolve_disk_descriptor(reference)
    from aptl.appliance.seat.image_trust import verify_remote_image, publish_verified_image

    receipt = verify_remote_image(
        cache_dir, str(descriptor.reference), descriptor.manifest_digest,
        descriptor.digest, descriptor.config_digest,
    )
    if require_config:
        # A tag can move between requests. Bind the launch declaration to the
        # same manifest as the disk before recording either as selected.
        cache_seat_image_config(descriptor, cache_dir)
    reused = (
        verified_cached_disk(
            cache_dir, digest=descriptor.digest, size_bytes=descriptor.size_bytes
        )
        is not None
    )
    disk_path = fetch_seat_disk(
        descriptor.reference,
        digest=descriptor.digest,
        size_bytes=descriptor.size_bytes,
        cache_dir=cache_dir,
        token=descriptor.token,
    )
    publish_verified_image(cache_dir, receipt)
    return StagedSeatImage(
        path=disk_path,
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
            filename=DISK_FILENAME,
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
