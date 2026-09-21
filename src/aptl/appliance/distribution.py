"""Authenticated transport-only chunking for large appliance artifacts."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import shutil
import stat
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal, Protocol, Self

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

from aptl.appliance.download import (
    StagedDownload,
    fetch_https_metadata,
    stage_https_artifact,
)
from aptl.utils.strict_json import model_validate_json_strict

_DIGEST = r"^sha256:[a-f0-9]{64}$"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_GITHUB_REPOSITORY = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)


class ApplianceDistributionError(RuntimeError):
    """An appliance transport could not be authenticated or reconstructed."""


class _StrictModel(BaseModel):
    """Immutable strict base for authenticated distribution documents."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class DistributionChunk(_StrictModel):
    """One ordered transport chunk, not a new appliance artifact identity."""

    index: int = Field(ge=0)
    name: str
    sha256: str = Field(pattern=_DIGEST)
    size_bytes: int = Field(ge=1, lt=2 * 1024**3)

    @model_validator(mode="after")
    def safe_name(self) -> Self:
        if not _SAFE_NAME.fullmatch(self.name):
            raise ValueError("distribution chunk name is unsafe")
        return self


class ApplianceDistributionIndex(_StrictModel):
    """Signed recipe for reconstructing canonical release artifact bytes."""

    schema_version: Literal["aptl.appliance-distribution/v1"]
    release_id: str = Field(min_length=1, max_length=128)
    manifest_digest: str = Field(pattern=_DIGEST)
    artifact_name: str
    artifact_sha256: str = Field(pattern=_DIGEST)
    artifact_size_bytes: int = Field(ge=1)
    encoding: Literal["identity"]
    chunks: tuple[DistributionChunk, ...] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_transport(self) -> Self:
        if not _SAFE_NAME.fullmatch(self.artifact_name):
            raise ValueError("distribution artifact name is unsafe")
        if [chunk.index for chunk in self.chunks] != list(range(len(self.chunks))):
            raise ValueError("distribution chunks must be contiguous and ordered")
        if len({chunk.name for chunk in self.chunks}) != len(self.chunks):
            raise ValueError("distribution chunk names must be unique")
        if sum(chunk.size_bytes for chunk in self.chunks) != self.artifact_size_bytes:
            raise ValueError("distribution chunk sizes do not match the artifact")
        return self


class DistributionSignature(_StrictModel):
    """Detached Ed25519 authentication for one canonical distribution index."""

    schema_version: Literal["aptl.appliance-distribution-signature/v1"]
    algorithm: Literal["ed25519"]
    key_id: str = Field(pattern=_DIGEST)
    index_digest: str = Field(pattern=_DIGEST)
    signature: str = Field(min_length=1, max_length=256)


@dataclass(frozen=True)
class DistributionBuildResult:
    """Paths and authenticated index produced by one distribution build."""

    index: ApplianceDistributionIndex
    index_path: Path
    signature_path: Path


MetadataFetcher = Callable[..., bytes]
ArtifactStager = Callable[..., StagedDownload]


class _DigestWriter(Protocol):
    """Minimal hashlib-compatible update surface used while streaming."""

    def update(self, payload: bytes) -> None: ...


def _canonical_index(index: ApplianceDistributionIndex) -> bytes:
    """Serialize an index to its signature-stable canonical representation."""

    return rfc8785.dumps(index.model_dump(mode="json"))


def _key_id(key: Ed25519PublicKey) -> str:
    """Derive the stable SHA-256 identity of an Ed25519 public key."""

    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"sha256:{hashlib.sha256(der).hexdigest()}"


def _open_regular_nofollow(path: Path) -> BinaryIO:
    """Open one regular file without following its final symbolic link."""

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise OSError("path is not a regular file")
    return os.fdopen(descriptor, "rb")


def _write_create_once(path: Path, payload: bytes, mode: int = 0o444) -> None:
    """Create and durably write one immutable distribution file."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(mode)


def _write_chunk(
    path: Path,
    source: BinaryIO,
    *,
    chunk_size: int,
    artifact_hash: _DigestWriter,
) -> tuple[str, int]:
    """Stream one create-once chunk without retaining large artifacts in memory."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o444)
    chunk_hash = hashlib.sha256()
    written = 0
    try:
        with os.fdopen(descriptor, "wb") as output:
            while written < chunk_size:
                payload = source.read(min(1024 * 1024, chunk_size - written))
                if not payload:
                    break
                output.write(payload)
                chunk_hash.update(payload)
                artifact_hash.update(payload)
                written += len(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return f"sha256:{chunk_hash.hexdigest()}", written


def split_distribution_artifact(
    *,
    source: Path,
    output_dir: Path,
    release_id: str,
    manifest_digest: str,
    private_key: Path,
    chunk_size: int = 1900 * 1024**2,
) -> DistributionBuildResult:
    """Split canonical bytes and sign their ordered reconstruction index."""

    if not 0 < chunk_size < 2 * 1024**3 or output_dir.exists():
        raise ApplianceDistributionError("distribution output or chunk size is invalid")
    try:
        with _open_regular_nofollow(private_key) as handle:
            private_key_pem = handle.read(64 * 1024 + 1)
        if len(private_key_pem) > 64 * 1024:
            raise ValueError("private key is too large")
        key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("not Ed25519")
        output_dir.mkdir(parents=True, mode=0o700)
        chunks: list[DistributionChunk] = []
        artifact_hash = hashlib.sha256()
        artifact_size = 0
        with _open_regular_nofollow(source) as handle:
            index = 0
            while True:
                name = f"{source.name}.part-{index:05d}"
                digest, size = _write_chunk(
                    output_dir / name,
                    handle,
                    chunk_size=chunk_size,
                    artifact_hash=artifact_hash,
                )
                if not size:
                    (output_dir / name).unlink(missing_ok=True)
                    break
                artifact_size += size
                chunks.append(
                    DistributionChunk(
                        index=index,
                        name=name,
                        sha256=digest,
                        size_bytes=size,
                    )
                )
                index += 1
                if size < chunk_size:
                    break
                if index == 1000:
                    if handle.read(1):
                        raise ValueError(
                            "artifact requires too many distribution chunks"
                        )
                    break
        if not chunks:
            raise ValueError("artifact is empty")
        distribution = ApplianceDistributionIndex(
            schema_version="aptl.appliance-distribution/v1",
            release_id=release_id,
            manifest_digest=manifest_digest,
            artifact_name=source.name,
            artifact_sha256=f"sha256:{artifact_hash.hexdigest()}",
            artifact_size_bytes=artifact_size,
            encoding="identity",
            chunks=tuple(chunks),
        )
        index_bytes = _canonical_index(distribution)
        index_path = output_dir / f"{source.name}.distribution.json"
        signature_path = output_dir / f"{source.name}.distribution.sig.json"
        _write_create_once(index_path, index_bytes)
        signature = DistributionSignature(
            schema_version="aptl.appliance-distribution-signature/v1",
            algorithm="ed25519",
            key_id=_key_id(key.public_key()),
            index_digest=f"sha256:{hashlib.sha256(index_bytes).hexdigest()}",
            signature=base64.b64encode(key.sign(index_bytes)).decode("ascii"),
        )
        _write_create_once(
            signature_path,
            rfc8785.dumps(signature.model_dump(mode="json")),
        )
        return DistributionBuildResult(distribution, index_path, signature_path)
    except (OSError, ValueError, TypeError) as exc:
        shutil.rmtree(output_dir, ignore_errors=True)
        raise ApplianceDistributionError("distribution build failed") from exc


def _verified_index(
    index_path: Path, signature_path: Path, public_key: Path
) -> ApplianceDistributionIndex:
    """Load and authenticate one canonical distribution index."""

    try:
        with _open_regular_nofollow(index_path) as handle:
            index_bytes = handle.read(1024 * 1024 + 1)
        with _open_regular_nofollow(signature_path) as handle:
            signature_bytes = handle.read(64 * 1024 + 1)
        if len(index_bytes) > 1024 * 1024 or len(signature_bytes) > 64 * 1024:
            raise ValueError("distribution metadata is too large")
        index = model_validate_json_strict(ApplianceDistributionIndex, index_bytes)
        signature = model_validate_json_strict(DistributionSignature, signature_bytes)
        with _open_regular_nofollow(public_key) as handle:
            public_key_pem = handle.read(64 * 1024 + 1)
        if len(public_key_pem) > 64 * 1024:
            raise ValueError("public key is too large")
        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("not Ed25519")
        if signature.key_id != _key_id(key):
            raise ValueError("wrong key")
        digest = f"sha256:{hashlib.sha256(index_bytes).hexdigest()}"
        if digest != signature.index_digest or index_bytes != _canonical_index(index):
            raise ValueError("index identity mismatch")
        key.verify(base64.b64decode(signature.signature, validate=True), index_bytes)
        return index
    except (OSError, ValueError, TypeError, InvalidSignature) as exc:
        raise ApplianceDistributionError(
            "distribution index authentication failed"
        ) from exc


def reconstruct_distribution(
    *,
    index_path: Path,
    signature_path: Path,
    chunks_dir: Path,
    public_key: Path,
    output: Path,
) -> Path:
    """Authenticate, reconstruct, and atomically publish canonical bytes."""

    index = _verified_index(index_path, signature_path, public_key)
    try:
        chunks_root = chunks_dir.resolve(strict=True)
    except OSError as exc:
        raise ApplianceDistributionError(
            "distribution chunks directory is unsafe"
        ) from exc
    if not chunks_root.is_dir() or chunks_dir.is_symlink():
        raise ApplianceDistributionError("distribution chunks directory is unsafe")
    if output.exists() or output.is_symlink():
        raise ApplianceDistributionError("distribution output already exists")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = output.with_name(f".{output.name}.{secrets.token_hex(8)}")
    digest = hashlib.sha256()
    size = 0
    try:
        with temporary.open("xb") as destination:
            for chunk in index.chunks:
                path = chunks_root / chunk.name
                with _open_regular_nofollow(path) as source:
                    chunk_digest = hashlib.sha256()
                    chunk_size = 0
                    for payload in iter(lambda: source.read(1024 * 1024), b""):
                        chunk_digest.update(payload)
                        digest.update(payload)
                        chunk_size += len(payload)
                        size += len(payload)
                        destination.write(payload)
                if (
                    f"sha256:{chunk_digest.hexdigest()}" != chunk.sha256
                    or chunk_size != chunk.size_bytes
                ):
                    raise ApplianceDistributionError(
                        "distribution chunk identity mismatch"
                    )
            destination.flush()
            os.fsync(destination.fileno())
        if (
            f"sha256:{digest.hexdigest()}" != index.artifact_sha256
            or size != index.artifact_size_bytes
        ):
            raise ApplianceDistributionError("reconstructed artifact identity mismatch")
        temporary.chmod(0o444)
        os.link(temporary, output, follow_symlinks=False)
        return output
    except ApplianceDistributionError:
        raise
    except (OSError, ValueError) as exc:
        raise ApplianceDistributionError("distribution reconstruction failed") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _distribution_asset_url(base_url: str, name: str) -> str:
    """Resolve one authenticated safe asset name beneath an HTTPS release URL."""

    parsed = urllib.parse.urlparse(base_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
        or not parsed.path.endswith("/")
        or not _SAFE_NAME.fullmatch(name)
    ):
        raise ApplianceDistributionError("distribution asset URL is invalid")
    encoded = urllib.parse.quote(name, safe="")
    return urllib.parse.urljoin(base_url, encoded)


def github_distribution_urls(
    *, repository: str, tag: str, artifact_name: str
) -> tuple[str, str, str]:
    """Return anonymous GitHub Release URLs for one distribution index."""

    if (
        not _GITHUB_REPOSITORY.fullmatch(repository)
        or not tag
        or len(tag) > 128
        or any(ord(character) < 0x21 for character in tag)
        or not _SAFE_NAME.fullmatch(artifact_name)
    ):
        raise ApplianceDistributionError("GitHub release selection is invalid")
    encoded_tag = urllib.parse.quote(tag, safe="")
    base = f"https://github.com/{repository}/releases/download/{encoded_tag}/"
    encoded_artifact = urllib.parse.quote(artifact_name, safe="")
    return (
        f"{base}{encoded_artifact}.distribution.json",
        f"{base}{encoded_artifact}.distribution.sig.json",
        base,
    )


def fetch_distribution_artifact(
    *,
    index_url: str,
    signature_url: str,
    chunks_base_url: str,
    expected_release_id: str,
    cache_dir: Path,
    public_key: Path,
    output: Path,
    fetch_metadata: MetadataFetcher = fetch_https_metadata,
    stage_artifact: ArtifactStager = stage_https_artifact,
) -> Path:
    """Authenticate metadata, fetch every chunk, and reconstruct automatically."""

    if not expected_release_id or len(expected_release_id) > 128:
        raise ApplianceDistributionError("distribution release identity is invalid")
    try:
        cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        cache_root = cache_dir.resolve(strict=True)
        if cache_dir.is_symlink() or not cache_root.is_dir():
            raise OSError("unsafe cache")
        metadata_dir = cache_root / f".metadata-{secrets.token_hex(8)}"
        assembly_dir = cache_root / f".assembly-{secrets.token_hex(8)}"
        metadata_dir.mkdir(mode=0o700)
        index_bytes = fetch_metadata(index_url, max_bytes=1024 * 1024)
        signature_bytes = fetch_metadata(signature_url, max_bytes=64 * 1024)
        index_path = metadata_dir / "distribution.json"
        signature_path = metadata_dir / "distribution.sig.json"
        _write_create_once(index_path, index_bytes, mode=0o400)
        _write_create_once(signature_path, signature_bytes, mode=0o400)
        index = _verified_index(index_path, signature_path, public_key)
        if index.release_id != expected_release_id:
            raise ApplianceDistributionError(
                "distribution release identity did not match selection"
            )
        if output.name != index.artifact_name:
            raise ApplianceDistributionError(
                "distribution output name did not match authenticated metadata"
            )
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if shutil.disk_usage(output.parent).free < index.artifact_size_bytes:
            raise ApplianceDistributionError(
                "insufficient disk space for reconstructed artifact"
            )
        assembly_dir.mkdir(mode=0o700)
        for chunk in index.chunks:
            staged = stage_artifact(
                url=_distribution_asset_url(chunks_base_url, chunk.name),
                cache_dir=cache_root / "chunks",
                filename=chunk.name,
                sha256=chunk.sha256,
                size_bytes=chunk.size_bytes,
            )
            os.link(
                staged.path,
                assembly_dir / chunk.name,
                follow_symlinks=False,
            )
        return reconstruct_distribution(
            index_path=index_path,
            signature_path=signature_path,
            chunks_dir=assembly_dir,
            public_key=public_key,
            output=output,
        )
    except ApplianceDistributionError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise ApplianceDistributionError("distribution fetch failed") from exc
    finally:
        for temporary in (locals().get("metadata_dir"), locals().get("assembly_dir")):
            if isinstance(temporary, Path):
                shutil.rmtree(temporary, ignore_errors=True)
