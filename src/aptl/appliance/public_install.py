"""Transactional installation of a signed public appliance release."""

from __future__ import annotations

import io
import os
import re
import secrets
import shutil
import stat
import tarfile
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from aptl.appliance.distribution import (
    ApplianceDistributionError,
    fetch_distribution_artifact,
    github_distribution_urls,
)
from aptl.appliance.download import fetch_https_metadata
from aptl.appliance.manifest import (
    ApplianceManifestError,
    verify_release_directory,
    verify_release_metadata,
)

_RELEASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_METADATA_BYTES = 1024 * 1024
_MAX_METADATA_MEMBERS = 1000


class AppliancePublicInstallError(RuntimeError):
    """A public appliance release could not be installed safely."""


class _ReleaseIdentity(Protocol):
    """Signed manifest or inspection carrying the selected release identity."""

    release_id: str


@dataclass(frozen=True)
class PublicReleaseInstallResult:
    """Location and reuse status of one admitted public release."""

    release_id: str
    release_dir: Path
    reused: bool


MetadataFetcher = Callable[..., bytes]
ArtifactFetcher = Callable[..., Path]
MetadataVerifier = Callable[[Path, Path], _ReleaseIdentity]
ReleaseVerifier = Callable[..., _ReleaseIdentity]


@dataclass(frozen=True)
class PublicReleaseSelection:
    """Immutable coordinates of one GitHub-hosted appliance release."""

    repository: str
    tag: str
    release_id: str


@dataclass(frozen=True)
class PublicReleaseInstallDependencies:
    """Injectable transfer and verification boundaries for one installation."""

    fetch_metadata: MetadataFetcher = fetch_https_metadata
    fetch_artifact: ArtifactFetcher = fetch_distribution_artifact
    verify_metadata: MetadataVerifier = verify_release_metadata
    verify_release: ReleaseVerifier = verify_release_directory


def _ensure_private_directory(path: Path) -> None:
    """Create or validate one owner-only directory without accepting a symlink."""

    if path.is_symlink():
        raise OSError("directory is a symlink")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.chmod(0o700)
    info = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise OSError("directory is not private")


def _copy_public_anchor(source: Path, destination: Path) -> None:
    """Atomically copy one bounded regular public key without following links."""

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}")
    try:
        descriptor = os.open(source, flags)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OSError("anchor is not regular")
            payload = handle.read(64 * 1024 + 1)
        if not payload or len(payload) > 64 * 1024:
            raise OSError("anchor has invalid size")
        output = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        with os.fdopen(output, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _metadata_member_path(member: tarfile.TarInfo) -> PurePosixPath | None:
    """Normalize one member name without allowing traversal or duplicates."""

    relative = PurePosixPath(member.name)
    parts = tuple(part for part in relative.parts if part not in {"", "."})
    if relative.is_absolute() or ".." in parts:
        raise ValueError("unsafe member path")
    if not parts:
        if member.isdir():
            return None
        raise ValueError("unsafe member path")
    return PurePosixPath(*parts)


def _write_metadata_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    relative: PurePosixPath,
) -> None:
    """Write one validated directory or bounded regular member."""

    target = destination.joinpath(*relative.parts)
    if member.isdir():
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        return
    if not member.isreg() or member.size < 0:
        raise ValueError("unsupported member type")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    source = archive.extractfile(member)
    if source is None:
        raise ValueError("member is unreadable")
    content = source.read(member.size + 1)
    if len(content) != member.size:
        raise ValueError("member size mismatch")
    with target.open("xb") as handle:
        handle.write(content)
    target.chmod(0o400)


def _extract_metadata_archive(payload: bytes, destination: Path) -> None:
    """Extract a bounded regular-file-only metadata archive into a new directory."""

    if not payload or len(payload) > _MAX_METADATA_BYTES:
        raise AppliancePublicInstallError("public release metadata archive is invalid")
    seen: set[PurePosixPath] = set()
    total_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            members = archive.getmembers()
            if not members or len(members) > _MAX_METADATA_MEMBERS:
                raise ValueError("invalid member count")
            for member in members:
                relative = _metadata_member_path(member)
                if relative is None:
                    continue
                if relative in seen:
                    raise ValueError("duplicate member")
                seen.add(relative)
                if member.isreg():
                    total_size += member.size
                    if total_size > _MAX_METADATA_BYTES:
                        raise ValueError("metadata is too large")
                _write_metadata_member(archive, member, destination, relative)
    except AppliancePublicInstallError:
        raise
    except (OSError, tarfile.TarError, ValueError) as exc:
        raise AppliancePublicInstallError(
            "public release metadata archive is unsafe"
        ) from exc


def install_public_release(
    *,
    selection: PublicReleaseSelection,
    release_public_key: Path,
    qualification_public_key: Path,
    seat_root: Path,
    cache_dir: Path,
    dependencies: PublicReleaseInstallDependencies = PublicReleaseInstallDependencies(),
) -> PublicReleaseInstallResult:
    """Download, authenticate, and atomically install one public release."""

    repository, tag, release_id = (
        selection.repository,
        selection.tag,
        selection.release_id,
    )
    fetch_metadata = dependencies.fetch_metadata
    fetch_artifact = dependencies.fetch_artifact
    verify_metadata = dependencies.verify_metadata
    verify_release = dependencies.verify_release
    if not _RELEASE_ID.fullmatch(release_id):
        raise AppliancePublicInstallError("public release identity is invalid")
    try:
        _index, _signature, assets_base = github_distribution_urls(
            repository=repository,
            tag=tag,
            artifact_name="aptl-golden.qcow2",
        )
        _ensure_private_directory(seat_root)
        launch_dir = seat_root / "launch"
        _ensure_private_directory(launch_dir)
        destination = launch_dir / "release"
        if destination.exists() or destination.is_symlink():
            inspection = verify_release(
                destination,
                release_public_key,
                qualification_public_key_path=qualification_public_key,
            )
            if inspection.release_id != release_id:
                raise AppliancePublicInstallError(
                    "a different appliance release is already installed"
                )
            _copy_public_anchor(release_public_key, launch_dir / "release-public.pem")
            _copy_public_anchor(
                qualification_public_key,
                launch_dir / "qualification-public.pem",
            )
            return PublicReleaseInstallResult(release_id, destination, True)

        staging = launch_dir / f".release-install-{secrets.token_hex(8)}"
        release_staging = staging / "release"
        staging.mkdir(mode=0o700)
        release_staging.mkdir(mode=0o700)
        encoded_name = urllib.parse.quote(f"{release_id}.metadata.tar", safe="")
        metadata = fetch_metadata(
            f"{assets_base}{encoded_name}",
            max_bytes=_MAX_METADATA_BYTES,
        )
        _extract_metadata_archive(metadata, release_staging)
        manifest = verify_metadata(release_staging, release_public_key)
        if manifest.release_id != release_id:
            raise AppliancePublicInstallError(
                "public release metadata identity did not match selection"
            )
        artifacts = release_staging / "artifacts"
        artifacts.mkdir(mode=0o700, exist_ok=True)
        for artifact_name in ("aptl-golden.qcow2", "offline-payload.tar"):
            index_url, signature_url, chunks_base_url = github_distribution_urls(
                repository=repository,
                tag=tag,
                artifact_name=artifact_name,
            )
            fetch_artifact(
                index_url=index_url,
                signature_url=signature_url,
                chunks_base_url=chunks_base_url,
                expected_release_id=release_id,
                cache_dir=cache_dir,
                public_key=release_public_key,
                output=artifacts / artifact_name,
            )
        inspection = verify_release(
            release_staging,
            release_public_key,
            qualification_public_key_path=qualification_public_key,
        )
        if inspection.release_id != release_id:
            raise AppliancePublicInstallError(
                "verified public release identity did not match selection"
            )
        os.replace(release_staging, destination)
        _copy_public_anchor(release_public_key, launch_dir / "release-public.pem")
        _copy_public_anchor(
            qualification_public_key,
            launch_dir / "qualification-public.pem",
        )
        return PublicReleaseInstallResult(release_id, destination, False)
    except AppliancePublicInstallError:
        raise
    except (ApplianceDistributionError, ApplianceManifestError, OSError) as exc:
        raise AppliancePublicInstallError("public release installation failed") from exc
    finally:
        candidate = locals().get("staging")
        if isinstance(candidate, Path):
            shutil.rmtree(candidate, ignore_errors=True)
