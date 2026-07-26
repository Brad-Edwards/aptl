"""Deterministic assembly of the closed first-boot offline payload."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from aptl.appliance.versioning import aptl_wheel_version, is_appliance_version

_ALLOWED_TOP_LEVEL = frozenset(
    {
        "wheelhouse",
        "project.tar",
        "oci-images.tar",
        "appliance-release.env",
        "aptl-appliance-first-boot",
        "aptl-appliance-first-boot.service",
    }
)
_SCENARIO_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
_INVALID_RELEASE_ENV = "invalid non-secret appliance release environment"


class OfflinePayloadError(RuntimeError):
    """The staged payload is incomplete, mutable, or outside its closed shape."""


@dataclass(frozen=True)
class OfflinePayloadResult:
    """Content identity of one finalized offline payload."""

    output_path: Path
    sha256: str
    size_bytes: int


def _validate_staged_paths(staging: Path) -> list[Path]:
    """Return a deterministic list after rejecting special files and links."""

    if staging.is_symlink() or not staging.is_dir():
        raise OfflinePayloadError("offline payload staging directory is invalid")
    entries = {path.name for path in staging.iterdir()}
    if entries != _ALLOWED_TOP_LEVEL:
        raise OfflinePayloadError("offline payload contains unexpected top-level files")
    paths = sorted(
        staging.rglob("*"),
        key=lambda path: path.relative_to(staging).as_posix(),
    )
    for path in paths:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise OfflinePayloadError("offline payload must not contain a symlink")
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise OfflinePayloadError("offline payload contains an unsupported file")
    return paths


def _wheel_version(path: Path) -> str | None:
    """Extract the normalized APTL version from one wheel filename."""

    return aptl_wheel_version(path.name)


def _release_environment(staging: Path) -> tuple[str, str]:
    """Read the two-field non-secret release environment."""

    env_text = (staging / "appliance-release.env").read_text(encoding="utf-8")
    lines = env_text.splitlines()
    if len(lines) != 2 or not env_text.endswith("\n"):
        raise OfflinePayloadError(_INVALID_RELEASE_ENV)
    scenario_prefix = "APTL_APPLIANCE_SCENARIO="
    version_prefix = "APTL_APPLIANCE_VERSION="
    if not lines[0].startswith(scenario_prefix) or not lines[1].startswith(
        version_prefix
    ):
        raise OfflinePayloadError(_INVALID_RELEASE_ENV)
    scenario = lines[0][len(scenario_prefix) :]
    version = lines[1][len(version_prefix) :]
    if not _SCENARIO_RE.fullmatch(scenario) or not is_appliance_version(version):
        raise OfflinePayloadError(_INVALID_RELEASE_ENV)
    return scenario, version


def _validate_wheelhouse(staging: Path, expected_version: str) -> None:
    """Require a closed wheelhouse with exactly one matching APTL wheel."""

    wheelhouse = staging / "wheelhouse"
    wheels = [path for path in wheelhouse.iterdir() if path.is_file()]
    if not wheels or any(path.suffix != ".whl" for path in wheels):
        raise OfflinePayloadError("offline payload wheelhouse is incomplete")
    aptl_versions = [
        version for path in wheels if (version := _wheel_version(path)) is not None
    ]
    if aptl_versions != [expected_version]:
        raise OfflinePayloadError(
            "offline payload must contain exactly one matching APTL wheel"
        )


def _validate_staging(staging: Path) -> list[Path]:
    """Validate the closed staging shape and return its deterministic paths."""

    paths = _validate_staged_paths(staging)
    for required in ("project.tar", "oci-images.tar"):
        if (staging / required).stat().st_size <= 0:
            raise OfflinePayloadError(f"offline payload {required} is empty")
    _scenario, version = _release_environment(staging)
    _validate_wheelhouse(staging, version)
    return paths


def _tar_info(path: Path, relative: str) -> tarfile.TarInfo:
    """Create reproducible metadata for one staged tar member."""

    info = tarfile.TarInfo(relative)
    path_info = path.stat(follow_symlinks=False)
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    if path.is_dir():
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        info.size = 0
    else:
        info.type = tarfile.REGTYPE
        info.mode = 0o755 if relative == "aptl-appliance-first-boot" else 0o644
        info.size = path_info.st_size
    return info


def _open_nofollow(path: Path) -> BinaryIO:
    """Open one regular payload path without following its final symlink."""

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.fdopen(os.open(path, flags), "rb")


def _write_tar(staging: Path, paths: list[Path], candidate: Path) -> None:
    """Write a deterministic USTAR archive from already-validated paths."""

    try:
        with tarfile.open(candidate, "w", format=tarfile.USTAR_FORMAT) as archive:
            for path in paths:
                relative = path.relative_to(staging).as_posix()
                info = _tar_info(path, relative)
                if path.is_dir():
                    archive.addfile(info)
                else:
                    with _open_nofollow(path) as handle:
                        archive.addfile(info, handle)
    except (OSError, tarfile.TarError) as exc:
        raise OfflinePayloadError("offline payload could not be assembled") from exc


def _hash_file(path: Path) -> tuple[str, int]:
    """Return the streaming SHA-256 identity and byte count for a file."""

    digest = hashlib.sha256()
    size = 0
    with _open_nofollow(path) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return f"sha256:{digest.hexdigest()}", size


def _remove_candidate(path: Path) -> None:
    """Best-effort remove an unpublished payload candidate."""

    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def build_offline_payload(
    staging_dir: Path,
    output_path: Path,
) -> OfflinePayloadResult:
    """Create a reproducible read-only tar without resolving any dependency."""

    staging = staging_dir.resolve()
    paths = _validate_staging(staging)
    output = output_path.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.exists() or output.is_symlink():
        raise OfflinePayloadError("offline payload output already exists")
    candidate = output.with_name(f".{output.name}.candidate-{secrets.token_hex(8)}")
    try:
        _write_tar(staging, paths, candidate)
        candidate.chmod(0o444)
        try:
            os.link(candidate, output, follow_symlinks=False)
        except FileExistsError as exc:
            raise OfflinePayloadError("offline payload output already exists") from exc
        digest, size = _hash_file(output)
        return OfflinePayloadResult(output, digest, size)
    finally:
        _remove_candidate(candidate)
