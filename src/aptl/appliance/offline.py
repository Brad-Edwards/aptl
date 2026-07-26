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
_RELEASE_ENV = re.compile(
    r"^APTL_APPLIANCE_SCENARIO=[a-z0-9][a-z0-9.-]*\n"
    r"APTL_APPLIANCE_VERSION=[0-9]+(?:\.[0-9]+){2}(?:[a-z0-9.+-]*)?\n$"
)
_APTL_WHEEL = re.compile(
    r"^aptl_labs-([0-9]+(?:\.[0-9]+){2}(?:[a-z0-9.+_]*)?)-[^/]+\.whl$"
)


class OfflinePayloadError(RuntimeError):
    """The staged payload is incomplete, mutable, or outside its closed shape."""


@dataclass(frozen=True)
class OfflinePayloadResult:
    """Content identity of one finalized offline payload."""

    output_path: Path
    sha256: str
    size_bytes: int


def _validate_staging(staging: Path) -> list[Path]:
    if staging.is_symlink() or not staging.is_dir():
        raise OfflinePayloadError("offline payload staging directory is invalid")
    entries = {path.name for path in staging.iterdir()}
    if entries != _ALLOWED_TOP_LEVEL:
        raise OfflinePayloadError("offline payload contains unexpected top-level files")
    paths = sorted(
        (path for path in staging.rglob("*")),
        key=lambda path: path.relative_to(staging).as_posix(),
    )
    for path in paths:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise OfflinePayloadError("offline payload must not contain a symlink")
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise OfflinePayloadError("offline payload contains an unsupported file")
    wheelhouse = staging / "wheelhouse"
    wheels = [path for path in wheelhouse.iterdir() if path.is_file()]
    aptl_wheels = [
        (path, match.group(1).replace("_", "-"))
        for path in wheels
        if (match := _APTL_WHEEL.fullmatch(path.name)) is not None
    ]
    if not wheels or any(path.suffix != ".whl" for path in wheels):
        raise OfflinePayloadError("offline payload wheelhouse is incomplete")
    for required in ("project.tar", "oci-images.tar"):
        if (staging / required).stat().st_size <= 0:
            raise OfflinePayloadError(f"offline payload {required} is empty")
    env_text = (staging / "appliance-release.env").read_text(encoding="utf-8")
    if not _RELEASE_ENV.fullmatch(env_text):
        raise OfflinePayloadError("invalid non-secret appliance release environment")
    env_version = env_text.split("APTL_APPLIANCE_VERSION=", 1)[1].strip()
    if len(aptl_wheels) != 1 or aptl_wheels[0][1] != env_version:
        raise OfflinePayloadError(
            "offline payload must contain exactly one matching APTL wheel"
        )
    return paths


def _tar_info(path: Path, relative: str) -> tarfile.TarInfo:
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


def _open_nofollow(path: Path):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.fdopen(os.open(path, flags), "rb")


def _write_tar(staging: Path, paths: list[Path], candidate: Path) -> None:
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
    digest = hashlib.sha256()
    size = 0
    with _open_nofollow(path) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return f"sha256:{digest.hexdigest()}", size


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
        try:
            candidate.unlink(missing_ok=True)
        except OSError:
            pass
