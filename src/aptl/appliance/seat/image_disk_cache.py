"""Digest keyed seat disk cache and its verification records."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from pathlib import Path

from aptl.appliance.seat.image_config import (
    SeatImageConfig,
    parse_seat_image_config,
)

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
DISK_FILENAME = "seat-disk.qcow2"


class SeatImageError(RuntimeError):
    """One seat VM disk could not be resolved from its registry reference."""


def _sha256_of(payload: bytes) -> str:
    """Return the content digest of a fetched document."""

    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _cache_entry(cache_dir: Path, digest: str) -> Path:
    """Return the contained disk cache path for one validated digest."""

    if not _DIGEST.fullmatch(digest):
        raise SeatImageError("seat image digest is not a lowercase sha256 digest")
    entry = cache_dir / digest.removeprefix("sha256:") / DISK_FILENAME
    if not entry.is_relative_to(cache_dir):
        raise SeatImageError("seat image cache entry escapes the cache")
    return entry


def _stamp_path(disk: Path) -> Path:
    """Return the verification stamp beside one cached disk."""

    return disk.with_suffix(".verified.json")


def write_verification_stamp(disk: Path, *, digest: str, size_bytes: int) -> None:
    """Record the identity established by a complete disk hash verification."""

    if disk.name != DISK_FILENAME or not re.fullmatch(
        r"[a-f0-9]{64}", disk.parent.name
    ):
        raise SeatImageError("seat disk verification path is invalid")
    status = disk.stat(follow_symlinks=False)
    if not stat.S_ISREG(status.st_mode):
        raise SeatImageError("seat disk verification requires a regular file")
    payload = json.dumps(
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
    ).encode()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
        file_flags |= os.O_NOFOLLOW
    directory_fd = os.open(disk.parent, directory_flags)
    temporary_name = f".seat-disk.verified.{secrets.token_hex(8)}"
    try:
        temporary_fd = os.open(
            temporary_name, file_flags, 0o600, dir_fd=directory_fd
        )
        with os.fdopen(temporary_fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            "seat-disk.verified.json",
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
    finally:
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def verified_cached_disk(
    cache_dir: Path, *, digest: str, size_bytes: int | None = None
) -> Path | None:
    """Reuse a disk only while its cheap, local verification record agrees."""

    disk = _cache_entry(cache_dir, digest)
    try:
        status = disk.stat(follow_symlinks=False)
        stamp = json.loads(_stamp_path(disk).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    expected = {
        "digest": digest,
        "inode": status.st_ino,
        "mtime_ns": status.st_mtime_ns,
        "mode": status.st_mode & 0o7777,
        "size_bytes": status.st_size,
    }
    if (
        not stat.S_ISREG(status.st_mode)
        or not isinstance(stamp, dict)
        or any(stamp.get(key) != value for key, value in expected.items())
        or (size_bytes is not None and status.st_size != size_bytes)
    ):
        return None
    return disk


def cached_seat_image_config(
    cache_dir: Path, *, disk_digest: str
) -> tuple[SeatImageConfig, str] | None:
    """Read the config previously bound to this disk, without a registry call."""

    entry = _cache_entry(cache_dir, disk_digest).parent
    try:
        binding = json.loads((entry / "seat-config-binding.json").read_bytes())
        payload = (entry / "seat-config.json").read_bytes()
        config_digest = binding["config_digest"]
        if (
            binding["disk_digest"] != disk_digest
            or not isinstance(config_digest, str)
            or not _DIGEST.fullmatch(config_digest)
            or _sha256_of(payload) != config_digest
        ):
            raise SeatImageError("cached seat image config does not match its disk")
        return parse_seat_image_config(payload), config_digest
    except FileNotFoundError:
        return None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SeatImageError("cached seat image config is invalid") from exc
