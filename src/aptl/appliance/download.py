"""Retry-safe HTTPS staging into a content-addressed appliance cache."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from email.message import Message
from pathlib import Path
from typing import Protocol

_DIGEST = re.compile(r"^sha256:([a-f0-9]{64})$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")


class ApplianceDownloadError(RuntimeError):
    """A remote appliance artifact could not be staged safely."""


class DownloadResponse(Protocol):
    """Bounded response surface used by the downloader and its tests."""

    status: int
    headers: object

    def read(self, size: int = -1) -> bytes: ...

    def geturl(self) -> str: ...

    def __enter__(self) -> DownloadResponse: ...

    def __exit__(self, *args: object) -> None: ...


OpenRequest = Callable[[urllib.request.Request], DownloadResponse]


@dataclass(frozen=True)
class StagedDownload:
    """Verified immutable cache entry."""

    path: Path
    sha256: str
    size_bytes: int
    reused: bool


class _BoundedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Permit only a small HTTPS-to-HTTPS redirect chain."""

    max_redirections = 5

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        """Admit only bounded HTTPS redirects."""

        if code not in {301, 302, 303, 307, 308}:
            return None
        source = urllib.parse.urlparse(req.full_url)
        destination = urllib.parse.urlparse(newurl)
        if source.scheme != "https" or destination.scheme != "https":
            raise urllib.error.HTTPError(
                newurl, code, "non-HTTPS artifact redirect", None, None
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_request(request: urllib.request.Request) -> DownloadResponse:
    """Open one artifact request with the bounded redirect policy."""

    opener = urllib.request.build_opener(_BoundedRedirectHandler())
    return opener.open(request, timeout=60)


def _file_identity(path: Path) -> tuple[str, int]:
    """Stream the SHA-256 identity and size of one regular file."""

    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        for payload in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(payload)
            size += len(payload)
    return f"sha256:{digest.hexdigest()}", size


def _header(headers: object, name: str) -> str | None:
    """Read one string-valued HTTP header from a response abstraction."""

    getter = getattr(headers, "get", None)
    value = getter(name) if callable(getter) else None
    return value if isinstance(value, str) else None


def _admit_response(
    response: DownloadResponse,
    *,
    offset: int,
    expected_size: int,
) -> None:
    """Validate status, final transport, and the exact response extent."""

    final_url = urllib.parse.urlparse(response.geturl())
    if final_url.scheme != "https":
        raise ApplianceDownloadError("artifact response did not remain on HTTPS")
    expected_status = 206 if offset else 200
    if response.status != expected_status:
        raise ApplianceDownloadError(
            "artifact server did not honor the bounded request"
        )
    if offset:
        expected_range = f"bytes {offset}-{expected_size - 1}/{expected_size}"
        if _header(response.headers, "Content-Range") != expected_range:
            raise ApplianceDownloadError("artifact resume range did not match")
    length = _header(response.headers, "Content-Length")
    if length is None or not length.isdecimal():
        raise ApplianceDownloadError("artifact response length is unavailable")
    if int(length) != expected_size - offset:
        raise ApplianceDownloadError("artifact response length did not match")


def fetch_https_metadata(
    url: str,
    *,
    max_bytes: int,
    open_request: OpenRequest = _open_request,
) -> bytes:
    """Fetch one bounded HTTPS metadata document before authenticating it.

    Distribution metadata cannot be content-addressed until its detached
    signature has been verified.  This narrow fetch therefore applies the
    same HTTPS/redirect constraints as artifact staging, requires an exact
    response length, and refuses to retain an oversized response.
    """

    parsed = urllib.parse.urlparse(url)
    if (
        not 0 < max_bytes <= 1024 * 1024
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ApplianceDownloadError("metadata download request is invalid")
    request = urllib.request.Request(url, method="GET")
    try:
        with open_request(request) as response:
            final_url = urllib.parse.urlparse(response.geturl())
            length = _header(response.headers, "Content-Length")
            if (
                response.status != 200
                or final_url.scheme != "https"
                or length is None
                or not length.isdecimal()
                or not 0 < int(length) <= max_bytes
            ):
                raise ApplianceDownloadError("metadata response is invalid")
            payload = response.read(max_bytes + 1)
            if len(payload) != int(length) or len(payload) > max_bytes:
                raise ApplianceDownloadError("metadata response length did not match")
            return payload
    except ApplianceDownloadError:
        raise
    except (OSError, ValueError) as exc:
        raise ApplianceDownloadError("metadata download failed") from exc


def stage_https_artifact(
    *,
    url: str,
    cache_dir: Path,
    filename: str,
    sha256: str,
    size_bytes: int,
    open_request: OpenRequest = _open_request,
) -> StagedDownload:
    """Resume, verify, and atomically publish one immutable cache entry."""

    match = _DIGEST.fullmatch(sha256)
    parsed = urllib.parse.urlparse(url)
    if (
        match is None
        or not _SAFE_NAME.fullmatch(filename)
        or size_bytes < 1
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ApplianceDownloadError("artifact download request is invalid")
    root = cache_dir.resolve()
    destination_dir = root / match.group(1)
    destination_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = destination_dir / filename
    if destination.exists() or destination.is_symlink():
        try:
            actual_digest, actual_size = _file_identity(destination)
        except OSError as exc:
            raise ApplianceDownloadError("cached artifact is unsafe") from exc
        if (actual_digest, actual_size) != (sha256, size_bytes):
            raise ApplianceDownloadError("cached artifact identity does not match")
        return StagedDownload(destination, sha256, size_bytes, reused=True)

    partial = destination_dir / f".{filename}.partial"
    try:
        offset = partial.stat(follow_symlinks=False).st_size if partial.exists() else 0
        if partial.is_symlink() or offset > size_bytes:
            raise ApplianceDownloadError("partial artifact is unsafe")
        required = size_bytes - offset
        if shutil.disk_usage(destination_dir).free < required:
            raise ApplianceDownloadError("insufficient disk space for artifact")
        request = urllib.request.Request(
            url,
            headers={"Range": f"bytes={offset}-"} if offset else {},
            method="GET",
        )
        output_flags = os.O_WRONLY | os.O_CLOEXEC
        output_flags |= os.O_APPEND if offset else os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            output_flags |= os.O_NOFOLLOW
        with open_request(request) as response:
            _admit_response(response, offset=offset, expected_size=size_bytes)
            descriptor = os.open(partial, output_flags, 0o600)
            with os.fdopen(descriptor, "ab" if offset else "wb") as output:
                written = offset
                while payload := response.read(1024 * 1024):
                    written += len(payload)
                    if written > size_bytes:
                        raise ApplianceDownloadError(
                            "artifact exceeded its declared size"
                        )
                    output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        actual_digest, actual_size = _file_identity(partial)
        if (actual_digest, actual_size) != (sha256, size_bytes):
            raise ApplianceDownloadError("downloaded artifact identity does not match")
        partial.chmod(0o444)
        os.replace(partial, destination)
        return StagedDownload(destination, sha256, size_bytes, reused=False)
    except ApplianceDownloadError:
        raise
    except (OSError, ValueError) as exc:
        raise ApplianceDownloadError("artifact download failed") from exc
