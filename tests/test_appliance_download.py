"""Authenticated public artifact staging tests."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest

from aptl.appliance.download import (
    ApplianceDownloadError,
    fetch_https_metadata,
    stage_https_artifact,
)


class _Response(io.BytesIO):
    def __init__(self, payload: bytes, *, status: int, headers: dict[str, str]):
        super().__init__(payload)
        self.status = status
        self.headers = headers

    def geturl(self) -> str:
        return "https://objects.example.test/artifact"


def test_download_resumes_and_publishes_content_addressed_bytes(tmp_path: Path) -> None:
    payload = b"qualified-appliance-bytes"
    digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"
    digest_dir = tmp_path / digest.removeprefix("sha256:")
    digest_dir.mkdir(parents=True)
    partial = digest_dir / ".disk.qcow2.partial"
    partial.write_bytes(payload[:9])
    requests = []

    def open_request(request):
        requests.append(request)
        remaining = payload[9:]
        return _Response(
            remaining,
            status=206,
            headers={
                "Content-Length": str(len(remaining)),
                "Content-Range": f"bytes 9-{len(payload) - 1}/{len(payload)}",
            },
        )

    staged = stage_https_artifact(
        url="https://example.test/disk.qcow2",
        cache_dir=tmp_path,
        filename="disk.qcow2",
        sha256=digest,
        size_bytes=len(payload),
        open_request=open_request,
    )

    assert staged.path.read_bytes() == payload
    assert staged.reused is False
    assert requests[0].headers["Range"] == "bytes=9-"
    assert staged.path.stat().st_mode & 0o777 == 0o444


def test_download_rejects_wrong_digest_and_keeps_partial(tmp_path: Path) -> None:
    payload = b"wrong"
    digest = "sha256:" + "a" * 64

    with pytest.raises(ApplianceDownloadError, match="identity"):
        stage_https_artifact(
            url="https://example.test/disk.qcow2",
            cache_dir=tmp_path,
            filename="disk.qcow2",
            sha256=digest,
            size_bytes=len(payload),
            open_request=lambda _request: _Response(
                payload,
                status=200,
                headers={"Content-Length": str(len(payload))},
            ),
        )

    assert not (tmp_path / ("a" * 64) / "disk.qcow2").exists()
    assert (tmp_path / ("a" * 64) / ".disk.qcow2.partial").exists()


def test_download_rejects_non_https_source(tmp_path: Path) -> None:
    with pytest.raises(ApplianceDownloadError, match="invalid"):
        stage_https_artifact(
            url="http://example.test/disk.qcow2",
            cache_dir=tmp_path,
            filename="disk.qcow2",
            sha256="sha256:" + "a" * 64,
            size_bytes=1,
        )


def test_metadata_fetch_is_bounded_and_requires_exact_length() -> None:
    payload = b'{"signed":"later"}'

    fetched = fetch_https_metadata(
        "https://github.example.test/release/index.json",
        max_bytes=1024,
        open_request=lambda _request: _Response(
            payload,
            status=200,
            headers={"Content-Length": str(len(payload))},
        ),
    )

    assert fetched == payload


def test_metadata_fetch_rejects_oversized_declaration() -> None:
    with pytest.raises(ApplianceDownloadError, match="response is invalid"):
        fetch_https_metadata(
            "https://github.example.test/release/index.json",
            max_bytes=8,
            open_request=lambda _request: _Response(
                b"too-large",
                status=200,
                headers={"Content-Length": "9"},
            ),
        )
