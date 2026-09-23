"""Seat VM disk resolution from an OCI registry reference."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aptl.appliance.download import ApplianceDownloadError, StagedDownload
from aptl.appliance.seat import image as seat_image
from aptl.appliance.seat.image import (
    DISK_MEDIA_TYPE,
    SeatImageError,
    parse_seat_image_reference,
    resolve_seat_image,
)

DISK_BYTES = b"qcow2-disk-bytes"
DISK_DIGEST = "sha256:" + hashlib.sha256(DISK_BYTES).hexdigest()


def _manifest(layers: list[dict[str, object]]) -> bytes:
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": layers,
        }
    ).encode()


def _disk_layer(size: int = len(DISK_BYTES)) -> dict[str, object]:
    return {"mediaType": DISK_MEDIA_TYPE, "digest": DISK_DIGEST, "size": size}


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch):
    """Serve canned registry documents and record what was requested."""

    state: dict[str, object] = {"documents": {}, "requests": [], "staged": []}

    def fake_metadata(url: str, *, max_bytes: int, headers=None, **_: object) -> bytes:
        state["requests"].append((url, dict(headers or {})))
        documents: dict[str, bytes] = state["documents"]  # type: ignore[assignment]
        for suffix, payload in documents.items():
            if url.endswith(suffix):
                return payload
        raise ApplianceDownloadError("not found")

    def fake_stage(*, url, cache_dir, filename, sha256, size_bytes, headers=None):
        state["staged"].append((url, sha256, size_bytes, dict(headers or {})))
        path = Path(cache_dir) / sha256.removeprefix("sha256:") / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(DISK_BYTES)
        return StagedDownload(path, sha256, size_bytes, reused=False)

    monkeypatch.setattr(seat_image, "fetch_https_metadata", fake_metadata)
    monkeypatch.setattr(seat_image, "stage_https_artifact", fake_stage)
    return state


def _serve(registry, *, manifest: bytes, token: str | None = "pull-token") -> None:
    documents = {"/manifests/latest": manifest}
    if token is not None:
        documents["/token?service=ghcr.io&scope=repository%3Aowner%2Fseat%3Apull"] = (
            json.dumps({"token": token}).encode()
        )
    registry["documents"] = documents


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("ghcr.io/owner/seat:v1", "ghcr.io/owner/seat:v1"),
        ("ghcr.io/owner/seat", "ghcr.io/owner/seat:latest"),
        (f"ghcr.io/owner/seat@{DISK_DIGEST}", f"ghcr.io/owner/seat@{DISK_DIGEST}"),
        ("registry.example:5000/a/b/c:tag", "registry.example:5000/a/b/c:tag"),
    ],
)
def test_reference_parsing_round_trips(reference: str, expected: str) -> None:
    assert str(parse_seat_image_reference(reference)) == expected


@pytest.mark.parametrize(
    "reference",
    [
        "",
        "   ",
        "seat:latest",
        "ghcr.io/Owner/seat",
        "ghcr.io/owner/seat@sha256:notadigest",
        "ghcr.io/owner/seat@SHA256:" + "a" * 64,
        "ghcr.io/owner/seat:bad tag",
        "ghcr.io/owner/seat:",
    ],
)
def test_ambiguous_references_are_refused(reference: str) -> None:
    # A reference selects what a seat boots, so it is refused rather than
    # normalized into something the operator did not write.
    with pytest.raises(SeatImageError):
        parse_seat_image_reference(reference)


def test_resolves_disk_layer_and_verifies_it_by_digest(registry, tmp_path) -> None:
    _serve(registry, manifest=_manifest([_disk_layer()]))

    staged = resolve_seat_image("ghcr.io/owner/seat:latest", cache_dir=tmp_path)

    assert staged.digest == DISK_DIGEST
    assert staged.path.read_bytes() == DISK_BYTES
    url, sha256, size, headers = registry["staged"][0]
    assert url.endswith(f"/v2/owner/seat/blobs/{DISK_DIGEST}")
    # The staging helper is what enforces the digest, so it must receive the
    # full sha256:<hex> form the manifest declared.
    assert sha256 == DISK_DIGEST
    assert size == len(DISK_BYTES)
    assert headers["Authorization"] == "Bearer pull-token"


def test_manifest_request_is_authenticated_and_accepts_oci_types(
    registry, tmp_path
) -> None:
    _serve(registry, manifest=_manifest([_disk_layer()]))

    resolve_seat_image("ghcr.io/owner/seat:latest", cache_dir=tmp_path)

    manifest_url, headers = next(
        entry for entry in registry["requests"] if "/manifests/" in entry[0]
    )
    assert manifest_url == "https://ghcr.io/v2/owner/seat/manifests/latest"
    assert headers["Authorization"] == "Bearer pull-token"
    assert "application/vnd.oci.image.manifest.v1+json" in headers["Accept"]


def test_registry_without_token_endpoint_still_resolves(registry, tmp_path) -> None:
    # A registry that needs no token must not be treated as unreachable.
    _serve(registry, manifest=_manifest([_disk_layer()]), token=None)

    staged = resolve_seat_image("ghcr.io/owner/seat:latest", cache_dir=tmp_path)

    assert staged.digest == DISK_DIGEST
    _, _, _, headers = registry["staged"][0]
    assert "Authorization" not in headers


def test_ordinary_container_image_is_refused(registry, tmp_path) -> None:
    # An ordinary image would otherwise be booted as though it were a disk.
    _serve(
        registry,
        manifest=_manifest(
            [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": DISK_DIGEST,
                    "size": 10,
                }
            ]
        ),
    )

    with pytest.raises(SeatImageError, match="not a seat VM disk"):
        resolve_seat_image("ghcr.io/owner/seat:latest", cache_dir=tmp_path)


def test_multiple_disk_layers_are_refused(registry, tmp_path) -> None:
    _serve(registry, manifest=_manifest([_disk_layer(), _disk_layer()]))

    with pytest.raises(SeatImageError, match="more than one disk layer"):
        resolve_seat_image("ghcr.io/owner/seat:latest", cache_dir=tmp_path)


@pytest.mark.parametrize(
    "layer",
    [
        {"mediaType": DISK_MEDIA_TYPE, "digest": "sha256:short", "size": 10},
        {"mediaType": DISK_MEDIA_TYPE, "digest": DISK_DIGEST, "size": 0},
        {"mediaType": DISK_MEDIA_TYPE, "digest": DISK_DIGEST, "size": -1},
        {"mediaType": DISK_MEDIA_TYPE, "digest": DISK_DIGEST},
        {"mediaType": DISK_MEDIA_TYPE, "size": 10},
    ],
)
def test_unusable_disk_descriptors_are_refused(registry, tmp_path, layer) -> None:
    _serve(registry, manifest=_manifest([layer]))

    with pytest.raises(SeatImageError):
        resolve_seat_image("ghcr.io/owner/seat:latest", cache_dir=tmp_path)


def test_oversized_disk_declaration_is_refused(registry, tmp_path) -> None:
    _serve(registry, manifest=_manifest([_disk_layer(size=1 << 60)]))

    with pytest.raises(SeatImageError):
        resolve_seat_image("ghcr.io/owner/seat:latest", cache_dir=tmp_path)


def test_missing_manifest_is_reported_against_the_reference(registry, tmp_path) -> None:
    registry["documents"] = {}

    with pytest.raises(SeatImageError, match="manifest is unavailable"):
        resolve_seat_image("ghcr.io/owner/seat:latest", cache_dir=tmp_path)


def test_non_json_manifest_is_refused(registry, tmp_path) -> None:
    _serve(registry, manifest=b"<html>not a manifest</html>")

    with pytest.raises(SeatImageError, match="not valid JSON"):
        resolve_seat_image("ghcr.io/owner/seat:latest", cache_dir=tmp_path)


def test_index_resolves_to_its_single_x86_64_manifest(registry, tmp_path) -> None:
    child = _manifest([_disk_layer()])
    child_digest = "sha256:" + hashlib.sha256(child).hexdigest()
    index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "digest": child_digest,
                    "platform": {"architecture": "amd64", "os": "linux"},
                },
                {
                    "digest": "sha256:" + "b" * 64,
                    "platform": {"architecture": "arm64", "os": "linux"},
                },
            ],
        }
    ).encode()
    registry["documents"] = {
        "/token?service=ghcr.io&scope=repository%3Aowner%2Fseat%3Apull": json.dumps(
            {"token": "pull-token"}
        ).encode(),
        "/manifests/latest": index,
        f"/manifests/{child_digest}": child,
    }

    staged = resolve_seat_image("ghcr.io/owner/seat:latest", cache_dir=tmp_path)

    assert staged.digest == DISK_DIGEST


def test_ambiguous_index_is_refused(registry, tmp_path) -> None:
    index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": "sha256:" + "a" * 64, "platform": {"architecture": "amd64"}},
                {"digest": "sha256:" + "b" * 64, "platform": {"architecture": "amd64"}},
            ],
        }
    ).encode()
    registry["documents"] = {"/manifests/latest": index}

    with pytest.raises(SeatImageError, match="exactly one x86_64 manifest"):
        resolve_seat_image("ghcr.io/owner/seat:latest", cache_dir=tmp_path)
