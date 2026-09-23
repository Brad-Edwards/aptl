"""Trusted Cosign identity must bind both remote acquisition and offline reuse."""

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aptl.appliance.seat.image_disk_cache import SeatImageError


REFERENCE = "ghcr.io/example/seat:stable"
MANIFEST = "sha256:" + "a" * 64
DISK = "sha256:" + "b" * 64
CONFIG = "sha256:" + "c" * 64


def public_key(tmp_path: Path, name: str = "publisher.pub") -> Path:
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    path = tmp_path / name
    path.write_bytes(key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return path


def claims(digest: str = MANIFEST, *, modern: bool = False) -> bytes:
    return json.dumps([{"critical": {
        "identity": {"docker-reference": "ghcr.io/example/seat" + (f"@{digest}" if modern else "")},
        "image": {"docker-manifest-digest": digest},
        "type": "https://sigstore.dev/cosign/sign/v1" if modern else "cosign container image signature",
    }}]).encode()


def test_unsigned_image_cannot_publish_a_trust_receipt(tmp_path, monkeypatch) -> None:
    from aptl.appliance.seat import image_trust
    cache = tmp_path / "cache"
    image_trust.configure_trust(cache, REFERENCE, public_key(tmp_path))
    monkeypatch.setattr(image_trust.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 1, b"", b"secret detail"))
    with pytest.raises(SeatImageError, match="signature verification failed"):
        image_trust.verify_remote_image(cache, REFERENCE, MANIFEST, DISK, CONFIG)
    assert not list(cache.glob("*/cosign-verification.json"))


@pytest.mark.parametrize("payload", [b"[]", claims("sha256:" + "d" * 64)])
def test_signature_for_another_manifest_is_rejected(tmp_path, monkeypatch, payload) -> None:
    from aptl.appliance.seat import image_trust
    cache = tmp_path / "cache"
    image_trust.configure_trust(cache, REFERENCE, public_key(tmp_path))
    monkeypatch.setattr(image_trust.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, payload, b""))
    with pytest.raises(SeatImageError):
        image_trust.verify_remote_image(cache, REFERENCE, MANIFEST, DISK, CONFIG)


@pytest.mark.parametrize("modern", [False, True], ids=["cosign-2", "cosign-3"])
def test_verified_cache_is_offline_and_rejects_trust_rotation(tmp_path, monkeypatch, modern) -> None:
    from aptl.appliance.seat import image_trust
    cache = tmp_path / "cache"
    image_trust.configure_trust(cache, REFERENCE, public_key(tmp_path))
    calls = []
    def verify(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, claims(modern=modern), b"")
    monkeypatch.setattr(image_trust.subprocess, "run", verify)
    receipt = image_trust.verify_remote_image(cache, REFERENCE, MANIFEST, DISK, CONFIG)
    image_trust.publish_verified_image(cache, receipt)
    assert calls[0][-1] == "ghcr.io/example/seat@" + MANIFEST
    assert "--key" in calls[0]
    image_trust.verify_cached_image(cache, REFERENCE, DISK, CONFIG)
    assert len(calls) == 1
    image_trust.configure_trust(cache, REFERENCE, public_key(tmp_path, "rotated.pub"))
    with pytest.raises(SeatImageError, match="trust"):
        image_trust.verify_cached_image(cache, REFERENCE, DISK, CONFIG)


@pytest.mark.parametrize("reference", [
    "ghcr.io/other/seat@" + MANIFEST,
    "ghcr.io/example/seat@sha256:" + "d" * 64,
    "ghcr.io/example/seat:stable",
])
def test_cosign_three_claim_rejects_wrong_signed_identity(reference) -> None:
    from aptl.appliance.seat import image_trust

    payload = json.loads(claims(modern=True))
    payload[0]["critical"]["identity"]["docker-reference"] = reference
    assert not image_trust._claims_match(json.dumps(payload).encode(), "ghcr.io/example/seat", MANIFEST)


def test_unknown_signed_statement_type_is_rejected() -> None:
    from aptl.appliance.seat import image_trust

    payload = json.loads(claims(modern=True))
    payload[0]["critical"]["type"] = "https://slsa.dev/provenance/v1"
    assert not image_trust._claims_match(json.dumps(payload).encode(), "ghcr.io/example/seat", MANIFEST)


def test_alternate_registry_requires_independent_trust(tmp_path) -> None:
    from aptl.appliance.seat import image_trust
    with pytest.raises(SeatImageError, match="public key"):
        image_trust.verify_remote_image(tmp_path, REFERENCE, MANIFEST, DISK, CONFIG)


def test_resolver_rejects_unsigned_artifact_before_disk_download(tmp_path, monkeypatch) -> None:
    from aptl.appliance.seat import image, image_trust
    from unittest.mock import Mock
    descriptor = image.SeatDiskDescriptor(
        image.parse_seat_image_reference(REFERENCE), DISK, 100, MANIFEST, None,
        CONFIG, 100,
    )
    monkeypatch.setattr(image, "resolve_disk_descriptor", lambda ref: descriptor)
    monkeypatch.setattr(image_trust, "verify_remote_image", Mock(side_effect=SeatImageError("unsigned")))
    fetch = Mock()
    monkeypatch.setattr(image, "fetch_seat_disk", fetch)
    monkeypatch.setattr(image, "cache_seat_image_config", lambda *a: None)
    with pytest.raises(SeatImageError, match="unsigned"):
        image.resolve_seat_image(REFERENCE, cache_dir=tmp_path, require_config=True)
    fetch.assert_not_called()


def test_digest_pin_rejects_different_manifest_bytes(monkeypatch) -> None:
    from aptl.appliance.seat import image
    manifest = {"layers": [{"mediaType": image.DISK_MEDIA_TYPE, "digest": DISK, "size": 100}]}
    monkeypatch.setattr(image, "_anonymous_token", lambda ref: None)
    monkeypatch.setattr(image, "_fetch_manifest", lambda *a: (manifest, "sha256:" + "d" * 64))
    with pytest.raises(SeatImageError, match="digest"):
        image.resolve_disk_descriptor("ghcr.io/example/seat@" + MANIFEST)


def test_index_child_must_match_advertised_digest(monkeypatch) -> None:
    from aptl.appliance.seat import image
    manifest = {"manifests": [{"digest": MANIFEST}]}
    monkeypatch.setattr(image, "fetch_https_metadata", lambda *a, **kw: b'{}')
    reference = image.parse_seat_image_reference(REFERENCE)
    with pytest.raises(SeatImageError, match="digest"):
        image._resolve_index(reference, manifest, None)


def test_rejected_config_preserves_prior_offline_trust(tmp_path, monkeypatch):
    from dataclasses import replace
    from aptl.appliance.seat import image, image_trust
    from tests.test_seat_image_config import _config

    cache = tmp_path / "cache"
    image_trust.configure_trust(cache, REFERENCE, public_key(tmp_path))
    monkeypatch.setattr(image_trust.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, claims(), b""))
    payload = _config()
    config_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    descriptor = image.SeatDiskDescriptor(
        image.parse_seat_image_reference(REFERENCE), DISK, 100, MANIFEST, None,
        config_digest, len(payload),
    )
    monkeypatch.setattr(image, "fetch_https_metadata", lambda *a, **k: payload)
    image.cache_seat_image_config(descriptor, cache)
    receipt = image_trust.verify_remote_image(cache, REFERENCE, MANIFEST, DISK, config_digest)
    image_trust.publish_verified_image(cache, receipt)
    receipt_path = cache / DISK[7:] / "cosign-verification.json"
    before = receipt_path.read_bytes()
    payload += b" "  # Valid JSON, different signed config for the same disk.
    candidate = replace(descriptor, config_digest="sha256:" + hashlib.sha256(payload).hexdigest(), config_size_bytes=len(payload))
    monkeypatch.setattr(image, "resolve_disk_descriptor", lambda ref: candidate)
    with pytest.raises(SeatImageError, match="rebound"):
        image.resolve_seat_image(REFERENCE, cache_dir=cache, require_config=True)
    assert receipt_path.read_bytes() == before
    image_trust.verify_cached_image(cache, REFERENCE, DISK, config_digest)
