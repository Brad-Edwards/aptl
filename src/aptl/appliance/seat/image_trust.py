"""Cosign admission and owner-private records for verified offline images.

Only the publisher's independently installed public key authorizes an image.
Registry credentials and keys shipped inside an image never establish trust.
The local verification receipt has the same ownership boundary as the disk's
verification stamp: an operator able to rewrite their private cache already
controls their own launcher. It is not a portable signed attestation.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from aptl.appliance.seat.image_disk_cache import SeatImageError, _cache_entry

_DEFAULT_REPOSITORY = "ghcr.io/brad-edwards/aptl-seat"
_MAX_BYTES = 256 * 1024


def _repository(reference: str) -> str:
    """Normalize the repository identity without its mutable tag or digest."""

    from aptl.appliance.seat.image import parse_seat_image_reference

    parsed = parse_seat_image_reference(reference)
    return f"{parsed.registry}/{parsed.repository}"


def _key_path(cache: Path, reference: str) -> Path:
    """Select the repository-scoped override or the bundled publisher anchor."""

    repository = _repository(reference)
    key = hashlib.sha256(repository.encode()).hexdigest()
    configured = cache / "trust" / f"{key}.pub"
    if configured.exists() or configured.is_symlink():
        return configured
    if repository == _DEFAULT_REPOSITORY:
        return Path(__file__).with_name("aptl-seat.pub")
    raise SeatImageError("alternate seat source requires an explicit trusted public key")


def _read_regular(path: Path, maximum: int = _MAX_BYTES) -> bytes:
    """Read a bounded regular trust file without following a final symlink."""

    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        with os.fdopen(os.open(path, flags), "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OSError("not regular")
            payload = handle.read(maximum + 1)
        if not payload or len(payload) > maximum:
            raise ValueError("invalid size")
        return payload
    except (OSError, ValueError) as exc:
        raise SeatImageError("seat trust file is unavailable or unsafe") from exc


def _write_private(path: Path, payload: bytes) -> None:
    """Atomically publish trust metadata in the owner's private cache."""

    from aptl.appliance.seat.persistence import _ensure_seat_root

    _ensure_seat_root(path.parent)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def configure_trust(cache: Path, reference: str, public_key: Path) -> None:
    """Install an operator-provided public key for exactly one repository."""

    payload = _read_regular(public_key, 16 * 1024)
    try:
        load_pem_public_key(payload)
    except (ValueError, TypeError) as exc:
        raise SeatImageError("seat public key is invalid") from exc
    key = hashlib.sha256(_repository(reference).encode()).hexdigest()
    _write_private(cache / "trust" / f"{key}.pub", payload)


def _claims_match(payload: bytes, repository: str, manifest: str) -> bool:
    """Bind supported verified Cosign claims to the exact repository and digest."""

    try:
        claims = json.loads(payload)
        return isinstance(claims, list) and any(
            claim["critical"]["type"] in {
                "cosign container image signature",
                "https://sigstore.dev/cosign/sign/v1",
            }
            and claim["critical"]["image"]["docker-manifest-digest"] == manifest
            and claim["critical"]["identity"]["docker-reference"] in {
                repository, f"{repository}@{manifest}",
            }
            for claim in claims
        )
    except (ValueError, TypeError, KeyError):
        return False


def verify_remote_image(
    cache: Path, reference: str, manifest: str, disk: str, config: str | None
) -> dict[str, object]:
    """Verify the immutable OCI manifest before fetching executable artifacts."""

    key_path = _key_path(cache, reference)
    public_key = _read_regular(key_path, 16 * 1024)
    repository = _repository(reference)
    # Force anonymous registry verification, independent of developer login.
    with tempfile.TemporaryDirectory(prefix="aptl-cosign-") as temporary:
        isolated_key = Path(temporary) / "publisher.pub"
        isolated_key.write_bytes(public_key)
        environment = dict(os.environ, DOCKER_CONFIG=temporary)
        environment.pop("COSIGN_REPOSITORY", None)
        try:
            result = subprocess.run(
                ["cosign", "verify", "--key", str(isolated_key),
                 "--output", "json", f"{repository}@{manifest}"],
                capture_output=True, check=False, timeout=180, env=environment,
            )
        except FileNotFoundError as exc:
            raise SeatImageError("install Cosign before acquiring a seat image") from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SeatImageError("seat image signature verification failed") from exc
    if result.returncode or len(result.stdout) > _MAX_BYTES or not _claims_match(
        result.stdout, repository, manifest
    ):
        raise SeatImageError("seat image signature verification failed")
    receipt = {
        "schema_version": "aptl.cosign-verification/v1",
        "repository": repository,
        "manifest_digest": manifest,
        "disk_digest": disk,
        "config_digest": config,
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "verified_claims": json.loads(result.stdout),
    }
    return receipt


def publish_verified_image(cache: Path, receipt: dict[str, object]) -> None:
    """Publish trust only after both signed artifacts have passed admission."""

    disk = str(receipt["disk_digest"])
    _write_private(
        _cache_entry(cache, disk).parent / "cosign-verification.json",
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(),
    )


def verify_cached_image(cache: Path, reference: str, disk: str, config: str) -> None:
    """Require prior Cosign admission under the current trust key, offline."""

    public_key = _read_regular(_key_path(cache, reference), 16 * 1024)
    try:
        receipt = json.loads(_read_regular(
            _cache_entry(cache, disk).parent / "cosign-verification.json"
        ))
        expected = {
            "schema_version": "aptl.cosign-verification/v1",
            "repository": _repository(reference),
            "disk_digest": disk,
            "config_digest": config,
            "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        }
        if any(receipt.get(name) != value for name, value in expected.items()):
            raise ValueError("trust mismatch")
        if not _claims_match(
            json.dumps(receipt["verified_claims"]).encode(),
            expected["repository"], receipt["manifest_digest"],
        ):
            raise ValueError("claims mismatch")
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise SeatImageError("cached seat image trust is invalid; use seat update") from exc
