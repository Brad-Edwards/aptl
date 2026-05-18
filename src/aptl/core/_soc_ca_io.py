"""Filesystem helpers for the SOC stack lab CA (SEC-006 / ADR-034).

Split out of :mod:`aptl.core.soc_ca` so the parent module stays under
its file-size budget. Everything in here is in-process I/O around the
gitignored ``config/soc_certs/`` tree: path containment, atomic writes,
mode enforcement, PEM encoding, and the keystore-invalidation helper.

These helpers stay public to the rest of the ``aptl.core`` package via
underscore-prefixed names — the *module itself* is private to soc_ca
and is not part of the public CLI/API surface.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Canonical project-relative output directory. ``ensure_soc_certs`` writes
# everything below ``project_dir / LAB_CA_RELDIR`` and refuses any path
# whose realpath escapes the project root.
LAB_CA_RELDIR = Path("config/soc_certs")

_CA_KEY_NAME = "lab-ca.key"
_CA_CERT_NAME = "lab-ca.pem"

# File names duplicated across the chain validator and the generator. They
# are constants here so the literal "keystore.p12" / "keystore.p12.password"
# never drifts between the two layers.
KEYSTORE_FILENAME = "keystore.p12"
KEYSTORE_PASSWORD_FILENAME = "keystore.p12.password"


class PathContainmentError(ValueError):
    """Raised when the CA output dir resolves outside the project root.

    Subclasses :class:`ValueError` to match :mod:`aptl.core.credentials`'s
    convention so policy callers can ``except ValueError`` AND match on
    the narrow type when distinguishing security-guardrail breaches from
    other render failures.
    """


def _canonical_output_dir(project_dir: Path) -> Path:
    """Resolve ``project_dir / LAB_CA_RELDIR`` and assert containment.

    Mirrors :func:`aptl.core.credentials._canonical_generated_path`: any
    symlink in the chain that rewrites the path is a refusal, because the
    CA key and server keys must land at exactly the literal expected
    location. A symlink pointing at ``.`` or at a tracked file would
    otherwise let the generator write secret material into a checked-in
    location.
    """
    project_root = project_dir.resolve()
    expected = project_root / LAB_CA_RELDIR
    raw = project_dir / LAB_CA_RELDIR

    if raw.exists() or raw.is_symlink():
        actual = raw.resolve()
        if actual != expected:
            raise PathContainmentError(
                f"SOC CA output {raw} resolves to {actual}, not the expected "
                f"{expected}; refusing to generate keys through a symlinked path."
            )
    # If raw does not exist yet, parent containment is enough — the dir
    # will be created at the canonical location below.
    if not expected.parent.resolve().is_relative_to(project_root):
        raise PathContainmentError(
            f"SOC CA parent {expected.parent} escapes project root {project_root}"
        )
    return expected


def _safe_service_subdir(output_dir: Path, name: str) -> Path:
    """Resolve ``output_dir / name`` and refuse a pre-planted symlink.

    Mirrors :func:`_canonical_output_dir` for the second tier of the
    cert tree. A symlink at ``config/soc_certs/misp`` pointing at e.g.
    ``/tmp/attacker`` would otherwise let ``mkdir(parents=True,
    exist_ok=True)`` follow it and write server.key + keystore material
    into the attacker-controlled location, breaking the ADR-029 secret
    boundary.
    """
    raw = output_dir / name
    expected = (output_dir.resolve()) / name
    if raw.exists() or raw.is_symlink():
        actual = raw.resolve()
        if actual != expected:
            raise PathContainmentError(
                f"SOC service subdir {raw} resolves to {actual}, not the "
                f"expected {expected}; refusing to generate keys through "
                "a symlinked path."
            )
    return expected


def _invalidate_keystore(svc_dir: Path) -> None:
    """Remove a stale PKCS#12 keystore + password file when its leaf cert
    was just regenerated. Idempotent — missing files are silently fine.

    Without this, a regenerated server.pem/server.key pair would still
    be paired with an obsolete keystore.p12, which is the very state
    codex flagged as "presence-only idempotency".
    """
    for name in (KEYSTORE_FILENAME, KEYSTORE_PASSWORD_FILENAME):
        path = svc_dir / name
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _pem_cert(cert: x509.Certificate) -> bytes:
    """Encode an X.509 cert as PEM bytes."""
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_private_key(key: rsa.RSAPrivateKey) -> bytes:
    """Encode an RSA private key as unencrypted PKCS#8 PEM bytes.

    The private material is protected at rest by filesystem mode (0o600)
    enforced by :func:`_atomic_write` + :func:`_enforce_mode`; encryption
    at the PEM layer would require an additional passphrase secret that
    the lab has no out-of-band channel to deliver.
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _atomic_write(target: Path, content: bytes, *, mode: int) -> None:
    """Write *content* atomically to *target* and chmod to *mode*.

    Mirrors :func:`aptl.core.credentials._atomic_write_secure`: temp file
    in the same directory, ``os.replace`` onto the target, then enforce
    mode. The 0600 transient mode of ``mkstemp`` plus the same-dir
    ``os.replace`` keeps a pre-planted ``<name>.tmp`` symlink from
    redirecting the secret outside the project, and a partial reader
    can never observe a half-written key file.
    """
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
        _enforce_mode(tmp, mode, kind="file")
        os.replace(tmp, target)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _enforce_mode(path: Path, mode: int, *, kind: str) -> None:
    """``chmod`` *path* and verify on POSIX (best-effort elsewhere)."""
    try:
        path.chmod(mode)
    except (OSError, NotImplementedError) as exc:
        if os.name == "posix":
            raise RuntimeError(
                f"Could not set required mode {oct(mode)} on SOC CA {kind} "
                f"{path}: {exc}"
            ) from exc
        return
    if os.name != "posix":
        return
    effective = path.stat().st_mode & 0o777
    if effective != mode:
        raise RuntimeError(
            f"SOC CA {kind} {path} retained mode {oct(effective)}, "
            f"required {oct(mode)}"
        )
