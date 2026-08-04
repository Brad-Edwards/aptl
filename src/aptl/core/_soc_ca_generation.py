"""Generate the lab CA and each SOC service's leaf pair (SEC-006, ADR-034).

Split out of :mod:`aptl.core.soc_ca`, which keeps the public API (dataclasses,
the service registry, and the ``ensure_soc_certs`` orchestrator). This module is
the write half: it materializes any missing CA pair, per-service leaf pair, and
PKCS#12 keystore under the gitignored output tree, enforcing the ADR-029
permission and symlink-containment contract on both the generate and the reuse
path. ``_generate_all`` stays re-exported from ``aptl.core.soc_ca``.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from aptl.core._soc_ca_builders import _build_ca, _build_server_cert
from aptl.core._soc_ca_chain import (
    _keystore_unlocks_to,
    _try_load_ca,
    _try_load_service_leaf,
)
from aptl.core._soc_ca_io import (
    KEYSTORE_FILENAME,
    KEYSTORE_PASSWORD_FILENAME,
    _atomic_write,
    _enforce_mode,
    _invalidate_keystore,
    _pem_cert,
    _pem_private_key,
    _safe_service_subdir,
)

if TYPE_CHECKING:
    from aptl.core.soc_ca import ServiceCert

_CA_KEY_NAME = "lab-ca.key"
_CA_CERT_NAME = "lab-ca.pem"


def _generate_all(
    output_dir: Path, services: tuple[ServiceCert, ...]
) -> None:
    """Generate any missing CA + service certificates under *output_dir*.

    Permission contract (ADR-029 § Secret at rest):

    - ``output_dir`` and each per-service subdir are ``0o700`` — the
      host-side access control. No other local user can traverse in.
    - Public certs (``lab-ca.pem``, ``server.pem``) are ``0o644`` so
      bind-mounts and operator inspection work without root.
    - Private keys (``lab-ca.key``, ``server.key``) and the env_file
      keystore-password blobs are ``0o600``.
    - PKCS#12 keystores are ``0o644`` because TheHive's non-root process reads
      the bind-mounted file as a container UID that may not match the host user
      that ran ``aptl lab start``. The owner-only parent directory remains the
      host-side access control.

    Symlink containment (ADR-029 § Secret at rest): each per-service
    subdirectory is verified to be a real directory under ``output_dir``
    before any write. A pre-planted ``config/soc_certs/<service>``
    symlink pointing outside the project would otherwise redirect
    generated private key material away from the gitignored tree.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    _enforce_mode(output_dir, 0o700, kind="directory")

    ca_key, ca_cert = _ensure_ca_pair(output_dir)

    for svc in services:
        _ensure_service_pair(output_dir, svc, ca_key, ca_cert)


def _ensure_ca_pair(
    output_dir: Path,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Load or generate the CA cert + key under *output_dir*.

    CA-pair validation: presence alone would let a drifted CA cert /
    key pair flow into ``_build_server_cert`` (which signs with the
    key while inheriting issuer from the unrelated cert) and ship
    certs no client can verify. Same chain shape as the per-service
    leaf reuse: both files exist + parse, derived public keys match,
    NotAfter is still in the future (with a renewal-window margin).
    """
    ca_cert_path = output_dir / _CA_CERT_NAME
    ca_key_path = output_dir / _CA_KEY_NAME
    reusable_ca, ca_cert, ca_key = _try_load_ca(ca_cert_path, ca_key_path)
    if not reusable_ca:
        ca_key, ca_cert = _build_ca()
        _atomic_write(ca_key_path, _pem_private_key(ca_key), mode=0o600)
        _atomic_write(ca_cert_path, _pem_cert(ca_cert), mode=0o644)
        return ca_key, ca_cert
    # Re-apply the permission contract on the reuse path. Codex
    # cycle-3 security finding: a pre-populated cert tree with
    # loose modes would otherwise survive a `lab start` cycle
    # because the consistency check accepted it.
    _enforce_mode(ca_cert_path, 0o644, kind="file")
    _enforce_mode(ca_key_path, 0o600, kind="file")
    # reusable_ca contract: _try_load_ca returns (True, cert, key) only
    # when both are non-None. The assert is a typing hint for static
    # checkers, not a runtime guard the caller relies on.
    assert ca_key is not None and ca_cert is not None
    return ca_key, ca_cert


def _ensure_service_pair(
    output_dir: Path,
    svc: ServiceCert,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
) -> None:
    """Materialize one service's leaf pair (+ optional keystore).

    Extracted from ``_generate_all`` so each iteration of the registry
    loop is a single named step instead of a 60-line inline body.
    """
    svc_dir = _safe_service_subdir(output_dir, svc.name)
    svc_dir.mkdir(parents=True, exist_ok=True)
    _enforce_mode(svc_dir, 0o700, kind="directory")
    svc_cert_path = svc_dir / svc.cert_filename
    svc_key_path = svc_dir / svc.key_filename

    # A service's leaf pair is considered re-usable only when ALL
    # of: both files exist; key loads; cert loads; cert + key share
    # the same public key (no partial-write drift); cert is issued
    # by the current CA with the required SANs; cert is not within
    # its renewal window. Any failure → full re-issue. The keystore
    # (if any) gets invalidated so it can be re-emitted from the
    # freshly-paired key/cert below.
    reusable, svc_key, svc_cert = _try_load_service_leaf(
        svc_key_path, svc_cert_path, svc, ca_cert
    )
    if not reusable:
        svc_key, svc_cert = _build_server_cert(svc, ca_key, ca_cert)
        _atomic_write(svc_key_path, _pem_private_key(svc_key), mode=0o600)
        _atomic_write(svc_cert_path, _pem_cert(svc_cert), mode=0o644)
        _invalidate_keystore(svc_dir)
    else:
        # Reuse path — re-apply the permission contract so a
        # pre-populated tree with relaxed modes doesn't ship as
        # "consistent" with private keys readable to other local
        # users (codex cycle-3 security finding).
        _enforce_mode(svc_cert_path, 0o644, kind="file")
        _enforce_mode(svc_key_path, 0o600, kind="file")

    if svc.needs_keystore:
        assert svc_key is not None and svc_cert is not None
        _ensure_service_keystore(svc_dir, svc, svc_key, svc_cert, ca_cert)


def _ensure_service_keystore(
    svc_dir: Path,
    svc: ServiceCert,
    svc_key: rsa.RSAPrivateKey,
    svc_cert: x509.Certificate,
    ca_cert: x509.Certificate,
) -> None:
    """Materialize the PKCS#12 keystore + password for a Play service.

    Splits out the keystore-only branch so ``_ensure_service_pair`` can
    stay below the project's cyclomatic-complexity gate. A stale
    keystore (one whose fingerprint disagrees with the new leaf) is
    invalidated first so the write branch below re-emits it from the
    freshly-paired key/cert.
    """
    ks_path = svc_dir / KEYSTORE_FILENAME
    pw_path = svc_dir / KEYSTORE_PASSWORD_FILENAME
    if (
        ks_path.is_file()
        and pw_path.is_file()
        and not _keystore_unlocks_to(ks_path, pw_path, svc_cert)
    ):
        # Stale keystore from an older run whose CA/leaf cycle
        # rotated. Invalidate so the next branch re-emits it.
        _invalidate_keystore(svc_dir)
    elif ks_path.is_file() and pw_path.is_file():
        # Reuse-path permission reapply (codex cycle-3 sec).
        _enforce_mode(ks_path, 0o644, kind="file")
        _enforce_mode(pw_path, 0o600, kind="file")
    if not (ks_path.is_file() and pw_path.is_file()):
        password = secrets.token_urlsafe(24)
        ks_bytes = pkcs12.serialize_key_and_certificates(
            name=svc.name.encode(),
            key=svc_key,
            cert=svc_cert,
            cas=[ca_cert],
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode()
            ),
        )
        _atomic_write(ks_path, ks_bytes, mode=0o644)
        # Write the password in Docker Compose ``env_file`` format
        # (``KEY=value``) so the TheHive/Cortex services can
        # consume it via ``env_file:`` rather than baking the
        # value into the rendered application.conf or passing it
        # in argv. The KEY name is the same env var Play's
        # ``${?HTTPS_KEYSTORE_PASSWORD}`` substitution expects.
        env_blob = f"HTTPS_KEYSTORE_PASSWORD={password}\n".encode()
        _atomic_write(pw_path, env_blob, mode=0o600)
