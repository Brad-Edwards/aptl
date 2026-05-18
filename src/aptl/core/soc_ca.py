"""Lab-managed CA + per-service certificates for the SOC stack (SEC-006).

Mirrors the result/error shape of :mod:`aptl.core.certs` (Wazuh INF-005)
but generates artifacts entirely in-process via the ``cryptography``
library. The Wazuh chain stays untouched per ADR-034 § Context.

Outputs land under ``config/soc_certs/`` (gitignored). The CA private key
and per-service private keys are control-plane secrets under ADR-029 —
never logged, never embedded in result envelopes, never copied into
``aptl.json`` or MCP JSON config. Public certificates are bind-mounted
read-only into client containers.

The service registry below is the extensibility seam called out in
ADR-034 § Decision: adding another SOC HTTPS service should be one more
:class:`ServiceCert` entry, not another generator or another CA.

Module layout: this file owns the public API (dataclasses + the
``ensure_soc_certs`` orchestrator + ``_generate_all`` generator).
Chain-validation helpers live in :mod:`aptl.core._soc_ca_chain`;
filesystem/path helpers live in :mod:`aptl.core._soc_ca_io`. The split
keeps each layer under SonarPython's file-size budget while letting the
public surface stay re-exported here.
"""

from __future__ import annotations

import secrets
import traceback
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from aptl.core._soc_ca_builders import _build_ca, _build_server_cert
from aptl.core._soc_ca_chain import (
    _all_artifacts_present_and_consistent,
    _keystore_unlocks_to,
    _try_load_ca,
    _try_load_service_leaf,
)
from aptl.core._soc_ca_io import (
    KEYSTORE_FILENAME,
    KEYSTORE_PASSWORD_FILENAME,
    LAB_CA_RELDIR,
    PathContainmentError,
    _atomic_write,
    _canonical_output_dir,
    _enforce_mode,
    _invalidate_keystore,
    _pem_cert,
    _pem_private_key,
    _safe_service_subdir,
)
from aptl.utils.logging import get_logger

log = get_logger("soc_ca")

# Re-exports for callers that still reach in through ``aptl.core.soc_ca``.
__all__ = (
    "CertResult",
    "LAB_CA_RELDIR",
    "PathContainmentError",
    "SOC_SERVICE_REGISTRY",
    "ServiceCert",
    "ensure_soc_certs",
)

# ---------------------------------------------------------------------------
# Public paths and dataclasses
# ---------------------------------------------------------------------------

_CA_KEY_NAME = "lab-ca.key"
_CA_CERT_NAME = "lab-ca.pem"


@dataclass(frozen=True)
class ServiceCert:  # NOSONAR python:S5663 - Python 3 dataclass; no need for explicit `object` base
    """One row of the SOC service certificate registry.

    Attributes:
        name: Subdirectory under the CA output dir; also the Docker
            service name used to derive the in-network DNS SAN.
        subject_cn: ``Subject CN`` for the issued cert. Conventional, not
            relied on for verification (SANs are what TLS actually checks).
        sans: SAN list. DNS hostnames as plain strings; IP literals are
            detected and emitted as IPAddress SAN entries.
        cert_filename: PEM cert filename inside ``<output>/<name>/``.
        key_filename: PEM private-key filename inside ``<output>/<name>/``.
        needs_keystore: ``True`` for Play-framework services (TheHive,
            Cortex) which consume a PKCS#12 keystore alongside the PEM
            files. Adds ``keystore.p12`` and ``keystore.p12.password``.
    """

    name: str
    subject_cn: str
    sans: tuple[str, ...]
    cert_filename: str = "server.pem"
    key_filename: str = "server.key"
    needs_keystore: bool = False


SOC_SERVICE_REGISTRY: tuple[ServiceCert, ...] = (
    ServiceCert(
        name="misp",
        subject_cn="aptl-misp",
        sans=("misp", "localhost", "127.0.0.1"),
    ),
    ServiceCert(
        name="thehive",
        subject_cn="aptl-thehive",
        sans=("thehive", "localhost", "127.0.0.1"),
        needs_keystore=True,
    ),
    ServiceCert(
        name="cortex",
        subject_cn="aptl-cortex",
        sans=("cortex", "localhost", "127.0.0.1"),
        needs_keystore=True,
    ),
    ServiceCert(
        name="shuffle-frontend",
        subject_cn="aptl-shuffle-frontend",
        sans=("shuffle-frontend", "localhost", "127.0.0.1"),
    ),
)


@dataclass
class CertResult:  # NOSONAR python:S5663 - Python 3 dataclass; no need for explicit `object` base
    """Outcome of :func:`ensure_soc_certs`.

    Mirrors :class:`aptl.core.certs.CertResult`: ``success`` is the
    pass/fail signal the orchestrator branches on; ``generated`` is
    informational (was new key material produced this run?).
    """

    success: bool
    generated: bool
    certs_dir: Path = Path()
    error: str = ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def ensure_soc_certs(project_dir: Path) -> CertResult:
    """Generate the lab CA + service certificates if any are missing.

    Returns a :class:`CertResult` with ``generated=False`` when every
    required artifact is already on disk; otherwise generates the missing
    pieces, writes them atomically with restrictive permissions, and
    returns ``generated=True``.

    The CA private key, each service private key, and each PKCS#12
    passphrase are written with mode ``0o600``. Public certs are ``0o644``
    so a container process running as a non-root UID can still read them
    across a bind mount.

    Never logs PEM content, key paths, or passphrases. Failure messages
    cite only the SOC tool name and the affected layer.
    """
    try:
        output_dir = _canonical_output_dir(project_dir)
    except PathContainmentError as exc:
        log.exception("soc_cert_generation: %s", exc)
        return _fail_containment(project_dir / LAB_CA_RELDIR, exc)

    if _all_artifacts_present_and_consistent(
        output_dir, _CA_CERT_NAME, _CA_KEY_NAME, SOC_SERVICE_REGISTRY
    ):
        log.info(
            "SOC stack lab CA already present and consistent at %s",
            output_dir,
        )
        return CertResult(success=True, generated=False, certs_dir=output_dir)

    log.info("Generating SOC stack lab CA + service certificates at %s", output_dir)
    return _generate_with_error_envelope(output_dir)


def _fail_containment(certs_dir: Path, exc: PathContainmentError) -> CertResult:
    """Build the :class:`CertResult` for a containment-check refusal.

    Kept as its own helper so the orchestrator's single-error-shape
    contract stays visible in one place — the message body is the
    exception itself, which is safe to surface (it names the rejected
    path, never key material).
    """
    return CertResult(
        success=False,
        generated=False,
        certs_dir=certs_dir,
        error=str(exc),
    )


def _generate_with_error_envelope(output_dir: Path) -> CertResult:
    """Wrap :func:`_generate_all` in the ADR-029 error-envelope policy.

    The cryptography stack raises a heterogeneous tree of exception
    classes (InvalidKey, UnsupportedAlgorithm, OSError from PKCS#12
    internals, etc.). The whole point of this layer is to convert ANY
    of them into a fatal :class:`CertResult` for the orchestrator while
    DROPPING the original exception message — payloads from cryptography
    / PKCS#12 paths can echo derived key material or PEM blocks (see
    ADR-029 § Secret at rest).

    Returns ``CertResult(success=True, generated=True)`` on success, or a
    failure result whose ``error`` field names the failing generator
    phase + exception class only.
    """
    try:
        _generate_all(output_dir)
    except PathContainmentError as exc:
        # Containment violation per-service subdir; the message itself
        # is safe (it names the rejected path, not key material).
        log.exception("soc_cert_generation: containment violation: %s", exc)
        return CertResult(
            success=False,
            generated=False,
            certs_dir=output_dir,
            error=f"SOC certificate generation failed: {exc}",
        )
    except Exception as exc:  # noqa: BLE001 — cryptography stack raises a heterogeneous tree; ADR-029 contract converts ANY of them to a fatal CertResult (see docstring for the catalog).
        layer = _classify_failure_layer(exc)
        log.exception(
            "soc_cert_generation: %s failed: %s",
            layer, exc.__class__.__name__,
        )
        return CertResult(
            success=False,
            generated=False,
            certs_dir=output_dir,
            error=(
                f"SOC certificate generation failed in {layer}: "
                f"{exc.__class__.__name__}"
            ),
        )
    return CertResult(success=True, generated=True, certs_dir=output_dir)


def _classify_failure_layer(exc: BaseException) -> str:
    """Map an exception traceback to the cert-generation layer that
    raised it.

    ``traceback.extract_tb`` returns frames outermost → innermost, so
    iterating forward and returning the first ``soc_ca.py`` frame would
    always surface the outer ``ensure_soc_certs`` wrapper. Iterate in
    reverse so we report the actual failing inner phase (e.g.
    ``_build_server_cert``, ``_atomic_write``, ``_safe_service_subdir``)
    that operators need to inspect.
    """
    frames = traceback.extract_tb(exc.__traceback__)
    for frame in reversed(frames):
        if frame.filename.endswith("soc_ca.py") and frame.name:
            return frame.name.lstrip("_")
    return "soc_ca"


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def _generate_all(output_dir: Path) -> None:
    """Generate any missing CA + service certificates under *output_dir*.

    Permission contract (ADR-029 § Secret at rest):

    - ``output_dir`` and each per-service subdir are ``0o700`` — the
      host-side access control. No other local user can traverse in.
    - Public certs (``lab-ca.pem``, ``server.pem``) are ``0o644`` so
      bind-mounts and operator inspection work without root.
    - Private keys (``lab-ca.key``, ``server.key``), PKCS#12 keystores,
      and the env_file keystore-password blobs are ``0o600``. The SOC
      service containers each have been verified live to read the
      private material at this mode (MISP nginx, TheHive Play, Shuffle
      nginx all run as the host UID 1000 in the lab images we ship);
      tightening the mode keeps an unprivileged process *inside* the
      container — different from the service user — from reading the
      private material via the bind mount.

    Symlink containment (ADR-029 § Secret at rest): each per-service
    subdirectory is verified to be a real directory under ``output_dir``
    before any write. A pre-planted ``config/soc_certs/<service>``
    symlink pointing outside the project would otherwise redirect
    generated private key material away from the gitignored tree.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    _enforce_mode(output_dir, 0o700, kind="directory")

    ca_key, ca_cert = _ensure_ca_pair(output_dir)

    for svc in SOC_SERVICE_REGISTRY:
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
        _enforce_mode(ks_path, 0o600, kind="file")
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
        _atomic_write(ks_path, ks_bytes, mode=0o600)
        # Write the password in Docker Compose ``env_file`` format
        # (``KEY=value``) so the TheHive/Cortex services can
        # consume it via ``env_file:`` rather than baking the
        # value into the rendered application.conf or passing it
        # in argv. The KEY name is the same env var Play's
        # ``${?HTTPS_KEYSTORE_PASSWORD}`` substitution expects.
        env_blob = f"HTTPS_KEYSTORE_PASSWORD={password}\n".encode()
        _atomic_write(pw_path, env_blob, mode=0o600)
