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
"""

from __future__ import annotations

import os
import secrets
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from aptl.utils.logging import get_logger

log = get_logger("soc_ca")

# ---------------------------------------------------------------------------
# Public paths and dataclasses
# ---------------------------------------------------------------------------

# Canonical project-relative output directory. ``ensure_soc_certs`` writes
# everything below ``project_dir / LAB_CA_RELDIR`` and refuses any path
# whose realpath escapes the project root.
LAB_CA_RELDIR = Path("config/soc_certs")

_CA_KEY_NAME = "lab-ca.key"
_CA_CERT_NAME = "lab-ca.pem"

# CA validity window — long enough that a lab redeploy doesn't churn.
_CA_VALIDITY_DAYS = 10 * 365
# Per-service validity — shorter than the CA so the operator regenerates
# server certs occasionally without ever touching the trust anchor.
_SVC_VALIDITY_DAYS = 5 * 365


@dataclass(frozen=True)
class ServiceCert:
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
class CertResult:
    """Outcome of :func:`ensure_soc_certs`.

    Mirrors :class:`aptl.core.certs.CertResult`: ``success`` is the
    pass/fail signal the orchestrator branches on; ``generated`` is
    informational (was new key material produced this run?).
    """

    success: bool
    generated: bool
    certs_dir: Path = Path()
    error: str = ""


class PathContainmentError(ValueError):
    """Raised when the CA output dir resolves outside the project root.

    Subclasses :class:`ValueError` to match :mod:`aptl.core.credentials`'s
    convention so policy callers can ``except ValueError`` AND match on
    the narrow type when distinguishing security-guardrail breaches from
    other render failures.
    """


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
        log.error("soc_cert_generation: %s", exc)
        return CertResult(
            success=False,
            generated=False,
            certs_dir=project_dir / LAB_CA_RELDIR,
            error=str(exc),
        )

    if _all_artifacts_present_and_consistent(output_dir):
        log.info(
            "SOC stack lab CA already present and consistent at %s",
            output_dir,
        )
        return CertResult(success=True, generated=False, certs_dir=output_dir)

    log.info("Generating SOC stack lab CA + service certificates at %s", output_dir)
    try:
        _generate_all(output_dir)
    except PathContainmentError as exc:
        # Containment violation per-service subdir; the message itself
        # is safe (it names the rejected path, not key material).
        log.error("soc_cert_generation: containment violation: %s", exc)
        return CertResult(
            success=False,
            generated=False,
            certs_dir=output_dir,
            error=f"SOC certificate generation failed: {exc}",
        )
    except Exception as exc:  # noqa: BLE001 - surfaced as a fatal CertResult
        # ADR-029 § Secret at rest: exception payloads from cryptography
        # / PKCS#12 paths can echo derived key material or PEM blocks.
        # Surface the LAYER (which generator phase tripped) and the
        # exception class so operators can fix the right artifact, but
        # drop the message body before it reaches LabResult.
        layer = _classify_failure_layer(exc)
        log.error(
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
    import traceback
    frames = traceback.extract_tb(exc.__traceback__)
    for frame in reversed(frames):
        if frame.filename.endswith("soc_ca.py") and frame.name:
            return frame.name.lstrip("_")
    return "soc_ca"


# ---------------------------------------------------------------------------
# Path handling
# ---------------------------------------------------------------------------


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


def _all_artifacts_present_and_consistent(output_dir: Path) -> bool:
    """Return True iff the CA + service tree is **cryptographically valid**.

    Presence-only checks let a partial-cleanup tree ship as "ready" even
    when the CA cert/key don't match, or when a leaf cert is signed by
    a CA that no longer exists on disk. Codex review #2 against this
    PR flagged that as a class — every artifact-presence shortcut now
    runs the same chain validation that ``_generate_all`` does when it
    actually has to build something:

    - All expected files exist.
    - CA key and CA cert form a valid pair (public key derived from key
      matches cert public key).
    - For each service, the on-disk private key derives the same public
      key as the on-disk cert.
    - The service cert is issued by the CA (issuer match + signature
      verifies + required SANs present).
    - For Play services, the PKCS#12 keystore unlocks with the password
      file and contains a cert with the same fingerprint as the on-disk
      cert.

    Any failure flips the early-return off, sending control into
    ``_generate_all`` where the inconsistent leaves get re-issued and
    stale keystores get invalidated.
    """
    ca_cert_path = output_dir / _CA_CERT_NAME
    ca_key_path = output_dir / _CA_KEY_NAME
    required = [ca_cert_path, ca_key_path]
    for svc in SOC_SERVICE_REGISTRY:
        svc_dir = output_dir / svc.name
        required.append(svc_dir / svc.cert_filename)
        required.append(svc_dir / svc.key_filename)
        if svc.needs_keystore:
            required.append(svc_dir / "keystore.p12")
            required.append(svc_dir / "keystore.p12.password")
    if not all(p.is_file() for p in required):
        return False

    try:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
        ca_key = serialization.load_pem_private_key(
            ca_key_path.read_bytes(), password=None
        )
    except (ValueError, TypeError):
        return False
    if (
        ca_key.public_key().public_numbers()
        != ca_cert.public_key().public_numbers()
    ):
        return False
    # CA cert must still be inside its validity window (with renewal margin).
    if not _cert_in_validity_window(ca_cert):
        return False

    for svc in SOC_SERVICE_REGISTRY:
        if not _per_service_artifacts_consistent(output_dir, svc, ca_cert):
            return False
    return True


def _per_service_artifacts_consistent(
    output_dir: Path,
    svc: ServiceCert,
    ca_cert: x509.Certificate,
) -> bool:
    """Return True iff *svc*'s leaf + (optional) keystore on disk are
    cryptographically consistent with *ca_cert* and inside the
    renewal window.

    Extracted from ``_all_artifacts_present_and_consistent`` to keep
    the parent function's cyclomatic complexity inside the project's
    ruff C901 gate (max 15). The per-service branch is independently
    testable and mirrors the in-loop checks ``_generate_all`` performs.
    """
    svc_dir = output_dir / svc.name
    try:
        cert = x509.load_pem_x509_certificate(
            (svc_dir / svc.cert_filename).read_bytes()
        )
        key = serialization.load_pem_private_key(
            (svc_dir / svc.key_filename).read_bytes(), password=None
        )
    except (ValueError, TypeError):
        return False
    if (
        key.public_key().public_numbers()
        != cert.public_key().public_numbers()
    ):
        return False
    if not _service_cert_consistent_with_ca(cert, svc, ca_cert):
        return False
    if not _cert_in_validity_window(cert):
        return False
    if not svc.needs_keystore:
        return True
    return _keystore_unlocks_to(
        svc_dir / "keystore.p12",
        svc_dir / "keystore.p12.password",
        cert,
    )


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

    ca_cert_path = output_dir / _CA_CERT_NAME
    ca_key_path = output_dir / _CA_KEY_NAME
    # CA-pair validation: presence alone would let a drifted CA cert /
    # key pair flow into ``_build_server_cert`` (which signs with the
    # key while inheriting issuer from the unrelated cert) and ship
    # certs no client can verify. Same chain shape as the per-service
    # leaf reuse: both files exist + parse, derived public keys match,
    # NotAfter is still in the future (with a renewal-window margin).
    reusable_ca, ca_cert, ca_key = _try_load_ca(ca_cert_path, ca_key_path)
    if not reusable_ca:
        ca_key, ca_cert = _build_ca()
        _atomic_write(ca_key_path, _pem_private_key(ca_key), mode=0o600)
        _atomic_write(ca_cert_path, _pem_cert(ca_cert), mode=0o644)
    else:
        # Re-apply the permission contract on the reuse path. Codex
        # cycle-3 security finding: a pre-populated cert tree with
        # loose modes would otherwise survive a `lab start` cycle
        # because the consistency check accepted it.
        _enforce_mode(ca_cert_path, 0o644, kind="file")
        _enforce_mode(ca_key_path, 0o600, kind="file")

    for svc in SOC_SERVICE_REGISTRY:
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
            ks_path = svc_dir / "keystore.p12"
            pw_path = svc_dir / "keystore.p12.password"
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


# Renewal window — once a cert is within this many days of its NotAfter,
# the consistency check treats it as no-longer-reusable so the next
# ``aptl lab start`` rotates the leaf (or the CA, when applied to it).
# 30 days is short enough to surface renewals before clients trip on
# expired certs and long enough that operators get a real warning gap.
_RENEWAL_WINDOW_DAYS = 30


def _cert_in_validity_window(cert: x509.Certificate) -> bool:
    """Return True iff *cert* is currently valid AND not within the
    renewal window of its NotAfter. False for expired or
    soon-to-expire certs so the generator rotates them.
    """
    now = datetime.now(timezone.utc)
    if cert.not_valid_before_utc > now:
        return False
    return cert.not_valid_after_utc - now > timedelta(days=_RENEWAL_WINDOW_DAYS)


def _try_load_ca(
    cert_path: Path,
    key_path: Path,
) -> tuple[bool, x509.Certificate | None, rsa.RSAPrivateKey | None]:
    """Return ``(reusable, ca_cert, ca_key)`` for the on-disk CA pair.

    ``reusable=True`` only when both files exist, both parse, the
    public key derived from the private key matches the cert public
    key (no CA-pair drift after a partial overwrite), and the cert
    is inside its validity window. ``False`` for any failure — caller
    re-issues the CA from scratch.
    """
    if not (cert_path.is_file() and key_path.is_file()):
        return False, None, None
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
    except (ValueError, TypeError):
        return False, None, None
    if (
        key.public_key().public_numbers()
        != cert.public_key().public_numbers()
    ):
        return False, None, None
    if not _cert_in_validity_window(cert):
        return False, None, None
    return True, cert, key


def _try_load_service_leaf(
    key_path: Path,
    cert_path: Path,
    svc: ServiceCert,
    ca_cert: x509.Certificate,
) -> tuple[bool, rsa.RSAPrivateKey | None, x509.Certificate | None]:
    """Return ``(reusable, key, cert)`` for an on-disk service leaf pair.

    ``reusable=True`` only when both files exist, both parse, the
    public key derived from the private key matches the cert's public
    key (no partial-write drift), and the cert is issued by *ca_cert*
    with the required SANs. ``False`` for any failure — caller
    re-issues the pair.
    """
    if not (key_path.is_file() and cert_path.is_file()):
        return False, None, None
    try:
        key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (ValueError, TypeError):
        return False, None, None
    if (
        key.public_key().public_numbers()
        != cert.public_key().public_numbers()
    ):
        return False, None, None
    if not _service_cert_consistent_with_ca(cert, svc, ca_cert):
        return False, None, None
    if not _cert_in_validity_window(cert):
        return False, None, None
    return True, key, cert


def _keystore_unlocks_to(
    ks_path: Path,
    pw_path: Path,
    expected_cert: x509.Certificate,
) -> bool:
    """Return True iff the keystore unlocks with the on-disk password
    AND contains a cert matching *expected_cert* by SHA-256 fingerprint.

    A stale keystore from a prior CA cycle would unlock with its own
    password but carry the previous leaf — the fingerprint mismatch is
    what flags the rotation. A corrupted password file fails the
    unlock and also returns False.
    """
    try:
        pw_blob = pw_path.read_text().strip()
        password = pw_blob.split("=", 1)[1]
        _, ks_cert, _ = pkcs12.load_key_and_certificates(
            ks_path.read_bytes(), password.encode()
        )
    except (ValueError, TypeError, IndexError):
        return False
    if ks_cert is None:
        return False
    return (
        ks_cert.fingerprint(hashes.SHA256())
        == expected_cert.fingerprint(hashes.SHA256())
    )


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


def _service_cert_consistent_with_ca(
    cert: x509.Certificate,
    svc: ServiceCert,
    ca_cert: x509.Certificate,
) -> bool:
    """Return True iff *cert* was issued by *ca_cert* AND matches *svc*'s SANs.

    Catches the case where the CA has been regenerated but stale
    service certs are still on disk: their issuer no longer matches
    the new CA, so clients that trust the new CA cannot verify them.
    """
    if cert.issuer != ca_cert.subject:
        return False
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            _signature_padding_for(cert),
            cert.signature_hash_algorithm,
        )
    except Exception:  # noqa: BLE001 - any failure invalidates the chain
        return False
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return False
    dns = set(san.value.get_values_for_type(x509.DNSName))
    ip = {str(v) for v in san.value.get_values_for_type(x509.IPAddress)}
    expected_dns = {s for s in svc.sans if _is_dns(s)}
    expected_ip = {s for s in svc.sans if not _is_dns(s)}
    if not expected_dns.issubset(dns):
        return False
    if not expected_ip.issubset(ip):
        return False
    return True


def _signature_padding_for(cert: x509.Certificate):
    """Return the signature padding for *cert*'s public key type."""
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    if isinstance(cert.public_key(), rsa.RSAPublicKey):
        return padding.PKCS1v15()
    raise ValueError(f"Unexpected key type {type(cert.public_key())!r}")


def _is_dns(value: str) -> bool:
    """Classify a SAN entry as DNS (True) or IP (False)."""
    try:
        ip_address(value)
        return False
    except ValueError:
        return True


def _invalidate_keystore(svc_dir: Path) -> None:
    """Remove a stale PKCS#12 keystore + password file when its leaf cert
    was just regenerated. Idempotent — missing files are silently fine.

    Without this, a regenerated server.pem/server.key pair would still
    be paired with an obsolete keystore.p12, which is the very state
    codex flagged as "presence-only idempotency".
    """
    for name in ("keystore.p12", "keystore.p12.password"):
        path = svc_dir / name
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _build_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Produce a fresh 4096-bit RSA CA cert + key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "APTL"),
            x509.NameAttribute(NameOID.COMMON_NAME, "APTL Lab Local CA"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=_CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_server_cert(
    svc: ServiceCert,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Produce a 2048-bit RSA server cert + key signed by *ca_cert*."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "APTL"),
            x509.NameAttribute(NameOID.COMMON_NAME, svc.subject_cn),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=_SVC_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(_san(svc.sans), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _san(values: Iterable[str]) -> x509.SubjectAlternativeName:
    """Convert a SAN list of strings into a SubjectAlternativeName extension.

    IP literals get :class:`x509.IPAddress` entries; anything else is
    treated as a DNS name. Splitting here keeps the registry rows plain
    strings.
    """
    entries: list[x509.GeneralName] = []
    for raw in values:
        try:
            ip = ip_address(raw)
            if isinstance(ip, (IPv4Address, IPv6Address)):
                entries.append(x509.IPAddress(ip))
                continue
        except ValueError:
            pass
        entries.append(x509.DNSName(raw))
    return x509.SubjectAlternativeName(entries)


# ---------------------------------------------------------------------------
# PEM encoding helpers
# ---------------------------------------------------------------------------


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_private_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ---------------------------------------------------------------------------
# Atomic write + permission enforcement
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Error scrubbing
# ---------------------------------------------------------------------------


def _scrub(exc: BaseException) -> str:
    """Legacy helper retained for backwards compatibility with the few
    call sites that still want a minimal class-only marker (e.g. for
    embedding in unrelated log lines that already carry their own
    context). New call sites should prefer ``_classify_failure_layer``
    and emit ``f"{layer}: {exc.__class__.__name__}"`` so the operator
    sees which generator phase tripped.
    """
    return exc.__class__.__name__
