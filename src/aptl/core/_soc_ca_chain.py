"""Chain-validation helpers for the SOC stack lab CA (SEC-006 / ADR-034).

Split out of :mod:`aptl.core.soc_ca` so the parent module stays under
its file-size budget. Everything in here is pure cryptographic
verification: load X.509 material from disk, check that derived public
keys agree across cert/key pairs, that leaf certs are issued by the
expected CA, and that PKCS#12 keystores unlock to the expected leaf.

These helpers stay package-private — their stability contract is the
same as :mod:`aptl.core.soc_ca` itself.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from aptl.core._soc_ca_io import (
    KEYSTORE_FILENAME,
    KEYSTORE_PASSWORD_FILENAME,
)

if TYPE_CHECKING:
    from aptl.core.soc_ca import ServiceCert


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
    reusable = False
    cert: x509.Certificate | None = None
    key: rsa.RSAPrivateKey | None = None

    if cert_path.is_file() and key_path.is_file():
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            key = serialization.load_pem_private_key(
                key_path.read_bytes(), password=None
            )
        except (ValueError, TypeError):
            cert = None
            key = None
        if cert is not None and key is not None:
            same_pubkey = (
                key.public_key().public_numbers()
                == cert.public_key().public_numbers()
            )
            if same_pubkey and _cert_in_validity_window(cert):
                reusable = True

    if not reusable:
        return False, None, None
    return True, cert, key


def _try_load_service_leaf(
    key_path: Path,
    cert_path: Path,
    svc: "ServiceCert",
    ca_cert: x509.Certificate,
) -> tuple[bool, rsa.RSAPrivateKey | None, x509.Certificate | None]:
    """Return ``(reusable, key, cert)`` for an on-disk service leaf pair.

    ``reusable=True`` only when both files exist, both parse, the
    public key derived from the private key matches the cert's public
    key (no partial-write drift), and the cert is issued by *ca_cert*
    with the required SANs. ``False`` for any failure — caller
    re-issues the pair.
    """
    reusable = False
    key: rsa.RSAPrivateKey | None = None
    cert: x509.Certificate | None = None

    if key_path.is_file() and cert_path.is_file():
        try:
            key = serialization.load_pem_private_key(
                key_path.read_bytes(), password=None
            )
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        except (ValueError, TypeError):
            key = None
            cert = None
        if key is not None and cert is not None:
            same_pubkey = (
                key.public_key().public_numbers()
                == cert.public_key().public_numbers()
            )
            chain_ok = (
                same_pubkey
                and _service_cert_consistent_with_ca(cert, svc, ca_cert)
                and _cert_in_validity_window(cert)
            )
            if chain_ok:
                reusable = True

    if not reusable:
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


def _service_cert_consistent_with_ca(
    cert: x509.Certificate,
    svc: "ServiceCert",
    ca_cert: x509.Certificate,
) -> bool:
    """Return True iff *cert* was issued by *ca_cert* AND matches *svc*'s SANs.

    Catches the case where the CA has been regenerated but stale
    service certs are still on disk: their issuer no longer matches
    the new CA, so clients that trust the new CA cannot verify them.
    """
    if cert.issuer != ca_cert.subject:
        return False
    if not _ca_signature_verifies(ca_cert, cert):
        return False
    return _sans_cover_service(cert, svc)


def _ca_signature_verifies(
    ca_cert: x509.Certificate, cert: x509.Certificate
) -> bool:
    """Return True iff *cert*'s signature verifies against *ca_cert*'s key.

    NOTE on the broad except: cryptography raises a heterogeneous set of
    subclasses on signature-verification failure (InvalidSignature,
    UnsupportedAlgorithm, plus internal OpenSSL-binding errors). The
    contract of this helper is "tell me whether the signature verifies,
    never raise"; the caller branches on the bool to decide whether to
    re-issue. Allowing the broad-except here is therefore part of the
    design, not a quality gap — same justification as the noqa(BLE001)
    in :func:`aptl.core.soc_ca.ensure_soc_certs` for the cryptography
    stack overall.
    """
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            _signature_padding_for(cert),
            cert.signature_hash_algorithm,
        )
    except Exception:  # noqa: BLE001 — any cryptography failure (InvalidSignature, AttributeError on a truncated cert, ValueError on bad encoding, TypeError on key-mismatch shapes, future classes) means the chain is broken; the consistency-check contract is "any failure ⇒ regenerate".
        return False
    return True


def _sans_cover_service(cert: x509.Certificate, svc: "ServiceCert") -> bool:
    """Return True iff *cert*'s SAN extension covers every required
    DNS/IP entry from *svc*.

    Extracted from :func:`_service_cert_consistent_with_ca` so each
    sub-check is independently testable and the parent stays under the
    multi-return budget.
    """
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return False
    dns = set(san.value.get_values_for_type(x509.DNSName))
    ip = {str(v) for v in san.value.get_values_for_type(x509.IPAddress)}
    expected_dns = {s for s in svc.sans if _is_dns(s)}
    expected_ip = {s for s in svc.sans if not _is_dns(s)}
    return expected_dns.issubset(dns) and expected_ip.issubset(ip)


def _signature_padding_for(cert: x509.Certificate) -> padding.AsymmetricPadding:
    """Return the signature padding for *cert*'s public key type."""
    if isinstance(cert.public_key(), rsa.RSAPublicKey):
        return padding.PKCS1v15()
    raise ValueError(f"Unexpected key type {type(cert.public_key())!r}")


def _is_dns(value: str) -> bool:
    """Classify a SAN entry as DNS (True) or IP (False)."""
    try:
        ip_address(value)
    except ValueError:
        return True
    return False


def _per_service_artifacts_consistent(
    output_dir: Path,
    svc: "ServiceCert",
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
    loaded = _load_service_leaf_pair(svc_dir, svc)
    if loaded is None:
        return False
    cert, key = loaded
    same_pubkey = (
        key.public_key().public_numbers()
        == cert.public_key().public_numbers()
    )
    leaf_ok = (
        same_pubkey
        and _service_cert_consistent_with_ca(cert, svc, ca_cert)
        and _cert_in_validity_window(cert)
    )
    keystore_ok = (
        not svc.needs_keystore
        or _keystore_unlocks_to(
            svc_dir / KEYSTORE_FILENAME,
            svc_dir / KEYSTORE_PASSWORD_FILENAME,
            cert,
        )
    )
    return leaf_ok and keystore_ok


def _load_service_leaf_pair(
    svc_dir: Path, svc: "ServiceCert"
) -> tuple[x509.Certificate, rsa.RSAPrivateKey] | None:
    """Load *svc*'s leaf cert + key from disk, or ``None`` on any parse
    failure. Extracted so :func:`_per_service_artifacts_consistent` stays
    inside the multi-return budget.
    """
    try:
        cert = x509.load_pem_x509_certificate(
            (svc_dir / svc.cert_filename).read_bytes()
        )
        key = serialization.load_pem_private_key(
            (svc_dir / svc.key_filename).read_bytes(), password=None
        )
    except (ValueError, TypeError):
        return None
    return cert, key


def _all_artifacts_present_and_consistent(
    output_dir: Path,
    ca_cert_name: str,
    ca_key_name: str,
    registry: tuple["ServiceCert", ...],
) -> bool:
    """Return True iff the CA + service tree is cryptographically valid.

    See the module docstring on :mod:`aptl.core.soc_ca` for the full
    contract: presence-only is not enough — every leaf must verify
    against the on-disk CA, every service key must derive the same
    public key as its cert, every keystore must unlock to a cert with
    the same fingerprint as the on-disk PEM.
    """
    ca_cert_path = output_dir / ca_cert_name
    ca_key_path = output_dir / ca_key_name
    required = _required_artifact_paths(
        output_dir, ca_cert_path, ca_key_path, registry
    )
    if not all(p.is_file() for p in required):
        return False
    ca_pair = _load_ca_pair(ca_cert_path, ca_key_path)
    if ca_pair is None:
        return False
    ca_cert, _ = ca_pair
    return all(
        _per_service_artifacts_consistent(output_dir, svc, ca_cert)
        for svc in registry
    )


def _load_ca_pair(
    ca_cert_path: Path, ca_key_path: Path
) -> tuple[x509.Certificate, rsa.RSAPrivateKey] | None:
    """Load the CA cert + key and return them iff the pair is internally
    consistent (matching public key, cert still in validity window).

    Returns ``None`` for any failure — the caller treats that as
    "regenerate". Extracted to keep
    :func:`_all_artifacts_present_and_consistent` under the
    multi-return budget.
    """
    try:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
        ca_key = serialization.load_pem_private_key(
            ca_key_path.read_bytes(), password=None
        )
    except (ValueError, TypeError):
        return None
    same_ca_pubkey = (
        ca_key.public_key().public_numbers()
        == ca_cert.public_key().public_numbers()
    )
    if not same_ca_pubkey or not _cert_in_validity_window(ca_cert):
        return None
    return ca_cert, ca_key


def _required_artifact_paths(
    output_dir: Path,
    ca_cert_path: Path,
    ca_key_path: Path,
    registry: tuple["ServiceCert", ...],
) -> list[Path]:
    """Return the full list of files that must exist for the CA tree
    to even be a candidate for the deeper chain check.

    Extracted so ``_all_artifacts_present_and_consistent`` reads as a
    pipeline of small checks rather than an inline path-building loop.
    """
    required: list[Path] = [ca_cert_path, ca_key_path]
    for svc in registry:
        svc_dir = output_dir / svc.name
        required.append(svc_dir / svc.cert_filename)
        required.append(svc_dir / svc.key_filename)
        if svc.needs_keystore:
            required.append(svc_dir / KEYSTORE_FILENAME)
            required.append(svc_dir / KEYSTORE_PASSWORD_FILENAME)
    return required


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
