"""X.509 builders for the SOC stack lab CA (SEC-006 / ADR-034).

Split out of :mod:`aptl.core.soc_ca` so the parent module stays under
its file-size budget. The functions here are pure constructors — they
do not touch the filesystem and do not consult any on-disk state.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aptl.core._soc_ca_chain import _san

if TYPE_CHECKING:
    from aptl.core.soc_ca import ServiceCert


# CA validity window — long enough that a lab redeploy doesn't churn.
_CA_VALIDITY_DAYS = 10 * 365
# Per-service validity — shorter than the CA so the operator regenerates
# server certs occasionally without ever touching the trust anchor.
_SVC_VALIDITY_DAYS = 5 * 365

# RSA key strengths for the lab CA and the per-service server certs.
# Production-grade by default. The test suite (tests/conftest.py) patches
# these down so the dozens of fresh-CA generations it drives are not
# dominated by 4096-bit prime search, which is CPU-bound and can stall on a
# loaded host. The CA-chain behaviour the tests assert — signing, SANs, EKU,
# permissions, regeneration — is independent of key strength.
_CA_KEY_SIZE = 4096
_SVC_KEY_SIZE = 2048


def _build_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Produce a fresh RSA CA cert + key (``_CA_KEY_SIZE`` bits)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=_CA_KEY_SIZE)
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
    svc: "ServiceCert",
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Produce an RSA server cert + key (``_SVC_KEY_SIZE`` bits) signed by *ca_cert*."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=_SVC_KEY_SIZE)
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
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
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
