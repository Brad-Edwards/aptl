"""Fail-closed validation for backend-owned certificate artifacts."""

from __future__ import annotations

import ipaddress
import stat
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

from aptl.core.deployment.realization import DeploymentGeneratedArtifactOutput

_ROOT_CA = "root-ca.pem"
_MANAGER_ROOT_CA = "root-ca-manager.pem"
_KEY_SUFFIX = "-key.pem"
_INVALID_PEM_ERROR = "Certificate bundle contains an invalid PEM output."


def validate_certificate_bundle(
    certs_dir: Path,
    outputs: tuple[DeploymentGeneratedArtifactOutput, ...],
    provenance_path: Path,
) -> list[str]:
    """Validate declared PEM outputs without exposing paths or key material."""

    paths = {output.path: certs_dir / output.path for output in outputs}
    error = _certificate_path_error(certs_dir, paths.values())
    if error is None:
        bundle = _load_certificate_bundle(paths)
        error = (
            _INVALID_PEM_ERROR
            if bundle is None
            else _loaded_bundle_error(certs_dir, provenance_path, *bundle)
        )
    return [error] if error is not None else []


def _certificate_path_error(
    certs_dir: Path,
    paths: Iterable[Path],
) -> str | None:
    """Return the first structural or permission error for bundle paths."""

    materialized_paths = tuple(paths)
    error: str | None = None
    if any(not path.is_file() for path in materialized_paths):
        error = "Certificate bundle is missing a declared output."
    elif _unsafe_permissions(certs_dir, materialized_paths):
        error = "Certificate bundle output permissions are unsafe."
    return error


def _load_certificate_bundle(
    paths: dict[str, Path],
) -> tuple[dict[str, x509.Certificate], dict[str, PrivateKeyTypes]] | None:
    """Load declared certificates and private keys as one fail-closed unit."""

    try:
        certificates = {
            name: x509.load_pem_x509_certificate(path.read_bytes())
            for name, path in paths.items()
            if not name.endswith(_KEY_SUFFIX)
        }
        private_keys = {
            name: load_pem_private_key(path.read_bytes(), password=None)
            for name, path in paths.items()
            if name.endswith(_KEY_SUFFIX)
        }
    except (OSError, TypeError, ValueError):
        return None
    return certificates, private_keys


def _loaded_bundle_error(
    certs_dir: Path,
    provenance_path: Path,
    certificates: dict[str, x509.Certificate],
    private_keys: dict[str, PrivateKeyTypes],
) -> str | None:
    """Validate cryptographic and provenance relationships in stable order."""

    error: str | None = None
    root = _load_valid_root(certs_dir, certificates)
    if root is None:
        error = "Certificate bundle has an invalid root authority."
    elif not _manager_root_matches(certificates, root):
        error = "Certificate bundle has inconsistent root authorities."
    elif not _key_pairs_match(private_keys, certificates):
        error = "Certificate bundle contains a key/certificate mismatch."
    elif not _chains_to_root(certificates, root):
        error = "Certificate bundle contains an invalid issuer chain."
    else:
        expected = _expected_identities(provenance_path)
        if expected is None or not _identities_match(certificates, expected):
            error = "Certificate bundle identity does not match its provenance."
    return error


def _load_valid_root(
    certs_dir: Path,
    certificates: dict[str, x509.Certificate],
) -> x509.Certificate | None:
    """Load the declared or canonical root and require a valid self-signature."""

    root = certificates.get(_ROOT_CA)
    if root is None:
        try:
            root = x509.load_pem_x509_certificate((certs_dir / _ROOT_CA).read_bytes())
        except (OSError, ValueError):
            root = None
    return root if root is not None and _valid_root(root) else None


def _manager_root_matches(
    certificates: dict[str, x509.Certificate],
    root: x509.Certificate,
) -> bool:
    """Require an optional manager root copy to match the canonical root."""

    manager_root = certificates.get(_MANAGER_ROOT_CA)
    return manager_root is None or manager_root.fingerprint(
        root.signature_hash_algorithm
    ) == root.fingerprint(root.signature_hash_algorithm)


def certificate_bundle_evidence(
    certs_dir: Path,
    outputs: tuple[DeploymentGeneratedArtifactOutput, ...],
    provenance_path: Path,
) -> dict[str, object] | None:
    """Return non-secret certificate proof only after full validation."""

    if validate_certificate_bundle(certs_dir, outputs, provenance_path):
        return None
    try:
        root = x509.load_pem_x509_certificate((certs_dir / _ROOT_CA).read_bytes())
    except (OSError, ValueError):
        return None
    return {
        "public_root_sha256": root.fingerprint(hashes.SHA256()).hex(),
        "chain_valid": True,
        "san_valid": True,
    }


def _unsafe_permissions(certs_dir: Path, paths: Iterable[Path]) -> bool:
    """Reject symlinks, exposed bundle directories, and writable outputs.

    Individual PEM files remain container-readable because Wazuh runs as a
    non-root uid that may differ from the host uid.  The owner-only directory
    is therefore the host-side confidentiality boundary for private keys.
    """

    unsafe = False
    try:
        unsafe = bool(
            certs_dir.is_symlink() or stat.S_IMODE(certs_dir.stat().st_mode) & 0o077
        )
        for path in paths:
            if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o022:
                unsafe = True
                break
    except OSError:
        unsafe = True
    return unsafe


def _valid_root(root: x509.Certificate) -> bool:
    """Return whether a certificate is a current self-signed CA root."""

    now = datetime.now(timezone.utc)
    try:
        constraints = root.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        root.verify_directly_issued_by(root)
    except (ValueError, x509.ExtensionNotFound):
        return False
    return bool(
        constraints.ca
        and root.subject == root.issuer
        and root.not_valid_before_utc <= now <= root.not_valid_after_utc
    )


def _key_pairs_match(
    private_keys: dict[str, PrivateKeyTypes],
    certificates: dict[str, x509.Certificate],
) -> bool:
    """Require every declared private key to match its sibling certificate."""

    for key_name, private_key in private_keys.items():
        cert_name = key_name.removesuffix(_KEY_SUFFIX) + ".pem"
        certificate = certificates.get(cert_name)
        if certificate is None:
            return False
        if _public_key_bytes(private_key.public_key()) != _public_key_bytes(
            certificate.public_key()
        ):
            return False
    return True


def _public_key_bytes(key: PublicKeyTypes) -> bytes:
    """Serialize a public key into a stable representation for comparison."""

    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _chains_to_root(
    certificates: dict[str, x509.Certificate], root: x509.Certificate
) -> bool:
    """Require every leaf certificate to be current and issued by the root."""

    now = datetime.now(timezone.utc)
    for name, certificate in certificates.items():
        if name in {_ROOT_CA, _MANAGER_ROOT_CA}:
            continue
        try:
            certificate.verify_directly_issued_by(root)
        except ValueError:
            return False
        if not (
            certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc
        ):
            return False
    return True


def _expected_identities(provenance_path: Path) -> dict[str, str] | None:
    """Parse the expected certificate common names and addresses."""

    try:
        payload = yaml.safe_load(provenance_path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        payload = None
    nodes = payload.get("nodes") if isinstance(payload, dict) else None
    expected: dict[str, str] = {}
    valid = isinstance(nodes, dict)
    for entries in nodes.values() if isinstance(nodes, dict) else ():
        if not isinstance(entries, list):
            valid = False
            break
        for entry in entries:
            if not isinstance(entry, dict):
                valid = False
                break
            name = entry.get("name")
            address = entry.get("ip")
            if not isinstance(name, str) or not isinstance(address, str):
                valid = False
                break
            expected[name] = address
        if not valid:
            break
    return expected if valid else None


def _identities_match(
    certificates: dict[str, x509.Certificate], expected: dict[str, str]
) -> bool:
    """Match each leaf's common name and SAN against provenance."""

    matched = True
    for filename, certificate in certificates.items():
        if filename in {_ROOT_CA, _MANAGER_ROOT_CA}:
            continue
        name = filename.removesuffix(".pem")
        if name == "admin":
            matched = _common_name(certificate) == "admin"
        else:
            address = expected.get(name)
            matched = bool(
                address is not None
                and _common_name(certificate) == name
                and _certificate_san_contains(certificate, address)
            )
        if not matched:
            break
    return matched


def _certificate_san_contains(
    certificate: x509.Certificate,
    expected: str,
) -> bool:
    """Return whether a certificate SAN contains an expected host or address."""

    try:
        alternative_names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return False
    return _san_contains(alternative_names, expected)


def _common_name(certificate: x509.Certificate) -> str | None:
    """Return the sole certificate common name, rejecting ambiguous subjects."""

    values = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if len(values) == 1 else None


def _san_contains(names: x509.SubjectAlternativeName, expected: str) -> bool:
    """Match an expected DNS name or IP address using the appropriate SAN type."""

    try:
        address = ipaddress.ip_address(expected)
    except ValueError:
        return expected in names.get_values_for_type(x509.DNSName)
    return address in names.get_values_for_type(x509.IPAddress)
