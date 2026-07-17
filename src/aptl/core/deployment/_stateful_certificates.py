"""Fail-closed validation for backend-owned certificate artifacts."""

from __future__ import annotations

import ipaddress
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

from aptl.core.deployment.realization import DeploymentGeneratedArtifactOutput

_ROOT_CA = "root-ca.pem"
_MANAGER_ROOT_CA = "root-ca-manager.pem"


def validate_certificate_bundle(
    certs_dir: Path,
    outputs: tuple[DeploymentGeneratedArtifactOutput, ...],
    provenance_path: Path,
) -> list[str]:
    """Validate declared PEM outputs without exposing paths or key material."""

    paths = {output.path: certs_dir / output.path for output in outputs}
    if any(not path.is_file() for path in paths.values()):
        return ["Certificate bundle is missing a declared output."]
    if _unsafe_permissions(certs_dir, paths.values()):
        return ["Certificate bundle output permissions are unsafe."]

    try:
        certificates = {
            name: x509.load_pem_x509_certificate(path.read_bytes())
            for name, path in paths.items()
            if not name.endswith("-key.pem")
        }
        private_keys = {
            name: load_pem_private_key(path.read_bytes(), password=None)
            for name, path in paths.items()
            if name.endswith("-key.pem")
        }
    except (OSError, TypeError, ValueError):
        return ["Certificate bundle contains an invalid PEM output."]

    root = certificates.get(_ROOT_CA)
    if root is None:
        try:
            root = x509.load_pem_x509_certificate((certs_dir / _ROOT_CA).read_bytes())
        except (OSError, ValueError):
            root = None
    if root is None or not _valid_root(root):
        return ["Certificate bundle has an invalid root authority."]
    manager_root = certificates.get(_MANAGER_ROOT_CA)
    if manager_root is not None and manager_root.fingerprint(
        root.signature_hash_algorithm
    ) != root.fingerprint(root.signature_hash_algorithm):
        return ["Certificate bundle has inconsistent root authorities."]

    if not _key_pairs_match(private_keys, certificates):
        return ["Certificate bundle contains a key/certificate mismatch."]
    if not _chains_to_root(certificates, root):
        return ["Certificate bundle contains an invalid issuer chain."]

    expected = _expected_identities(provenance_path)
    if expected is None or not _identities_match(certificates, expected):
        return ["Certificate bundle identity does not match its provenance."]
    return []


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


def _unsafe_permissions(certs_dir: Path, paths: Any) -> bool:
    """Reject symlinks, exposed bundle directories, and writable outputs.

    Individual PEM files remain container-readable because Wazuh runs as a
    non-root uid that may differ from the host uid.  The owner-only directory
    is therefore the host-side confidentiality boundary for private keys.
    """

    try:
        if certs_dir.is_symlink() or stat.S_IMODE(certs_dir.stat().st_mode) & 0o077:
            return True
        for path in paths:
            if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o022:
                return True
    except OSError:
        return True
    return False


def _valid_root(root: x509.Certificate) -> bool:
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
    private_keys: dict[str, Any],
    certificates: dict[str, x509.Certificate],
) -> bool:
    for key_name, private_key in private_keys.items():
        cert_name = key_name.removesuffix("-key.pem") + ".pem"
        certificate = certificates.get(cert_name)
        if certificate is None:
            return False
        if _public_key_bytes(private_key.public_key()) != _public_key_bytes(
            certificate.public_key()
        ):
            return False
    return True


def _public_key_bytes(key: Any) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _chains_to_root(
    certificates: dict[str, x509.Certificate], root: x509.Certificate
) -> bool:
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
    try:
        payload = yaml.safe_load(provenance_path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return None
    nodes = payload.get("nodes")
    if not isinstance(nodes, dict):
        return None
    expected: dict[str, str] = {}
    for entries in nodes.values():
        if not isinstance(entries, list):
            return None
        for entry in entries:
            if not isinstance(entry, dict):
                return None
            name = entry.get("name")
            address = entry.get("ip")
            if not isinstance(name, str) or not isinstance(address, str):
                return None
            expected[name] = address
    return expected


def _identities_match(
    certificates: dict[str, x509.Certificate], expected: dict[str, str]
) -> bool:
    for filename, certificate in certificates.items():
        if filename in {_ROOT_CA, _MANAGER_ROOT_CA}:
            continue
        name = filename.removesuffix(".pem")
        if name == "admin":
            if _common_name(certificate) != "admin":
                return False
            continue
        address = expected.get(name)
        if address is None or _common_name(certificate) != name:
            return False
        try:
            alternative_names = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
        except x509.ExtensionNotFound:
            return False
        if not _san_contains(alternative_names, address):
            return False
    return True


def _common_name(certificate: x509.Certificate) -> str | None:
    values = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if len(values) == 1 else None


def _san_contains(names: x509.SubjectAlternativeName, expected: str) -> bool:
    try:
        address = ipaddress.ip_address(expected)
    except ValueError:
        return expected in names.get_values_for_type(x509.DNSName)
    return address in names.get_values_for_type(x509.IPAddress)
