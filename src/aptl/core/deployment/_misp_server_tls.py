"""Deliver the pack's MISP leaf certificate where its image actually reads it.

The released TechVault pack owns this material: ``techvault-soc-certificates``
declares ``misp-certificate`` and ``misp-private-key``, and mounts them into the
MISP node at ``/opt/techvault/soc-certs``. That destination is the scenario's
substrate-neutral statement of *what* MISP receives. It is not where the
selected component looks: the pinned ``misp-core`` image's
``/etc/nginx/sites-available/misp443`` reads ``/etc/nginx/certs/cert.pem`` and
``/etc/nginx/certs/key.pem``, and generates a self-signed pair when they are
absent. Choosing how an authored certificate reaches the selected image is a
backend concern, so APTL makes that choice here.

A consumer mount lowers to ``mount_destination / output.path`` for both its
host source and its container target, so the host file has to carry the
image-native name. This module therefore stages a copy of the pack-produced
leaf under image-native filenames. The SOC certificate bundle remains the sole
*producer* of the material -- nothing here mints a key, derives an identity, or
signs anything. It is a delivery shape, and it is refreshed whenever the
bundle's bytes change so a rotated certificate can never leave a stale copy
serving traffic.
"""

from __future__ import annotations

from pathlib import Path

from aptl.core.credentials import (
    _atomic_write_secure,
    _canonical_generated_path,
    _ensure_secure_dir,
)
from aptl.core.deployment._compose_stateful_constants import (
    MISP_SERVER_TLS_ROOT_RELPATH,
    SOC_CERTS_ROOT_RELPATH,
)
from aptl.core.deployment.realization import DeploymentGeneratedArtifactRealization

MISP_SERVER_TLS_PROFILE = "techvault:misp-server-tls/v1"

#: Where the pinned image's nginx configuration reads its TLS material.
MISP_SERVER_TLS_MOUNT_DESTINATION = "/etc/nginx/certs"
MISP_SERVER_TLS_CERTIFICATE_OUTPUT = "server-certificate"
MISP_SERVER_TLS_PRIVATE_KEY_OUTPUT = "server-private-key"

#: Output name -> (image-native relative path, path within the SOC bundle).
_EXPECTED_OUTPUTS = {
    MISP_SERVER_TLS_CERTIFICATE_OUTPUT: ("cert.pem", "misp/server.pem"),
    MISP_SERVER_TLS_PRIVATE_KEY_OUTPUT: ("key.pem", "misp/server.key"),
}
_PRIVATE_OUTPUTS = frozenset({MISP_SERVER_TLS_PRIVATE_KEY_OUTPUT})


def realize_misp_server_tls(
    artifact: DeploymentGeneratedArtifactRealization,
    scenario_root: Path,
) -> str | None:
    """Stage the pack's MISP leaf under the filenames its image reads."""

    actual = {output.name: output.path for output in artifact.outputs}
    expected = {name: relative for name, (relative, _) in _EXPECTED_OUTPUTS.items()}
    invalid_contract = (
        artifact.provenance != MISP_SERVER_TLS_PROFILE
        or artifact.lifecycle != "reuse_valid"
        or actual != expected
    )
    error = (
        "MISP server TLS artifact does not match its producer contract."
        if invalid_contract
        else _stage_misp_server_tls(scenario_root)
    )
    return error


def _stage_misp_server_tls(scenario_root: Path) -> str | None:
    """Copy the authored leaf into the selected image's native layout."""

    try:
        root = _canonical_generated_path(scenario_root, MISP_SERVER_TLS_ROOT_RELPATH)
        _ensure_secure_dir(root)
        for name, (relative, source_relative) in _EXPECTED_OUTPUTS.items():
            source = _canonical_generated_path(
                scenario_root, SOC_CERTS_ROOT_RELPATH / source_relative
            )
            content = source.read_text(encoding="utf-8")
            if not content.strip():
                return (
                    "MISP server TLS material is missing from the certificate bundle."
                )
            target = _canonical_generated_path(
                scenario_root, MISP_SERVER_TLS_ROOT_RELPATH / relative
            )
            if _current(target) == content:
                continue
            _atomic_write_secure(target, content)
            # The certificate is public material and the key is not, but both
            # are staged owner-only: the mount is read-only, so the container
            # never needs group or world access to either.
            target.chmod(0o600 if name in _PRIVATE_OUTPUTS else 0o644)
    except (OSError, ValueError):
        return "MISP server TLS staging failed."
    return None


def _current(path: Path) -> str | None:
    """Return the staged bytes, or ``None`` when nothing is staged yet."""

    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


__all__ = (
    "MISP_SERVER_TLS_CERTIFICATE_OUTPUT",
    "MISP_SERVER_TLS_MOUNT_DESTINATION",
    "MISP_SERVER_TLS_PRIVATE_KEY_OUTPUT",
    "MISP_SERVER_TLS_PROFILE",
    "realize_misp_server_tls",
)
