"""SSL certificate generation for Wazuh Indexer.

Runs the docker compose cert generator if certificates do not already
exist, then fixes file permissions for container consumption.
"""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aptl.core import hostenv
from aptl.utils.logging import get_logger

log = get_logger("certs")

_CERTS_SUBDIR = "config/wazuh_indexer_ssl_certs"
_CERT_COMPOSE_FILE = "generate-indexer-certs.yml"
# Reused (already pulled) to chown the bind-mounted certs from inside a
# container, so ownership is repaired without escalating on the host.
_CERT_GENERATOR_IMAGE = "wazuh/wazuh-certs-generator:0.0.2"


@dataclass
class CertResult:
    """Result of SSL certificate generation."""

    success: bool
    generated: bool
    certs_dir: Path = Path()
    error: str = ""


def ensure_ssl_certs(project_dir: Path) -> CertResult:
    """Ensure SSL certificates exist for the Wazuh Indexer.

    If the certificates directory already exists, this is a no-op.
    Otherwise, runs the docker compose cert generator and fixes
    file permissions.

    Args:
        project_dir: Root directory of the APTL project (where
                     docker-compose.yml lives).

    Returns:
        CertResult indicating success, whether certs were generated,
        and the path to the certs directory.
    """
    certs_dir = project_dir / _CERTS_SUBDIR
    root_ca = certs_dir / "root-ca.pem"

    if certs_dir.exists() and root_ca.exists():
        log.info("SSL certificates already exist at %s", certs_dir)
        return CertResult(
            success=True,
            generated=False,
            certs_dir=certs_dir,
        )

    log.info("Generating SSL certificates...")

    # Run cert generator via docker compose
    try:
        result = subprocess.run(
            [
                "docker", "compose",
                "-f", _CERT_COMPOSE_FILE,
                "run", "--rm", "generator",
            ],
            capture_output=True,
            text=True,
            cwd=project_dir,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        log.error(
            "Certificate generation timed out after 300s. "
            "This may indicate a stuck container or slow image pull."
        )
        return CertResult(
            success=False,
            generated=False,
            certs_dir=certs_dir,
            error="Certificate generation timed out after 300s",
        )
    except (FileNotFoundError, OSError) as exc:
        log.error("Failed to run docker compose: %s", exc)
        return CertResult(
            success=False,
            generated=False,
            certs_dir=certs_dir,
            error=str(exc),
        )

    if result.returncode != 0:
        error_msg = result.stderr.strip() or "Certificate generation failed"
        log.error("Certificate generation failed: %s", error_msg)
        return CertResult(
            success=False,
            generated=False,
            certs_dir=certs_dir,
            error=error_msg,
        )

    ownership_error = _fix_cert_ownership(certs_dir, project_dir)
    if ownership_error is not None:
        return ownership_error

    log.info("SSL certificates generated successfully at %s", certs_dir)
    return CertResult(
        success=True,
        generated=True,
        certs_dir=certs_dir,
    )


def _fix_cert_ownership(certs_dir: Path, project_dir: Path) -> CertResult | None:
    """Repair ownership of container-generated certs without host sudo.

    A native Linux Docker engine writes the bind-mounted certificates as
    root. Instead of escalating on the host with ``sudo`` (which silently
    runs under passwordless sudo, breaks on Windows, and is unnecessary on
    Docker Desktop), chown the files back to the invoking user from *inside*
    a throwaway container — root within the container, no host privilege.

    Docker Desktop's file-sharing layer already maps ownership to the user,
    and an unknown/absent engine must not trigger any privileged action, so
    the fix runs only for a native Linux engine (see
    :func:`hostenv.needs_host_ownership_fix`).

    Returns ``None`` on success (or when no fix is needed), or a failing
    :class:`CertResult` describing the problem.
    """
    if not hostenv.needs_host_ownership_fix():
        log.info(
            "Skipping certificate ownership fix "
            "(not a native Linux Docker engine)."
        )
        return None

    uid = os.getuid()
    gid = os.getgid()
    log.info("Repairing certificate ownership via container (uid=%d gid=%d)...", uid, gid)
    try:
        perm_result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--entrypoint", "chown",
                "-v", f"{certs_dir}:/certificates",
                _CERT_GENERATOR_IMAGE,
                "-R", f"{uid}:{gid}", "/certificates",
            ],
            capture_output=True,
            text=True,
            cwd=project_dir,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        log.error("Ownership repair timed out after 60s")
        return CertResult(
            success=False,
            generated=True,
            certs_dir=certs_dir,
            error="Certificate ownership repair timed out after 60s",
        )
    except (FileNotFoundError, OSError) as exc:
        log.error("Failed to repair certificate ownership: %s", exc)
        return CertResult(
            success=False,
            generated=True,
            certs_dir=certs_dir,
            error=str(exc),
        )

    if perm_result.returncode != 0:
        error_msg = perm_result.stderr.strip() or "Certificate ownership repair failed"
        log.error("Failed to repair certificate ownership: %s", error_msg)
        return CertResult(
            success=False,
            generated=True,
            certs_dir=certs_dir,
            error=error_msg,
        )

    return None
