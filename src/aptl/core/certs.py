"""SSL certificate generation for Wazuh Indexer.

Runs the docker compose cert generator if certificates do not already
exist, then fixes file permissions for container consumption.
"""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aptl.utils.logging import get_logger

log = get_logger("certs")

_CERTS_SUBDIR = "config/wazuh_indexer_ssl_certs"
_CERT_COMPOSE_FILE = "generate-indexer-certs.yml"


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

    if certs_dir.exists():
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

    log.info("Fixing certificate permissions...")

    # Fix ownership: chown -R $(id -u):$(id -g)
    uid = os.getuid()
    gid = os.getgid()
    try:
        perm_result = subprocess.run(
            ["sudo", "chown", "-R", f"{uid}:{gid}", str(certs_dir)],
            capture_output=True,
            text=True,
            cwd=project_dir,
        )
    except (FileNotFoundError, OSError) as exc:
        log.error("Failed to fix certificate permissions: %s", exc)
        return CertResult(
            success=False,
            generated=True,
            certs_dir=certs_dir,
            error=str(exc),
        )

    if perm_result.returncode != 0:
        error_msg = perm_result.stderr.strip() or "Permission fix failed"
        log.error("Failed to fix permissions: %s", error_msg)
        return CertResult(
            success=False,
            generated=True,
            certs_dir=certs_dir,
            error=error_msg,
        )

    log.info("SSL certificates generated successfully at %s", certs_dir)
    return CertResult(
        success=True,
        generated=True,
        certs_dir=certs_dir,
    )
