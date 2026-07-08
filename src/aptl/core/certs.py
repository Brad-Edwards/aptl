"""SSL certificate generation for Wazuh Indexer."""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aptl.core import hostenv
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

    If the certificates directory already exists, this is a no-op. Otherwise,
    runs the docker compose cert generator. On native Linux Docker, the
    generator runs as the invoking host user so bind-mounted certificates are
    user-owned from creation. Docker Desktop does not need that override because
    its file-sharing layer maps ownership back to the host user.

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

    return _generate_ssl_certs(project_dir, certs_dir)


def _generate_ssl_certs(project_dir: Path, certs_dir: Path) -> CertResult:
    log.info("Generating SSL certificates...")
    error = _run_cert_generator(project_dir, certs_dir)
    result = error
    if result is None:
        log.info("SSL certificates generated successfully at %s", certs_dir)
        result = CertResult(success=True, generated=True, certs_dir=certs_dir)
    return result


def _run_cert_generator(project_dir: Path, certs_dir: Path) -> CertResult | None:
    error_msg = None
    try:
        result = subprocess.run(
            _cert_generator_command(certs_dir),
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
        error_msg = "Certificate generation timed out after 300s"
    except OSError as exc:
        log.error("Failed to run docker compose: %s", exc)
        error_msg = str(exc)
    else:
        if result.returncode != 0:
            error_msg = result.stderr.strip() or "Certificate generation failed"
            log.error("Certificate generation failed: %s", error_msg)

    failure = None
    if error_msg is not None:
        failure = CertResult(
            success=False,
            generated=False,
            certs_dir=certs_dir,
            error=error_msg,
        )
    return failure


def _cert_generator_command(certs_dir: Path) -> list[str]:
    command = [
        "docker", "compose",
        "-f", _CERT_COMPOSE_FILE,
        "run", "--rm",
    ]
    user = _native_linux_user()
    if user is not None:
        certs_dir.mkdir(parents=True, exist_ok=True)
        command += ["--user", user]
    command.append("generator")
    return command


def _native_linux_user() -> str | None:
    user = None
    if hostenv.needs_host_ownership_fix():
        user = f"{os.getuid()}:{os.getgid()}"
    return user
