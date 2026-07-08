"""SSL certificate generation for Wazuh Indexer."""

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aptl.core import hostenv
from aptl.utils.logging import get_logger

log = get_logger("certs")

_CERTS_SUBDIR = "config/wazuh_indexer_ssl_certs"
_CERT_COMPOSE_FILE = "generate-indexer-certs.yml"
_ROOT_CA = "root-ca.pem"
_MANAGER_ROOT_CA = "root-ca-manager.pem"


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
    runs the docker compose cert generator. On native Linux Docker, generated
    certificates are repaired back to the invoking host user after generation.
    Docker Desktop does not need that repair because its file-sharing layer maps
    ownership back to the host user.

    Args:
        project_dir: Root directory of the APTL project (where
                     docker-compose.yml lives).

    Returns:
        CertResult indicating success, whether certs were generated,
        and the path to the certs directory.
    """
    certs_dir = project_dir / _CERTS_SUBDIR
    root_ca = certs_dir / _ROOT_CA

    if certs_dir.exists() and root_ca.exists():
        alias_error = _ensure_manager_root_ca_alias(certs_dir)
        if alias_error is not None:
            return CertResult(
                success=False,
                generated=False,
                certs_dir=certs_dir,
                error=alias_error,
            )
        _ensure_user_writable_certs(certs_dir)
        log.info("SSL certificates already exist at %s", certs_dir)
        return CertResult(
            success=True,
            generated=False,
            certs_dir=certs_dir,
        )

    return _generate_ssl_certs(project_dir, certs_dir)


def _generate_ssl_certs(project_dir: Path, certs_dir: Path) -> CertResult:
    """Run certificate generation and convert the generator outcome."""
    log.info("Generating SSL certificates...")
    error = _run_cert_generator(project_dir, certs_dir)
    result = error
    if result is None:
        repair_error = _repair_native_linux_cert_ownership(certs_dir)
        if repair_error is not None:
            return CertResult(
                success=False,
                generated=False,
                certs_dir=certs_dir,
                error=repair_error,
            )
        alias_error = _ensure_manager_root_ca_alias(certs_dir)
        if alias_error is not None:
            return CertResult(
                success=False,
                generated=False,
                certs_dir=certs_dir,
                error=alias_error,
            )
        _ensure_user_writable_certs(certs_dir)
        log.info("SSL certificates generated successfully at %s", certs_dir)
        result = CertResult(success=True, generated=True, certs_dir=certs_dir)
    return result


def _ensure_manager_root_ca_alias(certs_dir: Path) -> str | None:
    """Ensure the Wazuh manager CA mount source exists.

    The upstream Wazuh cert generator emits ``root-ca.pem``. The manager
    service mounts the same CA as ``root-ca-manager.pem`` so Filebeat can read
    it at ``/etc/ssl/root-ca.pem`` without sharing the indexer path contract.
    """
    source = certs_dir / _ROOT_CA
    target = certs_dir / _MANAGER_ROOT_CA
    error = None
    if not target.exists():
        if not source.exists():
            error = f"Missing generated CA certificate: {source}"
        else:
            try:
                certs_dir.chmod(certs_dir.stat().st_mode | 0o700)
                shutil.copyfile(source, target)
            except OSError as exc:
                error = f"Failed to prepare manager root CA certificate: {exc}"
    return error


def _ensure_user_writable_certs(certs_dir: Path) -> None:
    """Make generated cert files removable by the invoking host user.

    The upstream generator emits read-only PEM files. On some Docker VM file
    sharing layers, notably macOS-backed mounts, that can prevent ordinary
    cleanup even when the files map back to the host user. This is a
    best-effort host-side chmod and never escalates privileges.
    """
    try:
        certs_dir.chmod(certs_dir.stat().st_mode | 0o700)
    except OSError as exc:
        log.warning(
            "Could not make generated cert directory writable (%s): %s", certs_dir, exc
        )
    for path in certs_dir.iterdir():
        if not path.is_file():
            continue
        try:
            path.chmod(path.stat().st_mode | 0o600)
        except OSError as exc:
            log.warning("Could not make generated cert writable (%s): %s", path, exc)


def _run_cert_generator(project_dir: Path, certs_dir: Path) -> CertResult | None:
    """Run the compose cert generator, returning a failure result when needed."""
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
        log.exception("Failed to run docker compose")
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
    """Build the Docker Compose command for the certificate generator."""
    if _native_linux_user() is not None:
        certs_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "docker",
        "compose",
        "-f",
        _CERT_COMPOSE_FILE,
        "run",
        "--rm",
    ]
    command.append("generator")
    return command


def _repair_native_linux_cert_ownership(certs_dir: Path) -> str | None:
    """Repair root-owned generator output on native Linux Docker.

    The upstream Wazuh cert generator image must run as root because its
    entrypoint is not executable by an arbitrary host uid. Native Linux Docker
    then leaves bind-mounted output root-owned. Use Docker itself, not host
    sudo, to chown the generated files back to the invoking user.
    """
    user = _native_linux_user()
    if user is None:
        return None

    result = subprocess.run(
        _cert_ownership_repair_command(certs_dir, user),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode == 0:
        return None

    detail = result.stderr.strip() or result.stdout.strip()
    if not detail:
        detail = "permission repair container failed"
    return f"Certificate permission repair failed: {detail}"


def _cert_ownership_repair_command(certs_dir: Path, user: tuple[int, int]) -> list[str]:
    """Build the Docker command that restores native-Linux host ownership."""
    uid, gid = user
    script = (
        f"chown -R {uid}:{gid} /certificates && "
        "find /certificates -type d -exec chmod u+rwx {} + && "
        "find /certificates -type f -exec chmod u+rw {} +"
    )
    return [
        "docker",
        "run",
        "--rm",
        "--entrypoint",
        "/bin/sh",
        "-v",
        f"{certs_dir.resolve()}:/certificates",
        "wazuh/wazuh-certs-generator:0.0.2",
        "-c",
        script,
    ]


def _native_linux_user() -> tuple[int, int] | None:
    """Return the host uid/gid that native Linux Docker output should use."""
    user = None
    if hostenv.needs_host_ownership_fix():
        user = (os.getuid(), os.getgid())
    return user
