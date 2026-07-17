"""SSL certificate generation for Wazuh Indexer."""

import hashlib
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from aptl.core import hostenv
from aptl.utils.logging import get_logger

log = get_logger("certs")

_CERTS_SUBDIR = "config/wazuh_indexer_ssl_certs"
_CERT_COMPOSE_FILE = "generate-indexer-certs.yml"
_ROOT_CA = "root-ca.pem"
_MANAGER_ROOT_CA = "root-ca-manager.pem"
_CERT_CLEANUP_TIMEOUT = 60


@dataclass
class CertResult:
    """Result of SSL certificate generation."""

    success: bool
    generated: bool
    certs_dir: Path = Path()
    error: str = ""


CommandRunner = Callable[..., subprocess.CompletedProcess]


def ensure_ssl_certs(
    project_dir: Path,
    *,
    run_command: CommandRunner | None = None,
) -> CertResult:
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
        _ensure_container_readable_certs(certs_dir)
        log.info("SSL certificates already exist at %s", certs_dir)
        return CertResult(
            success=True,
            generated=False,
            certs_dir=certs_dir,
        )

    return _generate_ssl_certs(project_dir, certs_dir, run_command)


def _generate_ssl_certs(
    project_dir: Path,
    certs_dir: Path,
    run_command: CommandRunner | None,
) -> CertResult:
    """Run certificate generation and convert the generator outcome."""
    log.info("Generating SSL certificates...")
    error = _run_cert_generator(project_dir, certs_dir, run_command)
    result = error
    if result is None:
        repair_error = _repair_native_linux_cert_ownership(certs_dir, run_command)
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
        _ensure_container_readable_certs(certs_dir)
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


def _ensure_container_readable_certs(certs_dir: Path) -> None:
    """Make generated cert files readable through non-root bind mounts.

    The upstream generator emits owner-only PEM files. Wazuh Indexer and Wazuh
    Dashboard run as non-root uid 1000 inside the container, which may not match
    the host uid that ran ``aptl lab start``. Keep the host-side directory
    private while widening the mounted files so the container processes can read
    them.
    """
    try:
        certs_dir.chmod(0o700)
    except OSError as exc:
        log.warning(
            "Could not make generated cert directory private (%s): %s", certs_dir, exc
        )
    for path in certs_dir.iterdir():
        if not path.is_file():
            continue
        try:
            path.chmod(0o644)
        except OSError as exc:
            log.warning("Could not make generated cert readable (%s): %s", path, exc)


def _run_cert_generator(
    project_dir: Path,
    certs_dir: Path,
    run_command: CommandRunner | None,
) -> CertResult | None:
    """Run the compose cert generator, returning a failure result when needed."""
    error_msg = None
    try:
        result = _execute_command(
            _cert_generator_command(project_dir, certs_dir),
            run_command=run_command,
            project_dir=project_dir,
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
            error_msg = _command_failure_detail(result)
            log.error("Certificate generation failed: %s", error_msg)

    cleanup_error = _cleanup_cert_generator(project_dir, run_command)
    if cleanup_error is not None:
        log.error("Certificate generator cleanup failed: %s", cleanup_error)
        if error_msg is None:
            error_msg = f"Certificate generator cleanup failed: {cleanup_error}"
        else:
            error_msg = f"{error_msg}; cleanup failed: {cleanup_error}"

    failure = None
    if error_msg is not None:
        failure = CertResult(
            success=False,
            generated=False,
            certs_dir=certs_dir,
            error=error_msg,
        )
    return failure


def _cert_generator_command(project_dir: Path, certs_dir: Path) -> list[str]:
    """Build the isolated Docker Compose command for the cert generator."""
    if _native_linux_user() is not None:
        certs_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "docker",
        "compose",
        "-p",
        _cert_generator_project_name(project_dir),
        "-f",
        _CERT_COMPOSE_FILE,
        "run",
        "--rm",
    ]
    command.append("generator")
    return command


def _cert_generator_project_name(project_dir: Path) -> str:
    """Return a stable project-scoped name for temporary generator resources."""

    digest = hashlib.sha256(str(project_dir.resolve()).encode("utf-8")).hexdigest()[:12]
    return f"aptl-certs-{digest}"


def _cleanup_cert_generator(
    project_dir: Path,
    run_command: CommandRunner | None,
) -> str | None:
    """Remove the generator's temporary container and overlapping bridge.

    ``docker compose run --rm`` removes the container but leaves its default
    network behind. Docker commonly assigns that bridge ``172.20.0.0/16``,
    which overlaps every TechVault network and blocks the SDL realization that
    immediately follows certificate generation on a fresh install.
    """

    command = [
        "docker",
        "compose",
        "-p",
        _cert_generator_project_name(project_dir),
        "-f",
        _CERT_COMPOSE_FILE,
        "down",
        "--remove-orphans",
    ]
    error: str | None = None
    try:
        result = _execute_command(
            command,
            run_command=run_command,
            project_dir=project_dir,
            timeout=_CERT_CLEANUP_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        error = f"timed out after {_CERT_CLEANUP_TIMEOUT}s"
    except OSError as exc:
        error = str(exc)
    else:
        if result.returncode != 0:
            error = _command_failure_detail(result)
    return error


def _command_failure_detail(result: subprocess.CompletedProcess) -> str:
    """Return bounded useful output from a failed Docker command."""

    detail = "\n".join(
        part.strip()
        for part in (result.stdout or "", result.stderr or "")
        if part.strip()
    )
    return detail or "Certificate generation failed"


def _repair_native_linux_cert_ownership(
    certs_dir: Path,
    run_command: CommandRunner | None,
) -> str | None:
    """Repair root-owned generator output on native Linux Docker.

    The upstream Wazuh cert generator image must run as root because its
    entrypoint is not executable by an arbitrary host uid. Native Linux Docker
    then leaves bind-mounted output root-owned. Use Docker itself, not host
    sudo, to chown the generated files back to the invoking user.
    """
    user = _native_linux_user()
    if user is None:
        return None

    try:
        result = _execute_command(
            _cert_ownership_repair_command(certs_dir, user),
            run_command=run_command,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return "Certificate permission repair timed out after 120s"
    except OSError as exc:
        return f"Certificate permission repair failed: {exc}"
    if result.returncode == 0:
        return None

    detail = result.stderr.strip() or result.stdout.strip()
    if not detail:
        detail = "permission repair container failed"
    return f"Certificate permission repair failed: {detail}"


def _execute_command(
    command: list[str],
    *,
    run_command: CommandRunner | None,
    timeout: int,
    project_dir: Path | None = None,
) -> subprocess.CompletedProcess:
    """Run through the deployment backend when supplied, else locally."""

    if run_command is not None:
        return run_command(command, timeout=timeout)
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=project_dir,
        timeout=timeout,
    )


def _cert_ownership_repair_command(certs_dir: Path, user: tuple[int, int]) -> list[str]:
    """Build the Docker command that restores native-Linux host ownership."""
    uid, gid = user
    script = (
        f"chown -R {uid}:{gid} /certificates && "
        "find /certificates -type d -exec chmod 700 {} + && "
        "find /certificates -type f -exec chmod 644 {} +"
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
