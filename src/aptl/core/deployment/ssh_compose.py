"""SSH Remote Docker Compose deployment backend.

Runs Docker Compose commands on a remote host over SSH by setting the
DOCKER_HOST environment variable to ``ssh://user@host``. This enables
deploying the lab to a dedicated server, classroom environment, or
cloud VM without changing scenario definitions or MCP configs.
"""

import os
import re
import subprocess
from pathlib import Path

from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.utils.logging import get_logger

log = get_logger("deployment.ssh_compose")

# Validation patterns for SSH parameters.
_HOST_RE = re.compile(r"^[\w.\-]+$|^\[[\w:]+\]$")
_USER_RE = re.compile(r"^[\w\-]+$")


class SSHComposeBackend(DockerComposeBackend):
    """SSH Remote Docker Compose deployment backend.

    Extends DockerComposeBackend to run all Docker commands against a
    remote Docker daemon over SSH.  Uses ``DOCKER_HOST=ssh://user@host``
    so that the local ``docker compose`` CLI transparently forwards
    commands to the remote host.

    The remote host must have:
    - Docker Engine installed and running
    - SSH access for the configured user
    - The project files available at ``remote_dir``
    """

    def __init__(
        self,
        project_dir: Path,
        host: str,
        user: str,
        *,
        ssh_key: str | None = None,
        ssh_port: int = 22,
        remote_dir: str | None = None,
        project_name: str = "aptl",
    ) -> None:
        # Validate parameters before constructing SSH URI.
        if not isinstance(ssh_port, int) or not (1 <= ssh_port <= 65535):
            raise ValueError(f"ssh_port must be int in 1-65535, got {ssh_port!r}")
        if not _USER_RE.match(user):
            raise ValueError(f"Invalid SSH user: {user!r}")
        if not _HOST_RE.match(host):
            raise ValueError(f"Invalid SSH host: {host!r}")
        if ssh_key is not None:
            key_path = Path(ssh_key)
            if not key_path.is_absolute():
                raise ValueError(
                    f"ssh_key must be an absolute path, got {ssh_key!r}"
                )
            if ".." in key_path.parts:
                raise ValueError(
                    f"ssh_key must not contain '..', got {ssh_key!r}"
                )

        super().__init__(project_dir=project_dir, project_name=project_name)
        self._host = host
        self._user = user
        self._ssh_key = ssh_key
        self._ssh_port = ssh_port
        self._remote_dir = remote_dir or str(project_dir)
        self._docker_host = f"ssh://{user}@{host}"
        if ssh_port != 22:
            self._docker_host = f"ssh://{user}@{host}:{ssh_port}"

    @property
    def host(self) -> str:
        return self._host

    @property
    def user(self) -> str:
        return self._user

    @property
    def docker_host(self) -> str:
        return self._docker_host

    def _run(
        self,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a command with DOCKER_HOST pointing to the remote daemon.

        Overrides the parent _run to inject the SSH-based DOCKER_HOST
        environment variable, causing all Docker CLI commands to execute
        against the remote host.

        Args:
            cmd: Command as a list of strings.
            timeout: Optional timeout in seconds.

        Returns:
            CompletedProcess result.
        """
        env = os.environ.copy()
        env["DOCKER_HOST"] = self._docker_host

        if self._ssh_key:
            # SSH_AUTH_SOCK won't help with a specific key file;
            # configure via ssh config or GIT_SSH_COMMAND-style env.
            # Docker's SSH transport respects the standard SSH config,
            # so users should add a Host entry.  We also set
            # DOCKER_SSH_IDENTITY for Docker's built-in SSH support.
            env["DOCKER_SSH_IDENTITY"] = self._ssh_key

        kwargs: dict = {
            "capture_output": True,
            "text": True,
            "env": env,
            # Use remote_dir as cwd context for compose file discovery.
            # Docker Compose with DOCKER_HOST=ssh:// sends the project
            # context; the local cwd determines which compose file is read.
            "cwd": self._project_dir,
        }
        if timeout is not None:
            kwargs["timeout"] = timeout

        log.debug(
            "Running via DOCKER_HOST=%s: %s",
            self._docker_host,
            " ".join(cmd),
        )
        return subprocess.run(cmd, **kwargs)

    def _run_streaming(
        self,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> int:
        """Streaming variant of ``_run`` with the same env injection.

        Inherits parent stdin/stdout/stderr (no capture) so the user can
        interact with a remote shell or watch logs live; sets
        ``DOCKER_HOST`` and optionally ``DOCKER_SSH_IDENTITY`` exactly as
        the captured ``_run`` override does.
        """
        env = os.environ.copy()
        env["DOCKER_HOST"] = self._docker_host
        if self._ssh_key:
            env["DOCKER_SSH_IDENTITY"] = self._ssh_key
        kwargs: dict = {
            "cwd": self._project_dir,
            "env": env,
            "check": False,
        }
        if timeout is not None:
            kwargs["timeout"] = timeout
        log.debug(
            "Streaming via DOCKER_HOST=%s: %s",
            self._docker_host,
            " ".join(cmd),
        )
        return subprocess.run(cmd, **kwargs).returncode

    def validate_connection(self) -> tuple[bool, str]:
        """Test SSH connectivity to the remote Docker daemon.

        Returns:
            Tuple of (success, error_message).
        """
        try:
            result = self._run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                timeout=30,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                log.info(
                    "Connected to remote Docker %s at %s",
                    version,
                    self._docker_host,
                )
                return True, ""
            return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, f"SSH connection to {self._docker_host} timed out"
        except (FileNotFoundError, OSError) as exc:
            return False, f"Failed to connect to {self._docker_host}: {exc}"
