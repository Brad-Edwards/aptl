"""SSH Remote Docker Compose deployment backend.

Runs Docker Compose commands on a remote host over SSH by setting the
DOCKER_HOST environment variable to ``ssh://user@host``. This enables
deploying the lab to a dedicated server, classroom environment, or
cloud VM without changing scenario definitions or MCP configs.
"""

import os
import re
from pathlib import Path

from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.runtime_materialization import (
    SHARED_DOCKER_PROFILE,
    RuntimeMaterializationProfile,
)
from aptl.core.lab_types import LabResult
from aptl.core.runtime_authority_policy import RuntimeAuthorityPolicy
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
        runtime_authority_policy: RuntimeAuthorityPolicy | None = None,
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
                raise ValueError(f"ssh_key must be an absolute path, got {ssh_key!r}")
            if ".." in key_path.parts:
                raise ValueError(f"ssh_key must not contain '..', got {ssh_key!r}")

        super().__init__(
            project_dir=project_dir,
            project_name=project_name,
            runtime_authority_policy=runtime_authority_policy,
        )
        self._host = host
        self._user = user
        self._ssh_key = ssh_key
        self._ssh_port = ssh_port
        self._remote_dir = remote_dir or str(project_dir)
        self._docker_host = f"ssh://{user}@{host}"
        if ssh_port != 22:
            self._docker_host = f"ssh://{user}@{host}:{ssh_port}"
        self._remote_target_qualified = False
        self._runtime_containment_evidence: dict[str, object] = {}

    @property
    def host(self) -> str:
        return self._host

    @property
    def user(self) -> str:
        return self._user

    @property
    def docker_host(self) -> str:
        return self._docker_host

    @property
    def supports_local_artifacts(self) -> bool:
        """Remote Docker cannot consume controller-local generated files."""

        return False

    def _runtime_materialization_profile(
        self, realization: object
    ) -> RuntimeMaterializationProfile:
        """Return the only containment envelope this provider has proved.

        SSH transport, daemon identity, and an empty Docker inventory do not
        establish a guest/hypervisor boundary.  Until an independently attested
        boundary provider supplies that evidence, this backend remains shared
        and high-authority SDL is reported as unsupported.
        """

        del realization
        return SHARED_DOCKER_PROFILE

    def _qualify_runtime_materialization_target(self) -> LabResult | None:
        """Qualify the configured remote daemon before any deployment mutation."""

        if self._runtime_authority_policy.target is None:
            return None
        result = self.bind_local_docker_socket()
        return None if result.success else result

    def bind_local_docker_socket(self) -> LabResult:
        """Bind and inspect the exact operator-selected remote Docker target.

        The inherited method intentionally supports only local sockets.  For the
        SSH provider, the operator-selected target is remote; support is claimed
        only when its immutable daemon identity matches policy and the native
        inventory contains no foreign workload, volume, or custom network.
        Those checks do not promote it to an isolated containment profile.
        """

        if self._remote_target_qualified:
            return self.revalidate_local_docker_socket()
        self._runtime_containment_evidence = {}
        target = self._runtime_authority_policy.target
        if (
            target is None
            or target.provider != "ssh-compose"
            or target.ssh_host != self._host
        ):
            return LabResult(
                success=False,
                error=(
                    "Runtime authority has no exact operator-selected isolated "
                    "Docker target."
                ),
            )
        daemon_id = self._current_docker_daemon_id()
        if daemon_id != target.daemon_id:
            return LabResult(
                success=False,
                error="Docker control endpoint identity changed.",
            )
        inventories = self._isolated_daemon_inventory()
        if inventories is None:
            return LabResult(
                success=False,
                error="Isolated Docker target inventory is unavailable.",
            )
        containers, volumes, networks = inventories
        if containers:
            return LabResult(
                success=False,
                error=(
                    "Isolated Docker target contains foreign containers; "
                    "refusing runtime authority."
                ),
            )
        if volumes:
            return LabResult(
                success=False,
                error=(
                    "Isolated Docker target contains foreign volumes; refusing "
                    "runtime authority."
                ),
            )
        foreign_networks = networks - {"bridge", "host", "none"}
        if foreign_networks:
            return LabResult(
                success=False,
                error=(
                    "Isolated Docker target contains foreign networks; refusing "
                    "runtime authority."
                ),
            )
        self._docker_daemon_id = daemon_id
        self._remote_target_qualified = True
        self._runtime_containment_evidence = {
            "daemon_id": daemon_id,
            "provider": "ssh-compose",
            "containment_profile": "shared-docker",
            "foreign_containers": 0,
            "foreign_volumes": 0,
            "foreign_networks": 0,
        }
        return LabResult(success=True)

    def revalidate_local_docker_socket(self) -> LabResult:
        """Re-attest the policy-bound remote daemon at mutation boundaries."""

        target = self._runtime_authority_policy.target
        daemon_id = self._current_docker_daemon_id()
        if (
            not self._remote_target_qualified
            or target is None
            or target.ssh_host != self._host
            or daemon_id != self._docker_daemon_id
            or daemon_id != target.daemon_id
        ):
            return LabResult(
                success=False,
                error="Docker control endpoint identity changed.",
            )
        return LabResult(success=True)

    def _isolated_daemon_inventory(
        self,
    ) -> tuple[set[str], set[str], set[str]] | None:
        """Return bounded native resource names used to prove an empty target."""

        commands = (
            ["docker", "ps", "-aq"],
            ["docker", "volume", "ls", "-q"],
            ["docker", "network", "ls", "--format", "{{.Name}}"],
        )
        values: list[set[str]] = []
        try:
            for command in commands:
                result = self._run(command, timeout=30)
                if result.returncode != 0:
                    return None
                values.append(
                    {
                        line.strip()
                        for line in result.stdout.splitlines()
                        if line.strip()
                    }
                )
        except (BackendTimeoutError, OSError):
            return None
        return values[0], values[1], values[2]

    def _subprocess_kwargs(
        self,
        *,
        streaming: bool,
        timeout: int | None,
    ) -> dict:
        """Inject ``DOCKER_HOST`` (and optional ``DOCKER_SSH_IDENTITY``)
        on top of the base backend's kwargs.

        Both captured and streaming runs go through the same env
        construction here; ``_run`` and ``_run_streaming`` are inherited
        from the base class (which calls ``self._subprocess_kwargs``).
        """
        kwargs = super()._subprocess_kwargs(streaming=streaming, timeout=timeout)
        env = os.environ.copy()
        env["DOCKER_HOST"] = self._docker_host
        if self._ssh_key:
            # SSH_AUTH_SOCK won't help with a specific key file;
            # configure via ssh config or GIT_SSH_COMMAND-style env.
            # Docker's SSH transport respects the standard SSH config,
            # so users should add a Host entry.  We also set
            # DOCKER_SSH_IDENTITY for Docker's built-in SSH support.
            env["DOCKER_SSH_IDENTITY"] = self._ssh_key
        kwargs["env"] = env
        return kwargs

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
        except BackendTimeoutError:
            return False, f"SSH connection to {self._docker_host} timed out"
        except OSError as exc:
            return False, f"Failed to connect to {self._docker_host}: {exc}"
