"""Fail-closed local Docker endpoint binding and revalidation."""

from __future__ import annotations

import os
import stat

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.lab_types import LabResult

_DOCKER_CONTROL_TIMEOUT = 30
_DOCKER_SOCKET_PATH = "/var/run/docker.sock"
_DOCKER_SOCKET_HOST = "unix:///var/run/docker.sock"
_DOCKER_ENDPOINT_UNAVAILABLE = "Docker control endpoint unavailable."
_DOCKER_ENDPOINT_CHANGED = "Docker control endpoint identity changed."


def _local_docker_socket_identity() -> tuple[int, int] | None:
    """Return an accessible non-symlink socket identity, or ``None``."""

    try:
        info = os.lstat(_DOCKER_SOCKET_PATH)
    except OSError:
        return None
    if not stat.S_ISSOCK(info.st_mode) or not os.access(
        _DOCKER_SOCKET_PATH,
        os.R_OK | os.W_OK,
    ):
        return None
    return int(info.st_dev), int(info.st_ino)


class DockerEndpointBindingMixin:
    """Pin Docker commands to one accessible local socket and daemon."""

    def bind_local_docker_socket(self) -> LabResult:
        """Bind all subsequent Docker commands to the exact local socket."""

        self._docker_socket_identity = None
        self._docker_daemon_id = None
        self._docker_host_override = None
        failure = self._local_authority_failure()
        identity = None
        if failure is None:
            identity, failure = self._binding_socket_identity()
        daemon_id = None
        if failure is None and identity is not None:
            daemon_id, failure = self._binding_daemon_identity(
                expected_socket=identity,
            )
        if failure is not None:
            self._docker_host_override = None
        else:
            self._docker_socket_identity = identity
            self._docker_daemon_id = daemon_id
        return failure or LabResult(success=True)

    def _local_authority_failure(self) -> LabResult | None:
        """Reject local socket authority on a backend without local artifacts."""

        if self.supports_local_artifacts:
            return None
        return LabResult(
            success=False,
            error="Docker control authority requires the local Docker daemon.",
        )

    @staticmethod
    def _binding_socket_identity() -> tuple[tuple[int, int] | None, LabResult | None]:
        """Return the accessible socket identity or an unavailable diagnostic."""

        identity = _local_docker_socket_identity()
        failure = (
            None
            if identity is not None
            else LabResult(success=False, error=_DOCKER_ENDPOINT_UNAVAILABLE)
        )
        return identity, failure

    def _binding_daemon_identity(
        self,
        *,
        expected_socket: tuple[int, int],
    ) -> tuple[str | None, LabResult | None]:
        """Bind the override and attest the daemon without a socket swap."""

        self._docker_host_override = _DOCKER_SOCKET_HOST
        daemon_id = self._current_docker_daemon_id()
        failure = None
        if daemon_id is None:
            failure = LabResult(success=False, error=_DOCKER_ENDPOINT_UNAVAILABLE)
        elif _local_docker_socket_identity() != expected_socket:
            failure = LabResult(success=False, error=_DOCKER_ENDPOINT_CHANGED)
        return daemon_id, failure

    def revalidate_local_docker_socket(self) -> LabResult:
        """Prove the socket and daemon identities have not changed."""

        failure: LabResult | None = None
        if self._docker_socket_identity is None or self._docker_daemon_id is None:
            failure = LabResult(
                success=False,
                error="Docker control endpoint is not bound.",
            )
        identity = None
        if failure is None:
            identity = _local_docker_socket_identity()
            if identity is None:
                failure = LabResult(
                    success=False,
                    error=_DOCKER_ENDPOINT_UNAVAILABLE,
                )
            elif identity != self._docker_socket_identity:
                failure = LabResult(
                    success=False,
                    error=_DOCKER_ENDPOINT_CHANGED,
                )
        if failure is None:
            daemon_id = self._current_docker_daemon_id()
            if (
                daemon_id != self._docker_daemon_id
                or _local_docker_socket_identity() != self._docker_socket_identity
            ):
                failure = LabResult(
                    success=False,
                    error=_DOCKER_ENDPOINT_CHANGED,
                )
        return failure or LabResult(success=True)

    def _current_docker_daemon_id(self) -> str | None:
        """Return the selected daemon identity within the fixed command timeout."""

        try:
            daemon = self._run(
                ["docker", "info", "--format", "{{.ID}}"],
                timeout=_DOCKER_CONTROL_TIMEOUT,
            )
        except BackendTimeoutError:
            daemon = None
        if daemon is None or daemon.returncode != 0 or not daemon.stdout.strip():
            return None
        return daemon.stdout.strip()
