"""Deployment backend protocol.

Defines the abstract interface for lab deployment backends. Each backend
implements lifecycle operations (start, stop, status, kill, pull) and
container interaction (list, logs, shell, exec, inspect) for a specific
deployment target (Docker Compose, SSH remote, Kubernetes, etc.).

Container interaction methods were added under CLI-004 (see ADR-023);
this lets local and SSH backends present a uniform surface so the same
CLI commands and core helpers (snapshot, flags, collectors) work without
caring whether the daemon is local or remote.

Follows the same Protocol pattern as RunStorageBackend in runstore.py.
"""

import subprocess
from typing import Protocol

from aptl.core.lab import LabResult, LabStatus


class DeploymentBackend(Protocol):
    """Protocol for lab deployment backends.

    Backends manage the deployment lifecycle (start, stop, status, kill,
    pull) and container interaction (list, logs, shell, exec, inspect).
    """

    def start(self, profiles: list[str], *, build: bool = True) -> LabResult:
        """Start lab services for the given profiles.

        Args:
            profiles: List of profile names to activate.
            build: If True, rebuild images before starting.

        Returns:
            LabResult indicating success or failure.
        """
        ...

    def stop(
        self, profiles: list[str], *, remove_volumes: bool = False
    ) -> LabResult:
        """Stop lab services.

        Args:
            profiles: List of profile names to include in the stop.
            remove_volumes: If True, also remove persistent volumes.

        Returns:
            LabResult indicating success or failure.
        """
        ...

    def status(self) -> LabStatus:
        """Query the current deployment status.

        Returns:
            LabStatus with container information.
        """
        ...

    def kill(self, profiles: list[str]) -> tuple[bool, str]:
        """Emergency-stop all lab containers.

        Sends immediate kill signal, then cleans up.

        Args:
            profiles: List of profile names to include.

        Returns:
            Tuple of (success, error_message).
        """
        ...

    def pull_images(self, images: list[str]) -> list[str]:
        """Pre-pull container images.

        Args:
            images: List of image references to pull.

        Returns:
            List of warning messages for images that failed to pull
            (non-fatal).
        """
        ...

    # Container interaction (CLI-004) -------------------------------------

    def container_list(
        self, *, all_containers: bool = True
    ) -> list[dict]:
        """List containers managed by this deployment.

        Args:
            all_containers: If True (default), include stopped containers.

        Returns:
            List of container metadata dicts as returned by
            ``docker compose ps --format json``. Empty on failure.
        """
        ...

    def container_logs(
        self,
        name: str,
        *,
        follow: bool = False,
        tail: int | None = None,
    ) -> int:
        """Stream a container's logs to the parent stdout/stderr.

        Args:
            name: Container name (as shown by container_list).
            follow: If True, follow log output (-f).
            tail: If set, show only the last N lines (--tail).

        Returns:
            The ``docker logs`` exit code.
        """
        ...

    def container_logs_capture(
        self,
        name: str,
        *,
        since: str | None = None,
        until: str | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        """Capture a container's logs (for programmatic consumption).

        Args:
            name: Container name.
            since: Optional RFC3339 timestamp; only logs >= this point.
            until: Optional RFC3339 timestamp; only logs <= this point.
            timeout: Optional timeout in seconds. Set this for
                archive collection so a stalled docker daemon doesn't
                hang the run forever.

        Returns:
            CompletedProcess with captured stdout/stderr.
        """
        ...

    def container_shell(
        self, name: str, *, shell: str | None = None
    ) -> int:
        """Open an interactive shell inside a running container.

        Inherits the parent terminal's stdin/stdout/stderr so the user
        gets a real TTY. When ``shell`` is None, tries ``/bin/bash``
        first and falls back to ``/bin/sh`` if bash is unavailable
        (exit code 126 or 127). An explicit ``shell`` skips the fallback.

        Args:
            name: Container name.
            shell: Optional explicit shell path. If None, auto-detect.

        Returns:
            The shell's exit code.
        """
        ...

    def container_exec(
        self,
        name: str,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a one-shot non-interactive command inside a container.

        Args:
            name: Container name.
            cmd: Command and arguments to execute.
            timeout: Optional timeout in seconds.

        Returns:
            CompletedProcess with captured stdout/stderr.
        """
        ...

    def container_inspect(self, name: str) -> dict:
        """Return parsed ``docker inspect`` output for a single container.

        Args:
            name: Container name.

        Returns:
            The first element of the ``docker inspect`` JSON array, or
            an empty dict on any failure (missing container, parse
            error, etc.).
        """
        ...

    def host_run(
        self,
        args: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        """Run an arbitrary host-level command (typically `docker …` /
        `docker compose …`) against the backend's Docker daemon.

        Used by callers that need docker capabilities not covered by the
        typed container-interaction methods — for example the snapshot
        module's `docker version`, `docker compose version`, `docker ps
        -a --filter`, and `docker network ls/inspect` calls. SSH backends
        route this through the same `DOCKER_HOST=ssh://…` environment as
        the rest of the Protocol so a snapshot taken against a remote
        lab actually inspects the remote daemon.

        Args:
            args: argv list to execute (e.g. `["docker", "version", …]`).
            timeout: optional timeout in seconds.

        Returns:
            The captured CompletedProcess.
        """
        ...
