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

from aptl.core.deployment.errors import BackendTimeoutError  # noqa: F401  (re-export)
from aptl.core.lab_types import LabResult, LabStatus

# Imported from ``aptl.core.lab_types`` (the leaf module) rather than
# ``aptl.core.lab``. Pre-#266 the import landed on lab.py directly,
# which created a load-order cycle (lab.py -> snapshot ->
# deployment.__init__ -> backend.py -> lab.py-mid-load) when lab.py
# was the first module loaded fresh. The leaf module has no back-edges,
# so the import is safe at runtime — keeping the names resolvable for
# ``typing.get_type_hints(DeploymentBackend.start)`` and other runtime
# introspection.


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

    def container_exists(self, name: str) -> bool:
        """Return True if the container belongs to this project.

        Cheap membership check that avoids enumerating every container
        on the daemon. Used by CLI commands (``logs``/``shell``) before
        executing into a user-supplied container name. Implementation
        detail: backends typically use ``docker inspect <name>`` plus a
        compose-project label check.
        """
        ...

    # Host inventory (CLI-004 / ADR-023) ----------------------------------
    #
    # These return parsed host-level information instead of exposing a
    # generic argv passthrough. Future non-Docker backends implement
    # them in their own terms; today both backends back them with the
    # docker CLI but the Protocol stays Docker-shape-agnostic.

    def host_versions(self) -> dict[str, str]:
        """Return parsed daemon-side software versions.

        Returns:
            Dict with keys ``docker`` and ``compose``. Each value is the
            version string as reported by the daemon, or empty string
            on probe failure (missing binary, daemon down, etc.).
        """
        ...

    def host_list_lab_containers(self) -> list[dict]:
        """Enumerate ``aptl-*`` containers visible to the daemon.

        Each row carries ``name``, ``image``, ``id``, ``status``,
        ``labels`` (dict), and ``ports`` (list of port-mapping strings).
        Catches containers outside the current compose project that
        nevertheless follow the lab's naming convention.
        """
        ...

    def host_list_lab_networks(self, name_prefix: str) -> list[str]:
        """List network names whose names start with ``name_prefix``."""
        ...

    def host_inspect_network(self, name: str) -> dict:
        """Return parsed network metadata.

        Returns:
            Dict with keys ``name``, ``subnet``, ``gateway``,
            ``containers`` (sorted list of attached container names).
            Empty dict on any failure.
        """
        ...
