"""Container-interaction slice of the deployment backend Protocol (CLI-004).

Split out of :mod:`aptl.core.deployment.backend` so the full
``DeploymentBackend`` interface stays within one file's size budget while
remaining a single structural type: ``DeploymentBackend`` inherits this
Protocol, so an implementation still satisfies one interface and callers still
see one type.

These are the per-container operations (list, logs, shell, exec, inspect,
listeners, existence, restart) that let local and SSH backends present a uniform
surface, so the same CLI commands and core helpers work whether the daemon is
local or remote.
"""

import subprocess
from typing import Any, Protocol

from aptl.core.deployment._proc_net_listeners import ContainerListeners


class ContainerOpsBackend(Protocol):
    """Per-container operations a deployment backend exposes."""

    def container_list(self, *, all_containers: bool = True) -> list[dict[str, Any]]:
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

    def container_shell(self, name: str, *, shell: str | None = None) -> int:
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

    def container_inspect(self, name: str) -> dict[str, Any]:
        """Return parsed ``docker inspect`` output for a single container.

        Args:
            name: Container name.

        Returns:
            The first element of the ``docker inspect`` JSON array, or
            an empty dict on any failure (missing container, parse
            error, etc.).
        """
        ...

    def observe_container_listeners(self, name: str) -> ContainerListeners | None:
        """Return a container's listeners read from outside its trust boundary.

        The trusted half of service-listener readback (issue #876): the kernel's
        per-netns socket tables, observed by a mechanism that executes no
        container-provided binary, so a workload cannot under-report its bind
        scope. Returns ``None`` when the listeners cannot be read, which the
        observer treats as a refused disclosure rather than an assumed match.
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

    def container_restart(self, name: str, *, timeout: int | None = None) -> None:
        """Restart a running container (docker restart <name>).

        Used by the wazuh-manager watchdog (#732) between compose retry
        attempts on hosts (Colima on macOS is the reproducible case) where
        s6-supervise gets stuck reporting EACCES on executable service
        `run` scripts and no wazuh daemon ever spawns — a docker-level
        restart clears the state.
        """
        ...
