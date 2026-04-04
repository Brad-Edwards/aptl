"""Deployment backend protocol.

Defines the abstract interface for lab deployment backends. Each backend
implements lifecycle operations (start, stop, status, kill, pull) for a
specific deployment target (Docker Compose, SSH remote, Kubernetes, etc.).

Follows the same Protocol pattern as RunStorageBackend in runstore.py.
"""

from typing import Protocol

from aptl.core.lab import LabResult, LabStatus


class DeploymentBackend(Protocol):
    """Protocol for lab deployment backends.

    Backends manage the deployment lifecycle: starting and stopping
    containers, querying status, emergency kill, and image pulling.
    Container interaction (exec, logs, inspect) is a separate concern.
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
