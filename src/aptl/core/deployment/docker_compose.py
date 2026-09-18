"""Local Docker Compose deployment backend.

Query, realization, and cleanup helpers live in focused sibling modules.
"""

import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
)
from aptl.core.config import validate_compose_project_name
from aptl.core.deployment._operator_access import ComposeOperatorAccessMixin
from aptl.core.deployment._compose_autoremove import ComposeAutoremoveMixin
from aptl.core.deployment._compose_base_substrate import ComposeBaseSubstrateMixin
from aptl.core.deployment._compose_boundary import DEFAULT_BOUNDARY_HELPER_IMAGE
from aptl.core.deployment._compose_owned_start import ComposeOwnedStartMixin
from aptl.core.deployment._compose_direct_network import ComposeDirectNetworkMixin
from aptl.core.deployment._compose_receipt_capture import ComposeReceiptCaptureMixin
from aptl.core.deployment._compose_resource_resolution import (
    ComposeResourceResolutionMixin,
)
from aptl.core.deployment._compose_image_fetch import ComposeImageFetchMixin
from aptl.core.deployment._compose_lifecycle import kill_compose_lab
from aptl.core.deployment._compose_project_cleanup import ComposeProjectCleanupMixin
from aptl.core.deployment._compose_project_inventory import (
    ComposeProjectInventoryMixin,
)
from aptl.core.deployment._compose_queries import ComposeQueryMixin
from aptl.core.deployment._compose_resource_ownership import (
    OwnershipConflictError,
    WorkspaceOwnership,
)
from aptl.core.deployment._compose_realization import ComposeRealizationMixin
from aptl.core.deployment._compose_runtime_inventory import (
    ComposeRuntimeInventoryMixin,
)
from aptl.core.deployment._compose_seed_attribution import (
    ComposeSeedAttributionMixin,
)
from aptl.core.deployment._compose_seed_execution import ComposeSeedExecutionMixin
from aptl.core.deployment._compose_stop import stop_compose_lab
from aptl.core.deployment._docker_endpoint_binding import DockerEndpointBindingMixin
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.lab_types import LabResult, LabStatus
from aptl.core.runtime_authority_policy import RuntimeAuthorityPolicy
from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")
_DOCKER_TIMEOUT = 30


class DockerComposeBackend(
    ComposeOwnedStartMixin,
    ComposeDirectNetworkMixin,
    ComposeReceiptCaptureMixin,
    ComposeResourceResolutionMixin,
    DockerEndpointBindingMixin,
    ComposeAutoremoveMixin,
    ComposeRuntimeInventoryMixin,
    ComposeProjectInventoryMixin,
    ComposeQueryMixin,
    ComposeRealizationMixin,
    ComposeSeedAttributionMixin,
    ComposeSeedExecutionMixin,
    ComposeBaseSubstrateMixin,
    ComposeOperatorAccessMixin,
    ComposeProjectCleanupMixin,
    ComposeImageFetchMixin,
):
    """Docker Compose deployment backend.

    Manages lab lifecycle via ``docker compose`` subprocess calls.
    All commands run against the docker-compose.yml in project_dir.
    Host/container query + inspect helpers are provided by
    ``ComposeProjectInventoryMixin`` and ``ComposeQueryMixin``.
    """

    def __init__(
        self,
        project_dir: Path,
        project_name: str = "aptl",
        *,
        offline_staged: bool = False,
        docker_socket_path: Path | None = None,
        runtime_authority_policy: RuntimeAuthorityPolicy | None = None,
    ) -> None:
        if docker_socket_path is not None and not docker_socket_path.is_absolute():
            raise ValueError("managed Docker socket must be absolute")
        self._configured_docker_socket_path = docker_socket_path
        self._project_dir = project_dir
        self._logical_project_name = validate_compose_project_name(project_name)
        self._project_name = self._logical_project_name
        self._resource_ownership: WorkspaceOwnership | None = None
        self._resource_attempt_id: str | None = None
        self._offline_staged = offline_staged
        self._runtime_authority_policy = (
            runtime_authority_policy or RuntimeAuthorityPolicy.empty()
        )
        self._runtime_authority_policy_configured = (
            runtime_authority_policy is not None
        )
        self._appliance_boundary: (
            tuple[
                ApplianceBoundaryPolicy,
                ApplianceBoundaryBinding,
            ]
            | None
        ) = None
        self._boundary_receipts: dict[str, dict[str, object]] = {}
        self._boundary_helper_image = DEFAULT_BOUNDARY_HELPER_IMAGE
        # ADR-088 phased startup (issue #889): safe portable readback evidence
        # from each proven service-search-index-schema materialization, keyed by
        # content-placement address. Consumed by realization observation to
        # disclose the concern only after real corroboration (SEM-218).
        self._service_index_materialization_evidence: dict[str, dict[str, object]] = {}
        self._docker_socket_identity: tuple[int, int] | None = None
        self._docker_daemon_id: str | None = None
        self._docker_host_override: str | None = None
        self._docker_socket_path: str | None = None
        self._docker_socket_host: str | None = None

    def configure_runtime_authority_policy(
        self,
        policy: RuntimeAuthorityPolicy,
    ) -> None:
        """Bind validated operator policy exactly once before admission."""

        if self._runtime_authority_policy_configured:
            raise ValueError("runtime authority policy is already configured")
        self._runtime_authority_policy = policy
        self._runtime_authority_policy_configured = True

    @property
    def project_dir(self) -> Path:
        return self._project_dir

    @property
    def project_name(self) -> str:
        return self._project_name

    @property
    def logical_project_name(self) -> str:
        """Return the user-facing project identity before provider scoping."""

        return self._logical_project_name

    @property
    def realization_root(self) -> Path:
        """The writable root generated realization output is written under.

        The engine checkout, never the pristine staged pack (issue #875).
        Realization observation reads generated artifacts back from here, so the
        write side and the read-back side share one authority and cannot drift.
        """

        return self._project_dir

    @property
    def supports_local_artifacts(self) -> bool:
        """Return whether bind sources are visible to the Docker daemon."""

        return True

    def _build_command(
        self,
        action: str,
        profiles: list[str],
        *,
        compose_files: Sequence[Path] | None = None,
        scenario_root: Path | None = None,
    ) -> list[str]:
        """Build a docker compose command with profile flags.

        Does NOT add action-specific flags (--build, -d, -v); callers
        are responsible for appending those after calling this method.

        Args:
            action: The compose action (up, down, ps, kill, etc.).
            profiles: List of docker compose profiles to activate.
            scenario_root: When realizing a scenario, the bundle root Compose
                must use as its effective project directory. Relative build
                contexts, binds, includes, and ``env_file`` entries resolve
                against it, never the caller cwd. The operator secret source
                stays the control-plane ``project_dir/.env``, bound explicitly
                so a bundle-local ``.env`` cannot override it (issue #874).
                ``None`` is the legacy direct path over the engine's own compose.

        Returns:
            Command as a list of strings suitable for subprocess.run().
        """
        cmd = ["docker", "compose", "-p", self._project_name]
        if scenario_root is not None:
            cmd.extend(["--project-directory", str(scenario_root)])
            # Always bind an explicit control-plane env source. With
            # --project-directory pointing at the bundle root, Compose would
            # otherwise auto-discover <scenario_root>/.env and let the bundle
            # control interpolation. Bind the operator .env when present, else an
            # empty source (os.devnull) — never the bundle-local .env (#874).
            env_file = self._project_dir / ".env"
            cmd.extend(
                ["--env-file", str(env_file if env_file.is_file() else os.devnull)]
            )
        for compose_file in compose_files or ():
            cmd.extend(["-f", str(compose_file)])

        for profile in profiles:
            cmd.extend(["--profile", profile])

        cmd.append(action)

        return cmd

    def _subprocess_kwargs(
        self,
        *,
        streaming: bool,
        timeout: int | None,
    ) -> dict[str, Any]:
        """Build the ``subprocess.run`` kwargs for this backend.

        Centralises ``cwd`` and any environment construction so
        captured (``_run``) and streaming (``_run_streaming``) modes
        share one codepath. The SSH backend overrides this once to
        inject ``DOCKER_HOST`` instead of duplicating the env block in
        both ``_run`` and ``_run_streaming``.
        """
        kwargs: dict[str, Any] = {"cwd": self._project_dir}
        if streaming:
            kwargs["check"] = False
        else:
            kwargs["capture_output"] = True
            kwargs["text"] = True
            kwargs["encoding"] = "utf-8"
            kwargs["errors"] = "replace"
        if timeout is not None:
            kwargs["timeout"] = timeout
        if self._docker_host_override is not None:
            env = os.environ.copy()
            env["DOCKER_HOST"] = self._docker_host_override
            env.pop("DOCKER_CONTEXT", None)
            kwargs["env"] = env
        return kwargs

    def _run(
        self,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess command in the project directory.

        Captures stdout/stderr; suitable for commands whose output the
        caller wants to parse or log. Translates
        ``subprocess.TimeoutExpired`` into ``BackendTimeoutError`` so
        callers don't depend on ``subprocess`` as an implementation
        detail.
        """
        kwargs = self._subprocess_kwargs(streaming=False, timeout=timeout)
        try:
            return subprocess.run(cmd, **kwargs)
        except subprocess.TimeoutExpired as exc:
            raise BackendTimeoutError(
                f"command timed out after {timeout}s: {' '.join(cmd[:3])}"
            ) from exc

    def _run_streaming(
        self,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> int:
        """Run a subprocess command inheriting parent stdin/stdout/stderr.

        Used for interactive sessions (``container_shell``) and live log
        streams (``container_logs``). The parent terminal is connected
        directly to the child process — no capturing.
        """
        kwargs = self._subprocess_kwargs(streaming=True, timeout=timeout)
        try:
            return subprocess.run(cmd, **kwargs).returncode
        except subprocess.TimeoutExpired as exc:
            raise BackendTimeoutError(
                f"command timed out after {timeout}s: {' '.join(cmd[:3])}"
            ) from exc

    def _run_with_input(
        self,
        cmd: list[str],
        payload: str,
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        """Run one fixed command with non-secret structured stdin."""

        kwargs = self._subprocess_kwargs(streaming=False, timeout=timeout)
        kwargs["input"] = payload
        try:
            return subprocess.run(cmd, **kwargs)
        except subprocess.TimeoutExpired as exc:
            raise BackendTimeoutError(
                f"command timed out after {timeout}s: {' '.join(cmd[:3])}"
            ) from exc

    def stop(self, profiles: list[str], *, remove_volumes: bool = False) -> LabResult:
        """Stop lab services via docker compose down.

        Args:
            profiles: List of profile names to include in the stop.
            remove_volumes: If True, also remove Docker volumes (-v flag).

        Returns:
            LabResult indicating success or failure.
        """
        try:
            self._prepare_owned_cleanup()
        except (BackendTimeoutError, OwnershipConflictError, OSError):
            return LabResult(
                success=False,
                error="Backend resource ownership conflict before Compose cleanup.",
            )
        return stop_compose_lab(
            self,
            profiles,
            remove_volumes=remove_volumes,
            timeout=_DOCKER_TIMEOUT,
        )

    def status(self) -> LabStatus:
        """Query all container states for the configured deployment project.

        Returns:
            LabStatus with container information.
        """
        return self._project_container_status()

    def kill(self, profiles: list[str]) -> tuple[bool, str]:
        """Emergency-stop all lab containers.

        Uses ``docker compose kill`` for immediate SIGKILL, followed by
        ``docker compose down`` to clean up stopped containers.

        Args:
            profiles: List of profile names to include.

        Returns:
            Tuple of (success, error_message).
        """
        try:
            self._prepare_owned_cleanup()
        except (BackendTimeoutError, OwnershipConflictError, OSError):
            return (
                False,
                "Backend resource ownership conflict before emergency cleanup.",
            )
        return kill_compose_lab(self, profiles, timeout=_DOCKER_TIMEOUT)
