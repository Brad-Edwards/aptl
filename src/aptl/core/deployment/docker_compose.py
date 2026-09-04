"""Local Docker Compose deployment backend.

Query, realization, and cleanup helpers live in focused sibling modules.
"""

import json
import os
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from aptl.core.deployment._compose_base_substrate import ComposeBaseSubstrateMixin
from aptl.core.deployment._compose_build_dedupe import (
    write_duplicate_build_override,
)
from aptl.core.deployment._compose_image_fetch import ComposeImageFetchMixin
from aptl.core.deployment._compose_lifecycle import kill_compose_lab
from aptl.core.deployment._compose_project_cleanup import ComposeProjectCleanupMixin
from aptl.core.deployment._compose_queries import ComposeQueryMixin
from aptl.core.deployment._compose_realization import ComposeRealizationMixin
from aptl.core.deployment._compose_runtime_inventory import (
    ComposeRuntimeInventoryMixin,
)
from aptl.core.deployment._compose_seed_attribution import (
    ComposeSeedAttributionMixin,
)
from aptl.core.deployment._compose_seed_execution import ComposeSeedExecutionMixin
from aptl.core.deployment._compose_stop import stop_compose_lab
from aptl.core.deployment._compose_boundary import (
    DEFAULT_BOUNDARY_HELPER_IMAGE,
)
from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
)
from aptl.core.config import validate_compose_project_name
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.lab_types import LabResult, LabStatus
from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")
_DOCKER_TIMEOUT = 30
_DOCKER_SOCKET_PATH = "/var/run/docker.sock"
_DOCKER_SOCKET_HOST = "unix:///var/run/docker.sock"


def _local_docker_socket_identity() -> tuple[int, int] | None:
    """Return an accessible non-symlink socket identity, or ``None``."""

    try:
        info = os.lstat(_DOCKER_SOCKET_PATH)
    except OSError:
        return None
    if not stat.S_ISSOCK(info.st_mode) or not os.access(
        _DOCKER_SOCKET_PATH, os.R_OK | os.W_OK
    ):
        return None
    return int(info.st_dev), int(info.st_ino)


class DockerComposeBackend(
    ComposeRuntimeInventoryMixin,
    ComposeQueryMixin,
    ComposeRealizationMixin,
    ComposeSeedAttributionMixin,
    ComposeSeedExecutionMixin,
    ComposeBaseSubstrateMixin,
    ComposeProjectCleanupMixin,
    ComposeImageFetchMixin,
):
    """Docker Compose deployment backend.

    Manages lab lifecycle via ``docker compose`` subprocess calls.
    All commands run against the docker-compose.yml in project_dir.
    Host/container query + inspect helpers are provided by
    ``ComposeQueryMixin``.
    """

    def __init__(
        self,
        project_dir: Path,
        project_name: str = "aptl",
        *,
        offline_staged: bool = False,
    ) -> None:
        self._project_dir = project_dir
        self._project_name = validate_compose_project_name(project_name)
        self._offline_staged = offline_staged
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

    @property
    def project_dir(self) -> Path:
        return self._project_dir

    @property
    def project_name(self) -> str:
        return self._project_name

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

    def bind_local_docker_socket(self) -> LabResult:
        """Bind all subsequent Docker commands to the exact local socket."""

        self._docker_socket_identity = None
        self._docker_daemon_id = None
        self._docker_host_override = None
        if not self.supports_local_artifacts:
            return LabResult(
                success=False,
                error="Docker control authority requires the local Docker daemon.",
            )
        identity = _local_docker_socket_identity()
        if identity is None:
            return LabResult(success=False, error="Docker control endpoint unavailable.")

        self._docker_host_override = _DOCKER_SOCKET_HOST
        try:
            daemon = self._run(
                ["docker", "info", "--format", "{{.ID}}"], timeout=_DOCKER_TIMEOUT
            )
        except BackendTimeoutError:
            daemon = None
        if daemon is None or daemon.returncode != 0 or not daemon.stdout.strip():
            self._docker_host_override = None
            return LabResult(success=False, error="Docker control endpoint unavailable.")
        if _local_docker_socket_identity() != identity:
            self._docker_host_override = None
            return LabResult(
                success=False, error="Docker control endpoint identity changed."
            )
        self._docker_socket_identity = identity
        self._docker_daemon_id = daemon.stdout.strip()
        return LabResult(success=True)

    def revalidate_local_docker_socket(self) -> LabResult:
        """Prove the socket and daemon identities have not changed."""

        if self._docker_socket_identity is None or self._docker_daemon_id is None:
            return LabResult(success=False, error="Docker control endpoint is not bound.")
        identity = _local_docker_socket_identity()
        if identity is None:
            return LabResult(success=False, error="Docker control endpoint unavailable.")
        if identity != self._docker_socket_identity:
            return LabResult(
                success=False, error="Docker control endpoint identity changed."
            )
        try:
            daemon = self._run(
                ["docker", "info", "--format", "{{.ID}}"], timeout=_DOCKER_TIMEOUT
            )
        except BackendTimeoutError:
            daemon = None
        if (
            daemon is None
            or daemon.returncode != 0
            or daemon.stdout.strip() != self._docker_daemon_id
            or _local_docker_socket_identity() != self._docker_socket_identity
        ):
            return LabResult(
                success=False, error="Docker control endpoint identity changed."
            )
        return LabResult(success=True)

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

    def start(
        self,
        profiles: list[str],
        *,
        build: bool = True,
        exclude_services: tuple[str, ...] = (),
        only_services: tuple[str, ...] = (),
        scenario_root: Path | None = None,
    ) -> LabResult:
        """Start lab services via docker compose up.

        Args:
            profiles: List of profile names to activate.
            build: If True, rebuild images before starting.
            exclude_services: Compose service names to scale to zero (ADR-048
                mixed realization): everything else in the active profiles
                starts normally, but a node the generic materializer already
                realized directly must not also start as a Compose container.
            only_services: When non-empty, bring up only these Compose services
                (and their ``depends_on`` closure), leaving the rest of the
                active profiles unstarted. Used by the ADR-088 phased startup
                (issue #889) to bring the materialization target service up and
                prove its initial state before the general workload — which
                consumes that state — is admitted. Do not race a materializer
                against an unrestricted ``compose up``.
            scenario_root: Bundle root the scenario's Compose model and build
                contexts resolve against (issue #874). ``None`` is the legacy
                direct path over the engine's own in-tree compose.

        Returns:
            LabResult indicating success or failure.
        """
        build = build and not self._offline_staged
        compose_files = self._start_compose_files(
            build=build, scenario_root=scenario_root
        )
        cmd = self._build_command(
            "up", profiles, compose_files=compose_files, scenario_root=scenario_root
        )
        if build:
            cmd.append("--build")
        if self._offline_staged:
            cmd.extend(["--pull", "never"])
        cmd.append("-d")
        for service in exclude_services:
            cmd += ["--scale", f"{service}=0"]
        # Positional service names must follow the options: `compose up -d <svc>`
        # starts only the named services plus their depends_on closure.
        cmd.extend(only_services)

        log.info("Starting lab with profiles: %s", profiles)
        log.debug("Command: %s", " ".join(cmd))

        result = self._run(cmd)

        if result.returncode != 0:
            log.error("Lab start failed: %s", result.stderr)
            return LabResult(success=False, error=result.stderr)

        log.info("Lab started successfully")
        return LabResult(success=True, message="Lab started")

    def _start_compose_files(
        self, *, build: bool, scenario_root: Path | None = None
    ) -> tuple[Path, ...] | None:
        """Return Compose files for startup, adding build dedupe when needed.

        The base ``docker-compose.yml`` and the build-dedupe override are
        scenario-declared inputs; they resolve against ``scenario_root`` (the
        bundle root) when realizing a scenario, else the engine's own tree.
        """

        root = scenario_root if scenario_root is not None else self._project_dir
        override = write_duplicate_build_override(root) if build else None
        return (root / "docker-compose.yml", override) if override is not None else None

    def stop(self, profiles: list[str], *, remove_volumes: bool = False) -> LabResult:
        """Stop lab services via docker compose down.

        Args:
            profiles: List of profile names to include in the stop.
            remove_volumes: If True, also remove Docker volumes (-v flag).

        Returns:
            LabResult indicating success or failure.
        """
        return stop_compose_lab(
            self,
            profiles,
            remove_volumes=remove_volumes,
            timeout=_DOCKER_TIMEOUT,
        )

    def status(self) -> LabStatus:
        """Query current lab status via docker compose ps.

        Returns:
            LabStatus with container information.
        """
        cmd = self._build_command("ps", profiles=[])
        cmd.extend(["--format", "json"])

        result = self._run(cmd)

        if result.returncode != 0:
            log.warning("Could not get lab status: %s", result.stderr)
            return LabStatus(running=False, error=result.stderr)

        try:
            # docker compose ps --format json outputs one JSON object per
            # line (NDJSON), not a JSON array.  Try array first, fall back
            # to NDJSON.
            stripped = result.stdout.strip()
            if not stripped:
                containers: list[dict[str, Any]] = []
            elif stripped.startswith("["):
                containers = json.loads(stripped)
            else:
                containers = [
                    json.loads(line) for line in stripped.splitlines() if line.strip()
                ]
        except json.JSONDecodeError:
            log.warning("Could not parse compose ps output")
            return LabStatus(running=False, error="Failed to parse container status")

        running = len(containers) > 0
        return LabStatus(running=running, containers=containers)

    def kill(self, profiles: list[str]) -> tuple[bool, str]:
        """Emergency-stop all lab containers.

        Uses ``docker compose kill`` for immediate SIGKILL, followed by
        ``docker compose down`` to clean up stopped containers.

        Args:
            profiles: List of profile names to include.

        Returns:
            Tuple of (success, error_message).
        """
        return kill_compose_lab(self, profiles, timeout=_DOCKER_TIMEOUT)
