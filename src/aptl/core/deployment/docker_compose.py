"""Local Docker Compose deployment backend.

Query, realization, and cleanup helpers live in focused sibling modules.
"""

import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from aptl.core.deployment._compose_base_substrate import ComposeBaseSubstrateMixin
from aptl.core.deployment._compose_build_dedupe import (
    write_duplicate_build_override,
)
from aptl.core.deployment._compose_image_fetch import ComposeImageFetchMixin
from aptl.core.deployment._compose_lifecycle import kill_compose_lab
from aptl.core.deployment._compose_queries import ComposeQueryMixin
from aptl.core.deployment._compose_realization import ComposeRealizationMixin
from aptl.core.deployment._compose_seed_attribution import (
    ComposeSeedAttributionMixin,
)
from aptl.core.deployment._compose_seed_safety import (
    assert_safe_relpath,
    redacted_stderr_hint,
)
from aptl.core.deployment._compose_stop import stop_compose_lab
from aptl.core.deployment._compose_boundary import (
    DEFAULT_BOUNDARY_HELPER_IMAGE,
)
from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
)
from aptl.core.deployment.errors import BackendSeedError, BackendTimeoutError
from aptl.core.lab_types import LabResult, LabStatus
from aptl.core.seed_spec import NamedVolumeSeed
from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")
_DOCKER_TIMEOUT = 30
_SEED_TIMEOUT = 600


class DockerComposeBackend(
    ComposeQueryMixin,
    ComposeRealizationMixin,
    ComposeSeedAttributionMixin,
    ComposeBaseSubstrateMixin,
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
        self._project_name = project_name
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

    @property
    def project_dir(self) -> Path:
        return self._project_dir

    @property
    def project_name(self) -> str:
        return self._project_name

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

    def start(
        self,
        profiles: list[str],
        *,
        build: bool = True,
        exclude_services: tuple[str, ...] = (),
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
            scenario_root: Bundle root the scenario's Compose model and build
                contexts resolve against (issue #874). ``None`` is the legacy
                direct path over the engine's own in-tree compose.

        Returns:
            LabResult indicating success or failure.
        """
        build = build and not self._offline_staged
        compose_files = self._start_compose_files(build=build, scenario_root=scenario_root)
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
        return (
            (root / "docker-compose.yml", override)
            if override is not None
            else None
        )

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

    def seed_named_volumes(
        self,
        seeds: Sequence[NamedVolumeSeed],
        *,
        seeder_image: str,
    ) -> None:
        """Materialize checked-in source into Compose named volumes (ADR-043).

        See :meth:`DeploymentBackend.seed_named_volumes`. Each seed is
        retired-then-copied by short-lived root containers run through the
        backend's own ``_run`` so this stays a narrow, typed operation
        rather than a generic Docker passthrough.
        """
        # Validate every declared relpath before the first Docker command so
        # an unsafe seed can never cause any container or volume side effect.
        for seed in seeds:
            for seed_file in seed.files:
                assert_safe_relpath(seed_file.src)
                assert_safe_relpath(seed_file.dest)
        for seed in seeds:
            self._ensure_labeled_seed_volume(seed)
            self._retire_legacy_seed_path(seed, seeder_image)
            self._seed_one_named_volume(seed, seeder_image)

    def _seed_one_named_volume(self, seed: NamedVolumeSeed, seeder_image: str) -> None:
        """Copy a seed's files into its project-scoped named volume."""
        # Project scoping (ADR-037): the real volume name is derived from
        # the configured compose project, never set as an explicit global.
        volume = f"{self._project_name}_{seed.volume_suffix}"
        cmd = [
            "docker",
            "run",
            *(["--pull=never"] if self._offline_staged else []),
            "--rm",
            "--user",
            "0:0",
            "--entrypoint",
            "/bin/sh",
            "-v",
            f"{seed.source_dir}:/src:ro",
            "-v",
            f"{volume}:/dest",
            seeder_image,
            "-c",
            self._build_seed_script(seed),
        ]
        result = self._run(cmd, timeout=_SEED_TIMEOUT)
        if result.returncode != 0:
            log.error(
                "Seed of volume %s failed (exit %s)%s",
                seed.volume_suffix,
                result.returncode,
                redacted_stderr_hint(result.stderr),
            )
            raise BackendSeedError(
                f"Seeding named volume '{seed.volume_suffix}' failed"
            )

    def _build_seed_script(self, seed: NamedVolumeSeed) -> str:
        """Build the fixed-path copy script for one seed.

        Only fixed container paths and validated relpaths enter shell text.
        """
        parts = ["set -e"]
        for seed_file in seed.files:
            assert_safe_relpath(seed_file.src)
            assert_safe_relpath(seed_file.dest)
            dest_dir = PurePosixPath(seed_file.dest).parent
            if dest_dir.name:
                parts.append(f"mkdir -p /dest/{dest_dir}")
            parts.append(f"cp -a /src/{seed_file.src} /dest/{seed_file.dest}")
        return "; ".join(parts)

    @staticmethod
    def _assert_safe_relpath(relpath: str) -> None:
        """Preserve the validation seam shared with content realization."""

        assert_safe_relpath(relpath)

    def _retire_legacy_seed_path(
        self, seed: NamedVolumeSeed, seeder_image: str
    ) -> None:
        """Remove a seed's pre-ADR-043 legacy host bind dir, if present.

        A root container mounts the parent and removes one validated child.
        """
        legacy = seed.legacy_retire_path
        if legacy is None:
            return
        name = legacy.name
        assert_safe_relpath(name)
        cmd = [
            "docker",
            "run",
            *(["--pull=never"] if self._offline_staged else []),
            "--rm",
            "--user",
            "0:0",
            "--entrypoint",
            "rm",
            "-v",
            f"{legacy.parent}:/legacy",
            seeder_image,
            "-rf",
            f"/legacy/{name}",
        ]
        result = self._run(cmd, timeout=_SEED_TIMEOUT)
        if result.returncode != 0:
            log.error(
                "Retire of legacy seed path %s failed (exit %s)%s",
                legacy,
                result.returncode,
                redacted_stderr_hint(result.stderr),
            )
            raise BackendSeedError(f"Retiring legacy seed path '{name}' failed")
