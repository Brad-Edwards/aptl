"""Local Docker Compose deployment backend.

Query, realization, and cleanup helpers live in focused sibling modules.
"""

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from aptl.core.deployment._compose_build_dedupe import (
    write_duplicate_build_override,
)
from aptl.core.deployment._compose_lifecycle import kill_compose_lab
from aptl.core.deployment._compose_queries import ComposeQueryMixin
from aptl.core.deployment._compose_realization import ComposeRealizationMixin
from aptl.core.deployment._compose_seed_safety import (
    assert_safe_relpath,
    redacted_stderr_hint,
)
from aptl.core.deployment._compose_stop import stop_compose_lab
from aptl.core.deployment.errors import BackendSeedError, BackendTimeoutError
from aptl.core.lab_types import LabResult, LabStatus
from aptl.core.seed_spec import NamedVolumeSeed
from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")

# Timeout for Docker Compose subprocess calls during kill operations.
# Generous enough for a large stack, short enough that a hung daemon
# won't block the kill switch indefinitely.
_DOCKER_TIMEOUT = 30

# Timeout for a single volume-seed / legacy-retire container (ADR-043).
# The copy itself is a handful of small files, but the first seed on a
# fresh host may pull the seeder image (already in the lab's supply
# chain), so the margin is deliberately generous.
_SEED_TIMEOUT = 600


class DockerComposeBackend(ComposeQueryMixin, ComposeRealizationMixin):
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
    ) -> None:
        self._project_dir = project_dir
        self._project_name = project_name

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
    ) -> list[str]:
        """Build a docker compose command with profile flags.

        Does NOT add action-specific flags (--build, -d, -v); callers
        are responsible for appending those after calling this method.

        Args:
            action: The compose action (up, down, ps, kill, etc.).
            profiles: List of docker compose profiles to activate.

        Returns:
            Command as a list of strings suitable for subprocess.run().
        """
        # Pin the compose project name. Without `-p`, docker compose derives the
        # project from the working-directory basename, which diverges from
        # `self._project_name` in any worktree not literally named after the
        # project (e.g. a `aptl3` git worktree). That divergence makes `start`
        # / `stop` (this builder) act on a different project than `status` and
        # the orphan-cleanup filters, so a lab started here cannot be stopped or
        # inspected and its networks collide with the real project's subnets.
        cmd = ["docker", "compose", "-p", self._project_name]
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
            # Decode captured docker/compose output as UTF-8 explicitly.
            # Without this, `text=True` decodes with the host's locale
            # codec, which on Windows is cp1252 and cannot decode the
            # non-ASCII bytes BuildKit emits (progress glyphs, box-drawing) —
            # the reader thread raises UnicodeDecodeError mid-build, the
            # compose call is seen as failed, and the 60s retry then
            # collides with the containers the first attempt already started.
            # `errors="replace"` keeps a stray byte from ever aborting a read.
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

    def start(self, profiles: list[str], *, build: bool = True) -> LabResult:
        """Start lab services via docker compose up.

        Args:
            profiles: List of profile names to activate.
            build: If True, rebuild images before starting.

        Returns:
            LabResult indicating success or failure.
        """
        compose_files = self._start_compose_files(build=build)
        cmd = self._build_command("up", profiles, compose_files=compose_files)
        if build:
            cmd.append("--build")
        cmd.append("-d")

        log.info("Starting lab with profiles: %s", profiles)
        log.debug("Command: %s", " ".join(cmd))

        result = self._run(cmd)

        if result.returncode != 0:
            log.error("Lab start failed: %s", result.stderr)
            return LabResult(success=False, error=result.stderr)

        log.info("Lab started successfully")
        return LabResult(success=True, message="Lab started")

    def _start_compose_files(self, *, build: bool) -> tuple[Path, ...] | None:
        """Return Compose files for startup, adding build dedupe when needed."""

        override = write_duplicate_build_override(self._project_dir) if build else None
        return (
            (self._project_dir / "docker-compose.yml", override)
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

    def pull_images(self, images: list[str]) -> list[str]:
        """Pre-pull container images via docker pull.

        Args:
            images: List of image references to pull.

        Returns:
            List of warning messages for images that failed to pull
            (non-fatal).
        """
        warnings: list[str] = []
        for image in images:
            try:
                result = self._run(["docker", "pull", image])
                if result.returncode != 0:
                    msg = f"Failed to pull {image}: {result.stderr.strip()}"
                    log.warning(msg)
                    warnings.append(msg)
                else:
                    log.info("Pulled %s", image)
            except OSError as exc:
                msg = f"Failed to pull {image}: {exc}"
                log.warning(msg)
                warnings.append(msg)
        return warnings

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

    def _ensure_labeled_seed_volume(self, seed: NamedVolumeSeed) -> None:
        """Create a missing seed volume with Compose project labels.

        A bare ``docker run -v`` auto-creates a missing named volume without
        labels. Compose happily reuses it, but the content observation gate
        (``observe_content_type``) refuses a volume it cannot attribute to
        this project, so a seeded volume must carry the same labels Compose
        itself would have written. Labels are immutable after creation, so
        this must happen before the first seeding ``docker run``.
        """
        volume = f"{self._project_name}_{seed.volume_suffix}"
        inspect = self._run(
            ["docker", "volume", "inspect", volume, "--format", "{{json .Labels}}"],
            timeout=_SEED_TIMEOUT,
        )
        if inspect.returncode == 0:
            if self._content_volume_owned_by_project(
                inspect.stdout, seed.volume_suffix
            ):
                return
            # Labels are immutable after creation and the volume may hold
            # runtime state, so an unattributed same-named volume is an
            # explicit operator decision, not something to adopt silently:
            # content observation would reject it late with a far less
            # actionable failure.
            log.error(
                "Named volume %s exists without Compose project attribution. "
                "Remove it with `docker volume rm %s` (seeded content is "
                "recreated from checked-in sources) and rerun `aptl lab start`.",
                volume,
                volume,
            )
            raise BackendSeedError(
                f"Named volume '{seed.volume_suffix}' exists without Compose "
                "project attribution"
            )
        create = self._run(
            [
                "docker",
                "volume",
                "create",
                "--label",
                f"com.docker.compose.project={self._project_name}",
                "--label",
                f"com.docker.compose.volume={seed.volume_suffix}",
                volume,
            ],
            timeout=_SEED_TIMEOUT,
        )
        if create.returncode != 0:
            log.error(
                "Labeled create of volume %s failed (exit %s)%s",
                seed.volume_suffix,
                create.returncode,
                redacted_stderr_hint(create.stderr),
            )
            raise BackendSeedError(
                f"Creating named volume '{seed.volume_suffix}' failed"
            )

    def _seed_one_named_volume(self, seed: NamedVolumeSeed, seeder_image: str) -> None:
        """Copy a seed's files into its project-scoped named volume."""
        # Project scoping (ADR-037): the real volume name is derived from
        # the configured compose project, never set as an explicit global.
        volume = f"{self._project_name}_{seed.volume_suffix}"
        cmd = [
            "docker",
            "run",
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
            # Name only the artifact in the raised message — raw Docker
            # stderr never reaches the exception (test_nonzero_exit_raises_
            # without_leaking_stderr). The operator-facing log line carries
            # a redacted stderr tail so a seed failure is diagnosable
            # without rerunning the docker command by hand (issue #716).
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

        Only the fixed container paths ``/src`` and ``/dest`` plus
        validated, code-defined relpaths appear in the returned string;
        the host source dir and the volume name travel through argv ``-v``
        flags, never the shell text (ADR-043 §Security Layers). Root
        ``cp`` overwrites prior content, so the seed is idempotent
        regardless of the existing owner.
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

        The directory may be owned by the in-container ``suricata`` UID
        (991), so the host operator cannot delete it. A root container
        mounts the host-owned *parent* and removes the single canonical
        child by name — a narrow, path-contained cleanup (ADR-043), in
        argv form against fixed container paths.
        """
        legacy = seed.legacy_retire_path
        if legacy is None:
            return
        name = legacy.name
        assert_safe_relpath(name)
        cmd = [
            "docker",
            "run",
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
            # Same redacted-hint contract as the seed path (issue #716): the
            # raised message names only the artifact; the log line carries a
            # redacted stderr tail for diagnosis.
            log.error(
                "Retire of legacy seed path %s failed (exit %s)%s",
                legacy,
                result.returncode,
                redacted_stderr_hint(result.stderr),
            )
            raise BackendSeedError(f"Retiring legacy seed path '{name}' failed")
