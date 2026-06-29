"""Docker Compose deployment backend.

Implements the DeploymentBackend protocol using local Docker Compose
subprocess calls. This is the default backend and wraps the logic
previously embedded directly in lab.py and kill.py.

Host- and container-level docker query/inspect operations live in
``ComposeQueryMixin`` (``_compose_queries.py``) to keep this module within
the size budget; they are mixed into ``DockerComposeBackend`` below.
"""

import json
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from aptl.core.deployment._compose_queries import ComposeQueryMixin
from aptl.core.deployment.errors import BackendSeedError, BackendTimeoutError
from aptl.core.deployment.realization import DeploymentRealizationSpec
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

# Seed file relpaths come from code-defined specs (never operator input),
# but they are embedded in the seed container's shell command, so they are
# validated defensively: a strict charset, no leading separator, and no
# parent-traversal component, so nothing can escape /src or /dest.
_SAFE_SEED_RELPATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_NETWORK_TOKEN_SEPARATORS = re.compile(r"[^a-z0-9]+")
_REALIZATION_TIMEOUT = 30


def _container_networks(container_info: dict[str, Any]) -> set[str]:
    """Return Docker network names from one container inspect payload."""

    networks = (
        container_info.get("NetworkSettings", {}).get("Networks")
        if isinstance(container_info, dict)
        else None
    )
    if not isinstance(networks, dict):
        return set()
    return {str(network_name) for network_name in networks if str(network_name)}


def _resolve_realization_networks(
    declared_networks: tuple[str, ...],
    managed_networks: set[str],
    project_name: str,
) -> tuple[set[str], list[str]]:
    """Resolve ACES network names to concrete project Docker network names."""

    desired: set[str] = set()
    missing: list[str] = []
    for declared in declared_networks:
        match = _match_managed_network(declared, managed_networks, project_name)
        if match is None:
            missing.append(declared)
        else:
            desired.add(match)
    return desired, missing


def _match_managed_network(
    declared: str,
    managed_networks: set[str],
    project_name: str,
) -> str | None:
    """Return the managed Docker network matching an ACES declaration."""

    for candidate in _network_name_candidates(declared, project_name):
        if candidate in managed_networks:
            return candidate
    return None


def _network_name_candidates(declared: str, project_name: str) -> tuple[str, ...]:
    """Return likely Compose network names for an ACES network identifier."""

    normalized = _network_token(declared)
    if not normalized:
        return ()
    stems = {normalized}
    if normalized.endswith("-net"):
        stems.add(normalized.removesuffix("-net"))
    if normalized.startswith("aptl-"):
        stems.add(normalized.removeprefix("aptl-"))
    candidates: list[str] = []
    for stem in sorted(stems):
        candidates.extend(
            [
                stem,
                f"aptl-{stem}",
                f"{project_name}_{stem}",
                f"{project_name}_aptl-{stem}",
                f"{project_name}-{stem}",
                f"{project_name}-aptl-{stem}",
            ]
        )
    return tuple(dict.fromkeys(candidates))


def _network_token(raw: str) -> str:
    """Normalize a network identifier for candidate-name generation."""

    return _NETWORK_TOKEN_SEPARATORS.sub("-", raw.strip().lower()).strip("-")


class DockerComposeBackend(ComposeQueryMixin):
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

    def _build_command(
        self,
        action: str,
        profiles: list[str],
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
        cmd = self._build_command("up", profiles)
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

    def realize(
        self,
        realization: DeploymentRealizationSpec,
        *,
        build: bool = True,
    ) -> LabResult:
        """Realize a typed scenario deployment through Docker Compose."""

        profiles = list(realization.profiles)
        start_result = self.start(profiles, build=build)
        if not start_result.success:
            return start_result
        failures = self._reconcile_realization_networks(realization)
        if failures:
            return LabResult(
                success=False,
                error="; ".join(failures[:5]),
            )
        return LabResult(success=True, message="Lab realized")

    def _reconcile_realization_networks(
        self,
        realization: DeploymentRealizationSpec,
    ) -> list[str]:
        """Align realized containers with the scenario-declared networks."""

        managed_networks = set(self.host_list_lab_networks(self._project_name))
        if not managed_networks:
            return ["APTL managed networks were not visible after startup."]

        failures: list[str] = []
        for node in realization.nodes:
            if not node.container_name or not node.networks:
                continue
            desired, missing = _resolve_realization_networks(
                node.networks,
                managed_networks,
                self._project_name,
            )
            if missing:
                failures.append(
                    "No managed Docker network matched ACES network(s) "
                    f"{', '.join(missing)} for node {node.name}."
                )
                continue
            info = self.container_inspect(node.container_name)
            if not info:
                failures.append(
                    f"Container {node.container_name} was not inspectable "
                    f"for realized node {node.name}."
                )
                continue
            current = _container_networks(info) & managed_networks
            failures.extend(
                self._disconnect_extra_networks(node.container_name, current, desired)
            )
            failures.extend(
                self._connect_missing_networks(node.container_name, current, desired)
            )
        return failures

    def _disconnect_extra_networks(
        self,
        container_name: str,
        current: set[str],
        desired: set[str],
    ) -> list[str]:
        """Detach a realized container from project networks outside its spec."""

        return self._change_network_memberships(
            container_name=container_name,
            network_names=current - desired,
            action="disconnect",
            preposition="from",
        )

    def _connect_missing_networks(
        self,
        container_name: str,
        current: set[str],
        desired: set[str],
    ) -> list[str]:
        """Attach a realized container to declared project networks it lacks."""

        return self._change_network_memberships(
            container_name=container_name,
            network_names=desired - current,
            action="connect",
            preposition="to",
        )

    def _change_network_memberships(
        self,
        *,
        container_name: str,
        network_names: set[str],
        action: str,
        preposition: str,
    ) -> list[str]:
        """Run one Docker network membership action across sorted networks."""

        failures: list[str] = []
        for network_name in sorted(network_names):
            result = self._run(
                ["docker", "network", action, network_name, container_name],
                timeout=_REALIZATION_TIMEOUT,
            )
            if result.returncode != 0:
                failures.append(
                    f"Failed to {action} {container_name} "
                    f"{preposition} {network_name}: "
                    f"{result.stderr.strip()}"
                )
        return failures

    def stop(
        self, profiles: list[str], *, remove_volumes: bool = False
    ) -> LabResult:
        """Stop lab services via docker compose down.

        Args:
            profiles: List of profile names to include in the stop.
            remove_volumes: If True, also remove Docker volumes (-v flag).

        Returns:
            LabResult indicating success or failure.
        """
        cmd = self._build_command("down", profiles=profiles)
        if remove_volumes:
            cmd.append("-v")

        log.info("Stopping lab (remove_volumes=%s)", remove_volumes)

        result = self._run(cmd)

        if result.returncode != 0:
            log.error("Lab stop failed: %s", result.stderr)
            return LabResult(success=False, error=result.stderr)

        log.info("Lab stopped successfully")
        return LabResult(success=True, message="Lab stopped")

    def status(self) -> LabStatus:
        """Query current lab status via docker compose ps.

        Returns:
            LabStatus with container information.
        """
        cmd = ["docker", "compose", "ps", "--format", "json"]

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
                    json.loads(line)
                    for line in stripped.splitlines()
                    if line.strip()
                ]
        except json.JSONDecodeError:
            log.warning("Could not parse compose ps output")
            return LabStatus(
                running=False, error="Failed to parse container status"
            )

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
        # Phase 1: docker compose kill (immediate SIGKILL)
        kill_cmd = ["docker", "compose"]
        for profile in profiles:
            kill_cmd.extend(["--profile", profile])
        kill_cmd.append("kill")

        log.info("Running: %s", " ".join(kill_cmd))
        kill_ok = False
        try:
            result = self._run(kill_cmd, timeout=_DOCKER_TIMEOUT)
            kill_ok = result.returncode == 0
            if not kill_ok:
                log.warning(
                    "docker compose kill stderr: %s", result.stderr.strip()
                )
        except BackendTimeoutError:
            log.warning(
                "docker compose kill timed out after %ds", _DOCKER_TIMEOUT
            )
        except OSError as exc:
            msg = f"docker compose kill failed: {exc}"
            log.error(msg)
            return False, msg

        # Phase 2: docker compose down (cleanup).  Treat non-zero exit as
        # a warning -- the important work (SIGKILL) already happened above.
        down_cmd = self._build_command("down", profiles=profiles)
        log.info("Running: %s", " ".join(down_cmd))
        try:
            result = self._run(down_cmd, timeout=_DOCKER_TIMEOUT)
            if result.returncode != 0:
                log.warning(
                    "docker compose down stderr: %s", result.stderr.strip()
                )
        except BackendTimeoutError:
            log.warning(
                "docker compose down timed out after %ds", _DOCKER_TIMEOUT
            )
        except OSError as exc:
            log.warning("docker compose down failed: %s", exc)

        if not kill_ok:
            return False, "docker compose kill returned non-zero"

        log.info("All lab containers stopped")
        return True, ""

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
        for seed in seeds:
            self._retire_legacy_seed_path(seed, seeder_image)
            self._seed_one_named_volume(seed, seeder_image)

    def _seed_one_named_volume(
        self, seed: NamedVolumeSeed, seeder_image: str
    ) -> None:
        """Copy a seed's files into its project-scoped named volume."""
        # Project scoping (ADR-037): the real volume name is derived from
        # the configured compose project, never set as an explicit global.
        volume = f"{self._project_name}_{seed.volume_suffix}"
        cmd = [
            "docker", "run", "--rm", "--user", "0:0",
            "--entrypoint", "/bin/sh",
            "-v", f"{seed.source_dir}:/src:ro",
            "-v", f"{volume}:/dest",
            seeder_image,
            "-c", self._build_seed_script(seed),
        ]
        result = self._run(cmd, timeout=_SEED_TIMEOUT)
        if result.returncode != 0:
            # Name only the artifact — raw Docker stderr stays out of the
            # raised message and is surfaced through the redacted log line.
            log.error(
                "Seed of volume %s failed (exit %s)",
                seed.volume_suffix, result.returncode,
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
            self._assert_safe_relpath(seed_file.src)
            self._assert_safe_relpath(seed_file.dest)
            dest_dir = PurePosixPath(seed_file.dest).parent
            if dest_dir.name:
                parts.append(f"mkdir -p /dest/{dest_dir}")
            parts.append(f"cp -a /src/{seed_file.src} /dest/{seed_file.dest}")
        return "; ".join(parts)

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
        self._assert_safe_relpath(name)
        cmd = [
            "docker", "run", "--rm", "--user", "0:0",
            "--entrypoint", "rm",
            "-v", f"{legacy.parent}:/legacy",
            seeder_image,
            "-rf", f"/legacy/{name}",
        ]
        result = self._run(cmd, timeout=_SEED_TIMEOUT)
        if result.returncode != 0:
            log.error(
                "Retire of legacy seed path %s failed (exit %s)",
                legacy, result.returncode,
            )
            raise BackendSeedError(
                f"Retiring legacy seed path '{name}' failed"
            )

    @staticmethod
    def _assert_safe_relpath(relpath: str) -> None:
        """Reject a seed relpath that is unsafe to embed in the seed command."""
        if (
            ".." in PurePosixPath(relpath).parts
            or not _SAFE_SEED_RELPATH.match(relpath)
        ):
            raise BackendSeedError(f"Unsafe seed relpath rejected: {relpath!r}")
