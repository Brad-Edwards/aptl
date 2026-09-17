"""Local Docker Compose deployment backend.

Query, realization, and cleanup helpers live in focused sibling modules.
"""

import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from aptl.core.deployment._compose_base_substrate import ComposeBaseSubstrateMixin
from aptl.core.deployment._compose_autoremove import ComposeAutoremoveMixin
from aptl.core.deployment._compose_build_dedupe import (
    write_duplicate_build_override,
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
    ResourceReceipt,
    WorkspaceOwnership,
    write_compose_ownership_override,
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
from aptl.core.deployment._compose_boundary import (
    DEFAULT_BOUNDARY_HELPER_IMAGE,
)
from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
)
from aptl.core.config import validate_compose_project_name
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult, LabStatus
from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")
_DOCKER_TIMEOUT = 30


class DockerComposeBackend(
    DockerEndpointBindingMixin,
    ComposeAutoremoveMixin,
    ComposeRuntimeInventoryMixin,
    ComposeProjectInventoryMixin,
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
    ``ComposeProjectInventoryMixin`` and ``ComposeQueryMixin``.
    """

    def __init__(
        self,
        project_dir: Path,
        project_name: str = "aptl",
        *,
        offline_staged: bool = False,
    ) -> None:
        self._project_dir = project_dir
        self._logical_project_name = validate_compose_project_name(project_name)
        self._project_name = self._logical_project_name
        self._resource_ownership: WorkspaceOwnership | None = None
        self._resource_attempt_id: str | None = None
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
        self._docker_socket_path: str | None = None
        self._docker_socket_host: str | None = None

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

    def _ensure_resource_ownership(
        self, *, attempt_id: str | None = None
    ) -> WorkspaceOwnership:
        """Load the durable workspace scope before backend mutation."""

        ownership = self._resource_ownership
        if ownership is None:
            ownership = WorkspaceOwnership.ensure(
                self._project_dir, self._logical_project_name
            )
            self._resource_ownership = ownership
            self._project_name = ownership.project_name
        if attempt_id is not None:
            # Validation is shared with label generation.
            ownership.labels(attempt_id=attempt_id)
            self._resource_attempt_id = attempt_id
        elif self._resource_attempt_id is None:
            self._resource_attempt_id = ownership.new_attempt_id()
        return ownership

    def _ownership_daemon_id(self) -> str:
        """Return the selected daemon identity or fail before resource access."""

        daemon_id = self._docker_daemon_id or self._current_docker_daemon_id()
        if not daemon_id:
            raise OwnershipConflictError("backend daemon identity is unavailable")
        self._docker_daemon_id = daemon_id
        return daemon_id

    def _resolve_owned_container_id(self, selector: str) -> str:
        """Resolve one semantic selector to a freshly verified native ID."""

        ownership = self._ensure_resource_ownership()
        candidates = ownership.candidates(
            selector,
            kind="container",
            daemon_id=self._ownership_daemon_id(),
        )
        if not candidates:
            raise OwnershipConflictError("container ownership is unrecorded")
        verified: list[str] = []
        for receipt in candidates:
            info = self._raw_container_inspect(receipt.native_id)
            if not info:
                continue
            if info.get("Id") != receipt.native_id:
                raise OwnershipConflictError("container native identity changed")
            config = info.get("Config")
            labels = config.get("Labels") if isinstance(config, dict) else None
            isolated_child = bool(
                receipt.managed_by == "child"
                and getattr(self, "_attempt_isolated_docker_daemon", False)
            )
            if not isolated_child and (
                not isinstance(labels, dict)
                or labels.get("aptl.workspace.id") != ownership.workspace_id
                or labels.get("aptl.lifecycle.project") != ownership.project_name
            ):
                raise OwnershipConflictError("container ownership labels changed")
            observed_name = str(info.get("Name", "")).removeprefix("/")
            if observed_name != receipt.external_name:
                raise OwnershipConflictError("container semantic binding changed")
            verified.append(receipt.native_id)
        if len(verified) != 1:
            raise OwnershipConflictError("container ownership is absent or ambiguous")
        return verified[0]

    def _resolve_owned_network_id(self, selector: str) -> str:
        """Resolve one recorded network to its freshly verified Docker ID."""

        ownership = self._ensure_resource_ownership()
        candidates = ownership.candidates(
            selector, kind="network", daemon_id=self._ownership_daemon_id()
        )
        verified: list[str] = []
        for receipt in candidates:
            info = self.host_inspect_network(receipt.native_id)
            labels = info.get("labels") if isinstance(info, dict) else None
            if not info:
                continue
            if (
                info.get("id") != receipt.native_id
                or info.get("name") != receipt.external_name
                or not isinstance(labels, dict)
                or labels.get("com.docker.compose.project") != ownership.project_name
            ):
                raise OwnershipConflictError("network ownership binding changed")
            verified.append(receipt.native_id)
        if len(verified) != 1:
            raise OwnershipConflictError("network ownership is absent or ambiguous")
        return verified[0]

    def _resolve_owned_volume_name(self, selector: str) -> str:
        """Resolve one recorded volume to its freshly verified Docker name."""

        ownership = self._ensure_resource_ownership()
        candidates = ownership.candidates(
            selector, kind="volume", daemon_id=self._ownership_daemon_id()
        )
        verified: list[str] = []
        for receipt in candidates:
            info = self._raw_volume_inspect(receipt.native_id)
            if not info:
                continue
            labels = info.get("Labels") if isinstance(info, dict) else None
            if (
                not isinstance(info, dict)
                or info.get("Name") != receipt.native_id
                or info.get("Name") != receipt.external_name
                or not isinstance(labels, dict)
                or labels.get("com.docker.compose.project") != ownership.project_name
            ):
                raise OwnershipConflictError("volume ownership binding changed")
            verified.append(receipt.native_id)
        if len(verified) != 1:
            raise OwnershipConflictError("volume ownership is absent or ambiguous")
        return verified[0]

    def _raw_volume_inspect(self, name: str) -> dict[str, Any]:
        """Inspect one Docker volume name without treating labels as authority."""

        result = self._run(
            ["docker", "volume", "inspect", name], timeout=_DOCKER_TIMEOUT
        )
        if result.returncode != 0:
            return {}
        try:
            payload = json.loads(result.stdout)
        except (TypeError, ValueError) as exc:
            raise OwnershipConflictError("volume ownership is uninspectable") from exc
        info = payload[0] if isinstance(payload, list) and payload else None
        if not isinstance(info, dict):
            raise OwnershipConflictError("volume ownership is uninspectable")
        return info

    def _remove_owned_containers(self, managed_by: str) -> list[str]:
        """Remove recorded containers by verified native ID, never by label query."""

        try:
            ownership = self._ensure_resource_ownership()
            receipts = tuple(
                receipt
                for receipt in ownership.receipts("container")
                if receipt.managed_by == managed_by
            )
            failures: list[str] = []
            for receipt in receipts:
                info = self._raw_container_inspect(receipt.native_id)
                if not info:
                    continue
                native_id = self._resolve_owned_container_id(receipt.native_id)
                result = self._run(["docker", "rm", "-f", native_id], timeout=60)
                if result.returncode != 0:
                    failures.append("failed to remove receipt-owned container")
            return failures
        except (OwnershipConflictError, OSError):
            return ["failed to establish container cleanup authority"]

    def _remove_owned_volumes(self) -> list[str]:
        """Remove only receipt-owned volumes that still verify on this daemon."""

        try:
            ownership = self._ensure_resource_ownership()
            failures: list[str] = []
            for receipt in ownership.receipts("volume"):
                probe = self._run(
                    ["docker", "volume", "inspect", receipt.native_id],
                    timeout=_DOCKER_TIMEOUT,
                )
                if probe.returncode != 0:
                    continue
                volume = self._resolve_owned_volume_name(receipt.native_id)
                result = self._run(
                    ["docker", "volume", "rm", volume], timeout=_DOCKER_TIMEOUT
                )
                if result.returncode != 0:
                    failures.append("failed to remove receipt-owned volume")
            return failures
        except (OwnershipConflictError, BackendTimeoutError, OSError):
            return ["failed to establish volume cleanup authority"]

    def _prepare_owned_cleanup(self) -> None:
        """Verify cleanup authority, allowing a provably empty new namespace."""

        ownership = self._ensure_resource_ownership()
        daemon_id = self._docker_daemon_id or self._current_docker_daemon_id()
        if daemon_id:
            self._docker_daemon_id = daemon_id
            self._verify_compose_namespace_is_owned(ownership, daemon_id)
            return
        if (
            self._scoped_compose_container_ids()
            or self._scoped_compose_network_ids()
            or self._scoped_compose_volume_names()
        ):
            raise OwnershipConflictError("backend daemon identity is unavailable")

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
        root = scenario_root if scenario_root is not None else self._project_dir
        try:
            attempt_id = (
                self._resource_attempt_id or WorkspaceOwnership.new_attempt_id()
            )
            ownership = self._ensure_resource_ownership(attempt_id=attempt_id)
            daemon_id = self._ownership_daemon_id()
        except OwnershipConflictError:
            return LabResult(
                success=False,
                error="Backend resource ownership conflict before Compose mutation.",
            )
        failure = self._start_preflight(profiles, root)
        if failure is not None:
            return failure
        build = build and not self._offline_staged
        compose_files = self._start_compose_files(
            build=build, scenario_root=scenario_root
        )
        if "otel" in profiles:
            compose_files = self._with_observability_files(
                compose_files or (root / "docker-compose.yml",), profiles
            )
        try:
            ownership_override, semantic_by_service, expected = (
                write_compose_ownership_override(
                    ownership,
                    attempt_id=attempt_id,
                    compose_files=tuple(
                        compose_files or (root / "docker-compose.yml",)
                    ),
                )
            )
            self._verify_compose_namespace_is_owned(
                ownership, daemon_id, expected=expected
            )
        except OwnershipConflictError:
            return LabResult(
                success=False,
                error="Backend resource ownership conflict before Compose mutation.",
            )
        compose_files = (
            *tuple(compose_files or (root / "docker-compose.yml",)),
            ownership_override,
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

        try:
            self._record_compose_container_receipts(
                ownership,
                daemon_id=daemon_id,
                attempt_id=attempt_id,
                semantic_by_service=semantic_by_service,
            )
            self._record_compose_network_receipts(
                ownership, daemon_id=daemon_id, attempt_id=attempt_id
            )
            self._record_compose_volume_receipts(
                ownership, daemon_id=daemon_id, attempt_id=attempt_id
            )
        except OwnershipConflictError:
            self._remove_owned_attempt_containers(attempt_id)
            return LabResult(
                success=False,
                error="Backend resource ownership could not be verified after Compose start.",
            )

        log.info("Lab started successfully")
        return LabResult(success=True, message="Lab started")

    def _start_preflight(self, profiles: list[str], root: Path) -> LabResult | None:
        """Run observability configuration and ownership checks before start."""

        failure = self._observability_preflight(
            DeploymentRealizationSpec(profiles=tuple(profiles), nodes=(), networks=()),
            root,
        )
        if failure is None and "otel" in profiles:
            failure = self._observability_ownership_check()
        return failure

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
        files = (root / "docker-compose.yml",)
        return (*files, override) if override is not None else files

    def _scoped_compose_container_ids(self) -> tuple[str, ...]:
        """Discover candidate container IDs inside the effective namespace."""

        result = self._run(
            [
                "docker",
                "ps",
                "-aq",
                "--filter",
                f"label=com.docker.compose.project={self._project_name}",
            ],
            timeout=_DOCKER_TIMEOUT,
        )
        if result.returncode != 0:
            raise OwnershipConflictError("Compose resource discovery failed")
        return tuple(
            dict.fromkeys(
                line.strip() for line in result.stdout.splitlines() if line.strip()
            )
        )

    def _scoped_compose_network_ids(self) -> tuple[str, ...]:
        """Discover candidate network IDs inside the effective namespace."""

        result = self._run(
            [
                "docker",
                "network",
                "ls",
                "--filter",
                f"label=com.docker.compose.project={self._project_name}",
                "--format",
                "{{.ID}}",
            ],
            timeout=_DOCKER_TIMEOUT,
        )
        if result.returncode != 0:
            raise OwnershipConflictError("Compose network discovery failed")
        return tuple(
            dict.fromkeys(
                line.strip() for line in result.stdout.splitlines() if line.strip()
            )
        )

    def _scoped_compose_volume_names(self) -> tuple[str, ...]:
        """Discover candidate volume native names inside the effective namespace."""

        result = self._run(
            [
                "docker",
                "volume",
                "ls",
                "--filter",
                f"label=com.docker.compose.project={self._project_name}",
                "--format",
                "{{.Name}}",
            ],
            timeout=_DOCKER_TIMEOUT,
        )
        if result.returncode != 0:
            raise OwnershipConflictError("Compose volume discovery failed")
        return tuple(
            dict.fromkeys(
                line.strip() for line in result.stdout.splitlines() if line.strip()
            )
        )

    def _verify_compose_namespace_is_owned(
        self,
        ownership: WorkspaceOwnership,
        daemon_id: str,
        *,
        expected: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        """Reject pre-existing namespace objects without immutable receipts."""

        for native_id in self._scoped_compose_container_ids():
            candidates = ownership.candidates(
                native_id,
                kind="container",
                daemon_id=daemon_id,
            )
            if len(candidates) != 1:
                raise OwnershipConflictError("Compose namespace contains foreign state")
            self._resolve_owned_container_id(native_id)
        for native_id in self._scoped_compose_network_ids():
            candidates = ownership.candidates(
                native_id, kind="network", daemon_id=daemon_id
            )
            if len(candidates) != 1:
                raise OwnershipConflictError("Compose namespace contains foreign state")
            self._resolve_owned_network_id(native_id)
        for native_name in self._scoped_compose_volume_names():
            candidates = ownership.candidates(
                native_name, kind="volume", daemon_id=daemon_id
            )
            if len(candidates) != 1:
                raise OwnershipConflictError("Compose namespace contains foreign state")
            self._resolve_owned_volume_name(native_name)
        if expected is not None:
            self._verify_expected_compose_resources(
                ownership, daemon_id=daemon_id, expected=expected
            )

    def _verify_expected_compose_resources(
        self,
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        expected: dict[str, tuple[str, ...]],
    ) -> None:
        """Reject exact-name collisions even when a foreign object has no labels."""

        for external_name in expected.get("container", ()):
            info = self._raw_container_inspect(external_name)
            if not info:
                continue
            native_id = str(info.get("Id", ""))
            if (
                not native_id
                or len(
                    ownership.candidates(
                        native_id, kind="container", daemon_id=daemon_id
                    )
                )
                != 1
            ):
                raise OwnershipConflictError("Compose container name is foreign")
            self._resolve_owned_container_id(native_id)
        for external_name in expected.get("network", ()):
            info = self.host_inspect_network(external_name)
            if not info:
                continue
            native_id = str(info.get("id", ""))
            if (
                not native_id
                or len(
                    ownership.candidates(native_id, kind="network", daemon_id=daemon_id)
                )
                != 1
            ):
                raise OwnershipConflictError("Compose network name is foreign")
            self._resolve_owned_network_id(native_id)
        for external_name in expected.get("volume", ()):
            if not self._raw_volume_inspect(external_name):
                continue
            if (
                len(
                    ownership.candidates(
                        external_name, kind="volume", daemon_id=daemon_id
                    )
                )
                != 1
            ):
                raise OwnershipConflictError("Compose volume name is foreign")
            self._resolve_owned_volume_name(external_name)

    def _record_compose_container_receipts(
        self,
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        attempt_id: str,
        semantic_by_service: dict[str, str],
    ) -> None:
        """Capture native IDs and complete owner tuples after Compose creation."""

        for native_id in self._scoped_compose_container_ids():
            existing = ownership.candidates(
                native_id, kind="container", daemon_id=daemon_id
            )
            if existing:
                if len(existing) != 1:
                    raise OwnershipConflictError("Compose owner tuple is ambiguous")
                self._resolve_owned_container_id(native_id)
                continue
            info = self._raw_container_inspect(native_id)
            config = info.get("Config") if isinstance(info, dict) else None
            labels = config.get("Labels") if isinstance(config, dict) else None
            service = (
                labels.get("com.docker.compose.service")
                if isinstance(labels, dict)
                else None
            )
            expected = ownership.labels(attempt_id=attempt_id)
            if (
                info.get("Id") != native_id
                or not isinstance(labels, dict)
                or any(labels.get(name) != value for name, value in expected.items())
                or labels.get("com.docker.compose.project") != ownership.project_name
                or service not in semantic_by_service
            ):
                raise OwnershipConflictError("Compose owner tuple is incomplete")
            semantic_name = semantic_by_service[str(service)]
            external_name = str(info.get("Name", "")).removeprefix("/")
            if external_name != ownership.container_name(semantic_name):
                raise OwnershipConflictError("Compose semantic binding changed")
            ownership.record(
                ResourceReceipt(
                    kind="container",
                    native_id=native_id,
                    external_name=external_name,
                    semantic_name=semantic_name,
                    node_address=str(labels.get("aptl.node.address") or service),
                    workspace_id=ownership.workspace_id,
                    project_name=ownership.project_name,
                    daemon_id=daemon_id,
                    attempt_id=attempt_id,
                    managed_by="compose",
                )
            )

    def _record_compose_network_receipts(
        self,
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        attempt_id: str,
    ) -> None:
        """Capture Compose-created network IDs after an empty/owned preflight."""

        for native_id in self._scoped_compose_network_ids():
            existing = ownership.candidates(
                native_id, kind="network", daemon_id=daemon_id
            )
            if existing:
                if len(existing) != 1:
                    raise OwnershipConflictError("Compose owner tuple is ambiguous")
                self._resolve_owned_network_id(native_id)
                continue
            info = self.host_inspect_network(native_id)
            labels = info.get("labels") if isinstance(info, dict) else None
            expected_labels = ownership.labels(attempt_id=attempt_id)
            semantic_name = (
                labels.get("com.docker.compose.network")
                if isinstance(labels, dict)
                else None
            )
            external_name = info.get("name") if isinstance(info, dict) else None
            if (
                info.get("id") != native_id
                or not isinstance(labels, dict)
                or labels.get("com.docker.compose.project") != ownership.project_name
                or any(
                    labels.get(label) != value
                    for label, value in expected_labels.items()
                )
                or not isinstance(semantic_name, str)
                or not semantic_name
                or not isinstance(external_name, str)
                or not external_name
            ):
                raise OwnershipConflictError(
                    "Compose network owner tuple is incomplete"
                )
            ownership.record(
                ResourceReceipt(
                    kind="network",
                    native_id=native_id,
                    external_name=external_name,
                    semantic_name=semantic_name,
                    node_address=semantic_name,
                    workspace_id=ownership.workspace_id,
                    project_name=ownership.project_name,
                    daemon_id=daemon_id,
                    attempt_id=attempt_id,
                    managed_by="compose",
                )
            )

    def _record_compose_volume_receipts(
        self,
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        attempt_id: str,
    ) -> None:
        """Capture Compose-created volume names after an empty/owned preflight."""

        for native_name in self._scoped_compose_volume_names():
            existing = ownership.candidates(
                native_name, kind="volume", daemon_id=daemon_id
            )
            if existing:
                if len(existing) != 1:
                    raise OwnershipConflictError("Compose owner tuple is ambiguous")
                self._resolve_owned_volume_name(native_name)
                continue
            result = self._run(
                ["docker", "volume", "inspect", native_name],
                timeout=_DOCKER_TIMEOUT,
            )
            try:
                payload = json.loads(result.stdout) if result.returncode == 0 else None
            except (TypeError, ValueError) as exc:
                raise OwnershipConflictError(
                    "Compose volume owner tuple is unreadable"
                ) from exc
            info = payload[0] if isinstance(payload, list) and payload else None
            labels = info.get("Labels") if isinstance(info, dict) else None
            expected_labels = ownership.labels(attempt_id=attempt_id)
            semantic_name = (
                labels.get("com.docker.compose.volume")
                if isinstance(labels, dict)
                else None
            )
            if (
                not isinstance(info, dict)
                or info.get("Name") != native_name
                or not isinstance(labels, dict)
                or labels.get("com.docker.compose.project") != ownership.project_name
                or any(
                    labels.get(label) != value
                    for label, value in expected_labels.items()
                )
                or not isinstance(semantic_name, str)
                or not semantic_name
            ):
                raise OwnershipConflictError("Compose volume owner tuple is incomplete")
            ownership.record(
                ResourceReceipt(
                    kind="volume",
                    native_id=native_name,
                    external_name=native_name,
                    semantic_name=semantic_name,
                    node_address=semantic_name,
                    workspace_id=ownership.workspace_id,
                    project_name=ownership.project_name,
                    daemon_id=daemon_id,
                    attempt_id=attempt_id,
                    managed_by="compose",
                )
            )

    def _remove_owned_attempt_containers(self, attempt_id: str) -> None:
        """Best-effort rollback of only IDs recorded for the failed attempt."""

        ownership = self._ensure_resource_ownership()
        for receipt in ownership.receipts("container"):
            if receipt.attempt_id != attempt_id:
                continue
            try:
                native_id = self._resolve_owned_container_id(receipt.native_id)
                self._run(["docker", "rm", "-f", native_id], timeout=60)
            except (OwnershipConflictError, OSError):
                continue

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
