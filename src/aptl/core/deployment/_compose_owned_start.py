"""Receipt-scoped Docker Compose startup orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aptl.core.deployment._compose_build_dedupe import (
    write_duplicate_build_override,
)
from aptl.core.deployment._compose_resource_ownership import (
    OwnershipConflictError,
    WorkspaceOwnership,
    write_compose_ownership_override,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult
from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")
_COMPOSE_FILE = "docker-compose.yml"
_PRE_MUTATION_CONFLICT = "Backend resource ownership conflict before Compose mutation."


@dataclass(frozen=True)
class _OwnedStartScope:
    """Prepared ownership inputs for one Compose mutation."""

    ownership: WorkspaceOwnership
    attempt_id: str
    daemon_id: str
    compose_files: tuple[Path, ...]
    semantic_by_service: dict[str, str]


class ComposeOwnedStartMixin:
    """Start Compose only after exact-name and receipt-backed preflight."""

    def start(
        self,
        profiles: list[str],
        *,
        build: bool = True,
        exclude_services: tuple[str, ...] = (),
        only_services: tuple[str, ...] = (),
        scenario_root: Path | None = None,
    ) -> LabResult:
        """Start lab services through the workspace-scoped Compose namespace."""

        root = scenario_root if scenario_root is not None else self._project_dir
        ownership_failure = self._initialize_start_ownership()
        if ownership_failure is not None:
            return ownership_failure
        preflight_failure = self._start_preflight(profiles, root)
        if preflight_failure is not None:
            return preflight_failure
        build = build and not self._offline_staged
        compose_files = self._start_compose_files(
            build=build, scenario_root=scenario_root
        ) or (root / _COMPOSE_FILE,)
        if "otel" in profiles:
            compose_files = self._with_observability_files(compose_files, profiles)
        return self._run_owned_compose_up(
            profiles,
            build=build,
            compose_files=compose_files,
            exclude_services=exclude_services,
            only_services=only_services,
            scenario_root=scenario_root,
        )

    def _initialize_start_ownership(self) -> LabResult | None:
        """Bind the workspace and daemon before any startup preflight."""

        try:
            attempt_id = (
                self._resource_attempt_id or WorkspaceOwnership.new_attempt_id()
            )
            self._ensure_resource_ownership(attempt_id=attempt_id)
            self._ownership_daemon_id()
        except OwnershipConflictError as exc:
            return self._ownership_failure(exc)
        return None

    def _start_with_compose_files(
        self,
        profiles: list[str],
        *,
        build: bool,
        compose_files: tuple[Path, ...],
        exclude_services: tuple[str, ...] = (),
        only_services: tuple[str, ...] = (),
        scenario_root: Path | None = None,
    ) -> LabResult:
        """Start lab services using a generated realization override."""

        return self._run_owned_compose_up(
            profiles,
            build=build and not self._offline_staged,
            compose_files=compose_files,
            exclude_services=exclude_services,
            only_services=only_services,
            scenario_root=scenario_root,
        )

    def _run_owned_compose_up(
        self,
        profiles: list[str],
        *,
        build: bool,
        compose_files: tuple[Path, ...],
        exclude_services: tuple[str, ...],
        only_services: tuple[str, ...],
        scenario_root: Path | None,
    ) -> LabResult:
        """Preflight, run, and receipt one Compose up operation."""

        prepared = self._prepare_owned_start(compose_files)
        if isinstance(prepared, LabResult):
            return prepared
        command = self._owned_up_command(
            profiles,
            scope=prepared,
            build=build,
            exclude_services=exclude_services,
            only_services=only_services,
            scenario_root=scenario_root,
        )
        result = self._run(command)
        if result.returncode != 0:
            log.error("Lab start failed: %s", result.stderr)
            return LabResult(success=False, error=result.stderr)
        return self._capture_started_resources(prepared, profiles)

    def _prepare_owned_start(
        self, compose_files: tuple[Path, ...]
    ) -> _OwnedStartScope | LabResult:
        """Build the final override and reject every pre-existing collision."""

        try:
            attempt_id = (
                self._resource_attempt_id or WorkspaceOwnership.new_attempt_id()
            )
            ownership = self._ensure_resource_ownership(attempt_id=attempt_id)
            daemon_id = self._ownership_daemon_id()
            override, semantic_by_service, expected = write_compose_ownership_override(
                ownership,
                attempt_id=attempt_id,
                compose_files=compose_files,
            )
            self._verify_compose_namespace_is_owned(
                ownership, daemon_id, expected=expected
            )
        except OwnershipConflictError as exc:
            return self._ownership_failure(exc)
        return _OwnedStartScope(
            ownership=ownership,
            attempt_id=attempt_id,
            daemon_id=daemon_id,
            compose_files=(*compose_files, override),
            semantic_by_service=semantic_by_service,
        )

    @staticmethod
    def _ownership_failure(exc: OwnershipConflictError) -> LabResult:
        """Log the controlled conflict class and return the public envelope."""

        log.error("Compose ownership preflight rejected the mutation: %s", exc)
        return LabResult(success=False, error=_PRE_MUTATION_CONFLICT)

    def _owned_up_command(
        self,
        profiles: list[str],
        *,
        scope: _OwnedStartScope,
        build: bool,
        exclude_services: tuple[str, ...],
        only_services: tuple[str, ...],
        scenario_root: Path | None,
    ) -> list[str]:
        """Build the final Compose command from prepared scoped inputs."""

        command = self._build_command(
            "up",
            profiles,
            compose_files=scope.compose_files,
            scenario_root=scenario_root,
        )
        if build:
            command.append("--build")
        if self._offline_staged:
            command.extend(["--pull", "never", "--no-build"])
        command.append("-d")
        for service in exclude_services:
            command.extend(["--scale", f"{service}=0"])
        command.extend(only_services)
        log.info("Starting lab with profiles: %s", profiles)
        log.debug("Command: %s", " ".join(command))
        return command

    def _capture_started_resources(
        self, scope: _OwnedStartScope, profiles: list[str]
    ) -> LabResult:
        """Record all Compose resources, or roll the whole attempt back.

        Rollback cannot be limited to what was receipted, because the failure
        mode is receipting itself: the first container receipt, a network
        capture, or a volume capture can fail after Compose created the object,
        and an object with no receipt was invisible to the old container-only
        rollback. The next preflight then found unreceipted objects in the
        namespace, classified it foreign, and the workspace could neither start
        nor clean up without manual Docker surgery (issue #1105).

        Compose labelled everything it made with this attempt's project, and
        preflight already established that project is ours, so `down` is the
        complete and correctly-scoped undo.
        """

        try:
            self._record_compose_container_receipts(
                scope.ownership,
                daemon_id=scope.daemon_id,
                attempt_id=scope.attempt_id,
                semantic_by_service=scope.semantic_by_service,
            )
            self._record_compose_network_receipts(
                scope.ownership,
                daemon_id=scope.daemon_id,
                attempt_id=scope.attempt_id,
            )
            self._record_compose_volume_receipts(
                scope.ownership,
                daemon_id=scope.daemon_id,
                attempt_id=scope.attempt_id,
            )
        except OwnershipConflictError as exc:
            log.exception("Compose post-start ownership capture failed: %s", exc)
            self._roll_back_started_project(scope, profiles)
            return LabResult(
                success=False,
                error=(
                    "Backend resource ownership could not be verified after "
                    "Compose start."
                ),
            )
        log.info("Lab started successfully")
        return LabResult(success=True, message="Lab started")

    def _roll_back_started_project(
        self, scope: _OwnedStartScope, profiles: list[str]
    ) -> None:
        """Undo everything this attempt started, receipted or not."""

        try:
            self._run(
                [
                    *self._build_command(
                        "down", profiles, compose_files=scope.compose_files
                    ),
                    "--volumes",
                    "--remove-orphans",
                ],
                timeout=300,
            )
        except (OSError, ValueError):
            log.exception("Compose rollback of a failed start did not complete")
        # Receipted containers may include directly-run resources Compose does
        # not know about, so this still runs — now as the remainder, not the
        # whole rollback.
        self._remove_owned_attempt_containers(scope.attempt_id)

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
        """Return base Compose files plus the optional build-dedupe override."""

        root = scenario_root if scenario_root is not None else self._project_dir
        override = write_duplicate_build_override(root) if build else None
        files = (root / _COMPOSE_FILE,)
        return (*files, override) if override is not None else files
