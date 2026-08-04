"""Compose file-set assembly, content delivery and model validation (issue #875).

Split out of ``_compose_realization.py`` (module-length budget): the stage of
realization that turns an admitted spec into the concrete set of Compose files
``compose up`` will be run with -- the generated base plus the port, stateful and
content overrides -- delivers content that is not carried by an override, and
validates the resulting effective model before anything is started.

The orchestration that sequences these stages stays in ``_compose_realization``;
this module owns only the file-set and model concerns.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from aptl.core.deployment._compose_content_realization import CONTENT_SEEDER_IMAGE
from aptl.core.deployment._compose_node_generation import (
    STATIC_COMPOSE_FILENAME,
    base_compose_file,
)
from aptl.core.deployment._compose_port_realization import write_port_override
from aptl.core.deployment._compose_stateful_realization import (
    effective_stateful_model_errors,
)
from aptl.core.deployment.errors import BackendSeedError, BackendTimeoutError
from aptl.core.deployment.realization import DeploymentRealizationSpec
from aptl.core.lab_types import LabResult

_COMPOSE_MODEL_VALIDATION_ERROR = "Generated Compose model validation failed."
_CONTENT_OVERRIDE_RELATIVE_PATH = Path(".aptl") / "realization" / "compose.content.yml"


class ComposeRealizationModelMixin:
    """Assemble, populate and validate the generated Compose model."""

    def _realization_compose_files(
        self,
        compose_files: tuple[Path, ...] | None,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
        realization_root: Path | None = None,
    ) -> tuple[Path, ...] | None:
        """Add generated realization overrides to the Compose file set.

        A static in-tree ``docker-compose.yml`` is read from ``scenario_root``;
        the generated base and overrides are written under ``realization_root``
        (the writable engine checkout), never the pristine pack (issue #875).
        ``realization_root`` defaults to ``scenario_root`` so in-tree, where the
        two coincide, is unchanged.
        """

        realization_root = realization_root or scenario_root
        port_override = write_port_override(realization_root, realization)
        stateful_override = self._write_stateful_realization_override(
            realization, realization_root
        )
        content_override = self._write_image_node_content_override(
            realization, scenario_root, realization_root
        )
        overrides = tuple(
            path
            for path in (port_override, stateful_override, content_override)
            if path is not None
        )
        if not overrides:
            return compose_files
        base_files = compose_files or (
            base_compose_file(realization, scenario_root, realization_root),
        )
        return (*base_files, *overrides)

    def _write_image_node_content_override(
        self,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
        realization_root: Path,
    ) -> Path | None:
        """Write a Compose override bind-mounting image nodes' declared content.

        Content bytes are resolved from the pack (``scenario_root``) and written
        under ``realization_root``; image-free content is delivered by the
        generic materializer, not here (issue #875).
        """

        from aptl.core.deployment._compose_content_mounts import (
            image_node_content_override,
        )

        # In-tree, a static docker-compose.yml already bind-mounts image-node
        # config and seed volumes deliver the rest, so no generated override is
        # needed; only a generated (env-pack) base needs image-node content bound
        # in (issue #875).
        if (scenario_root / STATIC_COMPOSE_FILENAME).exists():
            return None
        payload = image_node_content_override(
            realization, scenario_root, realization_root
        )
        if not payload["services"]:
            return None
        override_path = realization_root / _CONTENT_OVERRIDE_RELATIVE_PATH
        override_path.parent.mkdir(parents=True, exist_ok=True)
        override_path.write_text(
            yaml.safe_dump(payload, sort_keys=True), encoding="utf-8", newline="\n"
        )
        return override_path

    def _realize_content(
        self,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
    ) -> LabResult | None:
        """Materialize typed content placements; fail closed on any seed error.

        Returns ``None`` on success (or when there is nothing to realize) so
        the caller's ``result is None`` chain continues to the next step,
        matching the existing image/network step shape.
        """

        content = realization.content
        # For a generated (env-pack) base, image-node content is delivered as
        # Compose bind mounts, not seeded volumes, so it must not also be seeded
        # here (which would re-resolve and stage bytes into the pristine pack).
        # In-tree keeps the original seed path for every content item (issue #875).
        if not (scenario_root / STATIC_COMPOSE_FILENAME).exists():
            imaged = {image.address for image in realization.images}
            content = tuple(
                item for item in content if item.target_address not in imaged
            )
        if not content:
            return None
        try:
            self.realize_content(
                content,
                seeder_image=CONTENT_SEEDER_IMAGE,
                scenario_root=scenario_root,
            )
        except (BackendSeedError, BackendTimeoutError) as exc:
            return LabResult(
                success=False,
                error=f"Content placement realization failed: {exc}",
            )
        return None

    def _validate_realization_compose_model(
        self,
        profiles: list[str],
        compose_files: tuple[Path, ...] | None,
        realization: DeploymentRealizationSpec,
        scenario_root: Path,
        realization_root: Path | None = None,
    ) -> LabResult | None:
        """Render and inspect the effective generated model before startup.

        ``scenario_root`` is Compose's ``--project-directory`` (relative-path
        resolution); ``realization_root`` is where generated artifacts and their
        mount sources actually live, so the *expected* mounts must be computed
        against it, not the pristine pack (issue #875). They coincide in-tree.
        """

        realization_root = realization_root or scenario_root
        if compose_files is None:
            return None
        command = self._build_command(
            "config",
            profiles,
            compose_files=compose_files,
            scenario_root=scenario_root,
        )
        stateful = bool(
            realization.generated_artifacts or realization.persistent_volumes
        )
        error = (
            self._effective_compose_model_error(command, realization, realization_root)
            if stateful
            else self._compose_syntax_error(command)
        )
        return LabResult(success=False, error=error) if error is not None else None

    def _compose_syntax_error(self, command: list[str]) -> str | None:
        """Return a bounded error when Compose rejects a stateless model."""

        command.append("--quiet")
        result = self._run(command)
        return _COMPOSE_MODEL_VALIDATION_ERROR if result.returncode != 0 else None

    def _effective_compose_model_error(
        self,
        command: list[str],
        realization: DeploymentRealizationSpec,
        realization_root: Path,
    ) -> str | None:
        """Render and validate a stateful model without interpolating secrets.

        ``realization_root`` is where generated artifacts and their mount sources
        live; the expected-mount set is computed against it so it matches the
        override that was actually written (issue #875).
        """

        command.extend(["--no-interpolate", "--format", "json"])
        result = self._run(command)
        if result.returncode != 0:
            return _COMPOSE_MODEL_VALIDATION_ERROR
        try:
            payload = json.loads(result.stdout)
        except (TypeError, ValueError):
            return _COMPOSE_MODEL_VALIDATION_ERROR
        errors = effective_stateful_model_errors(
            payload,
            realization_root,
            self.project_name,
            realization,
        )
        return "; ".join(errors[:5]) if errors else None
