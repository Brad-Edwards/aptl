"""Docker Compose named-volume seed execution (ADR-043).

Split out of ``docker_compose.py`` (module-length budget). Materializes
checked-in source into Compose named volumes via short-lived root containers
run through the backend's own ``_run``, so this stays a narrow, typed
operation rather than a generic Docker passthrough. Depends on
``ComposeSeedAttributionMixin`` for volume labeling (``_ensure_labeled_seed_volume``).
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import PurePosixPath

from aptl.core.deployment._compose_seed_safety import (
    assert_safe_relpath,
    redacted_stderr_hint,
)
from aptl.core.deployment.errors import BackendSeedError
from aptl.core.seed_spec import NamedVolumeSeed
from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")
_SEED_TIMEOUT = 600


class ComposeSeedExecutionMixin(object):
    """Copy checked-in seed content into project-scoped named volumes."""

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

    @staticmethod
    def _build_seed_script(seed: NamedVolumeSeed) -> str:
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
