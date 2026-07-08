"""Docker Compose content-placement realization helpers.

Materializes ACES ``content-placement`` resources onto already-started
containers (ADR-046 content addendum). Directories are created with a
``docker exec mkdir -p``; source-backed files are copied from their
project-contained repo path, and inline/dataset content is written to a
project-contained temp file that is removed once the copy completes. Content is
streamed onto the container with ``docker cp``, which reads the host-side source
and pushes it to the daemon over the Engine API; this works identically for a
local daemon and for the SSH backend's remote daemon, so no shared filesystem is
assumed. The container name and target path travel as argv and the content
travels through the copied file, so no authored value is interpolated into shell
text. Both the local and SSH Compose backends share this behavior through the
inherited ``_run`` runner (ADR-037).
"""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath

from aptl.core.deployment.realization import (
    DeploymentContentPlacement,
    DeploymentRealizationSpec,
)
from aptl.core.lab_types import LabResult
from aptl.utils.logging import get_logger

log = get_logger("deployment.content_realization")

# Content copy/mkdir into a running container is a handful of small argv
# calls; the margin is deliberately generous for a busy daemon.
_CONTENT_REALIZATION_TIMEOUT = 120
_CONTENT_STAGING_DIR = Path(".aptl") / "realization" / "content"


class ComposeRealizationContentMixin:
    """Realize typed content placements through Docker Compose."""

    def _realize_content(
        self,
        realization: DeploymentRealizationSpec,
    ) -> LabResult | None:
        """Materialize each content placement; stop at the first failure."""

        for placement in realization.content:
            result = self._realize_one_content(placement)
            if result is not None:
                return result
        return None

    def _realize_one_content(
        self,
        placement: DeploymentContentPlacement,
    ) -> LabResult | None:
        """Route one content placement to its type-specific materializer."""

        if placement.content_type == "directory":
            return self._realize_content_directory(placement)
        return self._realize_content_file(placement)

    def _realize_content_directory(
        self,
        placement: DeploymentContentPlacement,
    ) -> LabResult | None:
        """Create the authored directory on the target container."""

        result = self._run(
            ["docker", "exec", placement.container_name, "mkdir", "-p", placement.target_path],
            timeout=_CONTENT_REALIZATION_TIMEOUT,
        )
        return self._content_failure(placement) if result.returncode != 0 else None

    def _realize_content_file(
        self,
        placement: DeploymentContentPlacement,
    ) -> LabResult | None:
        """Copy inline/source/dataset bytes onto the target container path."""

        if placement.source_path is not None:
            source = self._project_dir / placement.source_path
            if not source.is_file():
                return self._content_failure(placement)
            return self._copy_content_file(placement, source)
        if placement.content_text is not None:
            return self._copy_staged_content(placement)
        return self._content_failure(placement)

    def _copy_staged_content(
        self,
        placement: DeploymentContentPlacement,
    ) -> LabResult | None:
        """Stage inline/dataset bytes to a temp file, copy them, then remove it."""

        staged = self._stage_content_text(placement)
        try:
            return self._copy_content_file(placement, staged)
        finally:
            staged.unlink(missing_ok=True)

    def _copy_content_file(
        self,
        placement: DeploymentContentPlacement,
        source: Path,
    ) -> LabResult | None:
        """Create the target parent and copy one host file into the container."""

        parent = str(PurePosixPath(placement.target_path).parent)
        made = self._run(
            ["docker", "exec", placement.container_name, "mkdir", "-p", parent],
            timeout=_CONTENT_REALIZATION_TIMEOUT,
        )
        if made.returncode != 0:
            return self._content_failure(placement)
        copied = self._run(
            [
                "docker",
                "cp",
                str(source),
                f"{placement.container_name}:{placement.target_path}",
            ],
            timeout=_CONTENT_REALIZATION_TIMEOUT,
        )
        return self._content_failure(placement) if copied.returncode != 0 else None

    def _stage_content_text(
        self,
        placement: DeploymentContentPlacement,
    ) -> Path:
        """Write inline/dataset content to a contained, digest-named temp file.

        The file is removed by :meth:`_copy_staged_content` once ``docker cp``
        has streamed it into the container, so no staged content persists in the
        project tree after realization.
        """

        data = placement.content_text.encode("utf-8")
        digest = placement.digest or hashlib.sha256(data).hexdigest()
        staging_dir = self._project_dir / _CONTENT_STAGING_DIR
        staging_dir.mkdir(parents=True, exist_ok=True)
        staged = staging_dir / digest
        staged.write_bytes(data)
        return staged

    def _content_failure(
        self,
        placement: DeploymentContentPlacement,
    ) -> LabResult:
        """Return a name-only content-realization failure (no raw stderr)."""

        log.error(
            "Content realization failed for %s on %s",
            placement.address,
            placement.container_name,
        )
        return LabResult(
            success=False,
            error=f"Content realization failed for ACES content {placement.address}.",
        )
