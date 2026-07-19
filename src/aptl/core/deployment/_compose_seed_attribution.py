"""Compose-project attribution for seeded named volumes (issue #677).

Split from :mod:`aptl.core.deployment.docker_compose` (python:S104). A bare
``docker run -v`` auto-creates a missing named volume without labels; Compose
happily reuses it, but the content observation gate
(``observe_content_type``) refuses a volume it cannot attribute to the
project — so every seeded volume must carry the same labels Compose itself
would have written, established before the first seeding container runs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from aptl.core.deployment._compose_seed_safety import redacted_stderr_hint
from aptl.core.deployment.errors import BackendSeedError
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    import subprocess

    from aptl.core.seed_spec import NamedVolumeSeed

log = get_logger("deployment")

_SEED_TIMEOUT = 600


class ComposeSeedAttributionMixin:
    """Ensure seeded named volumes carry Compose project attribution."""

    _project_name: str

    def _run(
        self, cmd: list[str], *, timeout: int | None = None
    ) -> "subprocess.CompletedProcess":
        """Provided by the composing backend."""
        raise NotImplementedError

    def _content_volume_owned_by_project(
        self, raw_labels: str, logical_volume: str
    ) -> bool:
        """Provided by the composing backend."""
        raise NotImplementedError

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
