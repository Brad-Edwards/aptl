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
from aptl.core.deployment._compose_resource_ownership import (
    OwnershipConflictError,
    ResourceReceipt,
    WorkspaceOwnership,
)
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

        self._ensure_labeled_project_volume(seed.volume_suffix)

    def _ensure_labeled_project_volume(self, logical_volume: str) -> None:
        """Create or verify one receipt-owned Compose-compatible volume.

        Generic base containers and seed containers both use ``docker run -v``.
        Docker would otherwise auto-create a missing volume without labels or an
        ownership receipt, making a later Compose preflight correctly classify
        the same project-scoped name as foreign.
        """

        with self._project_volume_lock:
            self._ensure_labeled_project_volume_locked(logical_volume)

    def _ensure_labeled_project_volume_locked(self, logical_volume: str) -> None:
        """Inspect/create/receipt one volume as an indivisible local operation."""

        ownership = self._ensure_resource_ownership()
        attempt_id = self._resource_attempt_id
        if attempt_id is None:
            raise BackendSeedError("Backend attempt identity is unavailable")
        volume = f"{self._project_name}_{logical_volume}"
        inspect = self._run(
            ["docker", "volume", "inspect", volume, "--format", "{{json .Labels}}"],
            timeout=_SEED_TIMEOUT,
        )
        if inspect.returncode == 0:
            self._verify_existing_project_volume(logical_volume, volume, inspect.stdout)
        else:
            self._create_project_volume(
                logical_volume, volume, ownership=ownership, attempt_id=attempt_id
            )

    def _verify_existing_project_volume(
        self, logical_volume: str, volume: str, raw_labels: str
    ) -> None:
        """Accept one existing project volume only through its receipt and labels."""

        try:
            self._resolve_owned_volume_name(volume)
        except OwnershipConflictError as exc:
            raise BackendSeedError(
                f"Named volume '{logical_volume}' has no verified ownership receipt"
            ) from exc
        if self._content_volume_owned_by_project(raw_labels, logical_volume):
            return
        log.error(
            "Named volume %s exists without Compose project attribution. "
            "Remove it with `docker volume rm %s` (seeded content is "
            "recreated from checked-in sources) and rerun `aptl lab start`.",
            volume,
            volume,
        )
        raise BackendSeedError(
            f"Named volume '{logical_volume}' exists without Compose project attribution"
        )

    def _create_project_volume(
        self,
        logical_volume: str,
        volume: str,
        *,
        ownership: WorkspaceOwnership,
        attempt_id: str,
    ) -> None:
        """Create, re-inspect, and receipt one missing seed volume."""

        command = [
            "docker",
            "volume",
            "create",
            "--label",
            f"com.docker.compose.project={self._project_name}",
            "--label",
            f"com.docker.compose.volume={logical_volume}",
        ]
        for label, value in ownership.labels(attempt_id=attempt_id).items():
            command.extend(["--label", f"{label}={value}"])
        command.append(volume)
        create = self._run(command, timeout=_SEED_TIMEOUT)
        if create.returncode != 0:
            log.error(
                "Labeled create of volume %s failed (exit %s)%s",
                logical_volume,
                create.returncode,
                redacted_stderr_hint(create.stderr),
            )
            raise BackendSeedError(f"Creating named volume '{logical_volume}' failed")
        if create.stdout.strip() != volume:
            raise BackendSeedError(
                f"Creating named volume '{logical_volume}' returned no identity"
            )
        info = self._inspect_created_project_volume(logical_volume, volume)
        observed_labels = info.get("Labels") if isinstance(info, dict) else None
        expected_labels = {
            "com.docker.compose.project": self._project_name,
            "com.docker.compose.volume": logical_volume,
            **ownership.labels(attempt_id=attempt_id),
        }
        if (
            info.get("Name") != volume
            or not isinstance(observed_labels, dict)
            or any(
                observed_labels.get(label) != value
                for label, value in expected_labels.items()
            )
        ):
            raise BackendSeedError(
                f"Named volume '{logical_volume}' ownership could not be verified"
            )
        try:
            ownership.record(
                ResourceReceipt(
                    kind="volume",
                    native_id=volume,
                    external_name=volume,
                    semantic_name=logical_volume,
                    node_address=logical_volume,
                    workspace_id=ownership.workspace_id,
                    project_name=ownership.project_name,
                    daemon_id=self._ownership_daemon_id(),
                    attempt_id=attempt_id,
                    managed_by="direct",
                )
            )
        except OwnershipConflictError as exc:
            raise BackendSeedError(
                f"Could not record ownership for named volume '{logical_volume}'"
            ) from exc

    def _inspect_created_project_volume(
        self, logical_volume: str, volume: str
    ) -> dict[str, object]:
        """Re-inspect a created volume without converting uncertainty to absence."""

        try:
            return self._raw_volume_inspect(volume)
        except OwnershipConflictError as exc:
            raise BackendSeedError(
                f"Named volume '{logical_volume}' ownership is uninspectable"
            ) from exc
