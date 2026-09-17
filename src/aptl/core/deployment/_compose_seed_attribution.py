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
        ownership = self._ensure_resource_ownership()
        attempt_id = self._resource_attempt_id
        if attempt_id is None:
            raise BackendSeedError("Backend attempt identity is unavailable")
        volume = f"{self._project_name}_{seed.volume_suffix}"
        inspect = self._run(
            ["docker", "volume", "inspect", volume, "--format", "{{json .Labels}}"],
            timeout=_SEED_TIMEOUT,
        )
        if inspect.returncode == 0:
            self._verify_existing_seed_volume(seed, volume, inspect.stdout)
        else:
            self._create_seed_volume(
                seed, volume, ownership=ownership, attempt_id=attempt_id
            )

    def _verify_existing_seed_volume(
        self, seed: NamedVolumeSeed, volume: str, raw_labels: str
    ) -> None:
        """Accept one existing seed volume only through its receipt and labels."""

        try:
            self._resolve_owned_volume_name(volume)
        except OwnershipConflictError as exc:
            raise BackendSeedError(
                f"Named volume '{seed.volume_suffix}' has no verified ownership receipt"
            ) from exc
        if self._content_volume_owned_by_project(raw_labels, seed.volume_suffix):
            return
        log.error(
            "Named volume %s exists without Compose project attribution. "
            "Remove it with `docker volume rm %s` (seeded content is "
            "recreated from checked-in sources) and rerun `aptl lab start`.",
            volume,
            volume,
        )
        raise BackendSeedError(
            f"Named volume '{seed.volume_suffix}' exists without Compose project attribution"
        )

    def _create_seed_volume(
        self,
        seed: NamedVolumeSeed,
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
            f"com.docker.compose.volume={seed.volume_suffix}",
        ]
        for label, value in ownership.labels(attempt_id=attempt_id).items():
            command.extend(["--label", f"{label}={value}"])
        command.append(volume)
        create = self._run(command, timeout=_SEED_TIMEOUT)
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
        if create.stdout.strip() != volume:
            raise BackendSeedError(
                f"Creating named volume '{seed.volume_suffix}' returned no identity"
            )
        info = self._inspect_created_seed_volume(seed, volume)
        observed_labels = info.get("Labels") if isinstance(info, dict) else None
        expected_labels = {
            "com.docker.compose.project": self._project_name,
            "com.docker.compose.volume": seed.volume_suffix,
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
                f"Named volume '{seed.volume_suffix}' ownership could not be verified"
            )
        try:
            ownership.record(
                ResourceReceipt(
                    kind="volume",
                    native_id=volume,
                    external_name=volume,
                    semantic_name=seed.volume_suffix,
                    node_address=seed.volume_suffix,
                    workspace_id=ownership.workspace_id,
                    project_name=ownership.project_name,
                    daemon_id=self._ownership_daemon_id(),
                    attempt_id=attempt_id,
                    managed_by="direct",
                )
            )
        except OwnershipConflictError as exc:
            raise BackendSeedError(
                f"Could not record ownership for named volume '{seed.volume_suffix}'"
            ) from exc

    def _inspect_created_seed_volume(
        self, seed: NamedVolumeSeed, volume: str
    ) -> dict[str, object]:
        """Re-inspect a created volume without converting uncertainty to absence."""

        try:
            return self._raw_volume_inspect(volume)
        except OwnershipConflictError as exc:
            raise BackendSeedError(
                f"Named volume '{seed.volume_suffix}' ownership is uninspectable"
            ) from exc
