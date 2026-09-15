"""Verified retirement receipts for run-to-completion Compose nodes."""

from __future__ import annotations

from aptl.core.deployment._compose_service_health import (
    container_completed_successfully,
    runtime_expects_completion,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.observation import (
    CompletedContainerReceipt,
    DeploymentObservationContext,
)
from aptl.core.deployment.realization import DeploymentRealizationSpec

_REMOVE_TIMEOUT = 90
_OS_RELEASE_PATH = "/etc/os-release"
_OS_RELEASE_LIMIT = 64 * 1024


class ComposeAutoremoveMixin:
    """Realize ``autoremove`` after observing successful job completion."""

    def _retire_completed_autoremove_nodes(
        self,
        realization: DeploymentRealizationSpec,
        observation_context: DeploymentObservationContext,
    ) -> list[str]:
        """Remove declared one-shot containers and retain bounded readback proof.

        Compose has no service-level equivalent of ``docker run --rm``.  The
        backend therefore waits for a zero exit, captures only evidence needed
        by the post-apply gate, removes the exact project-owned container, and
        records a receipt only after Docker confirms that name is absent.
        """

        image_addresses = {image.address for image in realization.images}
        for node in realization.nodes:
            name = node.container_name
            if not name or not runtime_expects_completion(node.runtime):
                continue
            failure = self._retire_completed_autoremove_node(
                name,
                node.os,
                observation_context,
                require_image_digest=node.address in image_addresses,
                require_image_config_id=node.dynamic_composition,
            )
            if failure is not None:
                return [failure]
        return []

    def _retire_completed_autoremove_node(
        self,
        name: str,
        os_family: str,
        observation_context: DeploymentObservationContext,
        *,
        require_image_digest: bool,
        require_image_config_id: bool,
    ) -> str | None:
        """Retire one exact project container, returning a bounded failure."""

        try:
            if not self.container_exists(name):
                return f"container {name!r} is not owned by this Compose project"
            info = self.container_inspect(name)
            if not container_completed_successfully(info):
                return f"container {name!r} did not complete successfully"
            image_digest = self.container_image_digest(name)
            if require_image_digest and image_digest is None:
                return f"container {name!r} image identity could not be observed"
            image_config_id = (
                self.container_image_config_id(name)
                if require_image_config_id
                else None
            )
            if require_image_config_id and image_config_id is None:
                return f"container {name!r} substrate identity could not be observed"
            files: dict[str, bytes] = {}
            if os_family:
                os_release = self.container_file_read(
                    name,
                    _OS_RELEASE_PATH,
                    max_bytes=_OS_RELEASE_LIMIT,
                )
                if os_release is None:
                    return f"container {name!r} operating system could not be observed"
                files[_OS_RELEASE_PATH] = os_release
            result = self._run(["docker", "rm", name], timeout=_REMOVE_TIMEOUT)
            if result.returncode != 0:
                return f"container {name!r} could not be auto-removed"
            if self.container_inspect(name):
                return f"container {name!r} remained after auto-remove"
        except (BackendTimeoutError, OSError):
            return f"container {name!r} auto-remove observation failed"

        observation_context.record_completed_autoremove(
            name,
            CompletedContainerReceipt(
                inspect=info,
                image_digest=image_digest,
                image_config_id=image_config_id,
                files=files,
            ),
        )
        return None


__all__ = ["ComposeAutoremoveMixin"]
