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
from aptl.core.ephemeral_containers import remove_container_command

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

        receipt = None
        try:
            receipt, failure = self._completed_autoremove_receipt(
                name,
                os_family,
                require_image_digest=require_image_digest,
                require_image_config_id=require_image_config_id,
            )
            if failure is None:
                failure = self._remove_completed_container(name)
        except (BackendTimeoutError, OSError):
            failure = f"container {name!r} auto-remove observation failed"

        if failure is None and receipt is not None:
            observation_context.record_completed_autoremove(name, receipt)
        return failure

    def _completed_autoremove_receipt(
        self,
        name: str,
        os_family: str,
        *,
        require_image_digest: bool,
        require_image_config_id: bool,
    ) -> tuple[CompletedContainerReceipt | None, str | None]:
        """Capture all required readback before removing one completed node."""

        receipt = None
        failure = None
        if not self.container_exists(name):
            failure = f"container {name!r} is not owned by this Compose project"
        else:
            info = self.container_inspect(name)
            if not container_completed_successfully(info):
                failure = f"container {name!r} did not complete successfully"
            else:
                identities, failure = self._required_image_identities(
                    name,
                    require_digest=require_image_digest,
                    require_config_id=require_image_config_id,
                )
                files, file_failure = self._required_os_files(name, os_family)
                failure = failure or file_failure
                if failure is None:
                    receipt = CompletedContainerReceipt(
                        inspect=info,
                        image_digest=identities[0],
                        image_config_id=identities[1],
                        files=files,
                    )
        return receipt, failure

    def _required_image_identities(
        self, name: str, *, require_digest: bool, require_config_id: bool
    ) -> tuple[tuple[str | None, str | None], str | None]:
        """Read required image identities and report the first absent value."""

        digest = self.container_image_digest(name)
        config_id = self.container_image_config_id(name) if require_config_id else None
        failure = None
        if require_digest and digest is None:
            failure = f"container {name!r} image identity could not be observed"
        elif require_config_id and config_id is None:
            failure = f"container {name!r} substrate identity could not be observed"
        return (digest, config_id), failure

    def _required_os_files(
        self, name: str, os_family: str
    ) -> tuple[dict[str, bytes], str | None]:
        """Capture os-release only when the realization selected an OS family."""

        files: dict[str, bytes] = {}
        failure = None
        if os_family:
            payload = self.container_file_read(
                name, _OS_RELEASE_PATH, max_bytes=_OS_RELEASE_LIMIT
            )
            if payload is None:
                failure = f"container {name!r} operating system could not be observed"
            else:
                files[_OS_RELEASE_PATH] = payload
        return files, failure

    def _remove_completed_container(self, name: str) -> str | None:
        """Remove one exact container and verify that it is absent."""

        result = self._run(
            remove_container_command(
                self._resolve_owned_container_id(name), force=False
            ),
            timeout=_REMOVE_TIMEOUT,
        )
        failure = None
        if result.returncode != 0:
            failure = f"container {name!r} could not be auto-removed"
        elif self.container_inspect(name):
            failure = f"container {name!r} remained after auto-remove"
        return failure


__all__ = ["ComposeAutoremoveMixin"]
