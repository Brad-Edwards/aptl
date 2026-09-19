"""Receipt-backed resolution and mutation helpers for Compose resources."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from aptl.core.deployment._compose_resource_ownership import (
    OwnershipConflictError,
    ResourceReceipt,
    WorkspaceOwnership,
)
from aptl.core.deployment.errors import BackendSeedError, BackendTimeoutError

if TYPE_CHECKING:
    import subprocess

    from aptl.core.deployment._compose_base_substrate import BaseContainerSpec
    from aptl.core.deployment.realization import (
        DeploymentNetworkRealization,
        DeploymentSpawnImageRequirement,
    )

_DOCKER_TIMEOUT = 30
_COMPOSE_PROJECT_LABEL = "com.docker.compose.project"


class ComposeResourceResolutionMixin:
    """Resolve daemon-native resources only through durable receipts."""

    def _load_resource_ownership(self) -> WorkspaceOwnership | None:
        """Load an existing workspace scope without publishing new state."""

        ownership = self._resource_ownership
        if ownership is None:
            ownership = WorkspaceOwnership.load(
                self._project_dir, self._logical_project_name
            )
            if ownership is not None:
                self._resource_ownership = ownership
                self._project_name = ownership.project_name
        return ownership

    def _ensure_resource_ownership(
        self, *, attempt_id: str | None = None
    ) -> WorkspaceOwnership:
        """Load the durable workspace scope before backend mutation."""

        ownership = self._load_resource_ownership()
        if ownership is None:
            ownership = WorkspaceOwnership.ensure(
                self._project_dir, self._logical_project_name
            )
            self._resource_ownership = ownership
            self._project_name = ownership.project_name
        if attempt_id is not None:
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
            selector, kind="container", daemon_id=self._ownership_daemon_id()
        )
        if not candidates:
            raise OwnershipConflictError("container ownership is unrecorded")
        verified = tuple(
            receipt.native_id
            for receipt in candidates
            if self._container_receipt_is_current(ownership, receipt)
        )
        if len(verified) != 1:
            raise OwnershipConflictError("container ownership is absent or ambiguous")
        return verified[0]

    def _container_receipt_is_current(
        self, ownership: WorkspaceOwnership, receipt: ResourceReceipt
    ) -> bool:
        """Verify one recorded container against its current daemon object."""

        info = self._raw_container_inspect(receipt.native_id)
        if not info:
            return False
        if info.get("Id") != receipt.native_id:
            raise OwnershipConflictError("container native identity changed")
        config = info.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        isolated_child = bool(
            receipt.managed_by == "child"
            and getattr(self, "_attempt_isolated_docker_daemon", False)
        )
        if not isolated_child and not self._workspace_labels_match(ownership, labels):
            raise OwnershipConflictError("container ownership labels changed")
        observed_name = str(info.get("Name", "")).removeprefix("/")
        if observed_name != receipt.external_name:
            raise OwnershipConflictError("container semantic binding changed")
        return True

    @staticmethod
    def _workspace_labels_match(ownership: WorkspaceOwnership, labels: object) -> bool:
        """Return whether labels carry this workspace's immutable scope."""

        return bool(
            isinstance(labels, dict)
            and labels.get("aptl.workspace.id") == ownership.workspace_id
            and labels.get("aptl.lifecycle.project") == ownership.project_name
        )

    def _resolve_owned_network_id(self, selector: str) -> str:
        """Resolve one recorded network to its freshly verified Docker ID."""

        ownership = self._ensure_resource_ownership()
        candidates = ownership.candidates(
            selector, kind="network", daemon_id=self._ownership_daemon_id()
        )
        verified = tuple(
            receipt.native_id
            for receipt in candidates
            if self._network_receipt_is_current(ownership, receipt)
        )
        if len(verified) != 1:
            raise OwnershipConflictError("network ownership is absent or ambiguous")
        return verified[0]

    def _network_receipt_is_current(
        self, ownership: WorkspaceOwnership, receipt: ResourceReceipt
    ) -> bool:
        """Verify one recorded network against its current daemon object."""

        info = self.host_inspect_network(receipt.native_id)
        if not info:
            return False
        labels = info.get("labels") if isinstance(info, dict) else None
        if (
            info.get("id") != receipt.native_id
            or info.get("name") != receipt.external_name
            or not isinstance(labels, dict)
            or labels.get(_COMPOSE_PROJECT_LABEL) != ownership.project_name
        ):
            raise OwnershipConflictError("network ownership binding changed")
        return True

    def _resolve_owned_volume_name(self, selector: str) -> str:
        """Resolve one recorded volume to its freshly verified Docker name."""

        ownership = self._ensure_resource_ownership()
        candidates = ownership.candidates(
            selector, kind="volume", daemon_id=self._ownership_daemon_id()
        )
        verified = tuple(
            receipt.native_id
            for receipt in candidates
            if self._volume_receipt_is_current(ownership, receipt)
        )
        if len(verified) != 1:
            raise OwnershipConflictError("volume ownership is absent or ambiguous")
        return verified[0]

    def _volume_receipt_is_current(
        self, ownership: WorkspaceOwnership, receipt: ResourceReceipt
    ) -> bool:
        """Verify one recorded volume against its current daemon object."""

        info = self._raw_volume_inspect(receipt.native_id)
        if not info:
            return False
        labels = info.get("Labels") if isinstance(info, dict) else None
        if (
            info.get("Name") != receipt.native_id
            or info.get("Name") != receipt.external_name
            or not isinstance(labels, dict)
            or labels.get(_COMPOSE_PROJECT_LABEL) != ownership.project_name
        ):
            raise OwnershipConflictError("volume ownership binding changed")
        return True

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
        """Remove recorded containers by verified native ID."""

        try:
            ownership = self._ensure_resource_ownership()
            receipts = tuple(
                receipt
                for receipt in ownership.receipts("container")
                if receipt.managed_by == managed_by
            )
            failures = []
            for receipt in receipts:
                if not self._raw_container_inspect(receipt.native_id):
                    continue
                native_id = self._resolve_owned_container_id(receipt.native_id)
                if self._run(["docker", "rm", "-f", native_id], timeout=60).returncode:
                    failures.append("failed to remove receipt-owned container")
            return failures
        except (OwnershipConflictError, OSError):
            return ["failed to establish container cleanup authority"]

    def _remove_owned_volumes(self) -> list[str]:
        """Remove only receipt-owned volumes that still verify on this daemon."""

        try:
            ownership = self._ensure_resource_ownership()
            failures = []
            for receipt in ownership.receipts("volume"):
                if not self._raw_volume_inspect(receipt.native_id):
                    continue
                volume = self._resolve_owned_volume_name(receipt.native_id)
                if self._run(
                    ["docker", "volume", "rm", volume], timeout=_DOCKER_TIMEOUT
                ).returncode:
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
        elif any(
            (
                self._scoped_compose_container_ids(),
                self._scoped_compose_network_ids(),
                self._scoped_compose_volume_names(),
            )
        ):
            raise OwnershipConflictError("backend daemon identity is unavailable")

    def _owned_base_container_id(
        self,
        spec: BaseContainerSpec,
        *,
        external_name: str,
        daemon_id: str,
    ) -> str | None:
        """Return one active receipt-owned base container or reject collision."""

        ownership = self._ensure_resource_ownership()
        candidates = ownership.candidates(
            spec.container_name, kind="container", daemon_id=daemon_id
        )
        active = tuple(
            receipt
            for receipt in candidates
            if self._raw_container_inspect(receipt.native_id)
        )
        if len(active) > 1:
            raise self._base_ownership_error(spec)
        if active:
            try:
                return self._resolve_owned_container_id(active[0].native_id)
            except OwnershipConflictError as exc:
                raise self._base_ownership_error(spec) from exc
        if not candidates and self._raw_container_inspect(external_name):
            raise self._base_ownership_error(spec)
        return None

    def start_base_container(self, spec: BaseContainerSpec) -> None:
        """Start or reuse one receipt-owned generic base container."""

        ownership = self._ensure_resource_ownership()
        attempt_id = self._resource_attempt_id
        assert attempt_id is not None
        daemon_id = self._ownership_daemon_id()
        external_name = ownership.container_name(spec.container_name)
        network_bindings = getattr(self, "_base_networks_by_address", {}).get(
            spec.node_address
        )
        run_image_ref = self._resolve_base_run_image(spec)
        existing_id = self._owned_base_container_id(
            spec, external_name=external_name, daemon_id=daemon_id
        )
        if existing_id is not None and self._base_container_already_realized(
            existing_id, run_image_ref
        ):
            return
        if (
            existing_id is not None
            and self._run(["docker", "rm", "-f", existing_id], timeout=30).returncode
        ):
            raise BackendSeedError(
                f"failed to recover owned base container for node {spec.node_address}"
            )
        command = self._base_container_create_command(
            spec,
            network_bindings,
            run_image_ref,
            external_name=external_name,
            ownership_labels=ownership.labels(attempt_id=attempt_id),
        )
        result = self._run(command, timeout=180)
        self._complete_base_container_start(
            spec,
            network_bindings,
            result,
            external_name=external_name,
            daemon_id=daemon_id,
            attempt_id=attempt_id,
        )

    @staticmethod
    def _base_ownership_error(spec: BaseContainerSpec) -> BackendSeedError:
        """Build the bounded base-container ownership error."""

        return BackendSeedError(
            f"backend resource ownership conflict for node {spec.node_address}"
        )

    def _record_started_base_container(
        self,
        spec: BaseContainerSpec,
        result: subprocess.CompletedProcess,
        *,
        external_name: str | None,
        daemon_id: str | None,
        attempt_id: str | None,
    ) -> str:
        """Record a successful direct base-container creation and return its ID."""

        native_id = str(result.stdout or "").strip() if result.returncode == 0 else ""
        if result.returncode != 0:
            return ""
        if not all((native_id, external_name, daemon_id, attempt_id)):
            raise BackendSeedError(
                f"native identity unavailable for node {spec.node_address}"
            )
        ownership = self._ensure_resource_ownership()
        try:
            ownership.record(
                ResourceReceipt(
                    kind="container",
                    native_id=native_id,
                    external_name=str(external_name),
                    semantic_name=spec.container_name,
                    node_address=spec.node_address,
                    workspace_id=ownership.workspace_id,
                    project_name=ownership.project_name,
                    daemon_id=str(daemon_id),
                    attempt_id=str(attempt_id),
                    managed_by="direct",
                )
            )
        except OwnershipConflictError as exc:
            self._run(["docker", "rm", "-f", native_id], timeout=30)
            raise BackendSeedError(
                f"failed to record ownership for node {spec.node_address}"
            ) from exc
        return native_id

    def _record_created_network(
        self,
        network: DeploymentNetworkRealization,
        *,
        native_id: str,
        external_name: str,
        attempt_id: str,
    ) -> None:
        """Record one directly created realization network."""

        ownership = self._ensure_resource_ownership()
        ownership.record(
            ResourceReceipt(
                kind="network",
                native_id=native_id,
                external_name=external_name,
                semantic_name=network.name,
                node_address=network.name,
                workspace_id=ownership.workspace_id,
                project_name=ownership.project_name,
                daemon_id=self._ownership_daemon_id(),
                attempt_id=attempt_id,
                managed_by="direct",
            )
        )

    def _record_isolated_child_receipts(
        self,
        container_ids: tuple[str, ...],
        requirement: DeploymentSpawnImageRequirement,
    ) -> None:
        """Bind children from an attempt-dedicated daemon to native IDs."""

        ownership = self._ensure_resource_ownership()
        daemon_id = self._ownership_daemon_id()
        attempt_id = self._resource_attempt_id
        if attempt_id is None:
            raise OwnershipConflictError("backend attempt identity is unavailable")
        for native_id in container_ids:
            info = self._raw_container_inspect(native_id)
            external_name = str(info.get("Name", "")).removeprefix("/")
            if info.get("Id") != native_id or not external_name:
                raise OwnershipConflictError("spawned-child native identity changed")
            ownership.record(
                ResourceReceipt(
                    kind="container",
                    native_id=native_id,
                    external_name=external_name,
                    semantic_name=requirement.template_id,
                    node_address=requirement.node_address,
                    workspace_id=ownership.workspace_id,
                    project_name=ownership.project_name,
                    daemon_id=daemon_id,
                    attempt_id=attempt_id,
                    managed_by="child",
                )
            )

    def _remove_owned_attempt_containers(self, attempt_id: str) -> None:
        """Best-effort rollback of IDs recorded for one failed attempt."""

        ownership = self._ensure_resource_ownership()
        for receipt in ownership.receipts("container"):
            if receipt.attempt_id != attempt_id:
                continue
            try:
                native_id = self._resolve_owned_container_id(receipt.native_id)
                self._run(["docker", "rm", "-f", native_id], timeout=60)
            except (OwnershipConflictError, OSError):
                continue
