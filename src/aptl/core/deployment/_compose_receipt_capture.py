"""Compose namespace discovery, preflight, and receipt capture."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from aptl.core.deployment._compose_resource_ownership import (
    OwnershipConflictError,
    ResourceReceipt,
    WorkspaceOwnership,
)

_DOCKER_TIMEOUT = 30
_COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
_AMBIGUOUS_OWNER = "Compose owner tuple is ambiguous"
_FOREIGN_NAMESPACE = "Compose namespace contains foreign state"


class ComposeReceiptCaptureMixin:
    """Discover resources by labels, then establish authority by receipt."""

    def _scoped_compose_container_ids(self) -> tuple[str, ...]:
        """Discover candidate container IDs inside the effective namespace."""

        return self._scoped_resource_values(
            [
                "docker",
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                f"label={_COMPOSE_PROJECT_LABEL}={self._project_name}",
            ],
            "Compose resource discovery failed",
        )

    def _scoped_compose_network_ids(self) -> tuple[str, ...]:
        """Discover candidate network IDs inside the effective namespace."""

        return self._scoped_resource_values(
            [
                "docker",
                "network",
                "ls",
                "--no-trunc",
                "--filter",
                f"label={_COMPOSE_PROJECT_LABEL}={self._project_name}",
                "--format",
                "{{.ID}}",
            ],
            "Compose network discovery failed",
        )

    def _scoped_compose_volume_names(self) -> tuple[str, ...]:
        """Discover candidate volume names inside the effective namespace."""

        return self._scoped_resource_values(
            [
                "docker",
                "volume",
                "ls",
                "--filter",
                f"label={_COMPOSE_PROJECT_LABEL}={self._project_name}",
                "--format",
                "{{.Name}}",
            ],
            "Compose volume discovery failed",
        )

    def _scoped_resource_values(
        self, command: list[str], error: str
    ) -> tuple[str, ...]:
        """Run one label-scoped inventory and return unique values."""

        result = self._run(command, timeout=_DOCKER_TIMEOUT)
        if result.returncode != 0:
            raise OwnershipConflictError(error)
        return tuple(
            dict.fromkeys(
                line.strip() for line in result.stdout.splitlines() if line.strip()
            )
        )

    def _verify_compose_namespace_is_owned(
        self,
        ownership: WorkspaceOwnership,
        daemon_id: str,
        *,
        expected: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        """Reject pre-existing namespace objects without immutable receipts."""

        inventories = (
            (
                "container",
                self._scoped_compose_container_ids(),
                self._resolve_owned_container_id,
            ),
            (
                "network",
                self._scoped_compose_network_ids(),
                self._resolve_owned_network_id,
            ),
            (
                "volume",
                self._scoped_compose_volume_names(),
                self._resolve_owned_volume_name,
            ),
        )
        for kind, selectors, resolver in inventories:
            self._verify_scoped_receipts(
                ownership,
                daemon_id=daemon_id,
                kind=kind,
                selectors=selectors,
                resolver=resolver,
            )
        if expected is not None:
            self._verify_expected_compose_resources(
                ownership, daemon_id=daemon_id, expected=expected
            )

    @staticmethod
    def _verify_scoped_receipts(
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        kind: str,
        selectors: Iterable[str],
        resolver: Callable[[str], str],
    ) -> None:
        """Require one receipt and a fresh resolver match per discovered object."""

        for selector in selectors:
            if len(ownership.candidates(selector, kind=kind, daemon_id=daemon_id)) != 1:
                raise OwnershipConflictError(_FOREIGN_NAMESPACE)
            resolver(selector)

    def _verify_expected_compose_resources(
        self,
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        expected: dict[str, tuple[str, ...]],
    ) -> None:
        """Reject exact-name collisions even when a foreign object has no labels."""

        self._verify_expected_containers(
            ownership, daemon_id=daemon_id, names=expected.get("container", ())
        )
        self._verify_expected_networks(
            ownership, daemon_id=daemon_id, names=expected.get("network", ())
        )
        self._verify_expected_volumes(
            ownership, daemon_id=daemon_id, names=expected.get("volume", ())
        )

    def _verify_expected_containers(
        self,
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        names: Iterable[str],
    ) -> None:
        """Reject an unreceipted exact container-name collision."""

        for external_name in names:
            info = self._raw_container_inspect(external_name)
            if not info:
                continue
            native_id = str(info.get("Id", ""))
            self._require_exact_receipt(
                ownership,
                daemon_id=daemon_id,
                kind="container",
                native_id=native_id,
                error="Compose container name is foreign",
            )
            self._resolve_owned_container_id(native_id)

    def _verify_expected_networks(
        self,
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        names: Iterable[str],
    ) -> None:
        """Reject an unreceipted exact network-name collision."""

        for external_name in names:
            info = self.host_inspect_network(external_name)
            if not info:
                continue
            native_id = str(info.get("id", ""))
            self._require_exact_receipt(
                ownership,
                daemon_id=daemon_id,
                kind="network",
                native_id=native_id,
                error="Compose network name is foreign",
            )
            self._resolve_owned_network_id(native_id)

    def _verify_expected_volumes(
        self,
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        names: Iterable[str],
    ) -> None:
        """Reject an unreceipted exact volume-name collision."""

        for external_name in names:
            if not self._raw_volume_inspect(external_name):
                continue
            self._require_exact_receipt(
                ownership,
                daemon_id=daemon_id,
                kind="volume",
                native_id=external_name,
                error="Compose volume name is foreign",
            )
            self._resolve_owned_volume_name(external_name)

    @staticmethod
    def _require_exact_receipt(
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        kind: str,
        native_id: str,
        error: str,
    ) -> None:
        """Require exactly one receipt for an observed exact-name object."""

        candidates = (
            ownership.candidates(native_id, kind=kind, daemon_id=daemon_id)
            if native_id
            else ()
        )
        if len(candidates) != 1:
            raise OwnershipConflictError(error)

    def _record_compose_container_receipts(
        self,
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        attempt_id: str,
        semantic_by_service: dict[str, str],
    ) -> None:
        """Capture native container IDs after Compose creation."""

        for native_id in self._scoped_compose_container_ids():
            if self._verify_existing_receipt(
                ownership,
                daemon_id=daemon_id,
                kind="container",
                native_id=native_id,
                resolver=self._resolve_owned_container_id,
            ):
                continue
            self._record_compose_container(
                ownership,
                native_id=native_id,
                daemon_id=daemon_id,
                attempt_id=attempt_id,
                semantic_by_service=semantic_by_service,
            )

    @staticmethod
    def _verify_existing_receipt(
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        kind: str,
        native_id: str,
        resolver: Callable[[str], str],
    ) -> bool:
        """Verify an existing receipt and report whether one was present."""

        existing = ownership.candidates(native_id, kind=kind, daemon_id=daemon_id)
        if not existing:
            return False
        if len(existing) != 1:
            raise OwnershipConflictError(_AMBIGUOUS_OWNER)
        resolver(native_id)
        return True

    def _record_compose_container(
        self,
        ownership: WorkspaceOwnership,
        *,
        native_id: str,
        daemon_id: str,
        attempt_id: str,
        semantic_by_service: dict[str, str],
    ) -> None:
        """Validate and record one newly observed Compose container."""

        info = self._raw_container_inspect(native_id)
        config = info.get("Config") if isinstance(info, dict) else None
        labels = config.get("Labels") if isinstance(config, dict) else None
        service = (
            labels.get("com.docker.compose.service")
            if isinstance(labels, dict)
            else None
        )
        if (
            not self._complete_owner_labels(
                ownership,
                labels,
                attempt_id=attempt_id,
                compose_kind="service",
                semantic_name=service,
            )
            or info.get("Id") != native_id
            or service not in semantic_by_service
        ):
            raise OwnershipConflictError("Compose owner tuple is incomplete")
        semantic_name = semantic_by_service[str(service)]
        external_name = str(info.get("Name", "")).removeprefix("/")
        node_address = (
            labels.get("aptl.node.address") if isinstance(labels, dict) else None
        )
        if external_name != ownership.container_name(semantic_name):
            raise OwnershipConflictError("Compose semantic binding changed")
        ownership.record(
            ResourceReceipt(
                kind="container",
                native_id=native_id,
                external_name=external_name,
                semantic_name=semantic_name,
                node_address=str(node_address or service),
                workspace_id=ownership.workspace_id,
                project_name=ownership.project_name,
                daemon_id=daemon_id,
                attempt_id=attempt_id,
                managed_by="compose",
            )
        )

    def _record_compose_network_receipts(
        self,
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        attempt_id: str,
    ) -> None:
        """Capture Compose-created network IDs."""

        for native_id in self._scoped_compose_network_ids():
            if self._verify_existing_receipt(
                ownership,
                daemon_id=daemon_id,
                kind="network",
                native_id=native_id,
                resolver=self._resolve_owned_network_id,
            ):
                continue
            self._record_compose_network(
                ownership,
                native_id=native_id,
                daemon_id=daemon_id,
                attempt_id=attempt_id,
            )

    def _record_compose_network(
        self,
        ownership: WorkspaceOwnership,
        *,
        native_id: str,
        daemon_id: str,
        attempt_id: str,
    ) -> None:
        """Validate and record one newly observed Compose network."""

        info = self.host_inspect_network(native_id)
        labels = info.get("labels") if isinstance(info, dict) else None
        semantic_name = (
            labels.get("com.docker.compose.network")
            if isinstance(labels, dict)
            else None
        )
        external_name = info.get("name") if isinstance(info, dict) else None
        if (
            info.get("id") != native_id
            or not self._complete_owner_labels(
                ownership,
                labels,
                attempt_id=attempt_id,
                compose_kind="network",
                semantic_name=semantic_name,
            )
            or not isinstance(external_name, str)
            or not external_name
        ):
            raise OwnershipConflictError("Compose network owner tuple is incomplete")
        ownership.record(
            ResourceReceipt(
                kind="network",
                native_id=native_id,
                external_name=external_name,
                semantic_name=str(semantic_name),
                node_address=str(semantic_name),
                workspace_id=ownership.workspace_id,
                project_name=ownership.project_name,
                daemon_id=daemon_id,
                attempt_id=attempt_id,
                managed_by="compose",
            )
        )

    def _record_compose_volume_receipts(
        self,
        ownership: WorkspaceOwnership,
        *,
        daemon_id: str,
        attempt_id: str,
    ) -> None:
        """Capture Compose-created volume names."""

        for native_name in self._scoped_compose_volume_names():
            if self._verify_existing_receipt(
                ownership,
                daemon_id=daemon_id,
                kind="volume",
                native_id=native_name,
                resolver=self._resolve_owned_volume_name,
            ):
                continue
            self._record_compose_volume(
                ownership,
                native_name=native_name,
                daemon_id=daemon_id,
                attempt_id=attempt_id,
            )

    def _record_compose_volume(
        self,
        ownership: WorkspaceOwnership,
        *,
        native_name: str,
        daemon_id: str,
        attempt_id: str,
    ) -> None:
        """Validate and record one newly observed Compose volume."""

        info = self._raw_volume_inspect(native_name)
        labels = info.get("Labels") if isinstance(info, dict) else None
        semantic_name = (
            labels.get("com.docker.compose.volume")
            if isinstance(labels, dict)
            else None
        )
        if info.get("Name") != native_name or not self._complete_owner_labels(
            ownership,
            labels,
            attempt_id=attempt_id,
            compose_kind="volume",
            semantic_name=semantic_name,
        ):
            raise OwnershipConflictError("Compose volume owner tuple is incomplete")
        ownership.record(
            ResourceReceipt(
                kind="volume",
                native_id=native_name,
                external_name=native_name,
                semantic_name=str(semantic_name),
                node_address=str(semantic_name),
                workspace_id=ownership.workspace_id,
                project_name=ownership.project_name,
                daemon_id=daemon_id,
                attempt_id=attempt_id,
                managed_by="compose",
            )
        )

    @staticmethod
    def _complete_owner_labels(
        ownership: WorkspaceOwnership,
        labels: object,
        *,
        attempt_id: str,
        compose_kind: str,
        semantic_name: object,
    ) -> bool:
        """Return whether Compose and workspace owner labels are complete."""

        if not isinstance(labels, dict) or not isinstance(semantic_name, str):
            return False
        expected = ownership.labels(attempt_id=attempt_id)
        return bool(
            semantic_name
            and labels.get(_COMPOSE_PROJECT_LABEL) == ownership.project_name
            and labels.get(f"com.docker.compose.{compose_kind}") == semantic_name
            and all(labels.get(name) == value for name, value in expected.items())
        )
