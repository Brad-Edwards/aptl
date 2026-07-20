"""Tests for the generic node materialization engine (ADR-048).

The engine executes a node's planned generic operations against a backend
materialization surface, then verifies the result by read-after-write. It is
product-agnostic and translates internal/backend failures into the existing ACES
`LabResult` envelope, never a new exception hierarchy. "Container running" is
never accepted as proof; only observed state is.
"""

from __future__ import annotations

from aces_sdl.runtime_configuration import (
    RuntimeConfiguration,
    RuntimeLocalGroup,
    RuntimeLocalIdentityInventory,
    RuntimeLocalUser,
    RuntimePackage,
    ServiceManagerUnit,
)

from aces_sdl.runtime_filesystem import RuntimeFilesystemEntry, RuntimeFilesystemEntryType

from aptl.backends.aces_materializer import (
    EnsureDirectoryOp,
    EnsureUserOp,
    plan_node_materialization,
)
from aptl.backends.aces_materializer_engine import materialize_node


class _RecordingExecutor:
    """In-memory materialization surface: mutations accumulate, observers read
    them back. A realistic fake so the happy path genuinely materializes then
    verifies."""

    def __init__(self) -> None:
        self.base: dict[str, str] = {}
        self.installed: dict[tuple[str, str], set[str]] = {}
        self.groups: set[tuple[str, str]] = set()
        self.users: set[tuple[str, str]] = set()
        self.enabled: set[tuple[str, str]] = set()
        self.active: set[tuple[str, str]] = set()
        self.directories: set[tuple[str, str]] = set()

    def ensure_base_substrate(self, node_address: str, image_ref: str) -> None:
        self.base[node_address] = image_ref

    def ensure_directory(self, node_address: str, op: EnsureDirectoryOp) -> None:
        self.directories.add((node_address, op.path))

    def observe_directory(self, node_address: str, path: str) -> bool:
        return (node_address, path) in self.directories

    def install_packages(self, node_address: str, manager: str, packages: tuple[str, ...]) -> None:
        self.installed.setdefault((node_address, manager), set()).update(packages)

    def ensure_group(self, node_address: str, name: str, gid) -> None:
        self.groups.add((node_address, name))

    def ensure_user(self, node_address: str, op: EnsureUserOp) -> None:
        self.users.add((node_address, op.username))

    def enable_service_unit(self, node_address: str, unit_name: str) -> None:
        self.enabled.add((node_address, unit_name))

    def start_service_unit(self, node_address: str, unit_name: str) -> None:
        self.active.add((node_address, unit_name))

    def observe_installed_packages(
        self, node_address: str, manager: str, packages: tuple[str, ...]
    ) -> frozenset[str]:
        return frozenset(self.installed.get((node_address, manager), set()))

    def observe_local_group(self, node_address: str, name: str) -> bool:
        return (node_address, name) in self.groups

    def observe_local_user(self, node_address: str, username: str) -> bool:
        return (node_address, username) in self.users

    def observe_service_unit_enabled(self, node_address: str, unit_name: str) -> bool:
        return (node_address, unit_name) in self.enabled

    def observe_service_unit_active(self, node_address: str, unit_name: str) -> bool:
        return (node_address, unit_name) in self.active


def _full_runtime() -> RuntimeConfiguration:
    return RuntimeConfiguration(
        packages=[RuntimePackage(manager="apt", name="wazuh-manager", version="4.9.0")],
        local_identity=RuntimeLocalIdentityInventory(
            users=[RuntimeLocalUser(username="wazuh")],
            groups=[RuntimeLocalGroup(name="wazuh")],
        ),
        service_manager_units=[
            ServiceManagerUnit(
                unit_id="wazuh_manager",
                unit_name="wazuh-manager.service",
                enabled_state="enabled",
                active_state="active",
            ),
        ],
    )


class TestMaterializeNode:
    def test_happy_path_materializes_then_verifies_clean(self):
        ops = plan_node_materialization(os="linux", os_version="", runtime=_full_runtime())
        ex = _RecordingExecutor()
        result = materialize_node("techvault.wazuh-manager", ops, ex)
        assert result is None
        # Every op was actually executed against the backend surface.
        assert ex.base["techvault.wazuh-manager"]
        assert ex.installed[("techvault.wazuh-manager", "apt")] == {"wazuh-manager"}
        assert ("techvault.wazuh-manager", "wazuh") in ex.groups
        assert ("techvault.wazuh-manager", "wazuh") in ex.users
        assert ("techvault.wazuh-manager", "wazuh-manager.service") in ex.active

    def test_unverifiable_package_fails_closed(self):
        ops = plan_node_materialization(os="linux", os_version="", runtime=_full_runtime())

        class _SilentInstall(_RecordingExecutor):
            def install_packages(self, node_address, manager, packages):
                pass  # runs but materializes nothing; observation stays empty

        result = materialize_node("techvault.wazuh-manager", ops, _SilentInstall())
        assert result is not None and result.success is False
        assert "techvault.wazuh-manager" in (result.error or "")
        assert "wazuh-manager" in (result.error or "")

    def test_unverifiable_service_fails_closed(self):
        ops = plan_node_materialization(os="linux", os_version="", runtime=_full_runtime())

        class _SilentStart(_RecordingExecutor):
            def start_service_unit(self, node_address, unit_name):
                pass  # never becomes active

        result = materialize_node("techvault.wazuh-manager", ops, _SilentStart())
        assert result is not None and result.success is False
        assert "wazuh-manager.service" in (result.error or "")

    def test_backend_error_translates_to_labresult_not_exception(self):
        ops = plan_node_materialization(os="linux", os_version="", runtime=_full_runtime())

        class _Broken(_RecordingExecutor):
            def install_packages(self, node_address, manager, packages):
                raise RuntimeError("apt exploded internally with secret=hunter2")

        # No exception escapes; a fail-closed LabResult naming the node is returned.
        result = materialize_node("techvault.wazuh-manager", ops, _Broken())
        assert result is not None and result.success is False
        assert "techvault.wazuh-manager" in (result.error or "")
        # The raw internal detail is not echoed verbatim into the envelope.
        assert "hunter2" not in (result.error or "")

    def test_directory_entry_is_materialized_and_verified(self):
        runtime = RuntimeConfiguration(
            local_identity=RuntimeLocalIdentityInventory(
                groups=[RuntimeLocalGroup(name="bind")],
                users=[RuntimeLocalUser(username="bind")],
            ),
            filesystem_inventory=[
                RuntimeFilesystemEntry(
                    path="/var/log/named",
                    entry_type=RuntimeFilesystemEntryType.DIRECTORY,
                    owner_user="bind",
                    owner_group="bind",
                ),
            ],
        )
        ops = plan_node_materialization(os="linux", os_version="", runtime=runtime)
        ex = _RecordingExecutor()
        result = materialize_node("techvault.dns", ops, ex)
        assert result is None
        assert ("techvault.dns", "/var/log/named") in ex.directories

    def test_unverifiable_directory_fails_closed(self):
        runtime = RuntimeConfiguration(
            filesystem_inventory=[
                RuntimeFilesystemEntry(
                    path="/var/log/named",
                    entry_type=RuntimeFilesystemEntryType.DIRECTORY,
                ),
            ],
        )
        ops = plan_node_materialization(os="linux", os_version="", runtime=runtime)

        class _SilentDirectory(_RecordingExecutor):
            def ensure_directory(self, node_address, op):
                pass  # runs but materializes nothing

        result = materialize_node("techvault.dns", ops, _SilentDirectory())
        assert result is not None and result.success is False
        assert "/var/log/named" in (result.error or "")

    def test_empty_runtime_only_needs_base_substrate(self):
        ops = plan_node_materialization(os="linux", os_version="", runtime=None)
        ex = _RecordingExecutor()
        assert materialize_node("techvault.switch", ops, ex) is None
        assert ex.base["techvault.switch"]
