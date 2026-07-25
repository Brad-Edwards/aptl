"""Tests for the generic, scenario-agnostic node materializer planner (ADR-048).

The planner turns a node's declared ACES desired state into an ordered list of
generic materialization operations. It contains no per-product knowledge: two
nodes with identical declared state produce identical operations regardless of
any name. All product-specific detail (which packages, which users, which
service units) lives in the SDL, never here.
"""

from __future__ import annotations

import pytest
from aces_sdl.runtime_configuration import (
    RuntimeConfiguration,
    RuntimeDependencyManifest,
    RuntimeLocalGroup,
    RuntimeLocalIdentityInventory,
    RuntimeLocalUser,
    RuntimePackage,
    ServiceManagerUnit,
)
from aces_sdl.runtime_filesystem import RuntimeFilesystemEntry, RuntimeFilesystemEntryType

from aptl.backends.aces_materializer import (
    BaseSubstrateOp,
    EnableServiceUnitOp,
    EnsureDirectoryOp,
    EnsureGroupOp,
    EnsureUserOp,
    InstallDependencyManifestOp,
    InstallPackagesOp,
    PlaceFileOp,
    StartServiceUnitOp,
    UnsupportedOsFamilyError,
    base_image_for_os,
    plan_node_materialization,
)


class TestBaseImageForOs:
    def test_linux_resolves_to_a_fixed_generic_base(self):
        image = base_image_for_os("linux", "")
        assert isinstance(image, str) and image
        # The same os/version always maps to the same base (deterministic).
        assert base_image_for_os("linux", "") == image

    def test_unknown_os_family_fails_closed(self):
        # No silent default: an OS APTL has no generic base for is an error,
        # not a guessed image.
        with pytest.raises(UnsupportedOsFamilyError):
            base_image_for_os("plan9", "")


class TestPlanNodeMaterialization:
    def test_empty_runtime_yields_only_the_base_substrate(self):
        ops = plan_node_materialization(os="linux", os_version="", runtime=None)
        assert ops == (BaseSubstrateOp(image_ref=base_image_for_os("linux", "")),)

    def test_packages_group_by_manager_and_sort(self):
        runtime = RuntimeConfiguration(
            packages=[
                RuntimePackage(manager="apt", name="wazuh-manager", version="4.9.0"),
                RuntimePackage(manager="apt", name="curl", version="*"),
                RuntimePackage(manager="pip", name="requests", version="2.31.0"),
            ]
        )
        ops = plan_node_materialization(os="linux", os_version="", runtime=runtime)
        installs = [op for op in ops if isinstance(op, InstallPackagesOp)]
        assert installs == [
            InstallPackagesOp(manager="apt", packages=("curl", "wazuh-manager")),
            InstallPackagesOp(manager="pip", packages=("requests",)),
        ]

    def test_groups_ensured_before_users(self):
        runtime = RuntimeConfiguration(
            local_identity=RuntimeLocalIdentityInventory(
                users=[RuntimeLocalUser(username="wazuh", supplemental_groups=["wazuh"])],
                groups=[RuntimeLocalGroup(name="wazuh", gid=1000)],
            )
        )
        ops = plan_node_materialization(os="linux", os_version="", runtime=runtime)
        group_idx = next(i for i, op in enumerate(ops) if isinstance(op, EnsureGroupOp))
        user_idx = next(i for i, op in enumerate(ops) if isinstance(op, EnsureUserOp))
        assert group_idx < user_idx
        assert EnsureGroupOp(name="wazuh", gid=1000) in ops
        assert EnsureUserOp(
            username="wazuh", uid=None, primary_group="", supplemental_groups=("wazuh",),
            shell="", home="",
        ) in ops

    def test_service_units_enable_and_start_from_declared_state(self):
        runtime = RuntimeConfiguration(
            service_manager_units=[
                ServiceManagerUnit(
                    unit_id="wazuh_manager",
                    unit_name="wazuh-manager.service",
                    enabled_state="enabled",
                    active_state="active",
                ),
                ServiceManagerUnit(
                    unit_id="masked_unit",
                    unit_name="noise.service",
                    enabled_state="disabled",
                    active_state="inactive",
                ),
            ]
        )
        ops = plan_node_materialization(os="linux", os_version="", runtime=runtime)
        assert EnableServiceUnitOp(unit_name="wazuh-manager.service") in ops
        assert StartServiceUnitOp(unit_name="wazuh-manager.service") in ops
        # A unit declared disabled/inactive is not enabled or started.
        assert EnableServiceUnitOp(unit_name="noise.service") not in ops
        assert StartServiceUnitOp(unit_name="noise.service") not in ops

    def test_operation_order_is_base_packages_groups_users_enable_start(self):
        runtime = RuntimeConfiguration(
            packages=[RuntimePackage(manager="apt", name="curl", version="*")],
            local_identity=RuntimeLocalIdentityInventory(
                users=[RuntimeLocalUser(username="svc")],
                groups=[RuntimeLocalGroup(name="svc")],
            ),
            service_manager_units=[
                ServiceManagerUnit(
                    unit_id="svc",
                    unit_name="svc.service",
                    enabled_state="enabled",
                    active_state="active",
                ),
            ],
        )
        ops = plan_node_materialization(os="linux", os_version="", runtime=runtime)
        kinds = [type(op).__name__ for op in ops]
        assert kinds == [
            "BaseSubstrateOp",
            "InstallPackagesOp",
            "EnsureGroupOp",
            "EnsureUserOp",
            "EnableServiceUnitOp",
            "StartServiceUnitOp",
        ]

    def test_directory_filesystem_entries_ensured_after_identity_before_content(self):
        runtime = RuntimeConfiguration(
            local_identity=RuntimeLocalIdentityInventory(
                groups=[RuntimeLocalGroup(name="bind")],
                users=[RuntimeLocalUser(username="bind", primary_group="bind")],
            ),
            filesystem_inventory=[
                RuntimeFilesystemEntry(
                    path="/var/log/named",
                    entry_type=RuntimeFilesystemEntryType.DIRECTORY,
                    owner_user="bind",
                    owner_group="bind",
                    mode="0755",
                ),
            ],
        )
        ops = plan_node_materialization(os="linux", os_version="", runtime=runtime)
        assert EnsureDirectoryOp(
            path="/var/log/named", owner="bind", group="bind", mode="0755"
        ) in ops
        dir_idx = next(i for i, op in enumerate(ops) if isinstance(op, EnsureDirectoryOp))
        user_idx = next(i for i, op in enumerate(ops) if isinstance(op, EnsureUserOp))
        assert user_idx < dir_idx

    def test_non_directory_filesystem_entries_are_not_materialized(self):
        # An observed-fact FILE entry (no inline content) describes an
        # expected file, not something the planner can conjure from metadata
        # alone; it is not lowered into an op (content: is the file-placement
        # authority).
        runtime = RuntimeConfiguration(
            filesystem_inventory=[
                RuntimeFilesystemEntry(
                    path="/etc/bind/named.conf",
                    entry_type=RuntimeFilesystemEntryType.FILE,
                ),
            ],
        )
        ops = plan_node_materialization(os="linux", os_version="", runtime=runtime)
        assert not any(isinstance(op, EnsureDirectoryOp) for op in ops)

    def test_dependency_manifest_installed_after_content_before_services(self):
        runtime = RuntimeConfiguration(
            dependency_manifests=[
                RuntimeDependencyManifest(
                    ecosystem="pip", path="/app/pyproject.toml", name="aptl-labs"
                ),
            ],
            service_manager_units=[
                ServiceManagerUnit(
                    unit_id="svc", unit_name="svc.service", enabled_state="enabled", active_state="active"
                ),
            ],
        )
        content = (PlaceFileOp(path="/app/pyproject.toml", content="[project]\n"),)
        ops = plan_node_materialization(
            os="linux", os_version="", runtime=runtime, content=content
        )
        assert InstallDependencyManifestOp(
            ecosystem="pip", path="/app/pyproject.toml", name="aptl-labs"
        ) in ops
        manifest_idx = next(
            i for i, op in enumerate(ops) if isinstance(op, InstallDependencyManifestOp)
        )
        content_idx = next(i for i, op in enumerate(ops) if isinstance(op, PlaceFileOp))
        start_idx = next(i for i, op in enumerate(ops) if isinstance(op, StartServiceUnitOp))
        assert content_idx < manifest_idx < start_idx

    def test_planner_is_product_agnostic(self):
        # Identical declared state produces identical ops. The planner has no
        # notion of "wazuh" vs "misp" vs anything else; the invariant that
        # proves ACES can compose an arbitrary conformant SDL.
        runtime = RuntimeConfiguration(
            packages=[RuntimePackage(manager="apt", name="anything", version="1")],
        )
        a = plan_node_materialization(os="linux", os_version="", runtime=runtime)
        b = plan_node_materialization(os="linux", os_version="", runtime=runtime)
        assert a == b


class TestPackageFamilyBaseSelection:
    def test_family_from_declared_managers(self):
        from aces_sdl.runtime_configuration import RuntimeConfiguration, RuntimePackage
        from aptl.backends.aces_materializer import package_family
        assert package_family(None) == "debian"
        assert package_family(RuntimeConfiguration()) == "debian"
        assert package_family(
            RuntimeConfiguration(packages=[RuntimePackage(manager="apt", name="curl", version="*")])
        ) == "debian"
        assert package_family(
            RuntimeConfiguration(packages=[RuntimePackage(manager="dnf", name="httpd", version="*")])
        ) == "rhel"

    def test_non_service_base_is_family_aware(self):
        assert base_image_for_os("linux", "", family="debian") == "debian:12-slim"
        assert base_image_for_os("linux", "", family="rhel") == "rockylinux:9"

    def test_service_nodes_use_family_aware_systemd_substrate(self):
        # An apt service node keeps a Debian systemd base; a dnf service node
        # keeps a RHEL systemd base. Both are validated locally against Docker.
        deb = base_image_for_os("linux", "", runs_services=True, family="debian")
        rhel = base_image_for_os("linux", "", runs_services=True, family="rhel")
        assert deb != rhel
        assert "debian" in deb and "debian" not in rhel

    def test_unknown_family_fails_closed(self):
        with pytest.raises(UnsupportedOsFamilyError):
            base_image_for_os("linux", "", family="arch")
