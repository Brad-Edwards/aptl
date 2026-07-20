"""Tests for per-node materialization coordination (ADR-047)."""

from __future__ import annotations

from types import SimpleNamespace

from aces_sdl.runtime_configuration import (
    RuntimeConfiguration,
    RuntimeLocalGroup,
    RuntimeLocalIdentityInventory,
    RuntimeLocalUser,
    RuntimePackage,
)

from aptl.backends.aces_base_substrate import BaseContainerSpec
from aptl.backends.aces_node_materialization import realize_node, realize_nodes
from aptl.backends.aces_realization_model import NodeRealization


class _FakeBackend:
    """Records base-container starts and satisfies exec/observe generically."""

    def __init__(self) -> None:
        self.started: list[BaseContainerSpec] = []
        self.installed: set[str] = set()
        self.users: set[str] = set()
        self.groups: set[str] = set()

    @property
    def project_dir(self):
        return None

    def start_base_container(self, spec: BaseContainerSpec) -> None:
        self.started.append(spec)

    def copy_into_container(self, container, source_path, dest_path, is_directory):
        pass

    def container_exec(self, name, cmd, *, timeout=None):
        # Emulate the real container: mutations accumulate, observers read back.
        if cmd[:1] == ["dpkg-query"]:
            return SimpleNamespace(returncode=0, stdout="\n".join(sorted(self.installed)) + "\n")
        if "install" in cmd:
            self.installed.update(a for a in cmd if a in {"curl", "wazuh-manager"})
            return SimpleNamespace(returncode=0, stdout="")
        if cmd[:1] == ["groupadd"]:
            self.groups.add(cmd[-1])
            return SimpleNamespace(returncode=0, stdout="")
        if cmd[:1] == ["useradd"]:
            self.users.add(cmd[-1])
            return SimpleNamespace(returncode=0, stdout="")
        if cmd[:1] == ["getent"]:
            return SimpleNamespace(returncode=0 if cmd[-1] in self.groups else 1, stdout="")
        if cmd[:1] == ["id"]:
            return SimpleNamespace(returncode=0 if cmd[-1] in self.users else 1, stdout="")
        return SimpleNamespace(returncode=0, stdout="")


def _node() -> NodeRealization:
    return NodeRealization(
        address="techvault.analyst-box",
        name="analyst-box",
        aliases=(),
        profiles=(),
        backend_services=(),
        container_name=None,
        services=(),
        networks=(),
        static_addresses=(),
        os="linux",
        runtime=RuntimeConfiguration(
            packages=[RuntimePackage(manager="apt", name="curl", version="*")],
            local_identity=RuntimeLocalIdentityInventory(
                groups=[RuntimeLocalGroup(name="techvault")],
                users=[RuntimeLocalUser(username="analyst")],
            ),
        ),
    )


def test_realize_node_starts_base_then_materializes_and_verifies():
    backend = _FakeBackend()
    result = realize_node(_node(), backend)
    assert result is None, getattr(result, "error", None)
    # Base container was started from the node's generic substrate spec.
    assert len(backend.started) == 1
    assert backend.started[0].container_name == "aptl-analyst-box"
    # Declared state materialized.
    assert "curl" in backend.installed
    assert "analyst" in backend.users
    assert "techvault" in backend.groups


def test_realize_node_fails_closed_when_state_unverifiable():
    class _SilentBackend(_FakeBackend):
        def container_exec(self, name, cmd, *, timeout=None):
            if "install" in cmd:  # install "succeeds" but nothing is recorded
                return SimpleNamespace(returncode=0, stdout="")
            return super().container_exec(name, cmd, timeout=timeout)

    result = realize_node(_node(), _SilentBackend())
    assert result is not None and result.success is False
    assert "curl" in (result.error or "")


def _switch() -> NodeRealization:
    return NodeRealization(
        address="techvault.sw",
        name="sw",
        aliases=(),
        profiles=(),
        backend_services=(),
        container_name=None,
        services=(),
        networks=(),
        static_addresses=(),
        os="",  # a switch: no OS, nothing to materialize
    )


def test_realize_nodes_skips_os_less_nodes_and_materializes_the_rest():
    backend = _FakeBackend()
    assert realize_nodes([_switch(), _node()], backend) is None
    assert len(backend.started) == 1  # only the real node got a base container


def test_realize_nodes_fails_closed_on_first_failure():
    class _BrokenBackend(_FakeBackend):
        def start_base_container(self, spec):
            raise RuntimeError("cannot start base")

    result = realize_nodes([_node()], _BrokenBackend())
    assert result is not None and result.success is False
    assert "techvault.analyst-box" in (result.error or "")
