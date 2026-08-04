"""Tests for per-node materialization coordination (ADR-048)."""

from __future__ import annotations

from types import SimpleNamespace

from raes.runtime_configuration import (
    RuntimeConfiguration,
    RuntimeLocalGroup,
    RuntimeLocalIdentityInventory,
    RuntimeLocalUser,
    RuntimePackage,
)

from aptl.backends.raes_base_substrate import BaseContainerSpec
from aptl.backends.raes_node_materialization import realize_node, realize_nodes
from aptl.backends.raes_realization_model import NodeRealization


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


def _named_node(name: str) -> NodeRealization:
    node = _node()
    return NodeRealization(
        address=f"techvault.{name}",
        name=name,
        aliases=(),
        profiles=(),
        backend_services=(),
        container_name=None,
        services=(),
        networks=(),
        static_addresses=(),
        os="linux",
        runtime=node.runtime,
    )


class _ThreadSafeBackend(_FakeBackend):
    """`_FakeBackend` whose shared observation state is lock-guarded."""

    def __init__(self) -> None:
        super().__init__()
        import threading

        self._lock = threading.Lock()

    def container_exec(self, name, cmd, *, timeout=None):
        with self._lock:
            return super().container_exec(name, cmd, timeout=timeout)

    def start_base_container(self, spec):
        with self._lock:
            super().start_base_container(spec)


def test_realize_nodes_materializes_multiple_nodes():
    backend = _ThreadSafeBackend()
    nodes = [_named_node(f"box-{i}") for i in range(4)]

    assert realize_nodes(nodes, backend) is None
    assert len(backend.started) == 4
    assert {spec.container_name for spec in backend.started} == {
        f"aptl-box-{i}" for i in range(4)
    }


def test_realize_nodes_runs_nodes_concurrently():
    """A barrier that only releases when all nodes are in flight proves the
    materialization actually runs in parallel; a serial loop would time out."""
    import threading

    node_count = 4
    barrier = threading.Barrier(node_count)

    class _BarrierBackend(_ThreadSafeBackend):
        def start_base_container(self, spec):
            # Every node must reach here before any proceeds; a serial loop
            # would leave the barrier one party short and raise on timeout.
            barrier.wait(timeout=10)
            super().start_base_container(spec)

    backend = _BarrierBackend()
    nodes = [_named_node(f"box-{i}") for i in range(node_count)]

    assert realize_nodes(nodes, backend) is None
    assert len(backend.started) == node_count


def test_realize_nodes_returns_first_failure_in_declared_order():
    """When multiple nodes fail concurrently, the surfaced error is the first in
    declared node order, independent of which finished first."""

    class _SecondFailsFasterBackend(_ThreadSafeBackend):
        def start_base_container(self, spec):
            if spec.container_name == "aptl-box-0":
                import time

                time.sleep(0.2)  # first-in-order fails later
            raise RuntimeError(f"boom {spec.container_name}")

    nodes = [_named_node("box-0"), _named_node("box-1")]
    result = realize_nodes(nodes, _SecondFailsFasterBackend())

    assert result is not None
    assert result.success is False
    # Deterministic: box-0 is first in declared order even though box-1 failed first.
    assert "techvault.box-0" in (result.error or "")
