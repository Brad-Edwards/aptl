"""A declared listener is a readiness signal, not something to race.

A node realized from declared facts carries no healthcheck of its own, so the
container health wait passes the moment it starts. TheHive needs well over a
minute to bind 9000, so observation read the world too early and the exact
`service-listeners` requirement failed on timing alone (issue #1006).
"""

from __future__ import annotations

from dataclasses import dataclass

from aptl.core.deployment._declared_listener_readiness import await_declared_listeners


@dataclass
class _Listener:
    port: int


@dataclass
class _Runtime:
    service_listeners: tuple[_Listener, ...]


@dataclass
class _Node:
    container_name: str | None
    runtime: _Runtime | None


@dataclass
class _Listeners:
    sockets: tuple[tuple[str, str, int], ...]


class _Backend:
    """A backend whose listeners appear after a given number of reads."""

    def __init__(self, appears_after: int = 0, *, ports: tuple[int, ...] = (9000,)):
        self.appears_after = appears_after
        self.ports = ports
        self.reads = 0

    def observe_container_listeners(self, name: str) -> _Listeners:
        self.reads += 1
        if self.reads > self.appears_after:
            return _Listeners(tuple(("tcp", "::", port) for port in self.ports))
        return _Listeners(())


def _node(port: int = 9000, container: str | None = "aptl-thehive") -> _Node:
    return _Node(container_name=container, runtime=_Runtime((_Listener(port),)))


def test_listener_already_bound_returns_immediately():
    backend = _Backend(appears_after=0)

    assert await_declared_listeners(backend, (_node(),)) == []
    assert backend.reads == 1


def test_waits_for_a_slow_listener_rather_than_failing_the_boot():
    backend = _Backend(appears_after=2)

    failures = await_declared_listeners(backend, (_node(),), timeout=30, interval=0)

    assert failures == []
    assert backend.reads == 3


def test_listener_that_never_binds_still_fails():
    """Waiting for the truth, not assuming it: an absent listener is a failure."""
    backend = _Backend(appears_after=10_000)

    failures = await_declared_listeners(backend, (_node(),), timeout=0, interval=0)

    assert len(failures) == 1
    assert "did not bind" in failures[0]
    assert "aptl-thehive" in failures[0]
    assert "9000" in failures[0]


def test_ipv6_wildcard_bind_satisfies_the_declaration():
    """TheHive binds `::`; the declaration says 0.0.0.0. Both are wildcards."""
    backend = _Backend(appears_after=0, ports=(9000,))

    assert await_declared_listeners(backend, (_node(9000),)) == []


def test_nodes_without_declared_listeners_are_not_waited_on():
    backend = _Backend(appears_after=10_000)
    quiet = _Node(container_name="aptl-workstation", runtime=_Runtime(()))

    assert await_declared_listeners(backend, (quiet,)) == []
    assert backend.reads == 0


def test_every_unmet_node_is_named():
    backend = _Backend(appears_after=10_000)
    nodes = (_node(9000, "aptl-thehive"), _node(8443, "aptl-misp"))

    failures = await_declared_listeners(backend, nodes, timeout=0, interval=0)

    assert len(failures) == 1
    assert "aptl-thehive" in failures[0]
    assert "aptl-misp" in failures[0]


def test_listeners_are_awaited_only_after_providers_start_them(tmp_path):
    """A provider starts the process that binds its declared listener.

    Waiting for declared listeners before `realize_application_providers` waited
    up to the full bound for a port nothing had started, so a clean start with a
    provider-owned listener failed deterministically (issue #1006).
    """
    from unittest.mock import patch

    from aptl.core.deployment import _compose_post_start as post_start
    from aptl.core.deployment.docker_compose import DockerComposeBackend
    from aptl.core.deployment.observation import DeploymentObservationContext
    from aptl.core.deployment.realization import DeploymentRealizationSpec

    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    spec = DeploymentRealizationSpec(profiles=(), nodes=(), networks=())
    order: list[str] = []

    def record(name, result):
        def _call(*args, **kwargs):
            order.append(name)
            return result

        return _call

    with (
        patch.object(backend, "_reconcile_realization_networks", return_value=[]),
        patch.object(backend, "_await_realized_service_health", return_value=[]),
        patch.object(backend, "_realize_traffic_mirrors", return_value=[]),
        patch.object(
            post_start,
            "realize_application_providers",
            record("providers", []),
        ),
        patch.object(
            post_start, "realize_forwarding_agents", record("forwarding", [])
        ),
        patch.object(
            post_start, "await_declared_listeners", record("listeners", [])
        ),
        patch.object(
            backend, "_verify_stateful_authenticated_readiness", return_value=None
        ),
        patch.object(backend, "_verify_runtime_orchestration", return_value=None),
        patch.object(backend, "_realize_accounts_step", return_value=None),
        patch.object(backend, "_retire_completed_autoremove_nodes", return_value=[]),
    ):
        result = backend._post_start_result(spec, DeploymentObservationContext())

    assert result.success is True
    assert order.index("providers") < order.index("listeners")
