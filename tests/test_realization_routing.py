"""Realization routes per node, not from a whole-graph flag.

A mixed graph is normal under ADR-050: some nodes come from a pinned artifact,
some are built from a specification, some are composed from declared state. A
spec-level `image_free` boolean cannot express that, and using one as the route
authority contradicts the per-node artifact routing the rest of the pipeline
does.

The decision that actually matters is narrower: is there anything left for
Compose to start? Everything else is per node.
"""

from __future__ import annotations

from raes.runtime_configuration import RuntimeConfiguration, RuntimePackage

from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)


def _node(name: str, *, materialized: bool) -> DeploymentNodeRealization:
    runtime = (
        RuntimeConfiguration(
            packages=[RuntimePackage(manager="apt", name="curl", version="*")]
        )
        if materialized
        else None
    )
    return DeploymentNodeRealization(
        address=f"provision.node.{name}",
        name=name,
        service_name=name,
        container_name=f"aptl-{name}",
        networks=(),
        network_attachments=(),
        services=(),
        published_ports=(),
        ordering_dependencies=(),
        os="linux",
        os_version="",
        runtime=runtime,
    )


def _spec(*nodes) -> DeploymentRealizationSpec:
    return DeploymentRealizationSpec(
        profiles=(), nodes=tuple(nodes), networks=()
    )


def test_a_graph_with_compose_managed_nodes_needs_compose():
    from aptl.core.deployment._compose_realization import _needs_compose

    spec = _spec(_node("a", materialized=True), _node("b", materialized=False))

    assert _needs_compose(spec) is True


def test_a_fully_materialized_graph_does_not_need_compose():
    """Nothing is left for Compose to start, so its stages are skipped."""

    from aptl.core.deployment._compose_realization import _needs_compose

    spec = _spec(_node("a", materialized=True), _node("b", materialized=True))

    assert _needs_compose(spec) is False


def test_an_empty_graph_keeps_the_compose_path():
    """No nodes is not the same as everything materialized."""

    from aptl.core.deployment._compose_realization import _needs_compose

    assert _needs_compose(_spec()) is True


def test_the_spec_no_longer_carries_a_whole_graph_image_free_flag():
    """The flag contradicted per-node routing and must not come back."""

    import dataclasses

    fields = {f.name for f in dataclasses.fields(DeploymentRealizationSpec)}

    assert "image_free" not in fields


def _imaged_node(name: str) -> DeploymentNodeRealization:
    """A node realized from an artifact rather than from declared state."""

    node = _node(name, materialized=False)
    return node


def test_an_artifact_backed_node_is_compose_managed():
    """Replaces the removed image-free derivation: an image means Compose starts it.

    Previously asserted against a whole-graph predicate; the same property now
    holds at the routing level, where it actually decides anything.
    """

    from aptl.core.deployment._compose_realization import _needs_compose

    assert _needs_compose(_spec(_imaged_node("vendor"))) is True


def test_an_os_node_without_declared_state_is_compose_managed():
    """A node with neither declared runtime nor materialization stays on Compose."""

    from aptl.core.deployment._compose_realization import _needs_compose

    assert _needs_compose(_spec(_node("undeclared", materialized=False))) is True


def test_a_node_with_no_service_name_cannot_be_compose_managed():
    """Compose can only start something it has a service for."""

    import dataclasses

    from aptl.core.deployment._compose_realization import _needs_compose

    node = dataclasses.replace(_node("orphan", materialized=False), service_name="")

    assert _needs_compose(_spec(node)) is False
