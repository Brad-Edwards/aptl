"""A node must declare how it is realized; an empty declaration is not one.

The gate's job is to stop a container that carries the right name but none of the
behaviour from being accepted as a realized node. Its original predicate asked
only whether a node had *a* runtime object, which an entirely empty runtime
satisfies — so a node declaring listeners and nothing to provide them passed.

These tests pin the hollow cases, because they are the ones the gate exists for.
"""

from __future__ import annotations

from raes.runtime_configuration import RuntimeConfiguration

from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.validation.imagefree_gate import image_free_violations


def _spec(*nodes: DeploymentNodeRealization, images=()) -> DeploymentRealizationSpec:
    return DeploymentRealizationSpec(
        profiles=(), nodes=tuple(nodes), networks=(), images=tuple(images)
    )


def _node(address: str, *, runtime=None, services=()) -> DeploymentNodeRealization:
    return DeploymentNodeRealization(
        address=address,
        name=address.rsplit(".", 1)[-1],
        service_name=address.rsplit(".", 1)[-1],
        container_name="aptl-" + address.rsplit(".", 1)[-1],
        networks=(),
        network_attachments=(),
        services=tuple(services),
        published_ports=(),
        ordering_dependencies=(),
        os="linux",
        os_version="",
        runtime=runtime,
    )


def test_an_entirely_empty_runtime_is_not_a_declaration():
    """`runtime: {}` says nothing about how the node is realized."""

    violations = image_free_violations(_spec(_node("provision.node.hollow", runtime=RuntimeConfiguration())))

    assert violations, "an empty runtime was accepted as a declared realization"
    assert "hollow" in violations[0]


def test_declared_listeners_need_something_to_provide_them():
    """A node advertising services must declare the software behind them.

    This is the hollow node the contract names: right name, right ports, none of
    the behaviour.
    """

    from aptl.core.deployment.realization import DeploymentServicePort

    node = _node(
        "provision.node.pretender",
        runtime=RuntimeConfiguration(),
        services=(DeploymentServicePort(name="ssh", port=22, protocol="tcp"),),
    )

    assert image_free_violations(_spec(node))


def test_a_node_with_real_declared_state_passes():
    """The gate must not reject a genuinely declared node."""

    from raes.runtime_configuration import RuntimePackage

    node = _node(
        "provision.node.real",
        runtime=RuntimeConfiguration(
            packages=[RuntimePackage(manager="apt", name="openssh-server", version="*")]
        ),
    )

    assert image_free_violations(_spec(node)) == []


def test_an_image_backed_node_without_runtime_still_passes():
    """A vendor image is a declared realization even with no runtime block."""

    from aptl.core.deployment.realization import DeploymentImageRealization

    image = DeploymentImageRealization(
        address="provision.node.vendor",
        service_name="vendor",
        source_name="example/app",
        source_version="1.0",
        image_ref="example/app@sha256:" + "a" * 64,
        mode="pull",
        policy_rule="authored-exact-artifact",
    )

    assert image_free_violations(_spec(_node("provision.node.vendor"), images=(image,))) == []
