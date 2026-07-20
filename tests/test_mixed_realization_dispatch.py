"""Unit tests for mixed-realization node partitioning (ADR-048).

TechVault's real shape is permanently mixed: some nodes convert to the
generic materializer (`runtime:`), others stay on a declared vendor
`source:`. These pure functions decide which nodes materialize directly and
which Compose service names must be scaled to zero so neither side starts,
skips, or double-realizes the other's nodes. See
test_mixed_realization_integration.py for the real-Docker proof.
"""

from __future__ import annotations

from aces_sdl.runtime_configuration import RuntimeConfiguration

from aptl.core.deployment._compose_realization import (
    _image_free_node_addresses,
    _image_free_service_names,
)
from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)


def _node(address: str, *, runtime=None, service_name=None) -> DeploymentNodeRealization:
    return DeploymentNodeRealization(
        address=address,
        name=address.rsplit(".", 1)[-1],
        service_name=service_name,
        container_name=None,
        networks=(),
        os="linux",
        runtime=runtime,
    )


def _spec(nodes: tuple[DeploymentNodeRealization, ...]) -> DeploymentRealizationSpec:
    return DeploymentRealizationSpec(profiles=(), nodes=nodes, networks=())


class TestImageFreeNodeAddresses:
    def test_only_runtime_declaring_nodes_are_included(self):
        free = _node("provision.node.free", runtime=RuntimeConfiguration())
        legacy = _node("provision.node.legacy", runtime=None)
        addresses = _image_free_node_addresses(_spec((free, legacy)))
        assert addresses == frozenset({"provision.node.free"})

    def test_empty_when_nothing_declares_runtime(self):
        legacy = _node("provision.node.legacy", runtime=None)
        assert _image_free_node_addresses(_spec((legacy,))) == frozenset()


class TestImageFreeServiceNames:
    def test_returns_service_names_of_image_free_nodes_only(self):
        free = _node(
            "provision.node.free", runtime=RuntimeConfiguration(), service_name="free"
        )
        legacy = _node("provision.node.legacy", runtime=None, service_name="legacy")
        spec = _spec((free, legacy))
        names = _image_free_service_names(spec, _image_free_node_addresses(spec))
        assert names == ("free",)

    def test_image_free_node_without_a_compose_service_is_skipped(self):
        # A brand-new node with no legacy Compose definition at all (e.g. one
        # authored only after the image-free cutover) has nothing to exclude.
        free = _node("provision.node.free", runtime=RuntimeConfiguration(), service_name=None)
        spec = _spec((free,))
        names = _image_free_service_names(spec, _image_free_node_addresses(spec))
        assert names == ()

    def test_names_are_sorted_for_deterministic_argv(self):
        b = _node(
            "provision.node.b", runtime=RuntimeConfiguration(), service_name="b-service"
        )
        a = _node(
            "provision.node.a", runtime=RuntimeConfiguration(), service_name="a-service"
        )
        spec = _spec((b, a))
        names = _image_free_service_names(spec, _image_free_node_addresses(spec))
        assert names == ("a-service", "b-service")
