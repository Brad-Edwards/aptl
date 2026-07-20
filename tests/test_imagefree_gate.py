"""Tests for the static image-free realization gate (ADR-048 P7)."""

from __future__ import annotations

import pytest
from aces_sdl.runtime_configuration import (
    RuntimeConfiguration,
    RuntimePackage,
    ServiceManagerUnit,
)

from aptl.core.deployment.realization import (
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.validation.imagefree_gate import (
    ImageFreeGateError,
    assert_image_free,
    image_free_violations,
)


def _node(address, *, os="linux", runtime=...):
    return DeploymentNodeRealization(
        address=address, name=address, service_name=None, container_name=None,
        networks=(), os=os,
        runtime=RuntimeConfiguration() if runtime is ... else runtime,
    )


def _spec(nodes, *, image_free=True):
    return DeploymentRealizationSpec(
        profiles=(), nodes=tuple(nodes), networks=(), image_free=image_free
    )


def test_clean_image_free_realization_passes():
    node = _node(
        "n.box",
        runtime=RuntimeConfiguration(
            packages=[RuntimePackage(manager="apt", name="bind9", version="*")],
            service_manager_units=[
                ServiceManagerUnit(unit_id="n", unit_name="named.service", active_state="active")
            ],
        ),
    )
    assert image_free_violations(_spec([node])) == []
    assert_image_free(_spec([node]))  # does not raise


def test_not_image_free_flag_is_a_violation():
    node = _node("n.box")
    violations = image_free_violations(_spec([node], image_free=False))
    assert any("not image-free" in v for v in violations)


def test_os_node_without_runtime_is_a_violation():
    node = _node("n.box", runtime=None)
    violations = image_free_violations(_spec([node]))
    assert any("no runtime desired state" in v for v in violations)


def test_service_without_software_is_a_violation():
    node = _node(
        "n.box",
        runtime=RuntimeConfiguration(
            service_manager_units=[
                ServiceManagerUnit(unit_id="n", unit_name="named.service", active_state="active")
            ]
        ),
    )
    violations = image_free_violations(_spec([node]))
    assert any("no packages/software_components" in v for v in violations)


def test_assert_raises_with_all_violations():
    node = _node("n.box", runtime=None)
    spec = _spec([node], image_free=False)
    with pytest.raises(ImageFreeGateError) as exc:
        assert_image_free(spec)
    assert len(exc.value.violations) >= 2


def test_switch_nodes_are_ignored():
    # A switch has no os and nothing to materialize; it is not a violation.
    assert image_free_violations(_spec([_node("n.sw", os="", runtime=None)])) == []
