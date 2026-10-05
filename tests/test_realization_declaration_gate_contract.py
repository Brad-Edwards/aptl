"""Tests for the static realization-declaration gate (ADR-048 P7).

TechVault's real shape is permanently mixed: a compliant node resolves
through EITHER declared `runtime:` (the generic materializer) OR a
trust-policy-resolved `source:` (a transparently declared vendor image) -
never through docker-compose.yml alone with no SDL-declared realization.
"""

from __future__ import annotations

import pytest
from raes.runtime_configuration import (
    RuntimeConfiguration,
    RuntimePackage,
    ServiceManagerUnit,
)

from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.validation.realization_declaration_gate import (
    RealizationDeclarationGateError,
    assert_realization_declared,
    realization_declaration_violations,
)


def _node(address, *, os="linux", runtime=...):
    return DeploymentNodeRealization(
        address=address, name=address, service_name=None, container_name=None,
        networks=(), os=os,
        runtime=RuntimeConfiguration() if runtime is ... else runtime,
    )


def _image(address) -> DeploymentImageRealization:
    return DeploymentImageRealization(
        address=address,
        service_name=address,
        source_name="postgres",
        source_version="16-alpine",
        image_ref="postgres:16-alpine",
        mode="pull",
        policy_rule="allowed-source",
    )


def _spec(nodes, *, images=()):
    return DeploymentRealizationSpec(
        profiles=(), nodes=tuple(nodes), networks=(), images=tuple(images)
    )


def test_clean_runtime_node_passes():
    node = _node(
        "n.box",
        runtime=RuntimeConfiguration(
            packages=[RuntimePackage(manager="apt", name="bind9", version="*")],
            service_manager_units=[
                ServiceManagerUnit(unit_id="n", unit_name="named.service", active_state="active")
            ],
        ),
    )
    assert realization_declaration_violations(_spec([node])) == []
    assert_realization_declared(_spec([node]))  # does not raise


def test_node_with_a_resolved_image_source_passes():
    # A legitimate, transparently declared vendor image (source:) is not a
    # violation - TechVault's SOC-stack nodes are permanently this shape.
    node = _node("n.box", runtime=None)
    spec = _spec([node], images=[_image("n.box")])
    assert realization_declaration_violations(spec) == []
    assert_realization_declared(spec)  # does not raise


def test_node_with_neither_runtime_nor_image_is_a_violation():
    node = _node("n.box", runtime=None)
    violations = realization_declaration_violations(_spec([node]))
    assert any("neither declared runtime" in v for v in violations)


def test_service_without_software_is_a_violation():
    node = _node(
        "n.box",
        runtime=RuntimeConfiguration(
            service_manager_units=[
                ServiceManagerUnit(unit_id="n", unit_name="named.service", active_state="active")
            ]
        ),
    )
    violations = realization_declaration_violations(_spec([node]))
    assert any("no packages/software_components" in v for v in violations)


def test_assert_raises_with_the_violation():
    node = _node("n.box", runtime=None)
    spec = _spec([node])
    with pytest.raises(RealizationDeclarationGateError) as exc:
        assert_realization_declared(spec)
    assert len(exc.value.violations) == 1


def test_switch_nodes_are_ignored():
    # A switch has no os and nothing to materialize; it is not a violation.
    assert realization_declaration_violations(_spec([_node("n.sw", os="", runtime=None)])) == []


def test_mixed_realization_with_both_styles_passes():
    runtime_node = _node(
        "n.free",
        runtime=RuntimeConfiguration(
            packages=[RuntimePackage(manager="apt", name="curl", version="*")]
        ),
    )
    image_node = _node("n.image", runtime=None)
    spec = _spec([runtime_node, image_node], images=[_image("n.image")])
    assert realization_declaration_violations(spec) == []
