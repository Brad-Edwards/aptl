"""Lowering tests: a service-search-index-schema content-placement lowers to the
typed :class:`DeploymentServiceSearchIndexSchemaRealization` instead of being
rejected as an item-less dataset (issue #889).

The TechVault 6.0 pack no longer authors this retired Cortex initializer. These
tests retain APTL's generic lowering contract with the exact public planned
resource shape; RAES owns the independent compiler coverage for that shape.
"""

from __future__ import annotations

from pathlib import Path

from raes_contracts.planning import PlannedResource, RuntimeDomain

from aptl.backends.raes_content_realization import resolve_content_placement
from aptl.core.deployment.realization import (
    DeploymentServiceSearchIndexSchemaRealization,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _cortex_content_resource(tmp_path: Path):
    del tmp_path
    return PlannedResource(
        address="provision.content.cortex-job-index-schema",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload={
            "name": "cortex-job-index-schema",
            "content_name": "cortex-job-index-schema",
            "target_node": "thehive-es",
            "target_address": "provision.node.thehive-es",
            "spec": {
                "type": "dataset",
                "items": [],
                "sensitive": False,
                "tags": [],
            },
            "service_materialization": {
                "target_service_address": "provision.node.thehive-es.service.elasticsearch",
                "interface_profile": "service-search-index-schema",
                "profile_version": "1",
                "content_type": "dataset",
                "operation": "ensure-search-index-field-schema",
                "conflict_policy": "reject-unowned-collision",
                "readback": "canonical-portable-field-schema-digest",
                "field_semantics": {
                    "key": "exact-token",
                    "status": "exact-token",
                    "relations": "exact-token",
                },
                "canonical_field_schema_digest": (
                    "sha256:2d0661b00c76f58086aacece2f7a11612713f64f5b49952ec1bc5e53b3a42e37"
                ),
            },
        },
    )


def test_search_index_schema_content_lowers_to_typed_realization(tmp_path) -> None:
    resource = _cortex_content_resource(tmp_path)

    realization, diagnostics = resolve_content_placement(
        resource=resource,
        payload=resource.payload,
        target_address="provision.node.thehive-es",
        target_service=None,
        project_dir=PROJECT_ROOT,
    )

    assert diagnostics == []
    assert isinstance(realization, DeploymentServiceSearchIndexSchemaRealization)
    assert realization.address == resource.address
    assert realization.target_address == "provision.node.thehive-es"
    assert (
        realization.target_service_address
        == "provision.node.thehive-es.service.elasticsearch"
    )
    assert realization.field_semantics_map() == {
        "key": "exact-token",
        "status": "exact-token",
        "relations": "exact-token",
    }
    # The digest APTL carries must equal the RAES-compiled binding digest, so a
    # native readback proof compares against the authored desired state.
    assert (
        realization.field_schema_digest
        == resource.payload["service_materialization"]["canonical_field_schema_digest"]
    )


def test_non_projectable_field_semantic_fails_closed(tmp_path) -> None:
    resource = _cortex_content_resource(tmp_path)
    payload = dict(resource.payload)
    binding = dict(payload["service_materialization"])
    binding["field_semantics"] = {
        "key": "geo-shape"
    }  # not a portable semantic APTL can project
    payload["service_materialization"] = binding

    realization, diagnostics = resolve_content_placement(
        resource=resource,
        payload=payload,
        target_address="provision.node.thehive-es",
        target_service=None,
        project_dir=PROJECT_ROOT,
    )

    assert realization is None
    assert [d.code for d in diagnostics] == [
        "aptl.provisioner.content-placement-rejected"
    ]
    assert "service-index-schema-field-semantics-invalid" in diagnostics[0].message
