"""Lowering tests: a service-search-index-schema content-placement lowers to the
typed :class:`DeploymentServiceSearchIndexSchemaRealization` instead of being
rejected as an item-less dataset (issue #889).

The TechVault pack no longer declares this historical Cortex index, but the
scenario-independent lowering contract remains supported. These tests pin that
public plan-resource shape directly so removing one pack use does not silently
remove or weaken the generic materializer.
"""

from __future__ import annotations

from pathlib import Path

from raes_contracts.planning import PlannedResource, RuntimeDomain

from aptl.backends.raes_content_realization import resolve_content_placement
from aptl.backends.raes_service_index_schema import canonical_field_schema_digest
from aptl.core.deployment.realization import (
    DeploymentServiceSearchIndexSchemaRealization,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _cortex_content_resource() -> PlannedResource:
    fields = {
        "key": "exact-token",
        "status": "exact-token",
        "relations": "exact-token",
    }
    payload = {
        "content_name": "cortex-job-index-schema",
        "service_materialization": {
            "interface_profile": "service-search-index-schema",
            "profile_version": "1",
            "target_service_address": "provision.node.thehive-es.service.elasticsearch",
            "field_semantics": fields,
            "canonical_field_schema_digest": canonical_field_schema_digest(fields),
        },
    }
    return PlannedResource(
        address="provision.content.cortex-job-index-schema",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload=payload,
    )


def test_search_index_schema_content_lowers_to_typed_realization() -> None:
    resource = _cortex_content_resource()

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


def test_non_projectable_field_semantic_fails_closed() -> None:
    resource = _cortex_content_resource()
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
