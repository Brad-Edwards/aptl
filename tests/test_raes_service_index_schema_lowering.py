"""Lowering tests: a service-search-index-schema content-placement lowers to the
typed :class:`DeploymentServiceSearchIndexSchemaRealization` instead of being
rejected as an item-less dataset (issue #889).

Compiles the real installed TechVault env-pack (issue #875 architecture) so the
test binds to the actual contract APTL receives from a live plan, not a
hand-built approximation.
"""

from __future__ import annotations

import importlib.resources as ir
from pathlib import Path
from unittest.mock import MagicMock

from raes_contracts.planning import ProvisioningPlan

from aptl.backends.raes_content_realization import resolve_content_placement
from aptl.core.deployment.realization import DeploymentServiceSearchIndexSchemaRealization

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _pack_root() -> Path:
    return Path(str(ir.files("raes_env_packs") / "resources" / "packs" / "techvault"))


def _cortex_content_resource(tmp_path: Path):
    from raes_runtime.manager import RuntimeManager

    from aptl.backends.raes import create_aptl_runtime_target, parse_sdl_file
    from aptl.core.config import AptlConfig
    from aptl.core.scenario_bundle import env_pack_bundle

    bundle = env_pack_bundle(tmp_path, identity="techvault", source_pack=_pack_root())
    config = AptlConfig(
        lab={"name": "tv"},
        containers={
            "wazuh": True,
            "soc": True,
            "enterprise": True,
            "victim": True,
            "kali": True,
            "fileshare": True,
            "dns": True,
        },
    )
    target = create_aptl_runtime_target(
        project_dir=PROJECT_ROOT, config=config, backend=MagicMock(), bundle=bundle
    )
    scenario = parse_sdl_file(bundle.sdl_path)
    plan = RuntimeManager(target).plan(scenario)
    provisioning: ProvisioningPlan = plan.provisioning
    return next(
        resource
        for address, resource in provisioning.resources.items()
        if resource.resource_type == "content-placement" and "cortex-job-index-schema" in address
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
    assert realization.target_service_address == "provision.node.thehive-es.service.elasticsearch"
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
    binding["field_semantics"] = {"key": "geo-shape"}  # not a portable semantic APTL can project
    payload["service_materialization"] = binding

    realization, diagnostics = resolve_content_placement(
        resource=resource,
        payload=payload,
        target_address="provision.node.thehive-es",
        target_service=None,
        project_dir=PROJECT_ROOT,
    )

    assert realization is None
    assert [d.code for d in diagnostics] == ["aptl.provisioner.content-placement-rejected"]
    assert "service-index-schema-field-semantics-invalid" in diagnostics[0].message
