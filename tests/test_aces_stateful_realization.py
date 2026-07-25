"""Tests for ACES generated-artifact and persistent-volume lowering."""

from __future__ import annotations

from pathlib import Path

from aces_contracts.planning import (
    ChangeAction,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RuntimeDomain,
)

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig


def _resource(
    resource_type: str,
    name: str,
    spec: dict[str, object],
    *,
    ordering_dependencies: tuple[str, ...] = (),
) -> PlannedResource:
    address = f"provision.{resource_type}.{name}"
    return PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type=resource_type,
        payload={"name": name, "spec": spec},
        ordering_dependencies=ordering_dependencies,
    )


def _node(name: str) -> PlannedResource:
    return _resource(
        "node",
        name,
        {
            "node": {"name": name},
            "infrastructure": {},
        },
    )


def _plan(*resources: PlannedResource) -> ProvisioningPlan:
    mapped = {resource.address: resource for resource in resources}
    return ProvisioningPlan(
        resources=mapped,
        operations=[
            ProvisionOp(
                action=ChangeAction.CREATE,
                address=resource.address,
                resource_type=resource.resource_type,
                payload=resource.payload,
                ordering_dependencies=resource.ordering_dependencies,
                refresh_dependencies=resource.refresh_dependencies,
            )
            for resource in resources
        ],
    )


def _write_compose(project_dir: Path) -> None:
    (project_dir / "docker-compose.yml").write_text(
        """services:
  wazuh-indexer:
    profiles: [wazuh]
    image: wazuh/wazuh-indexer:4.12.0
  wazuh-manager:
    profiles: [wazuh]
    image: wazuh/wazuh-manager:4.12.0
"""
    )


def _config() -> AptlConfig:
    return AptlConfig(lab={"name": "test"}, containers={"wazuh": True})


def test_manifest_advertises_released_stateful_contract() -> None:
    manifest = create_aptl_manifest()

    assert manifest.provisioner.supports_generated_artifacts is True
    assert manifest.provisioner.supports_persistent_volumes is True


def test_interpreter_lowers_stateful_resources_into_deployment_spec(tmp_path: Path) -> None:
    _write_compose(tmp_path)
    artifact = _resource(
        "generated-artifact",
        "wazuh-indexer-certs",
        {
            "generator": "certificate_bundle",
            "lifecycle": "reuse_valid",
            "provenance": "config/certs.yml",
            "outputs": [
                {"name": "root-ca", "path": "root-ca.pem", "sensitivity": "public"},
                {
                    "name": "indexer-key",
                    "path": "wazuh.indexer-key.pem",
                    "sensitivity": "secret",
                },
            ],
            "consumers": [
                {
                    "node": "wazuh-indexer",
                    "target_address": "provision.node.wazuh-indexer",
                    "mount_destination": "/usr/share/wazuh-indexer/certs",
                    "access_mode": "read_only",
                }
            ],
        },
    )
    volume = _resource(
        "persistent-volume",
        "wazuh-indexer-data",
        {
            "lifecycle": "retain",
            "access_mode": "read_write_once",
            "consumers": [
                {
                    "node": "wazuh-indexer",
                    "target_address": "provision.node.wazuh-indexer",
                    "mount_destination": "/var/lib/wazuh-indexer",
                    "access_mode": "read_write",
                }
            ],
        },
        ordering_dependencies=(artifact.address,),
    )

    realization = interpret_provisioning_plan(
        plan=_plan(_node("wazuh-indexer"), _node("wazuh-manager"), artifact, volume),
        project_dir=tmp_path,
        config=_config(),
    )

    assert [item.code for item in realization.diagnostics] == []
    assert len(realization.generated_artifacts) == 1
    assert len(realization.persistent_volumes) == 1
    generated = realization.generated_artifacts[0]
    assert generated.address == artifact.address
    assert generated.generator == "certificate_bundle"
    assert generated.outputs[1].sensitivity == "secret"
    assert generated.consumers[0].service_name == "wazuh-indexer"
    persistent = realization.persistent_volumes[0]
    assert persistent.ordering_dependencies == (artifact.address,)
    assert persistent.consumers[0].mount_destination == "/var/lib/wazuh-indexer"

    spec = realization.deployment_spec(["wazuh", "otel"])
    assert spec.generated_artifacts == realization.generated_artifacts
    assert spec.persistent_volumes == realization.persistent_volumes


def test_interpreter_rejects_unknown_stateful_consumer_before_backend(tmp_path: Path) -> None:
    _write_compose(tmp_path)
    artifact = _resource(
        "generated-artifact",
        "orphaned-config",
        {
            "generator": "rendered_config",
            "lifecycle": "regenerate_on_change",
            "provenance": "config/wazuh-manager.conf.template",
            "outputs": [
                {"name": "manager-conf", "path": "ossec.conf", "sensitivity": "restricted"}
            ],
            "consumers": [
                {
                    "node": "missing",
                    "target_address": "provision.node.missing",
                    "mount_destination": "/var/ossec/etc/ossec.conf",
                    "access_mode": "read_only",
                }
            ],
        },
    )

    realization = interpret_provisioning_plan(
        plan=_plan(_node("wazuh-indexer"), artifact),
        project_dir=tmp_path,
        config=_config(),
    )

    assert realization.generated_artifacts == ()
    assert any(
        item.code == "aptl.provisioner.stateful-consumer-unresolved"
        for item in realization.diagnostics
    )
