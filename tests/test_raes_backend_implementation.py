"""Backend implementation selection respects RAES realization authority."""

from __future__ import annotations

from raes.runtime_configuration import RuntimeConfiguration
from raes_contracts.planning import (
    ChangeAction,
    PlannedRealizationConstraint,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RealizationAuthorityMode,
    RealizationResolutionSource,
    ResolvedRealizationAuthority,
    RuntimeDomain,
)


_ADDRESS = "provision.node.renamed"


def _resource(runtime: RuntimeConfiguration) -> PlannedResource:
    return PlannedResource(
        address=_ADDRESS,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload={
            "name": "renamed",
            "spec": {
                "node": {
                    "name": "renamed",
                    "os": "linux",
                    "runtime": runtime.model_dump(mode="python", by_alias=True),
                },
                "infrastructure": {},
            },
        },
    )


def _authority(kind: str, pointer: str) -> ResolvedRealizationAuthority:
    return ResolvedRealizationAuthority(
        address=_ADDRESS,
        field_path=f"nodes.renamed.{kind}",
        domain="runtime-realization",
        requirement_kind=kind,
        payload_pointer=pointer,
        mode=RealizationAuthorityMode.OPEN,
        source=RealizationResolutionSource.AUTHORED_SCOPE,
        governing_scope="#/realization",
    )


def _plan(
    runtime: RuntimeConfiguration,
    *,
    substrate_posture: str | None,
    authorities: tuple[ResolvedRealizationAuthority, ...] = (),
) -> tuple[ProvisioningPlan, PlannedResource]:
    resource = _resource(runtime)
    operation = ProvisionOp(
        action=ChangeAction.CREATE,
        address=resource.address,
        resource_type=resource.resource_type,
        payload=resource.payload,
    )
    constraints = (
        (
            PlannedRealizationConstraint(
                address=_ADDRESS,
                field_path="nodes.renamed.realization.compute_substrate",
                concern="compute-substrate",
                posture=substrate_posture,
                value_domain=None,
                governing_scope="#/realization",
                provenance="author-declared",
            ),
        )
        if substrate_posture is not None
        else ()
    )
    return (
        ProvisioningPlan(
            resources={resource.address: resource},
            operations=[operation],
            realization_authority=authorities,
            realization_constraints=constraints,
        ),
        resource,
    )


def test_semantic_profile_selects_an_image_without_using_the_node_name() -> None:
    from aptl.backends.raes_backend_implementation import (
        select_backend_node_implementation,
    )

    runtime = RuntimeConfiguration.model_validate(
        {
            "datastore_services": [
                {
                    "datastore_service_id": "cache",
                    "engine": "redis",
                    "version": "7",
                }
            ]
        }
    )
    plan, resource = _plan(runtime, substrate_posture="open")
    diagnostics = []

    selected = select_backend_node_implementation(
        plan=plan,
        resource=resource,
        runtime=runtime,
        service_name="renamed",
        diagnostics=diagnostics,
    )

    assert diagnostics == []
    assert selected is not None
    assert selected.image.policy_rule == "backend-open-profile"
    assert selected.image.image_ref.startswith("redis@sha256:")
    assert selected.selected_concerns == ("compute-substrate",)


def test_closed_compute_scope_refuses_the_matching_backend_profile() -> None:
    from aptl.backends.raes_backend_implementation import (
        select_backend_node_implementation,
    )

    runtime = RuntimeConfiguration.model_validate(
        {
            "datastore_services": [
                {
                    "datastore_service_id": "cache",
                    "engine": "redis",
                    "version": "7",
                }
            ]
        }
    )
    plan, resource = _plan(runtime, substrate_posture=None)
    diagnostics = []

    selected = select_backend_node_implementation(
        plan=plan,
        resource=resource,
        runtime=runtime,
        service_name="renamed",
        diagnostics=diagnostics,
    )

    assert selected is None
    assert [item.code for item in diagnostics] == [
        "aptl.provisioner.backend-implementation-not-authorized"
    ]


def test_profile_adds_only_runtime_concerns_with_open_authority() -> None:
    from aptl.backends.raes_backend_implementation import (
        select_backend_node_implementation,
    )

    runtime = RuntimeConfiguration.model_validate(
        {
            "software_components": [
                {
                    "component_id": "shuffle-frontend",
                    "name": "Shuffle frontend",
                    "version": "unversioned",
                }
            ]
        }
    )
    authorities = (
        _authority("runtime-environment", "/spec/node/runtime/environment"),
        _authority("published-ports", "/spec/node/runtime/network/published_ports"),
    )
    plan, resource = _plan(
        runtime,
        substrate_posture="open",
        authorities=authorities,
    )
    diagnostics = []

    selected = select_backend_node_implementation(
        plan=plan,
        resource=resource,
        runtime=runtime,
        service_name="renamed",
        diagnostics=diagnostics,
    )

    assert diagnostics == []
    assert selected is not None
    assert [item.name for item in selected.runtime.environment] == ["BACKEND_HOSTNAME"]
    assert len(selected.runtime.network.published_ports) == 2
    assert selected.selected_concerns == (
        "compute-substrate",
        "published-ports",
        "runtime-environment",
    )


def test_profile_refuses_partial_runtime_authority() -> None:
    from aptl.backends.raes_backend_implementation import (
        select_backend_node_implementation,
    )

    runtime = RuntimeConfiguration.model_validate(
        {
            "software_components": [
                {
                    "component_id": "shuffle-frontend",
                    "name": "Shuffle frontend",
                    "version": "unversioned",
                }
            ]
        }
    )
    plan, resource = _plan(
        runtime,
        substrate_posture="open",
        authorities=(
            _authority("runtime-environment", "/spec/node/runtime/environment"),
        ),
    )
    diagnostics = []

    selected = select_backend_node_implementation(
        plan=plan,
        resource=resource,
        runtime=runtime,
        service_name="renamed",
        diagnostics=diagnostics,
    )

    assert selected is None
    assert [item.code for item in diagnostics] == [
        "aptl.provisioner.backend-implementation-not-authorized"
    ]


def test_thehive_open_environment_selects_its_minimum_generated_prerequisite() -> None:
    from aptl.backends.raes_backend_implementation import (
        select_backend_node_implementation,
    )

    runtime = RuntimeConfiguration.model_validate(
        {
            "platform_applications": [
                {
                    "platform_application_id": "case-management",
                    "product": "TheHive",
                    "version": "5.4",
                }
            ]
        }
    )
    plan, resource = _plan(
        runtime,
        substrate_posture="open",
        authorities=(
            _authority("runtime-environment", "/spec/node/runtime/environment"),
            _authority(
                "runtime-container-command", "/spec/node/runtime/container/command"
            ),
            _authority(
                "published-ports", "/spec/node/runtime/network/published_ports"
            ),
        ),
    )
    diagnostics = []

    selected = select_backend_node_implementation(
        plan=plan,
        resource=resource,
        runtime=runtime,
        service_name="thehive",
        diagnostics=diagnostics,
    )

    assert diagnostics == []
    assert selected is not None
    assert len(selected.generated_artifacts) == 1
    artifact = selected.generated_artifacts[0]
    assert artifact.address == "backend.generated-artifact.cortex-service-credentials"
    assert artifact.name == "cortex-service-credentials"
    assert artifact.outputs[0].disposition == "producer_private"
    assert artifact.environment_consumers[0].target_address == _ADDRESS
    assert artifact.environment_consumers[0].service_name == "thehive"
    assert artifact.environment_consumers[0].environment_variable == "TH_CORTEX_KEYS"


def test_thehive_closed_environment_cannot_select_generated_prerequisite() -> None:
    from aptl.backends.raes_backend_implementation import (
        select_backend_node_implementation,
    )

    runtime = RuntimeConfiguration.model_validate(
        {
            "platform_applications": [
                {
                    "platform_application_id": "case-management",
                    "product": "TheHive",
                    "version": "5.4",
                }
            ]
        }
    )
    plan, resource = _plan(
        runtime,
        substrate_posture="open",
        authorities=(
            _authority(
                "runtime-container-command", "/spec/node/runtime/container/command"
            ),
            _authority(
                "published-ports", "/spec/node/runtime/network/published_ports"
            ),
        ),
    )
    diagnostics = []

    selected = select_backend_node_implementation(
        plan=plan,
        resource=resource,
        runtime=runtime,
        service_name="thehive",
        diagnostics=diagnostics,
    )

    assert selected is None
    assert [item.code for item in diagnostics] == [
        "aptl.provisioner.backend-implementation-not-authorized"
    ]


def test_open_compute_selects_node22_ssh_base_from_portable_semantics() -> None:
    from aptl.backends._raes_backend_implementation_profiles import (
        NODE22_SYSTEMD_BASE_IMAGE,
    )
    from aptl.backends.raes_backend_implementation import (
        select_backend_node_implementation,
    )

    runtime = RuntimeConfiguration.model_validate(
        {
            "software_components": [
                {
                    "component_id": "nodejs",
                    "name": "Node.js",
                    "version": "22",
                }
            ],
            "service_manager_units": [
                {
                    "unit_id": "ssh",
                    "unit_name": "ssh.service",
                    "enabled_state": "enabled",
                    "active_state": "active",
                }
            ],
        }
    )
    plan, resource = _plan(runtime, substrate_posture="open")
    diagnostics = []

    selected = select_backend_node_implementation(
        plan=plan,
        resource=resource,
        runtime=runtime,
        service_name="renamed",
        diagnostics=diagnostics,
    )

    assert diagnostics == []
    assert selected is not None
    assert selected.image is None
    assert selected.base_image_ref == NODE22_SYSTEMD_BASE_IMAGE
    assert selected.selected_concerns == ("compute-substrate",)


def test_suricata_profile_selects_passive_capture_on_all_node_interfaces() -> None:
    from aptl.backends.raes_backend_implementation import (
        select_backend_node_implementation,
    )

    runtime = RuntimeConfiguration.model_validate(
        {
            "network_detection_engines": [
                {
                    "network_detection_engine_id": "ids",
                    "implementation": "suricata",
                    "version": "7.0",
                }
            ]
        }
    )
    plan, resource = _plan(
        runtime,
        substrate_posture="open",
        authorities=(
            _authority(
                "runtime-container-entrypoint",
                "/spec/node/runtime/container/entrypoint",
            ),
            _authority(
                "linux-capabilities",
                "/spec/node/runtime/linux_capabilities",
            ),
        ),
    )
    diagnostics = []

    selected = select_backend_node_implementation(
        plan=plan,
        resource=resource,
        runtime=runtime,
        service_name="renamed",
        diagnostics=diagnostics,
    )

    assert diagnostics == []
    assert selected is not None
    assert selected.runtime.container is not None
    assert selected.runtime.container.entrypoint[-1].endswith("--pcap=any")


def test_active_directory_semantics_select_generic_samba_provider() -> None:
    from aptl.backends._raes_backend_implementation_profiles import (
        SAMBA_AD_BASE_IMAGE,
    )
    from aptl.backends.raes_backend_implementation import (
        select_backend_node_implementation,
    )

    runtime = RuntimeConfiguration.model_validate(
        {
            "identity_authorities": [
                {
                    "identity_authority_id": "corp-domain",
                    "kind": "domain",
                    "name": "Corporate directory",
                    "domain_name": "example.test",
                    "realm": "EXAMPLE.TEST",
                }
            ],
            "service_listeners": [
                {
                    "service_listener_id": "ldap",
                    "service": "ldap",
                    "protocol": "tcp",
                    "address": "0.0.0.0",
                    "port": 389,
                },
                {
                    "service_listener_id": "kerberos",
                    "service": "kerberos",
                    "protocol": "tcp",
                    "address": "0.0.0.0",
                    "port": 88,
                },
                {
                    "service_listener_id": "smb",
                    "service": "smb",
                    "protocol": "tcp",
                    "address": "0.0.0.0",
                    "port": 445,
                },
            ],
        }
    )
    plan, resource = _plan(runtime, substrate_posture="open")
    diagnostics = []

    selected = select_backend_node_implementation(
        plan=plan,
        resource=resource,
        runtime=runtime,
        service_name="renamed",
        diagnostics=diagnostics,
    )

    assert diagnostics == []
    assert selected is not None
    assert selected.base_image_ref == SAMBA_AD_BASE_IMAGE
    assert selected.base_use_image_command is True
    assert selected.base_run_capabilities == ("SYS_ADMIN",)
    assert selected.provider_kind == "samba-active-directory"
    assert dict(selected.provider_parameters) == {
        "domain": "EXAMPLE",
        "realm": "EXAMPLE.TEST",
    }
    assert selected.selected_concerns == ("compute-substrate",)
