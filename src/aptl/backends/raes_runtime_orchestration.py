"""Validate RAES runtime orchestration joins at the APTL backend boundary.

RAES owns the portable vocabulary. This module does not mirror it: it resolves
the authored same-node reference and admits only the one control-plane shape
the local Compose backend can faithfully enforce (issue #949).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Protocol

from raes.runtime_configuration import (
    RuntimeConfiguration,
    RuntimeControlInterface,
    RuntimeOrchestrationAuthority,
)
from raes_processor.compiler.addresses import _node_address

from aptl.core.lab_types import LabResult
from aptl.runtime_authority import (
    DOCKER_SOCKET_PATH,
    DeploymentDockerAuthorityAdmission,
    DeploymentSpawnImageRequirement,
)

if TYPE_CHECKING:
    from aptl.core.deployment.realization import DeploymentNodeRealization

_DIGEST_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_CHILD_LABEL = re.compile(
    r"^docker-label:([a-z0-9][a-z0-9._/-]*)=([a-z0-9][a-z0-9._-]*)$"
)
_MANAGEMENT_PROFILES = frozenset({"soc"})


class DockerControlBinder(Protocol):
    """The one backend operation scenario preparation needs."""

    def bind_local_docker_socket(self) -> LabResult:
        """Bind subsequent Docker operations to the admitted local socket."""
        ...


def _value(value: object) -> str:
    """Return an enum-or-string value in its portable spelling."""

    return str(getattr(value, "value", value) or "")


def docker_control_authorities(
    runtime: RuntimeConfiguration | None,
    *,
    node_address: str,
) -> tuple[tuple[RuntimeOrchestrationAuthority, RuntimeControlInterface], ...]:
    """Resolve Docker authorities to exact same-node control interfaces."""

    if runtime is None:
        return ()
    interfaces: dict[str, RuntimeControlInterface] = {}
    duplicate_ids: set[str] = set()
    for interface in runtime.local_control_interfaces:
        identifier = str(interface.control_interface_id or "")
        if identifier in interfaces:
            duplicate_ids.add(identifier)
        interfaces[identifier] = interface

    bindings: list[tuple[RuntimeOrchestrationAuthority, RuntimeControlInterface]] = []
    for authority in runtime.orchestration_authorities:
        interface = interfaces.get(str(authority.control_interface_ref or ""))
        valid = (
            _value(authority.engine) == "docker"
            and _value(authority.privilege_class) == "host_root_equivalent"
            and authority.control_interface_ref not in duplicate_ids
            and interface is not None
            and _value(getattr(interface, "kind", "")) == "unix_socket"
            and _value(getattr(interface, "access", "")) == "read_write"
            and getattr(interface, "path", "") == DOCKER_SOCKET_PATH
            and getattr(interface, "bind_source", "") == DOCKER_SOCKET_PATH
            and not getattr(interface, "protocol", "")
        )
        if not valid:
            raise ValueError(
                "aptl.provisioner.runtime-control-interface-invalid: "
                f"unsupported orchestration authority on {node_address}."
            )
        bindings.append((authority, interface))
    if len(bindings) > 1:
        raise ValueError(
            "aptl.provisioner.runtime-control-interface-invalid: "
            f"multiple Docker authorities on {node_address}."
        )
    return tuple(bindings)


def spawn_image_requirements(
    runtime: RuntimeConfiguration | None,
    *,
    node_address: str,
) -> tuple[DeploymentSpawnImageRequirement, ...]:
    """Return digest-qualified child-image requirements with provenance."""

    requirements: list[DeploymentSpawnImageRequirement] = []
    for authority, _interface in docker_control_authorities(
        runtime, node_address=node_address
    ):
        lifecycle = getattr(authority, "lifecycle_policy", None)
        timeout = str(getattr(lifecycle, "execution_timeout", "") or "")
        try:
            timeout_seconds = int(timeout)
            bounded = 0 < timeout_seconds <= 86400
        except ValueError:
            bounded = False
            timeout_seconds = 0
        if not bounded:
            raise ValueError(
                "aptl.provisioner.orchestration-lifecycle-unbounded: "
                f"missing finite execution timeout on {node_address}."
            )
        if not authority.spawn_templates:
            raise ValueError(
                "aptl.provisioner.spawn-image-identity-invalid: "
                f"empty child-image closure on {node_address}."
            )
        template_images = [
            str(template.image_ref or "") for template in authority.spawn_templates
        ]
        child_images = [
            str(child.image_ref or "") for child in authority.realized_children
        ]
        children = {
            str(child.image_ref or ""): child for child in authority.realized_children
        }
        if (
            len(template_images) != len(set(template_images))
            or len(child_images) != len(set(child_images))
            or set(child_images) != set(template_images)
        ):
            raise ValueError(
                "aptl.provisioner.spawn-child-correlation-invalid: "
                f"child correlation is incomplete on {node_address}."
            )
        for template in authority.spawn_templates:
            image_ref = str(template.image_ref or "")
            if not _DIGEST_IMAGE.fullmatch(image_ref):
                raise ValueError(
                    "aptl.provisioner.spawn-image-identity-invalid: "
                    f"mutable child image on {node_address}."
                )
            child = children[image_ref]
            label_match = _CHILD_LABEL.fullmatch(str(child.evidence_ref or ""))
            count = child.count
            child_image_ref = str(child.image_ref or "")
            if (
                label_match is None
                or isinstance(count, bool)
                or not isinstance(count, int)
                or not 0 < count <= 1000
                or child_image_ref != image_ref
            ):
                raise ValueError(
                    "aptl.provisioner.spawn-child-correlation-invalid: "
                    f"unsupported child correlation on {node_address}."
                )
            requirements.append(
                DeploymentSpawnImageRequirement(
                    node_address=node_address,
                    authority_id=str(authority.orchestration_authority_id),
                    template_id=str(template.template_id),
                    image_ref=image_ref,
                    execution_timeout_seconds=timeout_seconds,
                    child_label=f"{label_match.group(1)}={label_match.group(2)}",
                    expected_count=count,
                )
            )
    return tuple(requirements)


def admit_docker_authorities(
    nodes: tuple[DeploymentNodeRealization, ...],
) -> tuple[DeploymentDockerAuthorityAdmission, ...]:
    """Return one immutable admission per management-only authority holder."""

    admissions: list[DeploymentDockerAuthorityAdmission] = []
    for node in nodes:
        bindings = docker_control_authorities(node.runtime, node_address=node.address)
        if not bindings:
            continue
        networks = set(node.networks) | {
            attachment.network for attachment in node.network_attachments
        }
        container = getattr(node.runtime, "container", None)
        namespaces = getattr(container, "namespaces", None)
        network_namespace = getattr(namespaces, "network", None)
        management_only = (
            bool(node.service_name)
            and bool(networks)
            and bool(node.profiles)
            and set(node.profiles) <= _MANAGEMENT_PROFILES
            and not node.services
            and not node.published_ports
            and not getattr(network_namespace, "target_node_ref", None)
        )
        if not management_only:
            raise ValueError(
                "aptl.provisioner.runtime-authority-not-management-only: "
                f"Docker authority is not management-only on {node.address}."
            )
        authority, interface = bindings[0]
        requirements = spawn_image_requirements(node.runtime, node_address=node.address)
        allowed_mount_targets = {
            str(getattr(mount, "target", "") or "")
            for mount in getattr(node.runtime, "mounts", ())
            if getattr(mount, "target", "")
        }
        if getattr(node.runtime, "service_manager_units", ()):
            allowed_mount_targets.add("/sys/fs/cgroup")
        admissions.append(
            DeploymentDockerAuthorityAdmission(
                node_address=node.address,
                service_name=str(node.service_name),
                engine=_value(authority.engine),
                privilege_class=_value(authority.privilege_class),
                endpoint_kind=_value(interface.kind),
                endpoint_source=str(interface.bind_source),
                endpoint_target=str(interface.path),
                endpoint_read_write=_value(interface.access) == "read_write",
                spawn_requirements=requirements,
                allowed_mount_targets=tuple(sorted(allowed_mount_targets)),
            )
        )
    requirements = [
        requirement
        for admission in admissions
        for requirement in admission.spawn_requirements
    ]
    labels = [requirement.child_label for requirement in requirements]
    if len(labels) != len(set(labels)):
        raise ValueError(
            "aptl.provisioner.spawn-child-correlation-invalid: "
            "child correlation labels must be unique across authorities."
        )
    return tuple(admissions)


def prepare_runtime_orchestration_for_scenario(
    scenario: object,
    backend: DockerControlBinder,
) -> None:
    """Validate control joins and bind Docker before availability probes.

    Spawn-image identity belongs to backend realization, immediately before
    image preparation. Read-only planning still needs the selected daemon bound
    before ordinary artifact probes, but must not turn a downstream pack update
    into a prerequisite for installing this generic capability (#949/#285).
    """

    nodes = getattr(scenario, "nodes", None) or {}
    required = False
    for name, node in nodes.items():
        address = _node_address(name)
        runtime = getattr(node, "runtime", None)
        if docker_control_authorities(runtime, node_address=address):
            required = True
    if required:
        result = backend.bind_local_docker_socket()
        if not result.success:
            raise ValueError(result.error or "Docker control endpoint unavailable.")
