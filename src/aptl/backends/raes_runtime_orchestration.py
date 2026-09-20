"""Validate RAES runtime orchestration joins at the APTL backend boundary.

RAES owns the portable vocabulary. This module does not mirror it: it resolves
the authored same-node reference and admits only the one control-plane shape
the local Compose backend can faithfully enforce (issue #949).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from raes.runtime_configuration import (
    RuntimeConfiguration,
    RuntimeControlInterface,
    RuntimeOrchestrationAuthority,
)
from raes_contracts.addressing import render_compiled_address

from aptl.core.deployment._docker_image_identity import authored_tag_reference
from aptl.core.lab_types import LabResult
from aptl.runtime_authority import (
    DOCKER_SOCKET_PATH,
    DeploymentDockerAuthorityAdmission,
    DeploymentSpawnImageRequirement,
)

if TYPE_CHECKING:
    from aptl.core.deployment.realization import DeploymentNodeRealization



class DockerControlBinder(Protocol):
    """The one backend operation scenario preparation needs."""

    def bind_local_docker_socket(self) -> LabResult:
        """Bind subsequent Docker operations to the admitted local socket."""
        ...


def _value(value: object) -> str:
    """Return an enum-or-string value in its portable spelling."""

    return str(getattr(value, "value", value) or "")


def _control_interfaces_by_id(
    runtime: RuntimeConfiguration,
) -> tuple[dict[str, RuntimeControlInterface], set[str]]:
    """Index local interfaces while retaining ambiguous identifiers."""

    interfaces: dict[str, RuntimeControlInterface] = {}
    duplicate_ids: set[str] = set()
    for interface in runtime.local_control_interfaces:
        identifier = str(interface.control_interface_id or "")
        if identifier in interfaces:
            duplicate_ids.add(identifier)
        interfaces[identifier] = interface
    return interfaces, duplicate_ids


def _authority_class_is_supported(authority: RuntimeOrchestrationAuthority) -> bool:
    """Whether an authority requests the supported Docker privilege class."""

    return bool(
        _value(authority.engine) == "docker"
        and _value(authority.privilege_class) == "host_root_equivalent"
    )


def _control_interface_is_supported(interface: RuntimeControlInterface) -> bool:
    """Whether an interface is the exact canonical read-write Docker socket.

    RAES permits an in-world endpoint to omit its host bind source.  For the
    one host-root-equivalent Docker authority APTL supports, the backend then
    realizes that endpoint from its already-bound canonical local socket.  Any
    authored non-empty source must still match exactly.
    """

    return bool(
        _value(getattr(interface, "kind", "")) == "unix_socket"
        and _value(getattr(interface, "access", "")) == "read_write"
        and getattr(interface, "path", "") == DOCKER_SOCKET_PATH
        and getattr(interface, "bind_source", "") in {"", DOCKER_SOCKET_PATH}
        and not getattr(interface, "protocol", "")
    )


def _authority_binding_is_supported(
    authority: RuntimeOrchestrationAuthority,
    interface: RuntimeControlInterface | None,
    duplicate_ids: set[str],
) -> bool:
    """Whether one authority joins unambiguously to the canonical endpoint."""

    return bool(
        authority.control_interface_ref not in duplicate_ids
        and interface is not None
        and _authority_class_is_supported(authority)
        and _control_interface_is_supported(interface)
    )


def _docker_bind_source(interface: RuntimeControlInterface) -> str:
    """Resolve RAES's optional host source to APTL's admitted local endpoint."""

    return str(interface.bind_source or DOCKER_SOCKET_PATH)


def docker_control_authorities(
    runtime: RuntimeConfiguration | None,
    *,
    node_address: str,
) -> tuple[tuple[RuntimeOrchestrationAuthority, RuntimeControlInterface], ...]:
    """Resolve Docker authorities to exact same-node control interfaces."""

    if runtime is None:
        return ()
    interfaces, duplicate_ids = _control_interfaces_by_id(runtime)

    bindings: list[tuple[RuntimeOrchestrationAuthority, RuntimeControlInterface]] = []
    for authority in runtime.orchestration_authorities:
        interface = interfaces.get(str(authority.control_interface_ref or ""))
        if not _authority_binding_is_supported(authority, interface, duplicate_ids):
            raise ValueError(
                "aptl.provisioner.runtime-control-interface-invalid: "
                f"unsupported orchestration authority on {node_address}."
            )
        assert interface is not None
        bindings.append((authority, interface))
    if len(bindings) > 1:
        raise ValueError(
            "aptl.provisioner.runtime-control-interface-invalid: "
            f"multiple Docker authorities on {node_address}."
        )
    return tuple(bindings)


def _bounded_execution_timeout(
    authority: RuntimeOrchestrationAuthority,
    *,
    node_address: str,
) -> int:
    """Return the admitted finite execution deadline for one authority."""

    lifecycle = getattr(authority, "lifecycle_policy", None)
    raw_timeout = str(getattr(lifecycle, "execution_timeout", "") or "")
    try:
        timeout = int(raw_timeout)
    except ValueError:
        timeout = 0
    if not 0 < timeout <= 86400:
        raise ValueError(
            "aptl.provisioner.orchestration-lifecycle-unbounded: "
            f"missing finite execution timeout on {node_address}."
        )
    return timeout


def _spawn_image_requirement(
    authority: RuntimeOrchestrationAuthority,
    template: object,
    *,
    node_address: str,
    timeout: int,
) -> DeploymentSpawnImageRequirement:
    """Lower one template's authored image reference as written.

    ``RuntimeOrchestrationSpawnTemplate`` requires only ``template_id``;
    ``image_ref`` is an unconstrained string defaulting to empty. A tag-only,
    digest-only, or tag-and-digest reference is equally valid, and the backend
    realizes whichever the author wrote.
    """

    image_ref = str(getattr(template, "image_ref", "") or "")
    return DeploymentSpawnImageRequirement(
        node_address=node_address,
        authority_id=str(authority.orchestration_authority_id),
        template_id=str(getattr(template, "template_id", "")),
        image_ref=image_ref,
        execution_timeout_seconds=timeout,
        tag_reference=authored_tag_reference(image_ref) or "",
    )


def spawn_image_requirements(
    runtime: RuntimeConfiguration | None,
    *,
    node_address: str,
) -> tuple[DeploymentSpawnImageRequirement, ...]:
    """Return the images each authority's templates name, as authored.

    A spawn template is realization demand: it says which image to fetch so
    the authority can run it. It is not a bound on what the holder may launch
    -- a host-root-equivalent socket holder can pull, build, or reuse anything
    on that daemon regardless of what APTL staged -- so nothing here rejects a
    scenario on the strength of the image list.

    ``realized_children`` is an optional description of what the author
    observed. It is not read here: it is not desired state, not an image
    source, and not a correlation contract. Its ``evidence_ref`` and ``count``
    carry no APTL meaning.

    A template naming no image has nothing to fetch and yields no requirement.
    """

    requirements: list[DeploymentSpawnImageRequirement] = []
    for authority, _interface in docker_control_authorities(
        runtime, node_address=node_address
    ):
        if not authority.spawn_templates:
            continue
        timeout = _bounded_execution_timeout(authority, node_address=node_address)
        requirements.extend(
            _spawn_image_requirement(
                authority,
                template,
                node_address=node_address,
                timeout=timeout,
            )
            for template in authority.spawn_templates
            if str(template.image_ref or "")
        )
    return tuple(requirements)


def _node_networks(node: DeploymentNodeRealization) -> set[str]:
    """Return every network selected through either node representation."""

    return set(node.networks) | {
        attachment.network for attachment in node.network_attachments
    }


def _allowed_mount_targets(node: DeploymentNodeRealization) -> set[str]:
    """Return the admitted runtime mount footprint for one holder."""

    targets = {
        str(getattr(mount, "target", "") or "")
        for mount in getattr(node.runtime, "mounts", ())
        if getattr(mount, "target", "")
    }
    if getattr(node.runtime, "service_manager_units", ()):
        targets.add("/sys/fs/cgroup")
    return targets


def admit_docker_authorities(
    nodes: tuple[DeploymentNodeRealization, ...],
) -> tuple[DeploymentDockerAuthorityAdmission, ...]:
    """Return one immutable admission per authored authority holder.

    Network, profile, and service placement do not attenuate a raw Docker
    socket.  Whether the selected backend contains that authority is decided by
    the graph-wide runtime materialization gate, not by censoring valid SDL
    holder shapes here.
    """

    admissions: list[DeploymentDockerAuthorityAdmission] = []
    for node in nodes:
        bindings = docker_control_authorities(node.runtime, node_address=node.address)
        if not bindings:
            continue
        authority, interface = bindings[0]
        requirements = spawn_image_requirements(node.runtime, node_address=node.address)
        allowed_mount_targets = _allowed_mount_targets(node)
        admissions.append(
            DeploymentDockerAuthorityAdmission(
                node_address=node.address,
                service_name=str(node.service_name),
                engine=_value(authority.engine),
                privilege_class=_value(authority.privilege_class),
                endpoint_kind=_value(interface.kind),
                endpoint_source=_docker_bind_source(interface),
                endpoint_target=str(interface.path),
                endpoint_read_write=_value(interface.access) == "read_write",
                spawn_requirements=requirements,
                authority_id=str(authority.orchestration_authority_id),
                image_template_ids=tuple(
                    str(template.template_id) for template in authority.spawn_templates
                ),
                allowed_mount_targets=tuple(sorted(allowed_mount_targets)),
                allowed_networks=tuple(sorted(_node_networks(node))),
            )
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
        address = render_compiled_address("provision", "node", name)
        runtime = getattr(node, "runtime", None)
        if docker_control_authorities(runtime, node_address=address):
            required = True
    if required:
        result = backend.bind_local_docker_socket()
        if not result.success:
            raise ValueError(result.error or "Docker control endpoint unavailable.")
