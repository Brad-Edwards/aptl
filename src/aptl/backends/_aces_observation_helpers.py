"""Shared provider-readback helpers for ACES realization observation."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aptl.core.deployment._compose_realization_networks import (
    _match_managed_network,
)
from aptl.core.deployment._compose_service_health import (
    container_health,
    container_running,
)
from aptl.core.deployment.errors import (
    BackendSeedError,
    BackendTimeoutError,
)
from aptl.core.deployment.realization import (
    DeploymentGeneratedArtifactRealization,
    DeploymentPersistentVolumeRealization,
    DeploymentStatefulConsumer,
)
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.realization import DeploymentContentRealization

log = get_logger("realization-observe")


@dataclass(frozen=True)
class ObservedResource(object):
    """What the deployment backend was observed to have realized for one address.

    ``concerns`` maps a SEM-218 concern payload path to the value the backend
    actually realized there. A concern the backend cannot be seen to have
    realized is simply absent, so the gate sees an omission rather than an echo.
    """

    realized: bool
    concerns: dict[tuple[str, ...], object] = field(default_factory=dict)
    evidence: dict[str, object] = field(default_factory=dict)


def consumer_mount_evidence(
    consumers: tuple[DeploymentStatefulConsumer, ...],
) -> list[dict[str, str]]:
    """Describe each verified consumer mount without secret material."""

    return [
        {
            "target_address": consumer.target_address,
            "destination": consumer.mount_destination,
            "access_mode": consumer.access_mode,
            "service_health": "healthy",
        }
        for consumer in consumers
    ]


def mount_present(
    info: Mapping[str, Any],
    consumer: DeploymentStatefulConsumer,
    *,
    mount_type: str,
    source: str,
    destination: str | None = None,
) -> bool:
    """Return whether container inspection shows the exact desired mount."""

    mounts = info.get("Mounts")
    if not isinstance(mounts, list):
        return False
    for mount in mounts:
        if not isinstance(mount, Mapping):
            continue
        observed_source = (
            mount.get("Name") if mount_type == "volume" else mount.get("Source")
        )
        if (
            mount.get("Type") == mount_type
            and observed_source == source
            and mount.get("Destination") == (destination or consumer.mount_destination)
            and bool(mount.get("RW")) == (consumer.access_mode == "read_write")
        ):
            return True
    return False


# The realized dependency wiring lives on the DTOs as plan addresses
# (``provision.generated-artifact.X``); the declared spec states the same
# wiring in the author vocabulary (``generated_artifacts.X``). aces-sdl
# 0.23 carries the dependency fields inside the declared spec, so the
# observed spec must render the wiring the backend actually realized in
# that same vocabulary or the SEM-218 exact comparison rejects every
# artifact and volume (issue #677).
_AUTHOR_DEPENDENCY_PREFIXES = (
    ("provision.generated-artifact.", "generated_artifacts."),
    ("provision.persistent-volume.", "persistent_volumes."),
    ("provision.node.", "nodes."),
    ("provision.network.", "networks."),
)


def _author_dependency(address: str) -> str:
    """Render one realized dependency address in the author vocabulary."""

    for plan_prefix, author_prefix in _AUTHOR_DEPENDENCY_PREFIXES:
        if address.startswith(plan_prefix):
            return author_prefix + address[len(plan_prefix) :]
    return address


def _author_dependencies(addresses: tuple[str, ...]) -> list[str]:
    """Render realized dependency wiring in the author vocabulary."""

    return [_author_dependency(address) for address in addresses]


def artifact_spec(
    artifact: DeploymentGeneratedArtifactRealization,
) -> dict[str, object]:
    """Render the ACES concern value observed for a generated artifact."""

    return {
        "generator": artifact.generator,
        "lifecycle": artifact.lifecycle,
        "provenance": artifact.provenance,
        "outputs": [output.details() for output in artifact.outputs],
        "consumers": [consumer_spec(consumer) for consumer in artifact.consumers],
        "ordering_dependencies": _author_dependencies(artifact.ordering_dependencies),
        "refresh_dependencies": _author_dependencies(artifact.refresh_dependencies),
    }


def volume_spec(volume: DeploymentPersistentVolumeRealization) -> dict[str, object]:
    """Render the ACES concern value observed for a persistent volume."""

    return {
        "lifecycle": volume.lifecycle,
        "access_mode": volume.access_mode,
        "consumers": [consumer_spec(consumer) for consumer in volume.consumers],
        "ordering_dependencies": _author_dependencies(volume.ordering_dependencies),
        "refresh_dependencies": _author_dependencies(volume.refresh_dependencies),
    }


def consumer_spec(consumer: DeploymentStatefulConsumer) -> dict[str, object]:
    """Render one stateful consumer as a non-secret concern value."""

    return {
        "node": consumer.node_name,
        "mount_destination": consumer.mount_destination,
        "access_mode": consumer.access_mode,
        "target_address": consumer.target_address,
    }


def safe_inspect(backend: "DeploymentBackend", name: str) -> dict[str, Any]:
    """Inspect a project-owned container, treating uncertainty as absent."""

    try:
        if not backend.container_exists(name):
            return {}
        info = backend.container_inspect(name)
    except (BackendTimeoutError, OSError) as exc:
        log.warning(
            "could not inspect project container %s (%s)",
            name,
            type(exc).__name__,
        )
        return {}
    return info if isinstance(info, dict) else {}


# Wazuh manager and indexer restart themselves once during first boot, so a
# consumer container can legitimately read health='starting' for a bounded
# window between the realization health gate and observation. Observed on a
# loaded host: the restart cycle returns to healthy well inside two minutes;
# 180s keeps a generous margin (issue #677).
_SETTLE_TIMEOUT = 180
_SETTLE_INTERVAL = 5


def settled_inspect(backend: "DeploymentBackend", name: str) -> dict[str, Any]:
    """Inspect a container, waiting out transitional startup states.

    ``starting`` health and Docker's ``Restarting`` flag are transitional —
    not evidence of an unrealized resource — so observation waits for the
    container to settle before judging. Terminal states (missing, stopped,
    unhealthy) return immediately and fail closed exactly as before.
    """
    deadline = time.monotonic() + _SETTLE_TIMEOUT
    while True:
        info = safe_inspect(backend, name)
        if not _transitional_state(info) or time.monotonic() >= deadline:
            return info
        time.sleep(_SETTLE_INTERVAL)


def _transitional_state(info: Mapping[str, Any]) -> bool:
    """Return whether a container is mid-startup rather than settled."""

    state = info.get("State") if isinstance(info, Mapping) else None
    if not isinstance(state, Mapping):
        return False
    if state.get("Restarting") is True:
        return True
    return container_running(info) and container_health(info) == "starting"


def container_realized(info: Mapping[str, Any]) -> bool:
    """Return whether an inspected container is running and healthy if checked."""

    if not info or not container_running(info):
        return False
    health = container_health(info)
    return not health or health == "healthy"


def observed_content_type(
    backend: "DeploymentBackend",
    content: DeploymentContentRealization | None,
    container_name: str | None = None,
) -> str | None:
    """Return the destination kind observed by the deployment provider.

    ``observe_content_type`` reads back a Compose-managed named volume - it
    has nothing to inspect for image-free content (ADR-048), which the
    generic materializer places directly into a node's container filesystem,
    never a volume (``content.volume_suffix`` is empty for that shape). When
    a container name is available for that case, read back the destination
    directly instead of going through the volume-shaped provider probe.
    """

    if content is None:
        return None
    if not content.volume_suffix and container_name:
        return _observed_image_free_content_type(backend, container_name, content)
    try:
        observed = backend.observe_content_type(content)
    except (BackendSeedError, BackendTimeoutError, OSError) as exc:
        log.warning(
            "could not observe content type for %s (%s)",
            content.address,
            type(exc).__name__,
        )
        observed = None
    return observed if observed in ("file", "directory") else None


def _observed_image_free_content_type(
    backend: "DeploymentBackend",
    container_name: str,
    content: DeploymentContentRealization,
) -> str | None:
    """Read back an image-free content destination's kind via container_exec."""

    destination = "/" + content.dest_relpath.lstrip("/")
    try:
        if backend.container_exec(container_name, ["test", "-d", destination]).returncode == 0:
            return "directory"
        if backend.container_exec(container_name, ["test", "-f", destination]).returncode == 0:
            return "file"
    except (BackendTimeoutError, OSError) as exc:
        log.warning(
            "could not observe image-free content type for %s (%s)",
            content.address,
            type(exc).__name__,
        )
    return None


def observed_os_family(info: Mapping[str, Any]) -> str | None:
    """Return the container platform in the ACES OS-family vocabulary."""

    platform = info.get("Platform")
    if isinstance(platform, str) and platform.strip():
        return platform.strip().lower()
    return None


_DOMAIN_INFO_TIMEOUT = 30


def observed_domain_topology(
    backend: "DeploymentBackend",
    container: str,
    declared: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Attest a declared domain topology from the live directory, or nothing.

    ``samba-tool domain info`` exposes the runtime-observable core of the
    declaration — the served DNS domain, the NetBIOS domain, and (by
    answering for itself) the controller role. The remaining declared fields
    (domain id, profile, plan addresses) are definitional identity with no
    runtime counterpart, so the declared mapping is attested only when every
    observable field corroborates it; a mismatch, failed probe, or missing
    tooling attests nothing and the SEM-218 gate fails closed.
    """
    from aptl.core.deployment._account_provider import samba_domain_info

    container_exec = getattr(backend, "container_exec", None)
    if container_exec is None:
        # A backend without an exec seam (e.g. conformance stubs) cannot
        # corroborate the live domain; attest nothing and fail closed.
        return None
    try:
        result = container_exec(
            container, samba_domain_info(), timeout=_DOMAIN_INFO_TIMEOUT
        )
    except (BackendTimeoutError, OSError) as exc:
        log.warning(
            "could not observe domain topology in %s (%s)",
            container,
            type(exc).__name__,
        )
        return None
    corroborated = getattr(result, "returncode", 1) == 0 and _domain_info_corroborates(
        getattr(result, "stdout", "") or "", declared
    )
    return dict(declared) if corroborated else None


def _domain_info_corroborates(text: str, declared: Mapping[str, Any]) -> bool:
    """Return whether the live domain readback matches every observable field."""

    observed = _parse_samba_domain_info(text)
    dns_name = str(declared.get("dns_name", "")).lower()
    netbios_name = str(declared.get("netbios_name", "")).upper()
    return bool(
        dns_name
        and observed.get("domain") == dns_name
        and netbios_name
        and observed.get("netbios_domain") == netbios_name
        and (declared.get("role") != "controller" or observed.get("dc_name"))
    )


def _parse_samba_domain_info(text: str) -> dict[str, str]:
    """Extract the observable fields from ``samba-tool domain info`` output."""

    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip().lower().replace(" ", "_")] = value.strip()
    return {
        "domain": fields.get("domain", "").lower(),
        "netbios_domain": fields.get("netbios_domain", "").upper(),
        "dc_name": fields.get("dc_name", ""),
    }


def realized_network_names(
    backend: "DeploymentBackend",
    project_name: str,
) -> set[str]:
    """Return only the current Compose project's realized Docker networks."""

    try:
        names = backend.host_list_lab_networks(project_name)
    except (BackendTimeoutError, OSError) as exc:
        log.warning("could not list realized networks (%s)", type(exc).__name__)
        return set()
    return set(names) if isinstance(names, list | tuple | set) else set()


def network_realized(
    network_name: str,
    realized: set[str],
    project_name: str,
) -> bool:
    """Return whether a managed scenario network exists in provider readback."""

    return _match_managed_network(network_name, realized, project_name) is not None
