"""Authenticated outer-host boundary observation for seat launch."""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass

import rfc8785

from aptl.core.appliance_boundary import ApplianceBoundaryBinding, ApplianceBoundaryPolicy
from aptl.core.appliance_boundary_inventory import (
    BoundaryEndpoint,
    HostBoundaryObservation,
)

ListenerProbe = Callable[[], tuple[BoundaryEndpoint, ...]]


@dataclass(frozen=True)
class HostObservationBundle:
    """Observation plus the digest bound into the launch descriptor."""

    observation: HostBoundaryObservation
    observation_id: str


def observation_id_for(observation: HostBoundaryObservation) -> str:
    """Derive a stable host observation digest independent of completion flags."""

    payload = {
        "policy_digest": observation.policy_digest,
        "payload_digest": observation.payload_digest,
        "boot_id": observation.boot_id,
        "listeners": [item.model_dump(mode="json") for item in observation.listeners],
        "forbidden_reachability_passed": observation.forbidden_reachability_passed,
    }
    digest = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
    return f"sha256:{digest}"


def collect_loopback_listeners(
    *,
    probe: ListenerProbe | None = None,
) -> tuple[BoundaryEndpoint, ...]:
    """Return TCP listeners bound on loopback addresses."""

    if probe is not None:
        return probe()
    return _collect_listeners_via_ss()


def _collect_listeners_via_ss() -> tuple[BoundaryEndpoint, ...]:
    """Parse loopback TCP listeners from ``ss`` output when available."""

    try:
        result = subprocess.run(
            ["ss", "-H", "-ltn"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    if result.returncode != 0:
        return ()
    endpoints: list[BoundaryEndpoint] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        if local.startswith("[::1]:"):
            _, port_text = local.split("]:", 1)
            host = "127.0.0.1"
        elif local.startswith("127.0.0.1:"):
            _, port_text = local.split(":", 1)
            host = "127.0.0.1"
        else:
            continue
        try:
            port = int(port_text)
        except ValueError:
            continue
        endpoints.append(
            BoundaryEndpoint(
                audience="participant",
                address=host,
                port=port,
                protocol="tcp",
            )
        )
    return tuple(endpoints)


def map_publications_to_listeners(
    policy: ApplianceBoundaryPolicy,
    observed: Iterable[BoundaryEndpoint],
) -> tuple[BoundaryEndpoint, ...]:
    """Attach signed publication audiences to observed loopback listeners."""

    by_port = {(item.address, item.port, item.protocol) for item in observed}
    mapped: list[BoundaryEndpoint] = []
    for publication in policy.guest_publications:
        key = (publication.address, publication.port, publication.protocol)
        if key in by_port:
            mapped.append(
                BoundaryEndpoint(
                    audience=publication.audience,
                    address=publication.address,
                    port=publication.port,
                    protocol=publication.protocol,
                )
            )
    return tuple(mapped)


def build_host_observation(
    *,
    binding: ApplianceBoundaryBinding,
    boot_id: str,
    listeners: tuple[BoundaryEndpoint, ...],
    forbidden_reachability_passed: bool,
    complete: bool = True,
) -> HostObservationBundle:
    """Construct one authenticated host observation for the signed binding."""

    observation = HostBoundaryObservation(
        observation_id="pending",
        policy_digest=binding.policy_digest,
        payload_digest=binding.payload_digest,
        boot_id=boot_id,
        complete=complete,
        listeners=listeners,
        forbidden_reachability_passed=forbidden_reachability_passed,
    )
    observation_id = observation_id_for(observation)
    finalized = observation.model_copy(update={"observation_id": observation_id})
    return HostObservationBundle(
        observation=finalized,
        observation_id=observation_id,
    )


def host_boundary_findings(
    policy: ApplianceBoundaryPolicy,
    binding: ApplianceBoundaryBinding,
    host: HostBoundaryObservation,
) -> tuple[str, ...]:
    """Return host-only boundary finding codes."""

    findings: list[str] = []
    if host.observation_id != binding.host_observation_id:
        findings.append("boundary.host-observation-identity-mismatch")
    if host.policy_digest != binding.policy_digest:
        findings.append("boundary.host-policy-digest-mismatch")
    if host.payload_digest != binding.payload_digest:
        findings.append("boundary.host-payload-digest-mismatch")
    if host.boot_id != binding.boot_id:
        findings.append("boundary.host-boot-identity-mismatch")
    if not host.complete:
        findings.append("boundary.host-observation-incomplete")
    if not host.forbidden_reachability_passed:
        findings.append("boundary.host-forbidden-reachability")
    expected = {
        (item.audience, item.address, item.port, item.protocol)
        for item in policy.guest_publications
    }
    observed = {
        (item.audience, item.address, item.port, item.protocol)
        for item in host.listeners
    }
    if observed - expected:
        findings.append("boundary.host-listener-unapproved")
    if expected - observed:
        findings.append("boundary.host-listener-missing")
    return tuple(findings)
