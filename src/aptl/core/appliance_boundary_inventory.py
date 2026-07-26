"""Fresh fatal appliance-boundary inventory and verdict."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aptl.core.appliance_boundary import (
    ApplianceBoundaryBinding,
    ApplianceBoundaryPolicy,
    Digest,
)
from aptl.utils.redaction import redact


class _StrictObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class BoundaryEndpoint(_StrictObservation):
    audience: Literal["participant", "recovery"]
    address: str
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]


class HostBoundaryObservation(_StrictObservation):
    """Authenticated outer observation produced by the #824 adapter."""

    observation_id: str = Field(min_length=1, max_length=128)
    policy_digest: Digest
    payload_digest: Digest
    boot_id: str = Field(min_length=1, max_length=128)
    complete: bool
    listeners: tuple[BoundaryEndpoint, ...]
    forbidden_reachability_passed: bool


class BoundaryEnforcementObservation(_StrictObservation):
    authority: Literal["aces", "platform"]
    source_digest: Digest
    enforcement_digest: Digest
    families: tuple[Literal["bridge", "inet"], ...]
    default_deny_observed: bool


class BoundaryProbeObservation(_StrictObservation):
    identity: str = Field(min_length=1, max_length=128)
    authority: Literal["aces", "platform"]
    source: str = Field(min_length=1, max_length=160)
    destination: str = Field(min_length=1, max_length=160)
    protocol: Literal["any", "tcp", "udp", "icmp"]
    port: int | None = Field(default=None, ge=1, le=65535)
    expectation: Literal["reachable", "blocked"]
    passed: bool

    @model_validator(mode="after")
    def validate_transport_port(self) -> BoundaryProbeObservation:
        if (self.protocol in {"tcp", "udp"}) != (self.port is not None):
            raise ValueError("probe port must match its transport")
        return self


class DockerAuthorityHolder(_StrictObservation):
    identity: str = Field(min_length=1, max_length=128)
    label_selector: str = Field(min_length=1, max_length=160)
    daemon_id: str = Field(min_length=1, max_length=128)
    access: Literal["socket", "api"]
    privileged: bool
    host_pid_namespace: bool
    host_network_namespace: bool
    device_count: int = Field(ge=0)


class GuestBoundaryObservation(_StrictObservation):
    """Normalized selected-daemon and kernel observation."""

    policy_digest: Digest
    aces_plan_digest: Digest
    boot_id: str = Field(min_length=1, max_length=128)
    guest_daemon_id: str = Field(min_length=1, max_length=128)
    workbench_policy_version: str = Field(min_length=1, max_length=128)
    enforcements: tuple[BoundaryEnforcementObservation, ...]
    observation_complete: bool
    probes: tuple[BoundaryProbeObservation, ...]
    docker_authority_holders: tuple[DockerAuthorityHolder, ...]


@dataclass(frozen=True)
class BoundaryQualificationResult:
    passed: bool
    findings: tuple[str, ...]
    inventory: dict[str, object]


def qualify_appliance_boundary(
    policy: ApplianceBoundaryPolicy,
    binding: ApplianceBoundaryBinding,
    host: HostBoundaryObservation | None,
    guest: GuestBoundaryObservation,
    *,
    phase: Literal["image-qualification", "start"] = "start",
) -> BoundaryQualificationResult:
    """Compare both trust domains and return bounded redacted evidence."""

    findings: list[str] = []
    if host is None:
        findings.append("boundary.host-observation-missing")
    else:
        _append_host_findings(policy, binding, host, findings)
    _append_guest_findings(policy, binding, guest, findings)
    inventory = _inventory(policy, binding, host, guest, findings, phase)
    return BoundaryQualificationResult(
        passed=not findings,
        findings=tuple(findings),
        inventory=redact(inventory),
    )


def _append_host_findings(
    policy: ApplianceBoundaryPolicy,
    binding: ApplianceBoundaryBinding,
    host: HostBoundaryObservation,
    findings: list[str],
) -> None:
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


def _append_guest_findings(
    policy: ApplianceBoundaryPolicy,
    binding: ApplianceBoundaryBinding,
    guest: GuestBoundaryObservation,
    findings: list[str],
) -> None:
    comparisons = (
        (
            guest.policy_digest != binding.policy_digest,
            "boundary.guest-policy-digest-mismatch",
        ),
        (
            guest.aces_plan_digest != binding.aces_plan_digest,
            "boundary.guest-aces-plan-digest-mismatch",
        ),
        (
            guest.boot_id != binding.boot_id,
            "boundary.guest-boot-identity-mismatch",
        ),
        (
            guest.guest_daemon_id != binding.guest_daemon_id,
            "boundary.guest-daemon-identity-mismatch",
        ),
        (
            guest.workbench_policy_version != policy.workbench_policy_version,
            "boundary.guest-workbench-policy-mismatch",
        ),
        (
            not guest.observation_complete,
            "boundary.guest-observation-incomplete",
        ),
    )
    findings.extend(code for failed, code in comparisons if failed)
    _append_enforcement_findings(policy, binding, guest, findings)
    _append_probe_findings(binding, guest, findings)
    allowed = set(policy.docker_authority.allowed_holder_labels)
    if {holder.label_selector for holder in guest.docker_authority_holders} - allowed:
        findings.append("boundary.guest-docker-authority-unapproved")
    if any(
        holder.daemon_id != binding.guest_daemon_id
        for holder in guest.docker_authority_holders
    ):
        findings.append("boundary.guest-docker-daemon-mismatch")
    if any(
        holder.privileged
        or holder.host_pid_namespace
        or holder.host_network_namespace
        or holder.device_count
        for holder in guest.docker_authority_holders
    ):
        findings.append("boundary.guest-docker-authority-overprivileged")


def _append_enforcement_findings(
    policy: ApplianceBoundaryPolicy,
    binding: ApplianceBoundaryBinding,
    guest: GuestBoundaryObservation,
    findings: list[str],
) -> None:
    by_authority = {item.authority: item for item in guest.enforcements}
    if len(by_authority) != len(guest.enforcements) or "platform" not in by_authority:
        findings.append("boundary.guest-enforcement-incomplete")
        return
    platform = by_authority["platform"]
    if platform.source_digest != binding.policy_digest:
        findings.append("boundary.guest-platform-source-mismatch")
    if set(platform.families) != {"bridge", "inet"}:
        findings.append("boundary.guest-enforcement-incomplete")
    if policy.default_deny and not platform.default_deny_observed:
        findings.append("boundary.guest-default-deny-missing")
    aces = by_authority.get("aces")
    if binding.aces_boundary_required and aces is None:
        findings.append("boundary.guest-aces-enforcement-missing")
    elif aces is not None and aces.source_digest != binding.aces_plan_digest:
        findings.append("boundary.guest-aces-source-mismatch")


def _append_probe_findings(
    binding: ApplianceBoundaryBinding,
    guest: GuestBoundaryObservation,
    findings: list[str],
) -> None:
    required_authorities = {"platform"}
    if binding.aces_boundary_required:
        required_authorities.add("aces")
    for authority in sorted(required_authorities):
        scoped = [item for item in guest.probes if item.authority == authority]
        positive = [item for item in scoped if item.expectation == "reachable"]
        negative = [item for item in scoped if item.expectation == "blocked"]
        if not positive or any(not item.passed for item in positive):
            findings.append(f"boundary.guest-{authority}-positive-probe-failed")
        if not negative or any(not item.passed for item in negative):
            findings.append(f"boundary.guest-{authority}-negative-probe-failed")


def _inventory(
    policy: ApplianceBoundaryPolicy,
    binding: ApplianceBoundaryBinding,
    host: HostBoundaryObservation | None,
    guest: GuestBoundaryObservation,
    findings: list[str],
    phase: Literal["image-qualification", "start"],
) -> dict[str, object]:
    return {
        "schema_version": "aptl.appliance-boundary-inventory/v1",
        "phase": phase,
        "policy": {
            "id": policy.policy_id,
            "generation": policy.generation,
            "digest": binding.policy_digest,
        },
        "payload_digest": binding.payload_digest,
        "aces_plan_digest": binding.aces_plan_digest,
        "aces_boundary_required": binding.aces_boundary_required,
        "images": {
            "boundary_helper": binding.boundary_helper_image,
            "egress_proxy": binding.egress_proxy_image,
        },
        "boot_id": binding.boot_id,
        "host": (
            {"observation_id": host.observation_id, "complete": host.complete}
            if host is not None
            else {"missing": True}
        ),
        "guest": {
            "guest_daemon_id": guest.guest_daemon_id,
            "workbench_policy_version": guest.workbench_policy_version,
            "enforcements": [
                {
                    "authority": item.authority,
                    "source_digest": item.source_digest,
                    "enforcement_digest": item.enforcement_digest,
                    "families": list(item.families),
                    "default_deny_observed": item.default_deny_observed,
                }
                for item in guest.enforcements
            ],
            "probes": [
                {
                    "identity": item.identity,
                    "authority": item.authority,
                    "source": item.source,
                    "destination": item.destination,
                    "protocol": item.protocol,
                    "port": item.port,
                    "expectation": item.expectation,
                    "passed": item.passed,
                }
                for item in guest.probes
            ],
            "docker_authority_holders": [
                {
                    "identity": item.identity,
                    "label_selector": item.label_selector,
                    "daemon_id": item.daemon_id,
                    "access": item.access,
                }
                for item in guest.docker_authority_holders
            ],
            "observation_complete": guest.observation_complete,
        },
        "findings": list(findings),
        "passed": not findings,
    }
