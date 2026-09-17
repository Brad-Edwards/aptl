"""Guest management enrollment and refresh, independent of VM construction."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from aptl.backends.raes_evidence_acquisition import load_active_transcript_authorities
from aptl.backends.raes_profiles import normalized_identifier_aliases
from aptl.core._soc_ca_io import _atomic_write
from aptl.core.config import load_config
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.scenario_bundle import env_pack_bundle
from aptl.validation.curated_live_proof import expected_bundle_matrix
from aptl.workbench.access import (
    CallerGrant,
    Identifier,
    SeatAccessRecord,
    SeatEndpoint,
)
from aptl.workbench.dispatch import key_fingerprint, restricted_key, sshd_policy
from aptl.workbench.guest_binding import (
    ApplianceAccessPaths,
    GuestDispatchBinding,
    observe_guest,
    observe_guest_containers,
    read_private_binding,
    verify_guest_observation,
)
from aptl.workbench.profiles import WorkbenchConfigurationError


class EnrolledKey(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    grant_id: Identifier
    public_key: str
    profile: Literal["red", "blue"]
    expires_at: datetime


class TransportPreparation(BaseModel):
    """Operator inputs; contains no private key or model-provider credential."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    owner_id: Identifier
    seat_id: Identifier
    instance_id: Identifier
    generation: int = Field(strict=True, ge=1)
    guest_endpoint: SeatEndpoint
    outer_endpoint: SeatEndpoint
    project_dir: Path
    management_home: Path
    docker_socket: Path = Path("/var/run/docker.sock")
    node_executable: Path
    aptl_executable: Path
    host_key: Path
    host_public_key: Path
    username: str
    keys: tuple[EnrolledKey, ...] = Field(min_length=1, max_length=16)
    delivery: Literal["rootful-integration", "appliance"]
    appliance: ApplianceAccessPaths | None = None


def verify_full_inventory(matrix, containers):
    observed = set().union(
        *(set(normalized_identifier_aliases(name)) for name in containers)
    )
    if not matrix.service_aliases or any(
        not (set(aliases) & observed) for aliases in matrix.service_aliases.values()
    ):
        raise WorkbenchConfigurationError(
            "full TechVault workload inventory is incomplete"
        )


def prepare_guest_transport(
    request: TransportPreparation, output: Path
) -> GuestDispatchBinding:
    """Publish forced-key policy and discovery only for a live full deployment."""
    if not output.is_absolute() or output.exists():
        raise WorkbenchConfigurationError(
            "transport output must be a new absolute directory"
        )
    project = request.project_dir.resolve(strict=True)
    config = load_config(project / "aptl.json")
    if (
        config.scenario.source != "env-pack"
        or config.scenario.identity != "techvault"
        or config.deployment.provider != "docker-compose"
    ):
        raise WorkbenchConfigurationError(
            "host MCP requires canonical local full TechVault"
        )
    backend = DockerComposeBackend(
        project,
        config.deployment.project_name,
        docker_socket_path=request.docker_socket,
    )
    if not backend.bind_local_docker_socket().success:
        raise WorkbenchConfigurationError("guest Docker binding failed")
    containers = observe_guest_containers(backend)
    bundle = env_pack_bundle(project / ".aptl" / "transport-pack")
    verify_full_inventory(expected_bundle_matrix(project, config, bundle), containers)
    authorities = load_active_transcript_authorities(project)
    if len(authorities) != 1:
        raise WorkbenchConfigurationError("one live capture authority is required")
    now = datetime.now(UTC)
    record = SeatAccessRecord(
        schema_version="aptl.seat-access/v1",
        owner_id=request.owner_id,
        seat_id=request.seat_id,
        instance_id=request.instance_id,
        generation=request.generation,
        guest_boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        guest_daemon_id=backend._docker_daemon_id,
        guest_project=backend.project_name,
        container_ids=containers,
        scenario_pack=bundle.pack_identity,
        guest_endpoint=request.guest_endpoint,
        outer_endpoint=request.outer_endpoint,
        host_key_fingerprint=key_fingerprint(request.host_public_key.read_text()),
        observed_at=now,
        lifecycle_state="ready",
    )
    grants = []
    fingerprints = set()
    for key in request.keys:
        fingerprint = key_fingerprint(key.public_key)
        if (
            fingerprint in fingerprints
            or key.expires_at.tzinfo is None
            or not 0 < (key.expires_at - now).total_seconds() <= 86400
        ):
            raise WorkbenchConfigurationError(
                "caller keys must be unique and expire within 24 hours"
            )
        fingerprints.add(fingerprint)
        grants.append(
            CallerGrant(
                schema_version="aptl.mcp-grant/v1",
                grant_id=key.grant_id,
                owner_id=request.owner_id,
                seat_id=request.seat_id,
                instance_id=request.instance_id,
                generation=request.generation,
                public_key_fingerprint=fingerprint,
                profile=key.profile,
                expires_at=key.expires_at,
                revoked=False,
            )
        )
    if len({grant.grant_id for grant in grants}) != len(grants):
        raise WorkbenchConfigurationError("grant IDs must be unique")
    binding = GuestDispatchBinding(
        schema_version="aptl.mcp-dispatch/v1",
        access=record,
        grants=tuple(grants),
        project_dir=project,
        node_executable=request.node_executable,
        management_home=request.management_home,
        docker_socket=request.docker_socket,
        run_id=authorities[0]["run_id"],
        delivery=request.delivery,
        appliance=request.appliance,
    )
    verify_guest_observation(record, observe_guest(binding), run_id=binding.run_id)
    keys = "".join(
        restricted_key(
            public_key=key.public_key,
            executable=request.aptl_executable,
            binding=output / "binding.json",
            grant_id=key.grant_id,
        )
        for key in request.keys
    )
    policy = sshd_policy(
        port=request.guest_endpoint.port,
        address=request.guest_endpoint.address,
        username=request.username,
        host_key=request.host_key,
        authorized_keys=output / "authorized_keys",
    )
    output.mkdir(mode=0o700)
    for name, content in {
        "binding.json": binding.model_dump_json(),
        "access.json": record.model_dump_json(),
        "authorized_keys": keys,
        "sshd_config": policy,
        **{grant.grant_id + ".grant.json": grant.model_dump_json() for grant in grants},
    }.items():
        _atomic_write(output / name, (content + "\n").encode(), mode=0o600)
    return binding


def refresh_access(binding_path: Path, output: Path) -> SeatAccessRecord:
    """Refresh discovery without widening a grant or changing an instance."""
    binding = read_private_binding(binding_path)
    verify_guest_observation(
        binding.access, observe_guest(binding), run_id=binding.run_id
    )
    record = binding.access.model_copy(update={"observed_at": datetime.now(UTC)})
    _atomic_write(output, (record.model_dump_json() + "\n").encode(), mode=0o600)
    return record


def revoke_grant(binding_path: Path, grant_id: str) -> None:
    """Revoke the live authority; dispatchers re-read it during active calls."""
    import fcntl
    import os

    lock = binding_path.with_suffix(".mutation.lock")
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _revoke_locked(binding_path, grant_id)
    finally:
        os.close(descriptor)


def _revoke_locked(binding_path: Path, grant_id: str) -> None:
    binding = read_private_binding(binding_path)
    if grant_id not in {grant.grant_id for grant in binding.grants}:
        raise WorkbenchConfigurationError("unknown transport grant")
    grants = tuple(
        grant.model_copy(update={"revoked": True})
        if grant.grant_id == grant_id
        else grant
        for grant in binding.grants
    )
    updated = binding.model_copy(update={"grants": grants})
    _atomic_write(binding_path, (updated.model_dump_json() + "\n").encode(), mode=0o600)
