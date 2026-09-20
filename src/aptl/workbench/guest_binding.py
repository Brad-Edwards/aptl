"""Trusted dispatcher binding and live guest deployment checks."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aptl.backends.raes_evidence_acquisition import load_active_transcript_authorities
from aptl.core.appliance_boundary import ApplianceBoundaryBinding
from aptl.core.appliance_boundary_inventory import (
    GuestBoundaryObservation,
    HostBoundaryObservation,
    qualify_appliance_boundary,
)
from aptl.core.config import load_config
from aptl.core.deployment._compose_capture_apparatus import _BROKER_PATH
from aptl.core.deployment._compose_capture_config import KALI_CAPTURE_CONTAINER
from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.session import ScenarioSession
from aptl.utils.pathsafe import open_contained_nofollow
from aptl.workbench.access import CallerGrant, SeatAccessRecord
from aptl.workbench.dispatch import DispatchSelector
from aptl.workbench.profiles import ServerProfile, WorkbenchConfigurationError


class ApplianceAccessPaths(BaseModel):
    """Trusted supervisor paths, never supplied by the host participant."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    launch_descriptor: Path
    release_public_key: Path
    qualification_public_key: Path
    runtime_observation: Path
    candidate_trust: bool = False


class ApplianceAccessObservation(BaseModel):
    """Fresh management-owned boundary evidence from the appliance supervisor."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["aptl.mcp-boundary-observation/v1"]
    observed_at: datetime
    binding: ApplianceBoundaryBinding
    host: HostBoundaryObservation
    guest: GuestBoundaryObservation


class GuestDispatchBinding(BaseModel):
    """Private management configuration; it never comes from an SSH request."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["aptl.mcp-dispatch/v1"]
    access: SeatAccessRecord
    grants: tuple[CallerGrant, ...]
    project_dir: Path
    node_executable: Path
    management_home: Path
    docker_socket: Path = Path("/var/run/docker.sock")
    run_id: str = Field(pattern=r"^(?:[a-f0-9]{32}|run_[0-9]{8}T[0-9]{6}Z)$")
    # A production appliance supplies a verified launch and boundary observation
    # through its supervisor. This explicit software integration entry point
    # cannot mint appliance release qualification.
    delivery: Literal["rootful-integration", "appliance"]
    appliance: ApplianceAccessPaths | None = None

    @model_validator(mode="after")
    def validate_delivery(self) -> Self:
        """Require appliance evidence and absolute management paths."""
        if (self.delivery == "appliance") != (self.appliance is not None):
            raise ValueError(
                "appliance delivery requires verified launch and live boundary evidence"
            )
        if any(
            not path.is_absolute()
            for path in (
                self.project_dir,
                self.node_executable,
                self.management_home,
                self.docker_socket,
            )
        ):
            raise ValueError("guest management paths must be absolute")
        return self


def read_private_binding(path: Path) -> GuestDispatchBinding:
    """Read bounded owner-only management state through a no-follow descriptor."""
    return GuestDispatchBinding.model_validate_json(read_management_bytes(path))


def read_management_bytes(path: Path) -> bytes:
    """Read bounded private management state through a no-follow descriptor."""
    if not path.is_absolute():
        raise WorkbenchConfigurationError("management path must be absolute")
    root = Path(path.anchor)
    with open_contained_nofollow(root, path.relative_to(root)) as handle:
        info = os.fstat(handle.fileno())
        if info.st_uid not in {0, os.getuid()} or stat.S_IMODE(info.st_mode) != 0o600:
            raise WorkbenchConfigurationError("dispatcher binding must be private")
        content = handle.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        raise WorkbenchConfigurationError("dispatcher binding is too large")
    return content


def verify_guest_observation(
    record: SeatAccessRecord, observed: dict[str, Any], *, run_id: str
) -> None:
    """Compare current native identity and capture, not names or discovery alone."""
    expected = (
        record.guest_boot_id,
        record.guest_daemon_id,
        record.guest_project,
        record.container_ids,
        run_id,
    )
    actual = tuple(
        observed.get(field)
        for field in ("boot_id", "daemon_id", "project", "containers", "run_id")
    )
    capture = observed.get("capture", {})
    if (
        actual != expected
        or capture.get("ready") is not True
        or capture.get("run_id") != run_id
    ):
        raise WorkbenchConfigurationError("guest runtime admission failed")


def observe_guest(binding: GuestDispatchBinding) -> dict[str, Any]:
    """Use the deployment backend to prove ownership and required capture."""
    from aptl.core.lifecycle_guard import lifecycle_observation_lock

    with lifecycle_observation_lock(binding.project_dir):
        return _observe_stable_guest(binding)


def _observe_stable_guest(binding: GuestDispatchBinding) -> dict[str, Any]:
    """Observe receipt-bound inventory and required live capture authority."""
    project = binding.project_dir
    config = load_config(project / "aptl.json")
    if (
        config.deployment.provider != "docker-compose"
        or config.scenario.source != "env-pack"
        or config.scenario.identity != "techvault"
    ):
        raise WorkbenchConfigurationError("guest deployment mismatch")
    backend = DockerComposeBackend(
        project,
        config.deployment.project_name,
        docker_socket_path=binding.docker_socket,
    )
    if not backend.bind_local_docker_socket().success:
        raise WorkbenchConfigurationError("guest daemon binding failed")
    containers = observe_guest_containers(backend)
    if backend.project_name != binding.access.guest_project:
        raise WorkbenchConfigurationError("guest project identity changed")
    session = ScenarioSession(project / ".aptl").get_active()
    authorities = load_active_transcript_authorities(project)
    if not any(authority.get("run_id") == binding.run_id for authority in authorities):
        raise WorkbenchConfigurationError("required capture authority unavailable")
    captured = backend.container_exec(
        KALI_CAPTURE_CONTAINER, ["python3", _BROKER_PATH, "status"], timeout=5
    )
    capture = json.loads(captured.stdout) if captured.returncode == 0 else {}
    capture["ready"] = captured.returncode == 0
    return {
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "daemon_id": backend._docker_daemon_id,
        "project": backend.project_name,
        "containers": containers,
        "run_id": (session.run_id or session.trace_id)
        if session is not None
        else binding.run_id,
        "capture": capture,
    }


def observe_guest_containers(backend: DockerComposeBackend) -> dict[str, str]:
    """Bind semantic inventory to receipt-verified workspace resource IDs."""
    ownership = backend._ensure_resource_ownership()
    containers = {}
    for row in backend.host_list_lab_containers():
        if row.get("state") != "running":
            continue
        native_id = row["id"]
        receipts = ownership.candidates(
            native_id, kind="container", daemon_id=backend._docker_daemon_id
        )
        if len(receipts) != 1:
            raise WorkbenchConfigurationError("guest container receipt is ambiguous")
        # The backend revalidates the receipt's native ID, external name and
        # workspace labels before returning this inspect result.
        observed = backend.container_inspect(native_id)
        name = receipts[0].semantic_name
        if (
            name in containers
            or observed.get("Id") != native_id
            or observed.get("State", {}).get("Running") is not True
        ):
            raise WorkbenchConfigurationError("guest container identity mismatch")
        containers[name] = native_id
    return containers


class GuestAdmission:
    """One admitted connection, with persistent cleanup failure and a role lock."""

    def __init__(
        self, path: Path, grant_id: str, fingerprint: str, selector: DispatchSelector
    ) -> None:
        import threading

        self.path = path
        self.grant_id = grant_id
        self.fingerprint = fingerprint
        self.selector = selector
        self.binding = read_private_binding(path)
        self.guard = threading.Lock()
        self.descriptor = None
        self.taint = (
            path.parent
            / f"{self.binding.access.instance_id}-{self.binding.access.generation}.tainted"
        )
        self.server = self._server(self.binding)
        self.verified_launch = None
        if self.binding.appliance is not None:
            from aptl.appliance.launch import verify_launch_descriptor

            paths = self.binding.appliance
            if paths.candidate_trust:
                from aptl.appliance.candidate import verify_candidate_launch_descriptor

                self.verified_launch = verify_candidate_launch_descriptor(
                    paths.launch_descriptor, paths.release_public_key
                )
            else:
                self.verified_launch = verify_launch_descriptor(
                    paths.launch_descriptor,
                    paths.release_public_key,
                    paths.qualification_public_key,
                )
            if (
                self.verified_launch.descriptor.host_mcp_contract
                != "aptl.restricted-ssh-mcp/v1"
            ):
                raise WorkbenchConfigurationError(
                    "signed release does not permit host MCP access"
                )

    def _server(self, binding: GuestDispatchBinding) -> ServerProfile:
        """Resolve the current role and key-bound server authorization."""
        from datetime import UTC, datetime

        from aptl.workbench.access import authorize_server

        matches = [grant for grant in binding.grants if grant.grant_id == self.grant_id]
        if (
            len(matches) != 1
            or matches[0].public_key_fingerprint != self.fingerprint
            or binding.access.instance_id != self.selector.instance_id
            or binding.access.generation != self.selector.generation
        ):
            raise WorkbenchConfigurationError("MCP caller is not authorized")
        # Discovery freshness is a host-side requirement. Guest admission proves
        # live identity independently on every request and never trusts its age.
        live = binding.access.model_copy(update={"observed_at": datetime.now(UTC)})
        return authorize_server(live, matches[0], self.selector.server_id)

    def check_revocation(self) -> None:
        """Fast authority check independent of potentially slow Docker observations."""
        if self.taint.exists():
            raise WorkbenchConfigurationError("previous MCP cleanup was not proved")
        current = read_private_binding(self.path)
        if current.model_copy(update={"grants": self.binding.grants}) != self.binding:
            raise WorkbenchConfigurationError("guest binding changed during connection")
        if self._server(current) != self.server:
            raise WorkbenchConfigurationError("guest role changed during connection")
        self._verify_appliance_observation()

    def authorize(self) -> None:
        """Revalidate the caller and guest deployment before each operation."""
        self.check_revocation()
        with self.guard:
            verify_guest_observation(
                self.binding.access,
                observe_guest(self.binding),
                run_id=self.binding.run_id,
            )
        self.check_revocation()

    def _verify_appliance_observation(self) -> None:
        """Verify fresh boundary evidence against the signed launch binding."""
        if self.verified_launch is None:
            return
        observed = ApplianceAccessObservation.model_validate_json(
            read_management_bytes(self.binding.appliance.runtime_observation)
        )
        if (
            observed.observed_at.tzinfo is None
            or not 0 <= (datetime.now(UTC) - observed.observed_at).total_seconds() <= 5
        ):
            raise WorkbenchConfigurationError("appliance boundary observation is stale")
        descriptor = self.verified_launch.descriptor
        expected = {
            "policy_digest": descriptor.boundary_policy_digest,
            "payload_digest": descriptor.payload_digest,
            "raes_plan_digest": descriptor.participant_routes_digest,
            "boundary_helper_image": descriptor.boundary_helper_image,
            "egress_proxy_image": descriptor.egress_proxy_image,
            "host_observation_id": descriptor.host_observation_id,
            "guest_boot_id": self.binding.access.guest_boot_id,
            "guest_daemon_id": self.binding.access.guest_daemon_id,
            "raes_boundary_required": self.verified_launch.boundary_policy.internal_zone_isolation,
        }
        if any(
            getattr(observed.binding, key) != value for key, value in expected.items()
        ):
            raise WorkbenchConfigurationError("appliance access binding mismatch")
        verdict = qualify_appliance_boundary(
            self.verified_launch.boundary_policy,
            observed.binding,
            observed.host,
            observed.guest,
        )
        if not verdict.passed:
            raise WorkbenchConfigurationError("appliance boundary admission failed")
        endpoint = self.binding.access
        mapped = [
            item for item in observed.host.listeners if item.audience == "host-mcp"
        ]
        if len(mapped) != 1 or (
            mapped[0].address,
            mapped[0].port,
            mapped[0].guest_address,
            mapped[0].guest_port,
        ) != (
            endpoint.outer_endpoint.address,
            endpoint.outer_endpoint.port,
            endpoint.guest_endpoint.address,
            endpoint.guest_endpoint.port,
        ):
            raise WorkbenchConfigurationError("appliance MCP endpoint mapping mismatch")

    def __enter__(self) -> Self:
        """Acquire the per-server connection lock and validate admission."""
        import fcntl

        # A role/server may own at most one MCP process. This bounds backend and
        # remote terminal sessions even across different caller keys.
        lock = (
            self.path.parent
            / f"{self.binding.access.instance_id}-{self.selector.server_id}.lock"
        )
        self.descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.authorize()
        except BaseException:
            os.close(self.descriptor)
            self.descriptor = None
            raise
        return self

    def __exit__(self, *_: object) -> None:
        """Release the connection lock after relay cleanup."""
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None

    def cleanup(self, clean: bool) -> None:
        """Persist a taint when remote session teardown cannot be proved."""
        if not clean:
            from aptl.core._soc_ca_io import _atomic_write

            _atomic_write(
                self.taint,
                b"MCP teardown not proved; operator recovery required\n",
                mode=0o600,
            )

    def launch(self) -> tuple[tuple[str, ...], Path, dict[str, str]]:
        """Construct minimal guest-only environment from the canonical lab sync."""
        from aptl.workbench.agent import _admitted_executable

        project = self.binding.project_dir.resolve(strict=True)
        artifact = (project / self.server.artifact_ref).resolve(strict=True)
        if not artifact.is_relative_to(project):
            raise WorkbenchConfigurationError("MCP artifact escaped guest payload")
        node = _admitted_executable(self.binding.node_executable)
        env = self._service_environment(project, artifact)
        backend = DockerComposeBackend(
            project,
            load_config(project / "aptl.json").deployment.project_name,
            docker_socket_path=self.binding.docker_socket,
        )
        result = backend.bind_local_docker_socket()
        if not result.success:
            raise WorkbenchConfigurationError("guest Docker endpoint unavailable")
        endpoint = getattr(backend, "_docker_socket_path", None)
        if endpoint is not None:
            env["DOCKER_HOST"] = "unix://" + str(endpoint)
        if self.server.server_id == "aptl-red":
            from aptl.core.mcp_ingress import native_kali_ingress

            expected = self.binding.access.container_ids.get("aptl-kali", "")
            env.update(
                native_kali_ingress(backend.container_inspect("aptl-kali"), expected)
            )
        self.authorize()
        return (str(node), str(artifact)), project, env

    def _service_environment(self, project: Path, artifact: Path) -> dict[str, str]:
        """Load private service leases and the canonical ports for one MCP."""
        from aptl.core.lab import _expected_transcript_store, _server_config_port_refs
        from aptl.workbench.credentials import EphemeralCredentialBroker

        with open_contained_nofollow(project, ".mcp.json") as handle:
            info = os.fstat(handle.fileno())
            if (
                info.st_uid not in {0, os.getuid()}
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise WorkbenchConfigurationError(
                    "guest MCP service configuration must be private"
                )
            document = json.load(handle)
        values = document["mcpServers"][self.server.server_id]["env"]
        ports = _server_config_port_refs({"args": [str(artifact)]}, project)
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.binding.management_home),
            "APTL_MCP_DISABLE_DOTENV": "1",
            "APTL_STATE_DIR": str(project / ".aptl"),
            "APTL_MCP_RUN_STORE_BASE": str(
                _expected_transcript_store(project).resolve()
            ),
            "APTL_MCP_ADMITTED_RUN_ID": self.binding.run_id,
            "APTL_MCP_REQUIRE_REMOTE_CLOSE": "1",
        }
        for name in ports:
            value = values.get(name)
            if (
                not isinstance(value, str)
                or not value.isdecimal()
                or not 0 < int(value) <= 65535
            ):
                raise WorkbenchConfigurationError("guest MCP port is unavailable")
            env[name] = value
        if self.server.credential_aliases:
            broker = EphemeralCredentialBroker(values)
            lease = broker.prepare_named(
                self.server.server_id,
                self.binding.run_id,
                self.server.credential_aliases,
            )
            env.update(lease)
            broker.destroy_named(self.server.server_id, self.binding.run_id)
        return env
