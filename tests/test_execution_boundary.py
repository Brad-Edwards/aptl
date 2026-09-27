"""Selected-backend execution boundary observations for issue #958."""

from __future__ import annotations

import json
from dataclasses import dataclass

from aptl.core.execution_boundary import (
    bind_execution_boundary,
    observe_execution_boundary,
    revalidate_execution_boundary,
)


@dataclass
class _Process:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class _Backend:
    def __init__(
        self,
        *,
        endpoint: str = "unix:///var/run/docker.sock",
        environment: dict[str, str] | None = None,
        daemon: dict[str, object] | None = None,
        context_result: _Process | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.environment = environment or {}
        self.daemon = daemon or {
            "ID": "private-daemon-id",
            "OSType": "linux",
            "OperatingSystem": "Ubuntu 24.04",
            "KernelVersion": "6.8.0-test",
            "ServerVersion": "29.5.0",
        }
        self.context_result = context_result
        self.calls: list[list[str]] = []

    def docker_transport_environment(self) -> dict[str, str]:
        return self.environment

    def _run(self, argv: list[str], *, timeout: int) -> _Process:
        self.calls.append(argv)
        assert timeout <= 30
        if argv[:3] == ["docker", "context", "inspect"]:
            return self.context_result or _Process(stdout=json.dumps(self.endpoint))
        if argv[:2] == ["docker", "info"]:
            return _Process(stdout=json.dumps(self.daemon))
        raise AssertionError(argv)


def test_native_linux_requires_matching_local_kernel() -> None:
    backend = _Backend()
    observed = observe_execution_boundary(
        backend, host_system="linux", host_kernel="6.8.0-test"
    )
    assert observed.transport == "local-unix"
    assert observed.host_containment == "native-docker"
    assert observed.observation_status == "observed"
    assert observed.docker_version == "29.5.0"
    assert observed.override_source == "none"
    assert observed.evidence_refs == ()
    assert "private-daemon-id" not in str(observed.model_dump())


def test_bound_start_observation_is_reused_for_same_selected_daemon() -> None:
    backend = _Backend()
    initial = bind_execution_boundary(
        backend, host_system="linux", host_kernel="6.8.0-test"
    )
    backend.daemon["ServerVersion"] = "30.0.0"

    disclosed = revalidate_execution_boundary(
        backend, host_system="linux", host_kernel="6.8.0-test"
    )

    assert disclosed == initial
    assert disclosed.docker_version == "29.5.0"


def test_changed_daemon_or_endpoint_invalidates_bound_start_observation() -> None:
    backend = _Backend()
    bind_execution_boundary(backend, host_system="linux", host_kernel="6.8.0-test")
    backend.daemon["ID"] = "different-private-daemon-id"

    changed = revalidate_execution_boundary(
        backend, host_system="linux", host_kernel="6.8.0-test"
    )

    assert changed.observation_status == "mismatch"
    assert changed.host_containment == "unknown"
    assert changed.profile_ref == ""
    assert "different-private-daemon-id" not in str(changed.model_dump())

    backend.daemon["ID"] = "private-daemon-id"
    backend.environment["DOCKER_HOST"] = "ssh://remote.example"
    changed = revalidate_execution_boundary(
        backend, host_system="linux", host_kernel="6.8.0-test"
    )
    assert changed.observation_status == "mismatch"
    assert changed.override_source == "docker-host"


def test_unreadable_daemon_cannot_reuse_bound_native_label() -> None:
    backend = _Backend()
    bind_execution_boundary(backend, host_system="linux", host_kernel="6.8.0-test")
    backend.daemon = {}

    changed = revalidate_execution_boundary(
        backend, host_system="linux", host_kernel="6.8.0-test"
    )

    assert changed.observation_status == "unknown"
    assert changed.host_containment == "unknown"


def test_remote_ssh_override_never_claims_cli_host_containment() -> None:
    backend = _Backend(environment={"DOCKER_HOST": "ssh://user:secret@host.example"})
    observed = observe_execution_boundary(
        backend, host_system="linux", host_kernel="6.8.0-test"
    )
    assert observed.transport == "remote-ssh"
    assert observed.host_containment == "remote-unverified"
    assert observed.override_source == "docker-host"
    assert "secret" not in str(observed.model_dump())
    assert not any(argv[:3] == ["docker", "context", "inspect"] for argv in backend.calls)


def test_context_override_and_unreadable_endpoint_stay_unknown() -> None:
    backend = _Backend(
        environment={"DOCKER_CONTEXT": "private-context"},
        context_result=_Process(returncode=1, stderr="secret-token"),
    )
    observed = observe_execution_boundary(
        backend, host_system="linux", host_kernel="6.8.0-test"
    )
    assert observed.host_containment == "unknown"
    assert observed.observation_status == "unknown"
    assert observed.override_source == "docker-context"
    assert "secret-token" not in str(observed.model_dump())


def test_malformed_docker_host_is_reported_unknown_without_aborting() -> None:
    observed = observe_execution_boundary(
        _Backend(environment={"DOCKER_HOST": "ssh://[broken"}),
        host_system="linux",
        host_kernel="6.8.0-test",
    )

    assert observed.transport == "unknown"
    assert observed.override_source == "docker-host"
    assert observed.host_containment == "unknown"


def test_non_mapping_backend_transport_remains_unknown() -> None:
    from unittest.mock import MagicMock

    observed = observe_execution_boundary(MagicMock(), host_system="linux")

    assert observed.transport == "unknown"
    assert observed.observation_status == "unknown"


def test_desktop_is_vm_runtime_but_not_qualified_containment() -> None:
    backend = _Backend(
        daemon={
            "ID": "private-daemon-id",
            "OSType": "linux",
            "OperatingSystem": "Docker Desktop",
            "KernelVersion": "6.12.0-vm",
            "ServerVersion": "29.5.0",
        }
    )
    observed = observe_execution_boundary(
        backend, host_system="macos", host_kernel="24.0.0"
    )
    assert observed.daemon_runtime == "docker-vm"
    assert observed.host_containment == "docker-vm-unverified"
    assert observed.containment_verified is False


def test_local_linux_kernel_mismatch_is_not_native() -> None:
    observed = observe_execution_boundary(
        _Backend(), host_system="linux", host_kernel="different-kernel"
    )
    assert observed.host_containment == "unknown"
    assert observed.observation_status == "partial"


def test_raes_apply_details_disclose_the_selected_profile() -> None:
    """Run facts use the RAES-validated backend-owned apply details."""
    from raes_contracts.realization_structure import validate_realization_value

    from aptl.backends._raes_provisioner_start import execution_boundary_disclosure
    from aptl.backends.raes_manifest import create_aptl_manifest

    boundary = execution_boundary_disclosure(
        _Backend(environment={"DOCKER_HOST": "ssh://user:secret@host.example"}),
        host_system="linux",
        host_kernel="6.8.0-test",
    )

    assert "provisioning-plan-v1" in create_aptl_manifest().supported_contract_versions
    assert boundary["schema_version"] == "aptl.execution-boundary/v1"
    assert boundary["host_containment"] == "remote-unverified"
    assert boundary["profile_ref"] == "aptl/remote-docker-observed/v1"
    assert boundary["containment_verified"] is False
    assert boundary["evidence_refs"] == []
    assert "secret" not in str(boundary)
    assert validate_realization_value({"aptl_execution_boundary": boundary}).conformant


def test_sysctl_check_uses_selected_daemon_boundary_not_ambient_mode(
    tmp_path, mocker
) -> None:
    """An SSH daemon must not trigger a sysctl check on the CLI host."""
    from aptl.core import hostenv, lab
    from aptl.core.sysreqs import SysReqResult, ToolReqResult

    boundary = observe_execution_boundary(
        _Backend(environment={"DOCKER_HOST": "ssh://remote.example"}),
        host_system="linux",
        host_kernel="6.8.0-test",
    )
    sysctl = mocker.patch(
        "aptl.core.lab.check_max_map_count",
        return_value=SysReqResult(
            passed=True, current_value=0, required_value=262144, applicable=False
        ),
    )
    mocker.patch(
        "aptl.core.lab.check_docker_buildx",
        return_value=ToolReqResult(passed=True, command="docker buildx version"),
    )
    ctx = lab._LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        execution_boundary=boundary,
    )

    assert lab._step_check_sysreqs(ctx) is None
    sysctl.assert_called_once_with(selected_mode=hostenv.DOCKER_UNKNOWN)


def test_remote_backend_never_uses_cli_host_bridge_addresses(mocker) -> None:
    from aptl.core.lab import _docker_vm_hides_bridge_ips

    ambient = mocker.patch("aptl.core.lab.hostenv.docker_mode")
    boundary = observe_execution_boundary(
        _Backend(environment={"DOCKER_HOST": "ssh://remote.example"}),
        host_system="linux",
        host_kernel="6.8.0-test",
    )

    assert _docker_vm_hides_bridge_ips(boundary)
    ambient.assert_not_called()


def test_verified_guest_launch_reports_seat_as_unqualified_host_boundary(
    tmp_path, mocker
) -> None:
    """Guest daemon admission is not proof of the outer seat containment."""
    from aptl.core import lab

    mocker.patch("aptl.core.lab.find_config", return_value=tmp_path / "aptl.json")
    mocker.patch("aptl.core.lab.load_config", return_value=object())
    mocker.patch("aptl.core.lab._get_backend", return_value=_Backend())
    mocker.patch("aptl.core.lab._configure_verified_appliance_launch", return_value=None)
    mocker.patch("aptl.core.lab._load_admitted_start_surface", return_value=None)
    ctx = lab._LabStartContext(
        project_dir=tmp_path,
        skip_seed=False,
        appliance_launch_descriptor=tmp_path / "appliance-launch.json",
    )

    assert lab._step_load_config(ctx) is None
    assert ctx.execution_boundary is not None
    assert ctx.execution_boundary.host_containment == "seat-guest-unverified"
    assert ctx.execution_boundary.containment_verified is False


def test_raes_disclosure_distinguishes_configured_seat_guest() -> None:
    from aptl.backends._raes_provisioner_start import execution_boundary_disclosure

    backend = _Backend()
    backend._appliance_boundary = (object(), object())
    boundary = execution_boundary_disclosure(
        backend, host_system="linux", host_kernel="6.8.0-test"
    )

    assert boundary["host_containment"] == "seat-guest-unverified"
    assert boundary["profile_ref"] == "aptl/seat-vm-guest/v1"
    assert boundary["containment_verified"] is False
    assert boundary["evidence_refs"] == []


def test_raes_refuses_changed_daemon_before_realization(mocker) -> None:
    from raes_contracts.runtime_state import ApplyResult, RuntimeSnapshot

    from aptl.backends._raes_provisioner_start import ProvisionerStartMixin

    backend = _Backend()
    bind_execution_boundary(backend, host_system="linux", host_kernel="6.8.0-test")
    backend.daemon["ID"] = "different-private-daemon-id"
    realize = mocker.Mock()
    backend.realize = realize
    owner = mocker.Mock(spec=ProvisionerStartMixin)
    owner.deployment_backend = backend
    owner._attempt_id = "attempt-1"
    owner._failed_apply = lambda snapshot, diagnostics, _profiles, _realization: ApplyResult(
        success=False, snapshot=snapshot, diagnostics=diagnostics
    )

    result = ProvisionerStartMixin._start_and_observe_apparatus(
        owner, object(), RuntimeSnapshot(), [], [], object()
    )

    assert isinstance(result, ApplyResult)
    assert result.success is False
    assert result.diagnostics[0].code == "aptl.provisioner.execution-boundary-mismatch"
    realize.assert_not_called()
