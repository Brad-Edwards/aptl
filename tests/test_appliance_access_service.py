"""Guest access supervision coverage for the appliance seat transport."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from aptl.appliance import access_service
from aptl.appliance.seat.access import GuestRuntimeEvidence
from aptl.utils.strict_json import model_validate_json_strict
from aptl.workbench.guest_binding import (
    ApplianceAccessObservation,
    ApplianceAccessPaths,
)
from aptl.workbench.profiles import WorkbenchConfigurationError
from aptl.validation.participant_qualification_evidence import (
    QualificationCheckEvidence,
)
from tests.test_appliance_seat_access import _bundle, _public_key, _request


def test_host_key_generation_and_management_state_ownership(tmp_path: Path) -> None:
    key = tmp_path / "ssh" / "host-key"

    def generate(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        target = Path(argv[argv.index("-f") + 1])
        target.write_text("private")
        target.with_suffix(target.suffix + ".pub").write_text("public")
        return subprocess.CompletedProcess(argv, 0)

    with patch("aptl.appliance.access_service.subprocess.run", side_effect=generate):
        access_service._ensure_host_key(key)
        access_service._ensure_host_key(key)

    project = tmp_path / "project"
    state = project / ".aptl"
    state.mkdir(parents=True)
    (state / "state.json").write_text("{}")
    (project / ".mcp.json").write_text("{}")
    (project / "aptl.json").write_text('{"run_storage":{"local_path":"runs"}}')
    run_store = project / "runs"
    run_store.mkdir(mode=0o700)
    (run_store / "manifest.json").write_text("{}")
    owned: list[Path] = []
    with patch(
        "aptl.appliance.access_service.os.chown",
        side_effect=lambda path, *_args, **_kwargs: owned.append(Path(path)),
    ):
        access_service._assign_management_state(project, uid=1000, gid=1000)

    assert key.stat().st_mode & 0o777 == 0o600
    assert key.with_suffix(".pub").stat().st_mode & 0o777 == 0o644
    assert {state, state / "state.json", project / ".mcp.json"} <= set(owned)
    assert {run_store, run_store / "manifest.json"} <= set(owned)


def test_runtime_observation_and_evidence_are_bound_to_the_run(tmp_path: Path) -> None:
    request = _request()
    observation_path = tmp_path / "observation.json"
    with patch("aptl.appliance.access_service.os.chown"):
        access_service._write_runtime_observation(
            observation_path,
            request,
            request.guest_observation,
            uid=os.getuid(),
            gid=os.getgid(),
        )
    observed = model_validate_json_strict(
        ApplianceAccessObservation, observation_path.read_bytes()
    )
    assert observed.binding == request.binding

    project = tmp_path / "project"
    manifest = project / ".aptl" / "runs" / "run-1" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "aptl.run-record/v1",
                "outcome": "success",
                "backend_evidence": {
                    "range_snapshot": {"containers": [], "networks": []}
                },
            }
        )
    )
    config = SimpleNamespace(run_storage=SimpleNamespace(local_path=".aptl/runs"))
    with (
        patch("aptl.appliance.access_service.load_config", return_value=config),
        patch(
            "aptl.appliance.access_service._qualification_checks",
            return_value=(
                QualificationCheckEvidence(
                    check_id="live-check",
                    status="passed",
                    summary="live qualification passed",
                ),
            ),
        ),
    ):
        evidence = access_service._load_runtime_evidence(
            project, "run-1", qualification=True
        )

    assert evidence.run_id == "run-1"
    assert evidence.snapshot == {"containers": [], "networks": []}
    assert evidence.qualification_checks[0].check_id == "live-check"


def test_dispatch_home_gets_private_lab_identity_without_opening_supervisor_home(
    tmp_path, monkeypatch
):
    supervisor = tmp_path / "supervisor"
    source = supervisor / ".ssh" / "aptl_lab_key"
    source.parent.mkdir(mode=0o700, parents=True)
    source.write_bytes(b"fixture-lab-key")
    source.chmod(0o600)
    monkeypatch.setattr(Path, "home", lambda: supervisor)
    home = tmp_path / "dispatcher"
    home.mkdir(mode=0o700)
    access_service._prepare_dispatch_home(home, uid=os.getuid(), gid=os.getgid())
    copied = home / ".ssh" / "aptl_lab_key"
    assert copied.read_bytes() == source.read_bytes()
    assert copied.stat().st_mode & 0o777 == 0o600
    assert copied.parent.stat().st_mode & 0o777 == 0o700
    assert source.parent.stat().st_mode & 0o777 == 0o700
    copied.unlink()
    copied.symlink_to(source)
    uid = os.getuid()
    gid = os.getgid()
    with pytest.raises(WorkbenchConfigurationError):
        access_service._prepare_dispatch_home(home, uid=uid, gid=gid)


def test_dispatcher_ca_access_preserves_private_signing_keys(tmp_path):
    ca = tmp_path / "config" / "soc_certs"
    ca.mkdir(mode=0o700, parents=True)
    public = ca / "lab-ca.pem"
    public.write_bytes(b"public certificate")
    public.chmod(0o644)
    key = ca / "lab-ca.key"
    key.write_bytes(b"private fixture")
    key.chmod(0o600)
    service = ca / "thehive"
    service.mkdir(mode=0o700)
    access_service._prepare_dispatch_ca(tmp_path, gid=os.getgid())
    assert ca.stat().st_mode & 0o777 == 0o710
    assert key.stat().st_mode & 0o777 == 0o600
    assert service.stat().st_mode & 0o777 == 0o700


def test_guest_qualification_builds_every_profile_mcp_registration(
    tmp_path: Path,
) -> None:
    from aptl.validation import participant_mcp_smoke, participant_profile

    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "aptl": {"env": {"APTL_MODE": "offline"}},
                    "scenario": {"env": {"SCENARIO_MODE": "sealed"}},
                }
            }
        )
    )
    profile = SimpleNamespace(
        mcp_server_ids=("aptl", "scenario"),
        workbench_profiles=(
            SimpleNamespace(
                servers=(SimpleNamespace(server_id="aptl", artifact_ref="mcp/aptl.js"),)
            ),
            SimpleNamespace(
                servers=(
                    SimpleNamespace(
                        server_id="scenario", artifact_ref="mcp/scenario.js"
                    ),
                )
            ),
        ),
    )
    captured = {}

    def run(observed_profile, registrations):
        captured.update(registrations)
        assert observed_profile is profile
        return (
            QualificationCheckEvidence(
                check_id="live-check",
                status="passed",
                summary="live qualification passed",
            ),
        )

    with (
        patch.object(
            participant_profile, "load_participant_profile", return_value=profile
        ),
        patch.object(
            participant_mcp_smoke, "run_participant_mcp_smoke", side_effect=run
        ),
        patch(
            "aptl.appliance.access_service.shutil.which", return_value="/usr/bin/node"
        ),
    ):
        result = access_service._qualification_checks(project)

    assert result[0].status == "passed"
    assert set(captured) == {"aptl", "scenario"}
    assert captured["aptl"].argv == ("/usr/bin/node", str(project / "mcp/aptl.js"))
    assert captured["aptl"].env["APTL_MODE"] == "offline"


def test_guest_qualification_retries_failed_semantics_before_publishing(
    tmp_path: Path,
) -> None:
    from aptl.validation.participant_qualification_evidence import (
        QualificationCheckEvidence,
    )

    failed = (
        QualificationCheckEvidence(
            check_id="live-check",
            status="failed",
            summary="semantic backend operation failed",
        ),
    )
    passed = (
        QualificationCheckEvidence(
            check_id="live-check",
            status="passed",
            summary="semantic backend operation passed",
        ),
    )

    with patch(
        "aptl.appliance.access_service._run_qualification_attempt",
        side_effect=(failed, passed),
    ) as attempt:
        result = access_service._qualification_checks(
            tmp_path,
            timeout_seconds=10,
            retry_interval_seconds=0,
        )

    assert result == passed
    assert attempt.call_count == 2


def test_guest_qualification_fails_closed_after_semantic_deadline(
    tmp_path: Path,
) -> None:
    from aptl.validation.participant_qualification_evidence import (
        QualificationCheckEvidence,
    )

    failed = (
        QualificationCheckEvidence(
            check_id="live-check",
            status="failed",
            summary="semantic backend operation failed",
        ),
    )
    with (
        patch(
            "aptl.appliance.access_service._run_qualification_attempt",
            return_value=failed,
        ),
        patch(
            "aptl.appliance.access_service.time.monotonic",
            side_effect=(0.0, 1.0),
        ),
        pytest.raises(WorkbenchConfigurationError, match="qualification checks failed"),
    ):
        access_service._qualification_checks(
            tmp_path,
            timeout_seconds=1,
            retry_interval_seconds=0,
        )


def test_validate_request_accepts_the_signed_endpoint() -> None:
    request = _request()
    descriptor_path = Path("/tmp/descriptor.json")
    descriptor = SimpleNamespace(
        host_mcp_contract="aptl.restricted-ssh-mcp/v1",
        host_observation_id=request.binding.host_observation_id,
    )
    publication = SimpleNamespace(
        audience="host-mcp",
        address=request.guest_endpoint.address,
        port=request.guest_endpoint.port,
        protocol=request.guest_endpoint.protocol,
    )
    # verify_seat_launch hands back the descriptor and the policy it was
    # bound to, as a pair.
    launch = (descriptor, SimpleNamespace(guest_publications=(publication,)))
    with (
        patch(
            "aptl.appliance.access_service._descriptor_digest",
            return_value=request.launch_descriptor_digest,
        ),
        patch(
            "aptl.appliance.access_service.verify_seat_launch",
            return_value=launch,
        ),
        patch(
            "aptl.appliance.access_service.qualify_appliance_boundary",
            return_value=SimpleNamespace(passed=True),
        ),
    ):
        assert (
            access_service._validate_request(request, descriptor_path) == launch
        )


def test_access_supervisor_publishes_then_revokes_stopped_listener(
    tmp_path: Path,
) -> None:
    request = _request()
    request_path = tmp_path / "request.json"
    request_path.write_text("{}")
    state_dir = tmp_path / "state"
    output_dir = state_dir.parent / "runtime" / "access"
    project = tmp_path / "project"
    project.mkdir()
    bundle = _bundle(_public_key())
    bundle = bundle.model_copy(
        update={
            "runtime_evidence": bundle.runtime_evidence.model_copy(
                update={"run_id": "run_20260920T095212Z"}
            )
        }
    )
    binding = SimpleNamespace(
        access=bundle.access,
        grants=(bundle.grant,),
        run_id=bundle.runtime_evidence.run_id,
    )

    class Listener:
        def __init__(self) -> None:
            self.polls = iter((None, None, 1, 1))

        def poll(self) -> int | None:
            return next(self.polls, 1)

        def terminate(self) -> None:
            raise AssertionError("completed listener must not be terminated")

        def wait(self, timeout: float) -> int:
            del timeout
            return 1

    listener = Listener()
    call_order: list[str] = []

    def prepare(_configuration: object, target: Path) -> SimpleNamespace:
        call_order.append("prepare")
        target.mkdir(parents=True)
        (target / "sshd_config").write_text("fixture")
        return binding

    def ensure_key(path: Path) -> None:
        path.parent.mkdir(parents=True)
        path.write_text("private")
        path.with_suffix(path.suffix + ".pub").write_text(bundle.host_public_key)

    account = SimpleNamespace(
        pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(tmp_path / "home")
    )
    launch = (SimpleNamespace(), SimpleNamespace())
    with (
        patch(
            "aptl.appliance.access_service.read_guest_access_request",
            return_value=request,
        ),
        patch("aptl.appliance.access_service._validate_request", return_value=launch),
        patch("aptl.appliance.access_service._access_account", return_value=account),
        patch("aptl.appliance.access_service._ensure_host_key", side_effect=ensure_key),
        patch("aptl.appliance.access_service._assign_management_state"),
        patch("aptl.appliance.access_service._prepare_dispatch_home"),
        patch("aptl.appliance.access_service._prepare_dispatch_ca"),
        patch(
            "aptl.appliance.access_service._stage_dispatch_metadata",
            side_effect=lambda _launch, paths, *_args, **_kwargs: paths,
        ),
        patch(
            "aptl.appliance.access_service.prepare_guest_transport", side_effect=prepare
        ),
        patch("aptl.appliance.access_service.os.chown"),
        patch("aptl.appliance.access_service._write_runtime_observation"),
        patch("aptl.appliance.access_service.subprocess.Popen", return_value=listener),
        patch(
            "aptl.appliance.access_service._load_runtime_evidence",
            side_effect=lambda *_args, **_kwargs: (
                call_order.append("qualify") or bundle.runtime_evidence
            ),
        ),
        patch("aptl.appliance.access_service.publish_guest_access") as publish,
        patch("aptl.appliance.access_service.observe_guest", return_value=object()),
        patch("aptl.appliance.access_service.verify_guest_observation"),
        patch(
            "aptl.appliance.access_service.qualify_appliance_boundary",
            return_value=SimpleNamespace(passed=True),
        ),
        patch("aptl.appliance.access_service.time.sleep"),
        pytest.raises(WorkbenchConfigurationError, match="listener stopped"),
    ):
        access_service.serve_appliance_access(
            request_path=request_path,
            descriptor_path=tmp_path / "descriptor.json",
            device_path=tmp_path / "device.sock",
            output_dir=output_dir,
            run_id=bundle.runtime_evidence.run_id,
            project_dir=project,
            state_dir=state_dir,
            observe_boundary=lambda: request.guest_observation,
        )

    published = publish.call_args.args[1]
    assert published.seat_id == request.seat_id
    assert published.runtime_evidence == bundle.runtime_evidence
    assert call_order == ["qualify", "prepare"]
