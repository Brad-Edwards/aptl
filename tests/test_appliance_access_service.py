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
from aptl.workbench.guest_binding import ApplianceAccessObservation
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
    owned: list[Path] = []
    with patch(
        "aptl.appliance.access_service.os.chown",
        side_effect=lambda path, *_args, **_kwargs: owned.append(Path(path)),
    ):
        access_service._assign_management_state(project, uid=1000, gid=1000)

    assert key.stat().st_mode & 0o777 == 0o600
    assert key.with_suffix(".pub").stat().st_mode & 0o777 == 0o644
    assert {state, state / "state.json", project / ".mcp.json"} <= set(owned)


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
        return ("passed",)

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

    assert result == ("passed",)
    assert set(captured) == {"aptl", "scenario"}
    assert captured["aptl"].argv == ("/usr/bin/node", str(project / "mcp/aptl.js"))
    assert captured["aptl"].env["APTL_MODE"] == "offline"


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
    launch = SimpleNamespace(
        descriptor=descriptor,
        boundary_policy=SimpleNamespace(guest_publications=(publication,)),
    )
    with (
        patch(
            "aptl.appliance.access_service._descriptor_digest",
            return_value=request.launch_descriptor_digest,
        ),
        patch(
            "aptl.appliance.access_service.verify_launch_descriptor",
            return_value=launch,
        ),
        patch(
            "aptl.appliance.access_service.qualify_appliance_boundary",
            return_value=SimpleNamespace(passed=True),
        ),
    ):
        assert (
            access_service._validate_request(
                request,
                descriptor_path,
                Path("release.pem"),
                Path("qualification.pem"),
                candidate_trust=False,
            )
            is launch
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

    def prepare(_configuration: object, target: Path) -> SimpleNamespace:
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
    launch = SimpleNamespace(boundary_policy=object())
    with (
        patch(
            "aptl.appliance.access_service.read_guest_access_request",
            return_value=request,
        ),
        patch("aptl.appliance.access_service._validate_request", return_value=launch),
        patch("aptl.appliance.access_service.pwd.getpwnam", return_value=account),
        patch("aptl.appliance.access_service._ensure_host_key", side_effect=ensure_key),
        patch("aptl.appliance.access_service._assign_management_state"),
        patch(
            "aptl.appliance.access_service.prepare_guest_transport", side_effect=prepare
        ),
        patch("aptl.appliance.access_service.os.chown"),
        patch("aptl.appliance.access_service._write_runtime_observation"),
        patch("aptl.appliance.access_service.subprocess.Popen", return_value=listener),
        patch(
            "aptl.appliance.access_service._load_runtime_evidence",
            return_value=bundle.runtime_evidence,
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
            release_public_key=tmp_path / "release.pem",
            qualification_public_key=tmp_path / "qualification.pem",
            device_path=tmp_path / "device.sock",
            output_dir=output_dir,
            project_dir=project,
            state_dir=state_dir,
            observe_boundary=lambda: request.guest_observation,
        )

    published = publish.call_args.args[1]
    assert published.seat_id == request.seat_id
    assert published.runtime_evidence == bundle.runtime_evidence
