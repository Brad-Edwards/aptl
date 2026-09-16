"""Scope-admitted Kali capture apparatus realization and disclosure."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.realization import (
    DeploymentCaptureApparatus,
    DeploymentGeneratedArtifactOutput,
    DeploymentGeneratedArtifactRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.deployment._compose_stateful_model import artifact_source_path

_ROOT = Path(__file__).resolve().parents[1]


def _apparatus() -> DeploymentCaptureApparatus:
    return DeploymentCaptureApparatus(
        apparatus_id="aptl.apparatus.kali-session-capture",
        service_name="kali-capture",
        container_name="aptl-kali-capture",
        target_refs=("nodes.kali",),
        governing_scopes=("#/",),
        environment_visible=True,
        observer_effects=("PTY ingress is mediated by the capture broker",),
    )


def _capture_spec(project: Path) -> DeploymentRealizationSpec:
    artifact = DeploymentGeneratedArtifactRealization(
        address="provision.generated-artifact.techvault-ssh-keys",
        name="techvault-ssh-keys",
        generator="ssh_key_bundle",
        lifecycle="regenerate_on_change",
        provenance="techvault:ssh-access-profile/v1",
        outputs=(
            DeploymentGeneratedArtifactOutput(
                name="kali-pivot-private-key",
                path="kali/.ssh/kali_pivot_key",
                sensitivity="secret",
            ),
            DeploymentGeneratedArtifactOutput(
                name="kali-authorized-keys",
                path="kali/.ssh/authorized_keys",
                sensitivity="restricted",
            ),
        ),
        consumers=(),
    )
    source = artifact_source_path(project, artifact)
    private_key = source / "kali/.ssh/kali_pivot_key"
    private_key.parent.mkdir(parents=True, exist_ok=True)
    private_key.write_text("private-test-key")
    Path(f"{private_key}.pub").write_text("ssh-ed25519 AAAATEST aptl-kali-pivot\n")
    (source / "kali/.ssh/authorized_keys").write_text(
        "ssh-ed25519 AAAAOPERATOR aptl-control-plane\n"
    )
    return DeploymentRealizationSpec(
        profiles=("kali",),
        nodes=(
            DeploymentNodeRealization(
                address="provision.node.kali",
                name="kali",
                service_name="kali",
                container_name="aptl-kali",
                networks=("redteam-net",),
            ),
        ),
        networks=(),
        generated_artifacts=(artifact,),
        capture_apparatus=(_apparatus(),),
    )


def test_generated_realization_includes_only_admitted_capture_apparatus(tmp_path):
    scenario = tmp_path / "pack"
    scenario.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    (project / "docker-compose.capture.yml").write_text(
        (_ROOT / "docker-compose.capture.yml").read_text()
    )
    backend = DockerComposeBackend(project)
    spec = _capture_spec(project)

    files = backend._realization_compose_files(None, spec, scenario, project)
    documents = [yaml.safe_load(path.read_text()) for path in files or ()]
    services = {
        name: service
        for document in documents
        for name, service in document.get("services", {}).items()
    }

    assert set(services) == {"kali-capture"}
    assert services["kali-capture"]["container_name"] == "aptl-kali-capture"
    assert services["kali-capture"]["network_mode"] == "container:aptl-kali"
    assert "pid" not in services["kali-capture"]
    assert not services["kali-capture"].get("ports")


def test_generated_realization_omits_unadmitted_capture_apparatus(tmp_path):
    scenario = tmp_path / "pack"
    scenario.mkdir()
    backend = DockerComposeBackend(_ROOT)
    spec = DeploymentRealizationSpec(profiles=("kali",), nodes=(), networks=())

    files = backend._realization_compose_files(None, spec, scenario, _ROOT)

    assert not files


def test_capture_apparatus_asset_is_backend_owned_and_distributed():
    from aptl._asset_manifest import ASSET_ROOTS

    assert "docker-compose.capture.yml" in ASSET_ROOTS
    static = yaml.safe_load((_ROOT / "docker-compose.yml").read_text())
    assert "kali-capture" not in static["services"]


def test_capture_preparation_relocates_only_kali_ssh_to_loopback(tmp_path):
    backend = DockerComposeBackend(tmp_path)
    backend.container_exec_with_input = MagicMock(
        return_value=subprocess.CompletedProcess([], 0, "", "")
    )
    spec = _capture_spec(tmp_path)

    result = backend._prepare_capture_target(spec)

    assert result is None
    name, command, script = backend.container_exec_with_input.call_args.args
    assert name == "aptl-kali"
    assert command == ["sh", "-s"]
    assert "ListenAddress 127.0.0.1:2222" in script
    assert "systemctl restart ssh" in script
    assert "aptl-kali-pivot" in script
    assert "/home/kali/.ssh/authorized_keys" in script


def test_capture_preparation_failure_is_bounded(tmp_path):
    backend = DockerComposeBackend(tmp_path)
    backend.container_exec_with_input = MagicMock(
        return_value=subprocess.CompletedProcess([], 1, "", "source detail")
    )
    spec = _capture_spec(tmp_path)

    result = backend._prepare_capture_target(spec)

    assert result is not None
    assert result.error == "aptl.capture-apparatus.target-ingress-unavailable"
    assert "source detail" not in result.error


def test_dormant_capture_apparatus_is_verified_without_open_ingress(tmp_path):
    backend = DockerComposeBackend(tmp_path)
    spec = _capture_spec(tmp_path)
    backend.container_inspect = MagicMock(
        side_effect=(
            {
                "Config": {
                    "Labels": {"com.docker.compose.project": backend._project_name},
                    "Image": "aptl-kali-capture:test",
                },
                "HostConfig": {
                    "NetworkMode": "container:kali-id",
                    "PidMode": "",
                    "ReadonlyRootfs": True,
                    "CapDrop": ["ALL"],
                    "CapAdd": [
                        "CAP_CHOWN",
                        "CAP_DAC_OVERRIDE",
                        "CAP_NET_BIND_SERVICE",
                        "CAP_SETGID",
                        "CAP_SETUID",
                        "CAP_SYS_CHROOT",
                    ],
                },
                "State": {"Running": True},
                "Mounts": [
                    {
                        "Destination": "/var/log/aptl/captures",
                        "Type": "volume",
                        "RW": True,
                    }
                ],
                "NetworkSettings": {"Ports": {}},
                "Image": "sha256:" + "a" * 64,
            },
            {"Id": "kali-id"},
        )
    )
    backend.observe_container_listeners = MagicMock(
        side_effect=AssertionError("dormant apparatus has no broker listener")
    )

    observed = backend.observe_capture_apparatus(spec)

    assert observed is not None
    assert observed[0]["participant_ingress_state"] == ("dormant-awaiting-run-binding")
    assert observed[0]["linux_capabilities"] == [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_NET_BIND_SERVICE",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SYS_CHROOT",
    ]
    backend.observe_container_listeners.assert_not_called()


def test_capture_activation_binds_exact_plan_and_run(tmp_path, monkeypatch):
    backend = DockerComposeBackend(tmp_path)
    authority = {
        "run_id": "run-1",
        "plan_id": "capture-plan-1",
        "binding_id": "aptl.collector.redteam-session-transcript",
        "activated_at": "2026-09-14T10:00:00Z",
    }
    backend.container_exec = MagicMock(
        side_effect=(
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 1, "", ""),
            subprocess.CompletedProcess([], 0, __import__("json").dumps(authority), ""),
        )
    )
    monkeypatch.setattr(
        "aptl.core.deployment._compose_capture_apparatus.time.sleep",
        lambda _seconds: None,
    )

    observed = backend.activate_capture_apparatus(
        plan_id="capture-plan-1", run_id="run-1"
    )

    assert observed == authority
    activation = backend.container_exec.call_args_list[0]
    assert activation.args[0] == "aptl-kali-capture"
    assert "capture-plan-1" in activation.args[1]
    assert "run-1" in activation.args[1]
    status = backend.container_exec.call_args_list[-1]
    assert status.args[1][-1] == "status"


@pytest.mark.parametrize(
    "responses",
    [
        (subprocess.CompletedProcess([], 1, "", ""),),
        (
            subprocess.CompletedProcess([], 0, "", ""),
            *(subprocess.CompletedProcess([], 1, "", "") for _ in range(30)),
        ),
        (
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps(
                    {
                        "run_id": "wrong-run",
                        "plan_id": "capture-plan-1",
                        "binding_id": "aptl.collector.redteam-session-transcript",
                    }
                ),
                "",
            ),
        ),
    ],
    ids=("activation-command-fails", "status-times-out", "authority-mismatches"),
)
def test_capture_activation_fails_closed(responses, tmp_path, monkeypatch):
    backend = DockerComposeBackend(tmp_path)
    backend.container_exec = MagicMock(side_effect=responses)
    monkeypatch.setattr(
        "aptl.core.deployment._compose_capture_apparatus.time.sleep",
        lambda _seconds: None,
    )

    observed = backend.activate_capture_apparatus(
        plan_id="capture-plan-1", run_id="run-1"
    )

    assert observed is None


def test_capture_finalization_quiesces_before_export(tmp_path):
    backend = DockerComposeBackend(tmp_path)
    payload = {
        "authority": {"run_id": "run-1"},
        "accepted_session_ids": [],
        "sessions": [],
    }
    backend.container_exec = MagicMock(
        side_effect=(
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, __import__("json").dumps(payload), ""),
        )
    )

    assert backend.quiesce_capture_apparatus() is True
    observed = backend.export_capture_apparatus(expected_session_ids=())

    assert observed == {**payload, "expected_session_ids": []}
    commands = [call.args[1][-1] for call in backend.container_exec.call_args_list]
    assert commands == ["quiesce", "export"]


@pytest.mark.parametrize(
    "responses",
    [
        (subprocess.CompletedProcess([], 1, "", ""),),
        (
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 1, "", ""),
        ),
        (
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "[]", ""),
        ),
    ],
    ids=("quiesce-fails", "export-fails", "export-is-not-an-object"),
)
def test_capture_finalization_fails_closed(responses, tmp_path):
    backend = DockerComposeBackend(tmp_path)
    backend.container_exec = MagicMock(side_effect=responses)

    quiesced = backend.quiesce_capture_apparatus()
    if len(responses) == 1:
        assert quiesced is False
    else:
        assert quiesced is True
        assert backend.export_capture_apparatus(expected_session_ids=()) is None


def test_capture_finalization_rejects_broker_inventory_mismatch(tmp_path):
    backend = DockerComposeBackend(tmp_path)
    payload = {
        "authority": {"run_id": "run-1"},
        "accepted_session_ids": ["session-2"],
        "sessions": [],
    }
    backend.container_exec = MagicMock(
        side_effect=(
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, json.dumps(payload), ""),
        )
    )

    assert backend.quiesce_capture_apparatus() is True
    assert backend.export_capture_apparatus(expected_session_ids=("session-1",)) is None
