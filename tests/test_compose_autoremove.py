"""Exact Docker realization of SDL ``container.autoremove`` semantics."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from raes.runtime_configuration import RuntimeConfiguration

from aptl.core.deployment.docker_compose import DockerComposeBackend
from aptl.core.deployment.observation import DeploymentObservationContext
from aptl.core.deployment.realization import (
    DeploymentImageRealization,
    DeploymentNodeRealization,
    DeploymentRealizationSpec,
)
from aptl.core.lab_types import LabResult

_CONTAINER = "aptl-init"
_ADDRESS = "provision.node.init"
_IMAGE_DIGEST = "sha256:" + "a" * 64


def _runtime(*, autoremove: bool) -> RuntimeConfiguration:
    return RuntimeConfiguration.model_validate(
        {
            "container": {
                "autoremove": autoremove,
                "entrypoint": ["/bin/init"],
            }
        }
    )


def _spec(*, autoremove: bool = True) -> DeploymentRealizationSpec:
    return DeploymentRealizationSpec(
        profiles=(),
        nodes=(
            DeploymentNodeRealization(
                address=_ADDRESS,
                name="init",
                service_name="init",
                container_name=_CONTAINER,
                networks=(),
                os="linux",
                runtime=_runtime(autoremove=autoremove),
            ),
        ),
        networks=(),
        images=(
            DeploymentImageRealization(
                address=_ADDRESS,
                service_name="init",
                source_name="example/init",
                source_version=_IMAGE_DIGEST,
                image_ref=f"example/init@{_IMAGE_DIGEST}",
                mode="pull",
                policy_rule="authored-exact-artifact",
            ),
        ),
    )


def _completed_inspect() -> dict[str, object]:
    return {
        "State": {"Running": False, "Status": "exited", "ExitCode": 0},
        "Platform": "linux",
        "Config": {
            "Entrypoint": ["/bin/init"],
            "Labels": {"com.docker.compose.project": "aptl-test"},
        },
        "HostConfig": {
            "AutoRemove": False,
            "RestartPolicy": {"Name": "no"},
        },
        "Mounts": [],
    }


def test_completed_autoremove_container_is_removed_and_receipted(tmp_path):
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    context = DeploymentObservationContext()
    present = True
    inspect = _completed_inspect()

    def observed_inspect(_name):
        return inspect if present else {}

    def remove(cmd, *, timeout=None):
        nonlocal present
        # Not forced: a still-running container must refuse removal here, not
        # be killed. ``-v`` takes its anonymous volumes with it; without it they
        # outlive the container with nothing left to attribute them to the lab.
        assert cmd == ["docker", "rm", "-v", _CONTAINER]
        assert timeout is not None
        present = False
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with (
        patch.object(backend, "container_exists", side_effect=lambda _name: present),
        patch.object(backend, "container_inspect", side_effect=observed_inspect),
        patch.object(backend, "container_image_digest", return_value=_IMAGE_DIGEST),
        patch.object(
            backend,
            "container_file_read",
            return_value=b'ID="debian"\nVERSION_ID="12"\n',
        ),
        patch.object(backend, "_resolve_owned_container_id", return_value=_CONTAINER),
        patch.object(backend, "_run", side_effect=remove),
    ):
        failures = backend._retire_completed_autoremove_nodes(_spec(), context)

    assert failures == []
    assert context.autoremove_verified(_CONTAINER) is True
    assert context.completed_inspect(_CONTAINER) == inspect
    assert context.completed_image_digest(_CONTAINER) == _IMAGE_DIGEST
    assert (
        context.completed_file_read(_CONTAINER, "/etc/os-release", max_bytes=64 * 1024)
        == b'ID="debian"\nVERSION_ID="12"\n'
    )


def test_autoremove_failure_is_fail_closed_and_has_no_receipt(tmp_path):
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    context = DeploymentObservationContext()
    inspect = _completed_inspect()

    with (
        patch.object(backend, "container_exists", return_value=True),
        patch.object(backend, "container_inspect", return_value=inspect),
        patch.object(backend, "container_image_digest", return_value=_IMAGE_DIGEST),
        patch.object(
            backend,
            "container_file_read",
            return_value=b'ID="debian"\nVERSION_ID="12"\n',
        ),
        patch.object(backend, "_resolve_owned_container_id", return_value=_CONTAINER),
        patch.object(
            backend,
            "_run",
            return_value=subprocess.CompletedProcess(
                ["docker", "rm", "-v", _CONTAINER], 1, "", "private daemon detail"
            ),
        ),
    ):
        failures = backend._retire_completed_autoremove_nodes(_spec(), context)

    assert failures == [f"container {_CONTAINER!r} could not be auto-removed"]
    assert "private daemon detail" not in failures[0]
    assert context.autoremove_verified(_CONTAINER) is False


def test_container_without_autoremove_is_not_removed(tmp_path):
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    with patch.object(backend, "_run") as run:
        assert (
            backend._retire_completed_autoremove_nodes(
                _spec(autoremove=False), DeploymentObservationContext()
            )
            == []
        )
    run.assert_not_called()


def test_post_start_fails_when_completed_container_cannot_be_removed(tmp_path):
    backend = DockerComposeBackend(tmp_path, project_name="aptl-test")
    context = DeploymentObservationContext()
    with (
        patch.object(backend, "_reconcile_realization_networks", return_value=[]),
        patch.object(backend, "_await_realized_service_health", return_value=[]),
        patch.object(
            backend, "_verify_stateful_authenticated_readiness", return_value=None
        ),
        patch.object(backend, "_verify_runtime_orchestration", return_value=None),
        patch.object(backend, "_realize_accounts_step", return_value=None),
        patch.object(
            backend,
            "_retire_completed_autoremove_nodes",
            return_value=["container 'aptl-init' could not be auto-removed"],
        ),
    ):
        result = backend._post_start_result(_spec(), context)

    assert result == LabResult(
        success=False,
        error="container 'aptl-init' could not be auto-removed",
    )
