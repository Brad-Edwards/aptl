"""Tests for project-bounded cleanup of pre-created Compose volumes."""

from __future__ import annotations

from subprocess import CompletedProcess

import pytest

from aptl.core.deployment._compose_volume_cleanup import (
    project_scoped_volume_names,
    remove_leftover_project_volumes,
)


def test_project_scoped_volume_names_returns_labeled_project_volumes(mocker):
    """Volumes are discovered by Compose project label, not a filesystem model.

    Teardown is scenario-agnostic (issue #874): it must find the running range's
    volumes by project-scoped Docker identity so it works regardless of which
    bundle root the scenario was realized from.
    """

    run = mocker.Mock(
        return_value=CompletedProcess(
            [], 0, stdout="test_seeded_data\ntest_certs\n", stderr=""
        )
    )

    names, error = project_scoped_volume_names("test", run, timeout=30)

    assert error == ""
    assert names == {"test_seeded_data", "test_certs"}
    # Discovery is by the Compose project label, never by reading a compose file.
    (command,), _ = run.call_args
    assert command[:3] == ["docker", "volume", "ls"]
    assert "label=com.docker.compose.project=test" in command


def test_project_scoped_volume_names_reports_list_failure(mocker):
    run = mocker.Mock(
        return_value=CompletedProcess([], 1, stdout="", stderr="daemon down")
    )

    names, error = project_scoped_volume_names("test", run, timeout=30)

    assert names == set()
    assert "Failed to list project volumes for cleanup" in error


def test_project_scoped_volume_names_ignores_blank_lines(mocker):
    run = mocker.Mock(
        return_value=CompletedProcess([], 0, stdout="test_data\n\n", stderr="")
    )

    names, error = project_scoped_volume_names("test", run, timeout=30)

    assert error == ""
    assert names == {"test_data"}


def test_remove_leftover_project_volumes_skips_docker_when_none_expected(mocker):
    run = mocker.Mock()

    assert remove_leftover_project_volumes(set(), run, timeout=30) == []
    run.assert_not_called()


@pytest.mark.parametrize("failure", [OSError("daemon unavailable"), None])
def test_remove_leftover_project_volumes_reports_list_failure(mocker, failure):
    run = mocker.Mock()
    if failure is not None:
        run.side_effect = failure
    else:
        run.return_value = CompletedProcess([], 1, stdout="", stderr="list failed")

    errors = remove_leftover_project_volumes({"test_data"}, run, timeout=30)

    assert errors
    assert "Failed to list project volumes for cleanup" in errors[0]


def test_remove_leftover_project_volumes_skips_remove_when_absent(mocker):
    run = mocker.Mock(
        return_value=CompletedProcess([], 0, stdout="other_data\n", stderr="")
    )

    assert remove_leftover_project_volumes({"test_data"}, run, timeout=30) == []
    assert run.call_count == 1


def test_remove_leftover_project_volumes_reports_remove_exception(mocker):
    run = mocker.Mock(
        side_effect=[
            CompletedProcess([], 0, stdout="test_data\n", stderr=""),
            OSError("volume busy"),
        ]
    )

    errors = remove_leftover_project_volumes({"test_data"}, run, timeout=30)

    assert errors
    assert "Failed to remove project volumes" in errors[0]
