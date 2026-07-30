"""Tests for project-bounded cleanup of pre-created Compose volumes."""

from __future__ import annotations

from subprocess import CompletedProcess

import pytest

from aptl.core.deployment._compose_volume_cleanup import (
    project_scoped_volume_names,
    remove_leftover_project_volumes,
)


def test_project_scoped_volume_names_returns_prefix_scoped_project_volumes(mocker):
    """Volumes are discovered by the ``<project>_`` name prefix, not a filesystem
    model and not the Compose project label.

    Teardown is scenario-agnostic (issue #874): it finds the running range's
    volumes by project-scoped Docker identity so it works regardless of which
    bundle root the scenario was realized from. It must use the name prefix, not
    the Compose project label — APTL's ADR-043 content seeder creates named
    volumes directly (before ``compose up`` references them), so they carry no
    Compose label but do carry the project prefix; a label filter would silently
    leave every seeded data volume behind.
    """

    run = mocker.Mock(
        return_value=CompletedProcess(
            [],
            0,
            # test_seeded_data carries no compose label in reality; global-data
            # is a different scope and must not be swept.
            stdout="test_seeded_data\ntest_certs\nglobal-data\n",
            stderr="",
        )
    )

    names, error = project_scoped_volume_names("test", run, timeout=30)

    assert error == ""
    assert names == {"test_seeded_data", "test_certs"}
    # Discovery lists all volumes and scopes by prefix — no filesystem model and
    # no Compose label filter (which would miss seeder-created volumes).
    (command,), _ = run.call_args
    assert command == ["docker", "volume", "ls", "--format", "{{.Name}}"]


def test_project_scoped_volume_names_reports_list_failure(mocker):
    run = mocker.Mock(
        return_value=CompletedProcess([], 1, stdout="", stderr="daemon down")
    )

    names, error = project_scoped_volume_names("test", run, timeout=30)

    assert names == set()
    assert "Failed to list project volumes for cleanup" in error


def test_project_scoped_volume_names_ignores_blank_lines_and_other_projects(mocker):
    run = mocker.Mock(
        return_value=CompletedProcess(
            [], 0, stdout="test_data\n\nother_data\n", stderr=""
        )
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
