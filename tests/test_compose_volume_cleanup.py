"""Tests for project-bounded cleanup of pre-created Compose volumes."""

from __future__ import annotations

from subprocess import CompletedProcess

import pytest

from aptl.core.deployment._compose_volume_cleanup import (
    project_scoped_volume_names,
    remove_leftover_project_volumes,
)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("volumes: [\n", "while parsing"),
        ("- not-a-compose-mapping\n", "invalid Compose"),
        ("volumes: [invalid]\n", "invalid volumes"),
    ],
)
def test_project_scoped_volume_names_rejects_invalid_compose(
    tmp_path, content, message
):
    (tmp_path / "docker-compose.yml").write_text(content, encoding="utf-8")

    names, error = project_scoped_volume_names(tmp_path, "test")

    assert names == set()
    assert message in error


def test_project_scoped_volume_names_reports_missing_compose(tmp_path):
    names, error = project_scoped_volume_names(tmp_path, "test")

    assert names == set()
    assert "Failed to read project volumes for cleanup" in error


def test_project_scoped_volume_names_excludes_global_and_invalid_names(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "volumes:\n"
        "  1: {}\n"
        "  seeded_data:\n"
        "  shared_data: {external: true}\n"
        "  explicit_data: {name: global-data}\n",
        encoding="utf-8",
    )

    names, error = project_scoped_volume_names(tmp_path, "test")

    assert error == ""
    assert names == {"test_seeded_data"}


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

    assert errors and "Failed to list project volumes for cleanup" in errors[0]


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

    assert errors and "Failed to remove project volumes" in errors[0]
