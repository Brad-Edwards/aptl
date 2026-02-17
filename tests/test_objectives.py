"""Tests for objective evaluation dispatching.

Tests cover evaluate_objective dispatch for all objective types,
evaluate_all with skipping, and docker exec integration for
command_output and file_exists types.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from aptl.core.objectives import (
    EvaluationResult,
    ObjectiveResult,
    ObjectiveStatus,
    _check_command_output,
    _check_file_exists,
    _check_manual,
    evaluate_all,
    evaluate_objective,
)
from aptl.core.scenarios import (
    CommandOutputValidation,
    FileExistsValidation,
    Objective,
    ObjectiveType,
    WazuhAlertValidation,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _obj(
    obj_id: str = "obj-a",
    obj_type: ObjectiveType = ObjectiveType.MANUAL,
    points: int = 100,
    **kwargs,
) -> Objective:
    """Create an Objective for testing."""
    return Objective(
        id=obj_id,
        description=f"Test objective {obj_id}",
        type=obj_type,
        points=points,
        **kwargs,
    )


def _cmd_obj(
    obj_id: str = "cmd-obj",
    container: str = "victim",
    command: str = "echo hello",
    contains: list | None = None,
    regex: str | None = None,
) -> Objective:
    """Create a command_output Objective."""
    return _obj(
        obj_id=obj_id,
        obj_type=ObjectiveType.COMMAND_OUTPUT,
        command_output=CommandOutputValidation(
            container=container,
            command=command,
            contains=contains or [],
            regex=regex,
        ),
    )


def _file_obj(
    obj_id: str = "file-obj",
    container: str = "victim",
    path: str = "/tmp/test.txt",
    contains: str | None = None,
) -> Objective:
    """Create a file_exists Objective."""
    return _obj(
        obj_id=obj_id,
        obj_type=ObjectiveType.FILE_EXISTS,
        file_exists=FileExistsValidation(
            container=container,
            path=path,
            contains=contains,
        ),
    )


def _wazuh_obj(obj_id: str = "wazuh-obj") -> Objective:
    """Create a wazuh_alert Objective."""
    return _obj(
        obj_id=obj_id,
        obj_type=ObjectiveType.WAZUH_ALERT,
        wazuh_alert=WazuhAlertValidation(
            query={"match": {"rule.id": "1000"}},
        ),
    )


def _mock_completed_process(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["docker", "exec"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


# ---------------------------------------------------------------------------
# _check_manual
# ---------------------------------------------------------------------------


class TestCheckManual:
    """Tests for manual objective checker."""

    def test_returns_pending(self):
        result = _check_manual("obj-a")
        assert result.status == ObjectiveStatus.PENDING

    def test_includes_objective_id(self):
        result = _check_manual("obj-a")
        assert result.objective_id == "obj-a"

    def test_details_mention_manual(self):
        result = _check_manual("obj-a")
        assert "manual" in result.details.lower()


# ---------------------------------------------------------------------------
# _check_command_output
# ---------------------------------------------------------------------------


class TestCheckCommandOutput:
    """Tests for command_output objective checker."""

    @patch("aptl.core.objectives._docker_exec")
    def test_completed_when_all_match(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(stdout="hello world")

        result = _check_command_output("cmd-obj", _cmd_obj(contains=["hello"]))

        assert result.status == ObjectiveStatus.COMPLETED
        assert result.objective_id == "cmd-obj"

    @patch("aptl.core.objectives._docker_exec")
    def test_pending_when_contains_missing(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(stdout="hello world")

        result = _check_command_output(
            "cmd-obj",
            _cmd_obj(contains=["missing"]),
        )

        assert result.status == ObjectiveStatus.PENDING
        assert "missing" in result.details.lower()

    @patch("aptl.core.objectives._docker_exec")
    def test_pending_when_regex_no_match(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(stdout="hello world")

        result = _check_command_output(
            "cmd-obj",
            _cmd_obj(regex=r"^\d+$"),
        )

        assert result.status == ObjectiveStatus.PENDING
        assert "regex" in result.details.lower()

    @patch("aptl.core.objectives._docker_exec")
    def test_completed_with_regex_match(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(stdout="port 22 open")

        result = _check_command_output(
            "cmd-obj",
            _cmd_obj(regex=r"port \d+ open"),
        )

        assert result.status == ObjectiveStatus.COMPLETED

    @patch("aptl.core.objectives._docker_exec")
    def test_completed_no_conditions(self, mock_exec):
        """With no contains or regex, any output should complete."""
        mock_exec.return_value = _mock_completed_process(stdout="anything")

        result = _check_command_output("cmd-obj", _cmd_obj())

        assert result.status == ObjectiveStatus.COMPLETED

    @patch("aptl.core.objectives._docker_exec")
    def test_pending_on_exec_failure(self, mock_exec):
        mock_exec.side_effect = FileNotFoundError("docker not found")

        result = _check_command_output("cmd-obj", _cmd_obj())

        assert result.status == ObjectiveStatus.PENDING
        assert "failed" in result.details.lower()

    @patch("aptl.core.objectives._docker_exec")
    def test_pending_on_timeout(self, mock_exec):
        mock_exec.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=30)

        result = _check_command_output("cmd-obj", _cmd_obj())

        assert result.status == ObjectiveStatus.PENDING

    @patch("aptl.core.objectives._docker_exec")
    def test_uses_correct_container_name(self, mock_exec):
        """Container name should be prefixed with 'aptl-'."""
        mock_exec.return_value = _mock_completed_process(stdout="ok")

        _check_command_output("cmd-obj", _cmd_obj(container="victim"))

        call_args = mock_exec.call_args[0]
        assert call_args[0] == "aptl-victim"

    @patch("aptl.core.objectives._docker_exec")
    def test_multiple_contains_all_must_match(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(stdout="foo bar baz")

        result = _check_command_output(
            "cmd-obj",
            _cmd_obj(contains=["foo", "bar"]),
        )
        assert result.status == ObjectiveStatus.COMPLETED

    @patch("aptl.core.objectives._docker_exec")
    def test_multiple_contains_partial_fail(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(stdout="foo baz")

        result = _check_command_output(
            "cmd-obj",
            _cmd_obj(contains=["foo", "bar"]),
        )
        assert result.status == ObjectiveStatus.PENDING

    @patch("aptl.core.objectives._docker_exec")
    def test_completed_has_timestamp(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(stdout="ok")

        result = _check_command_output("cmd-obj", _cmd_obj())

        assert result.completed_at is not None


# ---------------------------------------------------------------------------
# _check_file_exists
# ---------------------------------------------------------------------------


class TestCheckFileExists:
    """Tests for file_exists objective checker."""

    @patch("aptl.core.objectives._docker_exec")
    def test_completed_when_file_exists(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(
            stdout="file content", returncode=0
        )

        result = _check_file_exists("file-obj", _file_obj())

        assert result.status == ObjectiveStatus.COMPLETED

    @patch("aptl.core.objectives._docker_exec")
    def test_pending_when_file_missing(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(
            stdout="", returncode=1
        )

        result = _check_file_exists("file-obj", _file_obj())

        assert result.status == ObjectiveStatus.PENDING
        assert "not found" in result.details.lower()

    @patch("aptl.core.objectives._docker_exec")
    def test_completed_with_matching_content(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(
            stdout="secret flag: abc123", returncode=0
        )

        result = _check_file_exists(
            "file-obj",
            _file_obj(contains="flag: abc123"),
        )

        assert result.status == ObjectiveStatus.COMPLETED

    @patch("aptl.core.objectives._docker_exec")
    def test_pending_with_wrong_content(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(
            stdout="some content", returncode=0
        )

        result = _check_file_exists(
            "file-obj",
            _file_obj(contains="expected"),
        )

        assert result.status == ObjectiveStatus.PENDING
        assert "missing expected content" in result.details.lower()

    @patch("aptl.core.objectives._docker_exec")
    def test_pending_on_exec_failure(self, mock_exec):
        mock_exec.side_effect = OSError("connection refused")

        result = _check_file_exists("file-obj", _file_obj())

        assert result.status == ObjectiveStatus.PENDING

    @patch("aptl.core.objectives._docker_exec")
    def test_uses_correct_container_name(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(returncode=0)

        _check_file_exists("file-obj", _file_obj(container="kali"))

        call_args = mock_exec.call_args[0]
        assert call_args[0] == "aptl-kali"

    @patch("aptl.core.objectives._docker_exec")
    def test_no_contains_check_when_none(self, mock_exec):
        """When contains is None, only file existence matters."""
        mock_exec.return_value = _mock_completed_process(
            stdout="any content", returncode=0
        )

        result = _check_file_exists(
            "file-obj",
            _file_obj(contains=None),
        )

        assert result.status == ObjectiveStatus.COMPLETED


# ---------------------------------------------------------------------------
# evaluate_objective dispatch
# ---------------------------------------------------------------------------


class TestEvaluateObjective:
    """Tests for the evaluate_objective dispatch function."""

    def test_manual_returns_pending(self):
        result = evaluate_objective(_obj())
        assert result.status == ObjectiveStatus.PENDING
        assert result.objective_id == "obj-a"

    def test_wazuh_alert_without_conn_returns_pending(self):
        result = evaluate_objective(
            _wazuh_obj(),
            wazuh_conn=None,
            scenario_start_time="2026-02-16T14:30:00+00:00",
        )
        assert result.status == ObjectiveStatus.PENDING
        assert "no wazuh" in result.details.lower()

    @patch("aptl.core.objectives._docker_exec")
    def test_command_output_dispatches(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(stdout="ok")

        result = evaluate_objective(_cmd_obj())

        assert result.status == ObjectiveStatus.COMPLETED

    @patch("aptl.core.objectives._docker_exec")
    def test_file_exists_dispatches(self, mock_exec):
        mock_exec.return_value = _mock_completed_process(stdout="data", returncode=0)

        result = evaluate_objective(_file_obj())

        assert result.status == ObjectiveStatus.COMPLETED


# ---------------------------------------------------------------------------
# evaluate_all
# ---------------------------------------------------------------------------


class TestEvaluateAll:
    """Tests for bulk objective evaluation."""

    def test_all_manual_returns_all_pending(self):
        objectives = [_obj("a"), _obj("b")]

        result = evaluate_all(objectives)

        assert len(result.results) == 2
        assert all(r.status == ObjectiveStatus.PENDING for r in result.results)
        assert result.all_complete is False

    def test_skips_completed_ids(self):
        objectives = [_obj("a", points=50), _obj("b", points=75)]

        result = evaluate_all(objectives, completed_ids={"a"})

        a_result = next(r for r in result.results if r.objective_id == "a")
        b_result = next(r for r in result.results if r.objective_id == "b")

        assert a_result.status == ObjectiveStatus.COMPLETED
        assert a_result.points_awarded == 50
        assert a_result.details == "Previously completed"
        assert b_result.status == ObjectiveStatus.PENDING

    def test_all_complete_when_all_skipped(self):
        objectives = [_obj("a"), _obj("b")]

        result = evaluate_all(objectives, completed_ids={"a", "b"})

        assert result.all_complete is True

    def test_has_evaluation_timestamp(self):
        objectives = [_obj("a")]

        result = evaluate_all(objectives)

        assert result.evaluated_at
        assert "T" in result.evaluated_at

    @patch("aptl.core.objectives._docker_exec")
    def test_mixed_types(self, mock_exec):
        """Should handle a mix of manual and automated objectives."""
        mock_exec.return_value = _mock_completed_process(stdout="ok")

        objectives = [_obj("manual-obj"), _cmd_obj("cmd-obj")]

        result = evaluate_all(objectives)

        manual = next(r for r in result.results if r.objective_id == "manual-obj")
        cmd = next(r for r in result.results if r.objective_id == "cmd-obj")

        assert manual.status == ObjectiveStatus.PENDING
        assert cmd.status == ObjectiveStatus.COMPLETED
        assert result.all_complete is False

    def test_empty_objectives_returns_all_complete(self):
        result = evaluate_all([])
        assert result.all_complete is True
        assert result.results == []

    def test_completed_ids_default_none(self):
        """Should work fine without providing completed_ids."""
        objectives = [_obj("a")]

        result = evaluate_all(objectives)

        assert len(result.results) == 1
        assert result.results[0].status == ObjectiveStatus.PENDING
