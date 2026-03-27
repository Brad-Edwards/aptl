"""Tests for objective evaluators."""

import asyncio
from unittest.mock import MagicMock

import pytest

from aptl.core.evaluators import (
    EvaluationResult,
    evaluate_command_output,
    evaluate_file_exists,
    evaluate_objective,
    evaluate_wazuh_alert,
)
from aptl.core.scenarios import (
    CommandOutputValidation,
    FileExistsValidation,
    Objective,
    ObjectiveType,
    WazuhAlertValidation,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SESSION_STARTED_AT = "2026-03-26T10:00:00+00:00"


@pytest.fixture
def wazuh_validation() -> WazuhAlertValidation:
    return WazuhAlertValidation(
        query={
            "bool": {
                "must": [
                    {"match": {"rule.groups": "authentication_failed"}},
                ]
            }
        },
        min_matches=5,
        time_window_seconds=600,
    )


@pytest.fixture
def command_validation() -> CommandOutputValidation:
    return CommandOutputValidation(
        container="kali",
        command="cat /tmp/flag.txt",
        contains=["FLAG{test_123}"],
    )


@pytest.fixture
def file_validation() -> FileExistsValidation:
    return FileExistsValidation(
        container="victim",
        path="/var/www/html/flag.txt",
        contains="FLAG{found}",
    )


# ---------------------------------------------------------------------------
# Wazuh alert evaluator
# ---------------------------------------------------------------------------


def test_wazuh_alert_pass(mocker, wazuh_validation):
    """Wazuh alert passes when min_matches are met."""
    mocker.patch(
        "aptl.core.evaluators._curl_json",
        return_value={
            "hits": {"total": {"value": 10}, "hits": []},
        },
    )
    result = asyncio.run(evaluate_wazuh_alert(
        "detect-auth", wazuh_validation, SESSION_STARTED_AT
    ))
    assert result.passed is True
    assert result.objective_id == "detect-auth"


def test_wazuh_alert_fail_insufficient_matches(mocker, wazuh_validation):
    """Wazuh alert fails when fewer than min_matches found."""
    mocker.patch(
        "aptl.core.evaluators._curl_json",
        return_value={
            "hits": {"total": {"value": 2}, "hits": []},
        },
    )
    result = asyncio.run(evaluate_wazuh_alert(
        "detect-auth", wazuh_validation, SESSION_STARTED_AT
    ))
    assert result.passed is False
    assert "2 matches" in result.detail


def test_wazuh_alert_unreachable(mocker, wazuh_validation):
    """Wazuh alert fails gracefully when indexer is unreachable."""
    mocker.patch("aptl.core.evaluators._curl_json", return_value=None)
    result = asyncio.run(evaluate_wazuh_alert(
        "detect-auth", wazuh_validation, SESSION_STARTED_AT
    ))
    assert result.passed is False
    assert "unreachable" in result.detail.lower()


def test_wazuh_alert_integer_total(mocker, wazuh_validation):
    """Handle integer total format from some ES versions."""
    mocker.patch(
        "aptl.core.evaluators._curl_json",
        return_value={"hits": {"total": 8, "hits": []}},
    )
    result = asyncio.run(evaluate_wazuh_alert(
        "detect-auth", wazuh_validation, SESSION_STARTED_AT
    ))
    assert result.passed is True


# ---------------------------------------------------------------------------
# Command output evaluator
# ---------------------------------------------------------------------------


def test_command_output_pass(mocker, command_validation):
    """Command output passes when all required strings are present."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Some output\nFLAG{test_123}\nMore output"
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=mock_result)

    result = asyncio.run(evaluate_command_output("find-flag", command_validation))
    assert result.passed is True


def test_command_output_missing_string(mocker, command_validation):
    """Command output fails when a required string is missing."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "No flag here"
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=mock_result)

    result = asyncio.run(evaluate_command_output("find-flag", command_validation))
    assert result.passed is False
    assert "Missing required string" in result.detail


def test_command_output_nonzero_exit(mocker, command_validation):
    """Command output fails when command returns non-zero."""
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=mock_result)

    result = asyncio.run(evaluate_command_output("find-flag", command_validation))
    assert result.passed is False


def test_command_output_container_unreachable(mocker, command_validation):
    """Command output fails when docker exec fails."""
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=None)
    result = asyncio.run(evaluate_command_output("find-flag", command_validation))
    assert result.passed is False
    assert "container unreachable" in result.detail.lower()


def test_command_output_regex_match(mocker):
    """Command output passes with regex match."""
    validation = CommandOutputValidation(
        container="kali",
        command="echo test",
        contains=[],
        regex=r"FLAG\{[a-z_]+\}",
    )
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Found: FLAG{secret_data}"
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=mock_result)

    result = asyncio.run(evaluate_command_output("regex-obj", validation))
    assert result.passed is True


def test_command_output_regex_no_match(mocker):
    """Command output fails when regex doesn't match."""
    validation = CommandOutputValidation(
        container="kali",
        command="echo test",
        contains=[],
        regex=r"FLAG\{[a-z_]+\}",
    )
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "No flag here"
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=mock_result)

    result = asyncio.run(evaluate_command_output("regex-obj", validation))
    assert result.passed is False
    assert "Regex not matched" in result.detail


# ---------------------------------------------------------------------------
# File exists evaluator
# ---------------------------------------------------------------------------


def test_file_exists_pass(mocker, file_validation):
    """File exists passes when file is found with expected content."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "FLAG{found}"
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=mock_result)

    result = asyncio.run(evaluate_file_exists("find-file", file_validation))
    assert result.passed is True


def test_file_exists_not_found(mocker, file_validation):
    """File exists fails when file is not found."""
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=mock_result)

    result = asyncio.run(evaluate_file_exists("find-file", file_validation))
    assert result.passed is False
    assert "not found" in result.detail.lower()


def test_file_exists_wrong_content(mocker, file_validation):
    """File exists fails when content doesn't match."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Wrong content"
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=mock_result)

    result = asyncio.run(evaluate_file_exists("find-file", file_validation))
    assert result.passed is False
    assert "missing content" in result.detail.lower()


def test_file_exists_no_content_check(mocker):
    """File exists passes when no content check is specified."""
    validation = FileExistsValidation(
        container="victim",
        path="/etc/hosts",
    )
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "127.0.0.1 localhost"
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=mock_result)

    result = asyncio.run(evaluate_file_exists("check-hosts", validation))
    assert result.passed is True


# ---------------------------------------------------------------------------
# Objective dispatcher
# ---------------------------------------------------------------------------


def test_evaluate_objective_manual():
    """Manual objectives return not-evaluable."""
    obj = Objective(
        id="manual-obj",
        description="Do something manually",
        type=ObjectiveType.MANUAL,
        points=100,
    )
    result = asyncio.run(evaluate_objective(obj, SESSION_STARTED_AT))
    assert result.passed is False
    assert "manual" in result.detail.lower()


def test_evaluate_objective_wazuh(mocker):
    """Dispatcher routes wazuh_alert objectives correctly."""
    mocker.patch(
        "aptl.core.evaluators._curl_json",
        return_value={"hits": {"total": {"value": 10}, "hits": []}},
    )
    obj = Objective(
        id="wazuh-obj",
        description="Detect alerts",
        type=ObjectiveType.WAZUH_ALERT,
        points=75,
        wazuh_alert=WazuhAlertValidation(
            query={"match_all": {}},
            min_matches=1,
        ),
    )
    result = asyncio.run(evaluate_objective(obj, SESSION_STARTED_AT))
    assert result.passed is True
    assert result.objective_id == "wazuh-obj"


def test_evaluate_objective_command(mocker):
    """Dispatcher routes command_output objectives correctly."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "FLAG{x}"
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=mock_result)

    obj = Objective(
        id="cmd-obj",
        description="Check command",
        type=ObjectiveType.COMMAND_OUTPUT,
        points=50,
        command_output=CommandOutputValidation(
            container="kali",
            command="cat /tmp/flag",
            contains=["FLAG{x}"],
        ),
    )
    result = asyncio.run(evaluate_objective(obj, SESSION_STARTED_AT))
    assert result.passed is True


def test_evaluate_objective_file(mocker):
    """Dispatcher routes file_exists objectives correctly."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "content"
    mocker.patch("aptl.core.evaluators._run_cmd", return_value=mock_result)

    obj = Objective(
        id="file-obj",
        description="Check file",
        type=ObjectiveType.FILE_EXISTS,
        points=50,
        file_exists=FileExistsValidation(
            container="victim",
            path="/tmp/test",
        ),
    )
    result = asyncio.run(evaluate_objective(obj, SESSION_STARTED_AT))
    assert result.passed is True
