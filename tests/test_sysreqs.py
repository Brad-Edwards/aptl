"""Tests for system requirements checking.

Tests are written FIRST (TDD). All subprocess calls are mocked.
"""

from unittest.mock import MagicMock

import pytest


class TestCheckMaxMapCount:
    """Tests for vm.max_map_count checking."""

    def test_passes_when_value_meets_minimum(self, mocker):
        """Should pass when vm.max_map_count >= required minimum."""
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.subprocess.run",
            return_value=MagicMock(
                returncode=0,
                stdout="vm.max_map_count = 262144\n",
                stderr="",
            ),
        )

        result = check_max_map_count()

        assert result.passed is True
        assert result.current_value == 262144
        assert result.required_value == 262144

    def test_passes_when_value_exceeds_minimum(self, mocker):
        """Should pass when vm.max_map_count > required minimum."""
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.subprocess.run",
            return_value=MagicMock(
                returncode=0,
                stdout="vm.max_map_count = 524288\n",
                stderr="",
            ),
        )

        result = check_max_map_count()

        assert result.passed is True
        assert result.current_value == 524288

    def test_fails_when_value_below_minimum(self, mocker):
        """Should fail when vm.max_map_count < required minimum."""
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.subprocess.run",
            return_value=MagicMock(
                returncode=0,
                stdout="vm.max_map_count = 65530\n",
                stderr="",
            ),
        )

        result = check_max_map_count()

        assert result.passed is False
        assert result.current_value == 65530
        assert result.required_value == 262144

    def test_handles_sysctl_command_failure(self, mocker):
        """Should return failure when sysctl command fails."""
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.subprocess.run",
            return_value=MagicMock(
                returncode=1,
                stdout="",
                stderr="sysctl: command not found",
            ),
        )

        result = check_max_map_count()

        assert result.passed is False
        assert result.current_value == 0
        assert "sysctl" in result.error.lower() or "command" in result.error.lower()

    def test_handles_malformed_sysctl_output(self, mocker):
        """Should return failure when sysctl output can't be parsed."""
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.subprocess.run",
            return_value=MagicMock(
                returncode=0,
                stdout="unexpected garbage output\n",
                stderr="",
            ),
        )

        result = check_max_map_count()

        assert result.passed is False
        assert result.current_value == 0
        assert result.error != ""

    def test_handles_empty_sysctl_output(self, mocker):
        """Should return failure when sysctl returns empty output."""
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.subprocess.run",
            return_value=MagicMock(
                returncode=0,
                stdout="",
                stderr="",
            ),
        )

        result = check_max_map_count()

        assert result.passed is False
        assert result.current_value == 0

    def test_custom_minimum_value(self, mocker):
        """Should respect a custom minimum value parameter."""
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.subprocess.run",
            return_value=MagicMock(
                returncode=0,
                stdout="vm.max_map_count = 100000\n",
                stderr="",
            ),
        )

        # With default minimum (262144), 100000 should fail
        result_fail = check_max_map_count()
        assert result_fail.passed is False

        # With custom minimum of 50000, 100000 should pass
        result_pass = check_max_map_count(minimum=50000)
        assert result_pass.passed is True
        assert result_pass.required_value == 50000
        assert result_pass.current_value == 100000

    def test_handles_subprocess_exception(self, mocker):
        """Should handle subprocess raising an exception."""
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.subprocess.run",
            side_effect=FileNotFoundError("sysctl not found"),
        )

        result = check_max_map_count()

        assert result.passed is False
        assert result.current_value == 0
        assert "not found" in result.error.lower()

    def test_sysctl_called_with_correct_args(self, mocker):
        """Should call sysctl with vm.max_map_count."""
        from aptl.core.sysreqs import check_max_map_count

        mock_run = mocker.patch(
            "aptl.core.sysreqs.subprocess.run",
            return_value=MagicMock(
                returncode=0,
                stdout="vm.max_map_count = 262144\n",
                stderr="",
            ),
        )

        check_max_map_count()

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "sysctl" in cmd
        assert "vm.max_map_count" in cmd
