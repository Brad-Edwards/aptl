"""Tests for system requirements checking.

Tests are written FIRST (TDD). All subprocess calls are mocked.
"""

from unittest.mock import MagicMock

import pytest


class TestCheckMaxMapCount:
    """Tests for vm.max_map_count checking."""

    @pytest.fixture(autouse=True)
    def _linux_native_docker(self, mocker):
        """Default existing tests to the only mode that enforces sysctl."""
        from aptl.core import hostenv

        mocker.patch(
            "aptl.core.sysreqs.hostenv.docker_mode",
            return_value=hostenv.DOCKER_LINUX_NATIVE,
        )

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
                stderr="sysctl: permission denied",
            ),
        )

        result = check_max_map_count()

        assert result.passed is False
        assert result.current_value == 0
        assert "permission denied" in result.error.lower()

    def test_skips_on_docker_desktop(self, mocker):
        """Docker Desktop manages the setting inside its Linux VM."""
        from aptl.core import hostenv
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.hostenv.docker_mode",
            return_value=hostenv.DOCKER_DESKTOP,
        )
        mock_run = mocker.patch("aptl.core.sysreqs.subprocess.run")

        result = check_max_map_count()

        assert result.passed is True
        assert result.applicable is False
        assert result.current_value == 0
        assert "Docker VM" in result.error
        mock_run.assert_not_called()

    def test_skips_on_non_linux_docker_vm(self, mocker):
        """Colima/Lima-style engines manage sysctls inside their Linux VM."""
        from aptl.core import hostenv
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.hostenv.docker_mode",
            return_value=hostenv.DOCKER_VM,
        )
        mock_run = mocker.patch("aptl.core.sysreqs.subprocess.run")

        result = check_max_map_count()

        assert result.passed is True
        assert result.applicable is False
        assert result.current_value == 0
        assert "docker_vm" in result.error
        mock_run.assert_not_called()

    def test_skips_when_docker_mode_unknown(self, mocker):
        """Unknown Docker mode is not treated as a host sysctl failure."""
        from aptl.core import hostenv
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.hostenv.docker_mode",
            return_value=hostenv.DOCKER_UNKNOWN,
        )
        mock_run = mocker.patch("aptl.core.sysreqs.subprocess.run")

        result = check_max_map_count()

        assert result.passed is True
        assert result.applicable is False
        mock_run.assert_not_called()

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
        """Missing sysctl is not applicable, not a startup failure."""
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.subprocess.run",
            side_effect=FileNotFoundError("sysctl not found"),
        )

        result = check_max_map_count()

        assert result.passed is True
        assert result.applicable is False
        assert result.current_value == 0
        assert "not found" in result.error.lower()

    def test_oid_absent_is_not_applicable(self, mocker):
        """Hosts without this OID should not fail lab startup."""
        from aptl.core.sysreqs import check_max_map_count

        mocker.patch(
            "aptl.core.sysreqs.subprocess.run",
            return_value=MagicMock(
                returncode=1,
                stdout="",
                stderr=(
                    "sysctl: cannot stat /proc/sys/vm/max_map_count: "
                    "No such file or directory"
                ),
            ),
        )

        result = check_max_map_count()

        assert result.passed is True
        assert result.applicable is False
        assert result.current_value == 0
        assert "not applicable" in result.error.lower()

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
