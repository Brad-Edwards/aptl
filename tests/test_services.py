"""Tests for service readiness polling.

Subprocess calls are mocked; the monotonic clock and sleep are injected into
``wait_for_service`` as explicit value sequences rather than patched on the
module, so a drift in the clock-call count fails loudly via StopIteration.
"""

from pathlib import Path
from unittest.mock import MagicMock, call

import pytest


class TestWaitForService:
    """Tests for the generic retry-poll loop."""

    def test_succeeds_immediately_when_check_fn_returns_true(self):
        """Should return ready=True without retries when check passes."""
        from aptl.core.services import wait_for_service

        check_fn = MagicMock(return_value=True)

        # start (0.0) + on-ready elapsed (0.1). The explicit finite sequence
        # fails loudly (StopIteration) if the clock-call count drifts.
        result = wait_for_service(
            check_fn=check_fn,
            timeout=60,
            interval=5,
            service_name="test-service",
            time_source=iter([0.0, 0.1]).__next__,
            sleep=lambda _seconds: None,
        )

        assert result.ready is True
        assert check_fn.call_count == 1

    def test_retries_until_success_within_timeout(self):
        """Should retry and eventually succeed when check_fn starts failing."""
        from aptl.core.services import wait_for_service

        check_fn = MagicMock(side_effect=[False, False, True])

        # start(0) + now after fail 1 (5) + now after fail 2 (10) + on-ready (15)
        result = wait_for_service(
            check_fn=check_fn,
            timeout=60,
            interval=5,
            service_name="test-service",
            time_source=iter([0.0, 5.0, 10.0, 15.0]).__next__,
            sleep=lambda _seconds: None,
        )

        assert result.ready is True
        assert check_fn.call_count == 3

    def test_times_out_when_check_fn_always_fails(self):
        """Should return ready=False when timeout is exceeded."""
        from aptl.core.services import wait_for_service

        check_fn = MagicMock(return_value=False)

        # start(0) then now reads 5,10,15,20,25,30; at 30 >= deadline(30) → timeout
        result = wait_for_service(
            check_fn=check_fn,
            timeout=30,
            interval=5,
            service_name="test-service",
            time_source=iter([0.0, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0]).__next__,
            sleep=lambda _seconds: None,
        )

        assert result.ready is False
        assert "timeout" in result.error.lower() or "timed out" in result.error.lower()

    def test_respects_interval_between_checks(self):
        """Should sleep for the specified interval between checks."""
        from aptl.core.services import wait_for_service

        sleep_mock = MagicMock()
        check_fn = MagicMock(side_effect=[False, False, True])

        wait_for_service(
            check_fn=check_fn,
            timeout=60,
            interval=10,
            service_name="test-service",
            time_source=iter([0.0, 5.0, 10.0, 15.0]).__next__,
            sleep=sleep_mock,
        )

        # Sleep should be called with the interval between failed checks
        for c in sleep_mock.call_args_list:
            assert c[0][0] == 10

    def test_reports_elapsed_time(self):
        """Should report elapsed seconds in the result."""
        from aptl.core.services import wait_for_service

        check_fn = MagicMock(side_effect=[False, True])

        result = wait_for_service(
            check_fn=check_fn,
            timeout=60,
            interval=5,
            service_name="test-service",
            time_source=iter([0.0, 5.0, 12.5]).__next__,
            sleep=lambda _seconds: None,
        )

        assert result.ready is True
        assert result.elapsed_seconds == pytest.approx(12.5, abs=1.0)

    def test_handles_check_fn_exception(self):
        """Should treat exceptions from check_fn as failures and continue retrying."""
        from aptl.core.services import wait_for_service

        check_fn = MagicMock(
            side_effect=[ConnectionError("refused"), False, True]
        )

        result = wait_for_service(
            check_fn=check_fn,
            timeout=60,
            interval=5,
            service_name="test-service",
            time_source=iter([0.0, 5.0, 10.0, 15.0]).__next__,
            sleep=lambda _seconds: None,
        )

        assert result.ready is True
        assert check_fn.call_count == 3

    def test_timeout_zero_fails_immediately(self):
        """Should fail/return immediately with timeout=0 (C7)."""
        from aptl.core.services import wait_for_service

        check_fn = MagicMock(return_value=False)

        # start(0.0) + deadline check now(0.0); now >= deadline(0.0) → timeout
        result = wait_for_service(
            check_fn=check_fn,
            timeout=0,
            interval=1,
            service_name="test-service",
            time_source=iter([0.0, 0.0]).__next__,
            sleep=lambda _seconds: None,
        )

        assert result.ready is False
        # Should have checked at most once before timing out
        assert check_fn.call_count <= 1

    def test_emits_progress_on_bounded_cadence_when_requested(self):
        """Optional progress reports should name the service and elapsed timeout."""
        from aptl.core.services import wait_for_service

        check_fn = MagicMock(side_effect=[False, False, False, True])
        progress = MagicMock()

        result = wait_for_service(
            check_fn=check_fn,
            timeout=120,
            interval=10,
            service_name="Wazuh Indexer",
            time_source=iter([0.0, 5.0, 20.0, 35.0, 45.0]).__next__,
            sleep=lambda _seconds: None,
            progress=progress,
        )

        assert result.ready is True
        assert progress.call_args_list == [
            call("Readiness: Wazuh Indexer still waiting (5/120s)."),
            call("Readiness: Wazuh Indexer still waiting (35/120s)."),
        ]

    def test_progress_is_silent_by_default(self):
        """The progress hook is opt-in for programmatic callers."""
        from aptl.core.services import wait_for_service

        check_fn = MagicMock(side_effect=[False, True])

        result = wait_for_service(
            check_fn=check_fn,
            timeout=60,
            interval=5,
            service_name="test-service",
            time_source=iter([0.0, 5.0, 10.0]).__next__,
            sleep=lambda _seconds: None,
        )

        assert result.ready is True


class TestCheckIndexerReady:
    """Tests for the Wazuh Indexer readiness check."""

    def test_returns_true_on_successful_curl(self, mocker):
        """Should return True when curl succeeds."""
        from aptl.core.services import check_indexer_ready

        mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="", stderr=""),
        )

        assert check_indexer_ready(
            url="https://localhost:9200",
            username="admin",
            password="secret",
        ) is True

    def test_returns_false_on_curl_failure(self, mocker):
        """Should return False when curl fails."""
        from aptl.core.services import check_indexer_ready

        mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=7, stdout="", stderr="Connection refused"),
        )

        assert check_indexer_ready(
            url="https://localhost:9200",
            username="admin",
            password="secret",
        ) is False

    def test_returns_false_on_subprocess_exception(self, mocker):
        """Should return False when subprocess raises."""
        from aptl.core.services import check_indexer_ready

        mocker.patch(
            "aptl.core.services.subprocess.run",
            side_effect=FileNotFoundError("curl not found"),
        )

        assert check_indexer_ready(
            url="https://localhost:9200",
            username="admin",
            password="secret",
        ) is False

    def test_calls_curl_with_correct_args(self, mocker):
        """Should call curl with -k (insecure), -s (silent), -f (fail on error)."""
        from aptl.core.services import check_indexer_ready

        mock_run = mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="", stderr=""),
        )

        check_indexer_ready(
            url="https://localhost:9200",
            username="admin",
            password="secret",
        )

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "curl" in cmd
        assert "-k" in cmd
        assert "-s" in cmd
        assert "-f" in cmd
        assert "https://localhost:9200" in cmd


class TestCheckManagerApiReady:
    """Tests for the Wazuh Manager API readiness check."""

    def test_returns_true_on_successful_check(self, mocker):
        """Should return True when API responds with any HTTP status."""
        from aptl.core.services import check_manager_api_ready

        mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="401", stderr=""),
        )

        assert check_manager_api_ready(
            container_name="aptl-wazuh-manager",
        ) is True

    def test_returns_true_on_200(self, mocker):
        """Should return True when API responds with 200."""
        from aptl.core.services import check_manager_api_ready

        mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="200", stderr=""),
        )

        assert check_manager_api_ready(
            container_name="aptl-wazuh-manager",
        ) is True

    def test_returns_false_on_failure(self, mocker):
        """Should return False when docker command fails."""
        from aptl.core.services import check_manager_api_ready

        mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=1, stdout="", stderr="Error"),
        )

        assert check_manager_api_ready(
            container_name="aptl-wazuh-manager",
        ) is False

    def test_returns_false_on_no_http_response(self, mocker):
        """Should return False when curl gets no HTTP response."""
        from aptl.core.services import check_manager_api_ready

        mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=7, stdout="000", stderr=""),
        )

        assert check_manager_api_ready(
            container_name="aptl-wazuh-manager",
        ) is False

    def test_uses_docker_exec(self, mocker):
        """Should use docker exec to run curl inside the container."""
        from aptl.core.services import check_manager_api_ready

        mock_run = mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="401", stderr=""),
        )

        check_manager_api_ready(
            container_name="aptl-wazuh-manager",
        )

        cmd = mock_run.call_args[0][0]
        assert "docker" in cmd
        assert "aptl-wazuh-manager" in cmd
        assert "curl" in cmd
        assert "-f" not in cmd


class TestSSHConnection:
    """Tests for SSH connectivity testing."""

    def test_returns_true_on_successful_ssh(self, mocker):
        """Should return True when SSH succeeds."""
        from aptl.core.services import test_ssh_connection

        mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="SSH OK", stderr=""),
        )

        assert test_ssh_connection(
            host="localhost",
            port=2022,
            user="labadmin",
            key_path=Path("/home/user/.ssh/aptl_lab_key"),
        ) is True

    def test_returns_false_on_ssh_failure(self, mocker):
        """Should return False when SSH fails."""
        from aptl.core.services import test_ssh_connection

        mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=255, stdout="", stderr="Connection refused"),
        )

        assert test_ssh_connection(
            host="localhost",
            port=2022,
            user="labadmin",
            key_path=Path("/home/user/.ssh/aptl_lab_key"),
        ) is False

    def test_returns_false_on_exception(self, mocker):
        """Should return False when subprocess raises."""
        from aptl.core.services import test_ssh_connection

        mocker.patch(
            "aptl.core.services.subprocess.run",
            side_effect=FileNotFoundError("ssh not found"),
        )

        assert test_ssh_connection(
            host="localhost",
            port=2022,
            user="labadmin",
            key_path=Path("/home/user/.ssh/aptl_lab_key"),
        ) is False

    def test_uses_correct_ssh_args(self, mocker):
        """Should call ssh with -i key, -o options, port, and user@host."""
        from aptl.core.services import test_ssh_connection

        mock_run = mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="", stderr=""),
        )

        test_ssh_connection(
            host="localhost",
            port=2022,
            user="labadmin",
            key_path=Path("/home/user/.ssh/aptl_lab_key"),
        )

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "ssh" in cmd
        assert "-i" in cmd
        assert "/home/user/.ssh/aptl_lab_key" in " ".join(cmd)
        assert "-p" in cmd
        assert "2022" in " ".join(str(x) for x in cmd)
        assert "labadmin@localhost" in cmd
