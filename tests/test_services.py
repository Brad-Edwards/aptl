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

        check_fn = MagicMock(side_effect=[ConnectionError("refused"), False, True])

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
    """Tests for the Wazuh Indexer readiness check.

    ``check_indexer_ready`` now delegates entirely to
    ``check_indexer_status`` (issue #623) — the readiness question is
    just "did we get a 2xx". These tests mock the delegate boundary;
    the argv-safety guarantee itself is covered by
    ``TestCheckIndexerStatus`` and ``tests/test_curl_safe.py``.
    """

    def test_returns_true_for_status_200(self, mocker):
        """Should return True for a 2xx status."""
        from aptl.core.services import check_indexer_ready

        mocker.patch("aptl.core.services.check_indexer_status", return_value=200)

        assert (
            check_indexer_ready(
                url="https://localhost:9200",
                username="admin",
                password="secret",
            )
            is True
        )

    def test_returns_false_for_status_401(self, mocker):
        """A 401 means the indexer is listening but rejected the
        credentials -- that is NOT ready, but it is also not "no
        response", which is the whole point of the #623 fix."""
        from aptl.core.services import check_indexer_ready

        mocker.patch("aptl.core.services.check_indexer_status", return_value=401)

        assert (
            check_indexer_ready(
                url="https://localhost:9200",
                username="admin",
                password="secret",
            )
            is False
        )

    def test_returns_false_when_status_is_none(self, mocker):
        """No HTTP response at all (transport failure, timeout, or
        connection refused) is still "not ready"."""
        from aptl.core.services import check_indexer_ready

        mocker.patch("aptl.core.services.check_indexer_status", return_value=None)

        assert (
            check_indexer_ready(
                url="https://localhost:9200",
                username="admin",
                password="secret",
            )
            is False
        )


class TestCheckIndexerStatus:
    """Tests for the indexer classification probe (issue #623).

    Distinguishes "not listening yet" (``None``) from "listening but
    rejecting the configured credentials" (401/403) so callers can tell
    a stale-credential state apart from a still-starting container.
    """

    def test_returns_the_status_code_from_curl_status(self, mocker):
        from aptl.core.services import check_indexer_status

        mock_curl_status = mocker.patch(
            "aptl.core.services.curl_status", return_value=401
        )

        result = check_indexer_status(
            url="https://localhost:9200",
            username="admin",
            password="secret",
        )

        assert result == 401
        mock_curl_status.assert_called_once_with(
            "https://localhost:9200",
            auth=("admin", "secret"),
            insecure=True,
            timeout=10,
        )

    def test_returns_none_when_curl_status_returns_none(self, mocker):
        from aptl.core.services import check_indexer_status

        mocker.patch("aptl.core.services.curl_status", return_value=None)

        assert (
            check_indexer_status(
                url="https://localhost:9200",
                username="admin",
                password="secret",
            )
            is None
        )

    def test_password_never_reaches_subprocess_argv(self, mocker):
        """End-to-end guardrail at the real subprocess boundary (not the
        ``curl_status`` delegate) -- this is the actual ADR-029 fix for
        #623: the indexer readiness probe no longer puts the password on
        the curl command line."""
        from aptl.core.services import check_indexer_status
        from aptl.utils import curl_safe

        captured: dict = {}

        def fake_run(cmd, *args, **kwargs):
            captured["cmd"] = list(cmd)
            return MagicMock(returncode=0, stdout="401", stderr="")

        mocker.patch.object(curl_safe.subprocess, "run", side_effect=fake_run)

        result = check_indexer_status(
            url="https://localhost:9200",
            username="admin",
            password="super-secret-password",
        )

        assert result == 401
        joined = " ".join(str(a) for a in captured["cmd"])
        assert "admin" not in joined
        assert "super-secret-password" not in joined


class TestCheckManagerApiReady:
    """Tests for the Wazuh Manager API readiness check."""

    def test_returns_true_on_successful_check(self, mocker):
        """Authenticated readiness requires a successful manager-status body."""
        from aptl.core.services import check_manager_api_ready

        request = mocker.patch(
            "aptl.core.services.curl_json",
            side_effect=[
                {"error": 0, "data": {"token": "bounded-token"}},
                {
                    "error": 0,
                    "data": {"affected_items": [{"wazuh-manager": "running"}]},
                },
            ],
        )

        assert (
            check_manager_api_ready(
                url="https://localhost:55000",
                username="api-user",
                password="api-password",
            )
            is True
        )
        assert request.call_count == 2

    def test_returns_false_when_authentication_fails(self, mocker):
        from aptl.core.services import check_manager_api_ready

        mocker.patch(
            "aptl.core.services.curl_json",
            return_value=None,
        )

        assert (
            check_manager_api_ready(
                url="https://localhost:55000",
                username="api-user",
                password="api-password",
            )
            is False
        )

    def test_returns_false_when_manager_status_is_not_semantically_successful(
        self, mocker
    ):
        from aptl.core.services import check_manager_api_ready

        mocker.patch(
            "aptl.core.services.curl_json",
            side_effect=[
                {"error": 0, "data": {"token": "bounded-token"}},
                {"error": 1, "data": {"affected_items": []}},
            ],
        )

        assert (
            check_manager_api_ready(
                url="https://localhost:55000",
                username="api-user",
                password="api-password",
            )
            is False
        )

    def test_credentials_use_permissioned_header_path_not_url(self, mocker):
        from aptl.core.services import check_manager_api_ready

        request = mocker.patch(
            "aptl.core.services.curl_json",
            return_value=None,
        )

        check_manager_api_ready(
            url="https://localhost:55000",
            username="api-user",
            password="api-password",
        )

        kwargs = request.call_args.kwargs
        assert kwargs["auth_header"].startswith("Basic ")
        assert "api-user" not in request.call_args.args[0]
        assert "api-password" not in request.call_args.args[0]


class TestSSHConnection:
    """Tests for SSH connectivity testing."""

    def test_returns_true_on_successful_ssh(self, mocker):
        """Should return True when SSH succeeds."""
        from aptl.core.services import test_ssh_connection

        mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="SSH OK", stderr=""),
        )

        assert (
            test_ssh_connection(
                host="localhost",
                port=2022,
                user="labadmin",
                key_path=Path("/home/user/.ssh/aptl_lab_key"),
            )
            is True
        )

    def test_returns_false_on_ssh_failure(self, mocker):
        """Should return False when SSH fails."""
        from aptl.core.services import test_ssh_connection

        mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(
                returncode=255, stdout="", stderr="Connection refused"
            ),
        )

        assert (
            test_ssh_connection(
                host="localhost",
                port=2022,
                user="labadmin",
                key_path=Path("/home/user/.ssh/aptl_lab_key"),
            )
            is False
        )

    def test_returns_false_on_exception(self, mocker):
        """Should return False when subprocess raises."""
        from aptl.core.services import test_ssh_connection

        mocker.patch(
            "aptl.core.services.subprocess.run",
            side_effect=FileNotFoundError("ssh not found"),
        )

        assert (
            test_ssh_connection(
                host="localhost",
                port=2022,
                user="labadmin",
                key_path=Path("/home/user/.ssh/aptl_lab_key"),
            )
            is False
        )

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
        # Compare via str(Path(...)) so the separator matches the host: the
        # product passes str(key_path), which is backslashed on Windows and
        # forward-slashed on POSIX. OpenSSH accepts either on its platform.
        assert str(Path("/home/user/.ssh/aptl_lab_key")) in " ".join(cmd)
        assert "-p" in cmd
        assert "2022" in " ".join(str(x) for x in cmd)
        assert "labadmin@localhost" in cmd
