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

    def test_retry_sleep_is_clamped_to_the_remaining_budget(self):
        """No probe may start after the deadline (issue #1002 review).

        With 1s of budget left and a 10s interval, the loop sleeps only that
        second, makes its last probe at the deadline, and then times out,
        instead of sleeping past the deadline and probing again.
        """
        from aptl.core.services import wait_for_service

        check_fn = MagicMock(return_value=False)
        sleeps: list[float] = []

        # start(0); now after probe 1 (1.0); after probe 2 (11.0); after 3 (12.0)
        result = wait_for_service(
            check_fn=check_fn,
            timeout=12,
            interval=10,
            service_name="test-service",
            time_source=iter([0.0, 1.0, 11.0, 12.0]).__next__,
            sleep=sleeps.append,
        )

        assert result.ready is False
        assert check_fn.call_count == 3
        assert sleeps == [10, 1.0]

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


def _outcome(status=None, payload=None, exit_code=0, failure=None):
    from aptl.utils.curl_safe import CurlOutcome

    return CurlOutcome(exit_code, status, payload, failure)


_TOKEN = {"error": 0, "data": {"token": "bounded-token"}}
_RUNNING = {"error": 0, "data": {"affected_items": [{"wazuh-manager": "running"}]}}
_ROOT_401 = {"title": "Unauthorized", "detail": "No authorization token provided"}


def _probe(mocker, *outcomes):
    from aptl.core.services import probe_manager_api

    request = mocker.patch("aptl.core.services.curl_request", side_effect=outcomes)
    result = probe_manager_api(
        url="https://localhost:55000/",
        username="api-user",
        password="api-password",
    )
    return result, request


class TestProbeManagerApi:
    """Phase-classified Wazuh manager API probe (issue #1002).

    Each attempt proves transport with a credential-free request before any
    credential is sent, then authenticates, then checks manager status. The
    probe reports the phase that stopped it and a normalized category so the
    polling owner can tell warm-up from a terminal condition.
    """

    def test_ready_after_all_three_phases(self, mocker):
        result, request = _probe(
            mocker,
            _outcome(401, _ROOT_401),
            _outcome(200, _TOKEN),
            _outcome(200, _RUNNING),
        )

        assert result.ready is True
        assert (result.phase, result.category) == ("ready", "ready")
        assert result.observed_components == ("wazuh-manager",)
        urls = [c.args[0] for c in request.call_args_list]
        assert urls == [
            "https://localhost:55000/",
            "https://localhost:55000/security/user/authenticate",
            "https://localhost:55000/manager/status",
        ]

    def test_transport_phase_sends_no_credentials(self, mocker):
        result, request = _probe(mocker, _outcome(exit_code=35))

        assert request.call_count == 1
        kwargs = request.call_args.kwargs
        assert kwargs.get("auth_header") is None
        assert kwargs["insecure"] is True
        assert result.ready is False
        assert (result.phase, result.category) == ("transport", "tls_handshake")
        assert result.curl_exit == 35
        assert result.http_status is None

    def test_authentication_uses_basic_header_file_not_url(self, mocker):
        _, request = _probe(mocker, _outcome(401, _ROOT_401), _outcome(401))

        auth_call = request.call_args_list[1]
        assert auth_call.kwargs["auth_header"].startswith("Basic ")
        assert auth_call.kwargs["method"] == "POST"
        assert "api-user" not in auth_call.args[0]
        assert "api-password" not in auth_call.args[0]

    def test_manager_status_uses_bearer_token(self, mocker):
        _, request = _probe(
            mocker,
            _outcome(401, _ROOT_401),
            _outcome(200, _TOKEN),
            _outcome(200, _RUNNING),
        )

        assert request.call_args_list[2].kwargs["auth_header"] == "Bearer bounded-token"

    @pytest.mark.parametrize("status", [401, 403])
    def test_rejected_credentials_are_an_authentication_failure(self, mocker, status):
        result, _ = _probe(mocker, _outcome(401, _ROOT_401), _outcome(status))

        assert (result.phase, result.category) == (
            "authentication",
            "credentials_rejected",
        )
        assert result.http_status == status

    def test_transport_failure_after_listener_answered_keeps_its_phase(self, mocker):
        result, _ = _probe(mocker, _outcome(401, _ROOT_401), _outcome(exit_code=56))

        assert (result.phase, result.category) == ("authentication", "connection_reset")
        assert result.curl_exit == 56

    @pytest.mark.parametrize(
        "payload",
        [None, {"error": 1}, {"error": 0, "data": {"token": ""}}, ["not", "a", "map"]],
    )
    def test_missing_token_is_an_invalid_response(self, mocker, payload):
        result, request = _probe(
            mocker, _outcome(401, _ROOT_401), _outcome(200, payload)
        )

        assert (result.phase, result.category) == ("authentication", "invalid_response")
        assert request.call_count == 2

    def test_other_http_status_is_classified_as_http_error(self, mocker):
        result, _ = _probe(mocker, _outcome(401, _ROOT_401), _outcome(500))

        assert (result.phase, result.category) == ("authentication", "http_error")
        assert result.http_status == 500

    @pytest.mark.parametrize(
        "payload", [{"error": 1, "data": {"affected_items": []}}, {"error": 0}, None]
    )
    def test_unready_manager_status_fails_the_status_phase(self, mocker, payload):
        result, _ = _probe(
            mocker,
            _outcome(401, _ROOT_401),
            _outcome(200, _TOKEN),
            _outcome(200, payload),
        )

        assert (result.phase, result.category) == ("manager_status", "not_ready")

    def test_describe_is_bounded_and_secret_free(self, mocker):
        result, _ = _probe(
            mocker,
            _outcome(401, _ROOT_401),
            _outcome(200, _TOKEN),
            _outcome(exit_code=28),
        )

        text = result.describe()
        assert text == "manager_status phase failed: timeout (curl exit 28)"
        assert "bounded-token" not in text + repr(result)
        assert "api-password" not in text + repr(result)

    def test_describe_names_the_http_status(self, mocker):
        result, _ = _probe(mocker, _outcome(401, _ROOT_401), _outcome(401))

        assert result.describe() == (
            "authentication phase failed: credentials_rejected (HTTP 401)"
        )


class TestProbeIndexerApi:
    """Phase-classified Wazuh indexer probe (issue #1002).

    Same contract as the manager probe: a credential-free transport request
    first, then authentication. A listener still starting is classified from
    curl's exit, never collapsed into a status-only "no response".
    """

    def _probe(self, mocker, *outcomes):
        from aptl.core.services import probe_indexer_api

        request = mocker.patch("aptl.core.services.curl_request", side_effect=outcomes)
        result = probe_indexer_api(
            url="https://localhost:9200/",
            username="admin",
            password="indexer-secret",
        )
        return result, request

    def test_ready_after_transport_and_authentication(self, mocker):
        result, request = self._probe(mocker, _outcome(401), _outcome(200))

        assert result.ready is True
        assert [c.args[0] for c in request.call_args_list] == [
            "https://localhost:9200/",
            "https://localhost:9200/",
        ]
        assert request.call_args_list[0].kwargs.get("auth_header") is None
        assert request.call_args_list[1].kwargs["auth_header"].startswith("Basic ")

    def test_tls_warm_up_keeps_curl_exit_and_sends_no_credentials(self, mocker):
        result, request = self._probe(mocker, _outcome(exit_code=35))

        assert request.call_count == 1
        assert request.call_args.kwargs.get("auth_header") is None
        assert (
            result.describe() == "transport phase failed: tls_handshake (curl exit 35)"
        )

    @pytest.mark.parametrize("status", [401, 403])
    def test_rejected_credentials(self, mocker, status):
        """The #623 retained-volume mismatch is a classified authentication failure."""
        result, _ = self._probe(mocker, _outcome(401), _outcome(status))

        assert result.describe() == (
            f"authentication phase failed: credentials_rejected (HTTP {status})"
        )

    def test_other_status_is_an_http_error(self, mocker):
        result, _ = self._probe(mocker, _outcome(401), _outcome(503))

        assert (result.phase, result.category) == ("authentication", "http_error")

    def test_password_never_reaches_subprocess_argv(self, mocker):
        """End-to-end at the real subprocess boundary (ADR-029, #623)."""
        from aptl.core.services import probe_indexer_api
        from aptl.utils import curl_safe

        argv: list[list[str]] = []

        def fake_run(cmd, *args, **kwargs):
            argv.append(list(cmd))
            return MagicMock(returncode=0, stdout="{}\n200", stderr="")

        mocker.patch.object(curl_safe.subprocess, "run", side_effect=fake_run)

        result = probe_indexer_api(
            url="https://localhost:9200",
            username="admin",
            password="super-secret-password",
        )

        assert result.ready is True
        joined = " ".join(" ".join(cmd) for cmd in argv)
        assert "admin" not in joined
        assert "super-secret-password" not in joined


class TestManagerApiWarmUpIsQuiet:
    """Regression for issue #1002 at the real subprocess boundary.

    During a clean boot the realized manager has no healthcheck, so the
    authenticated probe runs while the API is still starting. Docker's
    published-port proxy accepts the connection and closes it when nothing
    listens in the container, which curl reports as exit 35. That is an
    expected warm-up state: the probe must answer "not ready" without logging
    a WARNING per attempt.
    """

    def test_no_https_response_is_not_ready_and_logs_no_warning(self, mocker, caplog):
        from aptl.core.services import probe_manager_api
        from aptl.utils import curl_safe

        mocker.patch.object(
            curl_safe.subprocess,
            "run",
            return_value=MagicMock(returncode=35, stdout="", stderr=""),
        )

        with caplog.at_level("DEBUG", logger="aptl"):
            probe = probe_manager_api(
                url="https://localhost:55000",
                username="api-user",
                password="api-password",
            )

        assert probe.ready is False
        assert (probe.phase, probe.category, probe.curl_exit) == (
            "transport",
            "tls_handshake",
            35,
        )
        assert [r for r in caplog.records if r.levelno >= 30] == []


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

    def test_returns_true_when_a_forced_command_denies_the_session(self, mocker):
        """Reachability is proven by authentication, not by getting a shell.

        Kali's sshd runs the capture wrapper as its `ForceCommand`: a session
        without a control-plane-issued capture capability is denied with exit
        70, because an authenticated participant must never receive an
        unrecorded shell. The probe ran a bare `echo`, so it was denied on every
        boot and the lab was reported `degraded_unusable` while SSH was in fact
        up and authenticating.

        A remote exit status only exists because ssh connected and authenticated
        first. Only ssh's own 255 means the transport or the key failed.
        """
        from aptl.core.services import test_ssh_connection

        mocker.patch(
            "aptl.core.services.subprocess.run",
            return_value=MagicMock(
                returncode=70,
                stdout="",
                stderr="[aptl-wrap-shell] capture capability missing; access denied",
            ),
        )

        assert (
            test_ssh_connection(
                host="localhost",
                port=22,
                user="kali",
                key_path=Path("/home/user/.ssh/aptl_lab_key"),
            )
            is True
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
