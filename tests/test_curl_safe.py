"""Tests for the shared secret-safe curl helpers.

Subprocess calls are mocked; no real network I/O happens here. The
critical guarantee under test is that credentials never appear in the
``subprocess.run`` argv — only in a 0600 temp file passed via ``-H @file``
(ADR-029), mirroring the pattern already covered for ``curl_json`` in
test_misp_suricata_sync.py.
"""

import os
import stat
import subprocess

import pytest


class TestCurlRequest:
    """Tests for ``aptl.utils.curl_safe.curl_request`` (issue #1002).

    The classification seam readiness owners poll through: it keeps curl's
    numeric exit and the HTTP status apart so a warm-up transport failure is
    distinguishable from a rejected credential, and it leaves severity to the
    caller instead of logging a warning per attempt.
    """

    def _run(
        self,
        monkeypatch,
        *,
        returncode=0,
        stdout="{}\n200",
        side_effect=None,
        **kwargs,
    ):
        from aptl.utils import curl_safe

        captured: dict = {"files": {}}

        def fake_run(cmd, *args, **kw):
            captured["cmd"] = list(cmd)
            captured.setdefault("modes", {})
            for arg in cmd:
                if isinstance(arg, str) and arg.startswith("@"):
                    path = arg[1:]
                    captured["modes"][path] = stat.S_IMODE(os.stat(path).st_mode)
                    with open(path) as fh:
                        captured["files"][path] = fh.read()
            if side_effect is not None:
                raise side_effect
            return type(
                "Result",
                (),
                {"returncode": returncode, "stdout": stdout, "stderr": "secret-ish"},
            )()

        monkeypatch.setattr(curl_safe.subprocess, "run", fake_run)
        outcome = curl_safe.curl_request(
            kwargs.pop("url", "https://localhost:55000/"), **kwargs
        )
        return captured, outcome

    def test_http_response_carries_status_and_parsed_payload(self, monkeypatch):
        captured, outcome = self._run(monkeypatch, stdout='{"error": 0}\n200')
        assert outcome.exit_code == 0
        assert outcome.http_status == 200
        assert outcome.payload == {"error": 0}
        assert outcome.category == "http_response"
        assert "Accept: application/json" in captured["cmd"]
        assert "Content-Type: application/json" not in captured["cmd"]

    def test_http_error_status_is_reported_not_swallowed(self, monkeypatch):
        """No ``-f``: a 401 is an HTTP answer, not a transport failure."""
        captured, outcome = self._run(
            monkeypatch, stdout='{"title": "Unauthorized"}\n401'
        )
        assert "-f" not in captured["cmd"]
        assert "-sf" not in captured["cmd"]
        assert outcome.http_status == 401
        assert outcome.category == "http_response"

    @pytest.mark.parametrize(
        ("returncode", "category"),
        [
            (7, "connection_refused"),
            (28, "timeout"),
            (35, "tls_handshake"),
            (52, "empty_reply"),
            (56, "connection_reset"),
            (60, "curl_error"),
        ],
    )
    def test_no_http_response_is_classified_from_the_exit_code(
        self, monkeypatch, returncode, category
    ):
        _, outcome = self._run(monkeypatch, returncode=returncode, stdout="\n000")
        assert outcome.exit_code == returncode
        assert outcome.http_status is None
        assert outcome.payload is None
        assert outcome.category == category

    def test_timeout_and_spawn_failure_have_no_exit_code(self, monkeypatch):
        _, timed_out = self._run(
            monkeypatch,
            side_effect=subprocess.TimeoutExpired(cmd="curl", timeout=10),
        )
        _, missing = self._run(monkeypatch, side_effect=OSError("curl not found"))
        assert (timed_out.exit_code, timed_out.category) == (None, "request_timeout")
        assert (missing.exit_code, missing.category) == (None, "curl_unavailable")
        assert timed_out.http_status is None
        assert missing.http_status is None

    def test_non_json_body_keeps_status_without_payload(self, monkeypatch):
        _, outcome = self._run(monkeypatch, stdout="<html>ok</html>\n200")
        assert outcome.http_status == 200
        assert outcome.payload is None

    def test_never_logs_a_warning(self, monkeypatch, caplog):
        """Severity belongs to the polling owner, not the transport seam."""
        with caplog.at_level("DEBUG", logger="aptl"):
            self._run(monkeypatch, returncode=35, stdout="\n000")
            self._run(
                monkeypatch,
                side_effect=subprocess.TimeoutExpired(cmd="curl", timeout=10),
            )
        assert [r for r in caplog.records if r.levelno >= 30] == []

    def test_secrets_travel_in_0600_files_never_argv_or_outcome(self, monkeypatch):
        captured, outcome = self._run(
            monkeypatch,
            stdout='{"data": {"token": "bearer-token-value"}}\n200',
            auth_header="Basic c3VwZXItc2VjcmV0",
            body={"password": "body-secret"},
            method="POST",
            insecure=True,
        )
        joined = " ".join(captured["cmd"])
        assert "c3VwZXItc2VjcmV0" not in joined
        assert "body-secret" not in joined
        # While curl runs, each secret file is readable by its owner only.
        if hasattr(os, "fchmod"):
            assert len(captured["modes"]) == 2
            assert set(captured["modes"].values()) == {0o600}
        contents = "".join(captured["files"].values())
        assert "Authorization: Basic c3VwZXItc2VjcmV0" in contents
        assert "body-secret" in contents
        assert all(not os.path.exists(path) for path in captured["files"])
        assert "bearer-token-value" not in repr(outcome)
        assert "secret-ish" not in repr(outcome)
        method_at = captured["cmd"].index("-X")
        assert captured["cmd"][method_at : method_at + 2] == ["-X", "POST"]
        assert "-k" in captured["cmd"]
        assert "Content-Type: application/json" in captured["cmd"]

    def test_temp_files_are_unlinked_on_timeout(self, monkeypatch):
        captured, _ = self._run(
            monkeypatch,
            auth_header="Basic abc",
            side_effect=subprocess.TimeoutExpired(cmd="curl", timeout=10),
        )
        assert captured["files"]
        assert all(not os.path.exists(path) for path in captured["files"])

    def test_ca_cert_path_is_used_when_not_insecure(self, monkeypatch):
        captured, _ = self._run(monkeypatch, ca_cert_path="/etc/aptl/lab-ca.pem")
        assert "--cacert" in captured["cmd"]
        assert "-k" not in captured["cmd"]


class TestBasicAuthHeader:
    """Tests for ``aptl.utils.curl_safe.basic_auth_header``."""

    def test_encodes_credentials_as_basic_token(self):
        import base64

        from aptl.utils.curl_safe import basic_auth_header

        header = basic_auth_header("admin", "SecretPassword")
        assert header.startswith("Basic ")
        token = header.removeprefix("Basic ")
        assert base64.b64decode(token).decode() == "admin:SecretPassword"

    def test_never_exposes_raw_password_in_the_header_value(self):
        from aptl.utils.curl_safe import basic_auth_header

        # The value is base64 of ``user:pass``; the cleartext password must
        # not appear verbatim (that is the whole point of using a header).
        assert "SecretPassword" not in basic_auth_header("admin", "SecretPassword")
