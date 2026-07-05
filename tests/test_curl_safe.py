"""Tests for the shared secret-safe curl status probe (``curl_status``).

Subprocess calls are mocked; no real network I/O happens here. The
critical guarantee under test is that Basic-auth credentials passed to
``curl_status`` never appear in the ``subprocess.run`` argv — only in a
0600 temp file passed via ``-H @file`` (ADR-029), mirroring the pattern
already covered for ``curl_json`` in test_misp_suricata_sync.py.
"""

import os
import subprocess

import pytest


class TestCurlStatus:
    """Tests for ``aptl.utils.curl_safe.curl_status``."""

    def _run(self, monkeypatch, *, stdout="200", side_effect=None, **kwargs):
        from aptl.utils import curl_safe

        captured: dict = {}

        def fake_run(cmd, *args, **kw):
            captured["cmd"] = list(cmd)
            for arg in cmd:
                if isinstance(arg, str) and arg.startswith("@"):
                    path = arg[1:]
                    captured["header_path"] = path
                    try:
                        with open(path) as fh:
                            captured["header_contents"] = fh.read()
                    except OSError:
                        pass
            if side_effect is not None:
                raise side_effect
            return type(
                "Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""}
            )()

        monkeypatch.setattr(curl_safe.subprocess, "run", fake_run)
        result = curl_safe.curl_status(
            kwargs.pop("url", "https://localhost:9200"), **kwargs
        )
        return captured, result

    def test_returns_200_from_parsed_stdout(self, monkeypatch):
        _, result = self._run(monkeypatch, stdout="200")
        assert result == 200

    def test_returns_401_from_parsed_stdout(self, monkeypatch):
        _, result = self._run(monkeypatch, stdout="401")
        assert result == 401

    def test_returns_none_for_curl_000_no_http_response(self, monkeypatch):
        """curl emits ``000`` in %{http_code} when it never got an HTTP
        response at all (e.g. connection refused) — that must not be
        mistaken for a real status code."""
        _, result = self._run(monkeypatch, stdout="000")
        assert result is None

    def test_returns_none_on_timeout(self, monkeypatch):
        _, result = self._run(
            monkeypatch,
            side_effect=subprocess.TimeoutExpired(cmd="curl", timeout=10),
        )
        assert result is None

    def test_returns_none_on_os_error(self, monkeypatch):
        _, result = self._run(monkeypatch, side_effect=OSError("curl not found"))
        assert result is None

    def test_returns_none_on_non_digit_stdout(self, monkeypatch):
        _, result = self._run(monkeypatch, stdout="")
        assert result is None

    def test_never_raises_on_transport_failure(self, monkeypatch):
        """Never raise — matches the fault-tolerant curl_safe contract.

        The absence of a try/except here is deliberate: if ``curl_status``
        regressed to letting the ``OSError`` propagate, this test would
        error out naturally, which is the failure signal we want.
        """
        _, result = self._run(monkeypatch, side_effect=OSError("boom"))
        assert result is None

    def test_credentials_never_appear_in_argv(self, monkeypatch):
        """Basic-auth credentials MUST NOT be observable via ``ps`` or
        ``/proc/<pid>/cmdline`` — they go into a 0600 temp header file,
        never argv (ADR-029)."""
        captured, result = self._run(
            monkeypatch,
            stdout="200",
            auth=("admin", "super-secret-password"),
            insecure=True,
        )
        cmd = captured["cmd"]
        joined = " ".join(str(a) for a in cmd)
        assert "admin" not in joined
        assert "super-secret-password" not in joined
        assert result == 200

    def test_auth_header_passed_via_at_file(self, monkeypatch):
        captured, _ = self._run(
            monkeypatch, stdout="200", auth=("admin", "secret"), insecure=True
        )
        cmd = captured["cmd"]
        assert "-H" in cmd
        header_args = [a for a in cmd if isinstance(a, str) and a.startswith("@")]
        assert len(header_args) == 1
        header_path = header_args[0][1:]
        assert captured["header_path"] == header_path
        # The header file DOES carry the credentials -- it's just not on argv.
        assert "Authorization: Basic" in captured["header_contents"]

    def test_no_dash_f_flag_so_error_codes_are_returned_verbatim(self, monkeypatch):
        """Unlike curl_json's ``-sf``, curl_status must NOT use ``-f`` --
        otherwise curl would swallow 4xx/5xx and never report the real
        status via %{http_code}."""
        captured, _ = self._run(monkeypatch, stdout="401", auth=("a", "b"))
        cmd = captured["cmd"]
        assert "-f" not in cmd
        assert "-w" in cmd
        assert "%{http_code}" in cmd
        assert "-o" in cmd
        assert os.devnull in cmd

    def test_insecure_sets_dash_k(self, monkeypatch):
        captured, _ = self._run(monkeypatch, stdout="200", insecure=True)
        assert "-k" in captured["cmd"]

    def test_ca_cert_path_sets_dash_dash_cacert(self, monkeypatch):
        captured, _ = self._run(
            monkeypatch, stdout="200", ca_cert_path="/etc/aptl/lab-ca.pem"
        )
        cmd = captured["cmd"]
        assert "--cacert" in cmd
        assert "/etc/aptl/lab-ca.pem" in cmd
        assert "-k" not in cmd

    def test_header_temp_file_is_unlinked_after_call(self, monkeypatch):
        captured, _ = self._run(
            monkeypatch, stdout="200", auth=("admin", "secret"), insecure=True
        )
        header_path = captured["header_path"]
        assert not os.path.exists(header_path)

    def test_header_temp_file_is_unlinked_even_on_timeout(self, monkeypatch):
        captured, result = self._run(
            monkeypatch,
            auth=("admin", "secret"),
            insecure=True,
            side_effect=subprocess.TimeoutExpired(cmd="curl", timeout=10),
        )
        assert result is None
        header_path = captured.get("header_path")
        assert header_path is not None
        assert not os.path.exists(header_path)


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
