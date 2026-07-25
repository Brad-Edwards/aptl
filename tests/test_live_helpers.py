"""Unit coverage for live-smoke configuration helpers."""

from __future__ import annotations

import subprocess

from tests import helpers


def test_credential_falls_back_to_generated_project_env(monkeypatch):
    monkeypatch.delenv("MISP_API_KEY", raising=False)
    monkeypatch.setattr(helpers, "PROJECT_ENV", {"MISP_API_KEY": "generated"})

    assert helpers._credential("MISP_API_KEY", "legacy") == "generated"


def test_credential_prefers_explicit_process_environment(monkeypatch):
    monkeypatch.setenv("MISP_API_KEY", "operator")
    monkeypatch.setattr(helpers, "PROJECT_ENV", {"MISP_API_KEY": "generated"})

    assert helpers._credential("MISP_API_KEY", "legacy") == "operator"


def test_curl_json_uses_lab_ca_for_soc_https(tmp_path, monkeypatch):
    ca_path = tmp_path / "lab-ca.pem"
    ca_path.touch()
    monkeypatch.setattr(helpers, "LAB_CA_PATH", str(ca_path))
    run = monkeypatch.setattr
    captured = {}

    def fake_run(cmd, timeout):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

    run(helpers, "run_cmd", fake_run)

    assert helpers.curl_json(f"{helpers.MISP_URL}/events/restSearch") == {}
    assert captured["cmd"][1:3] == ["--cacert", str(ca_path)]
