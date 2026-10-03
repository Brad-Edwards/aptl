"""The post-boot guest probe checks both modes without emitting credentials."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _probe():
    path = Path(__file__).resolve().parents[1] / "appliance/guest/seat-privilege-qualification.py"
    spec = importlib.util.spec_from_file_location("seat_privilege_qualification", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("mode", ["event", "password", "passwordless"])
def test_guest_probe_requires_real_mode_invariants(tmp_path: Path, monkeypatch, mode: str) -> None:
    probe = _probe()
    overlay = tmp_path / "overlay"
    desktop = overlay / "desktop"
    (desktop / "initdb").mkdir(parents=True)
    authentication = "none" if mode == "event" else mode
    selected = "event" if mode == "event" else "administrative"
    (overlay / "desktop-privileges.json").write_text(json.dumps({
        "mode": selected, "authentication": authentication,
    }))
    rdp = "chosen password" if mode == "password" else "generated password"
    (desktop / "credentials.json").write_text(json.dumps({"rdp": rdp}))
    (desktop / "initdb/002-seat.sql").write_text(rdp.encode().hex())
    handoff = tmp_path / "run-ready"
    handoff.write_text("ready\n")
    sudoers = tmp_path / "sudoers"
    if mode != "event":
        sudoers.write_text(
            "aptl ALL=(ALL:ALL) NOPASSWD:ALL\n" if mode == "passwordless"
            else "aptl ALL=(ALL:ALL) ALL\n"
        )
    if mode == "password":
        (overlay / "desktop-admin-password").write_text(rdp)
    password_input = tmp_path / "seat-qualification-password"
    password_input.write_text(rdp)
    for name, value in (
        ("MODE", mode), ("OVERLAY", overlay), ("SUDOERS", sudoers),
        ("HANDOFF", handoff), ("PASSWORD_INPUT", password_input),
    ):
        monkeypatch.setattr(probe, name, value)
    monkeypatch.setattr(probe.os, "geteuid", lambda: 0)
    monkeypatch.setattr(probe.subprocess, "run", lambda *_args, **_kwargs: (
        SimpleNamespace(stdout="aptl")
    ))

    def as_aptl(*argv, input_value=None):
        if argv[0] == "/bin/sh":
            return True
        if mode == "passwordless":
            return True
        if mode == "password":
            return input_value == rdp + "\n"
        return False

    monkeypatch.setattr(probe, "_as_aptl", as_aptl)
    checks = probe.check()
    assert all(checks.values()), checks
    assert rdp not in json.dumps(checks)
    if mode == "event":
        monkeypatch.setattr(probe.subprocess, "run", lambda *_args, **_kwargs: (
            SimpleNamespace(stdout="aptl docker")
        ))
        assert probe.check()["groups"] is False
