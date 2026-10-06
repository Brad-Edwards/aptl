"""The post-boot guest probe checks both modes without emitting credentials."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
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


@pytest.mark.parametrize("restart_passes", [True, False])
def test_qualifier_checks_permissions_after_restart(tmp_path: Path, restart_passes: bool) -> None:
    """A permission failure after a real launch sequence must fail qualification."""
    root = Path(__file__).resolve().parents[1]
    binaries = tmp_path / "bin"
    binaries.mkdir()
    fixture = binaries / "fixture"
    fixture.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "name = Path(sys.argv[0]).name\n"
        "args = sys.argv[1:]\n"
        "if name == 'aptl':\n"
        "    seat = Path(args[args.index('--seat-root') + 1])\n"
        "    if args[1] == 'start':\n"
        "        overlay = seat / 'instances/seat-01.qcow2'\n"
        "        overlay.parent.mkdir(parents=True, exist_ok=True)\n"
        "        overlay.touch()\n"
        "    print('{}')\n"
        "elif name == 'virt-customize':\n"
        "    for index, arg in enumerate(args):\n"
        "        if arg == '--copy-in' and 'seat-qualification-password:' in args[index + 1]:\n"
        "            assert Path(args[index + 1].rsplit(':', 1)[0]).is_file()\n"
        "elif name == 'virt-cat':\n"
        "    overlay = Path(args[args.index('-a') + 1])\n"
        "    mode = overlay.parents[1].name\n"
        "    count_file = overlay.with_suffix('.count')\n"
        "    count = int(count_file.read_text()) + 1 if count_file.exists() else 1\n"
        "    count_file.write_text(str(count))\n"
        "    passed = count == 1 or os.environ['RESTART_PASSES'] == '1'\n"
        "    print(json.dumps({'mode': mode, 'passed': passed, 'checks': {'sudo': passed}}))\n"
    )
    fixture.chmod(0o755)
    for name in ("aptl", "virt-customize", "virt-cat"):
        (binaries / name).symlink_to(fixture)
    environment = {
        **os.environ,
        "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
        "APTL_SEAT_CLI": str(binaries / "aptl"),
        "APTL_SEAT_LIBGUESTFS_SUDO": "0",
        "TMPDIR": str(tmp_path),
        "RESTART_PASSES": "1" if restart_passes else "0",
    }
    # Stub only the host KVM prerequisite; the runner and its report validation
    # execute normally against fake external tools, without launching a VM.
    result = subprocess.run(
        ["bash", "-c",
         'test() { if [[ "$2" == /dev/kvm ]]; then return 0; fi; builtin test "$@"; }; '
         'source "$1" "$2"',
         "qualifier-test", str(root / "scripts/appliance/qualify-seat-privileges.sh"),
         "ghcr.io/example/seat@sha256:" + "a" * 64],
        cwd=root, env=environment, text=True, capture_output=True, timeout=30,
    )
    reports = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    if restart_passes:
        assert result.returncode == 0, result.stderr
        assert [(report["mode"], report["phase"]) for report in reports] == [
            (mode, phase)
            for mode in ("event", "password", "passwordless")
            for phase in ("first-boot", "restart")
        ]
    else:
        assert result.returncode != 0
        assert "guest privilege checks failed" in result.stderr
        assert [(report["mode"], report["phase"]) for report in reports] == [
            ("event", "first-boot"),
        ]
