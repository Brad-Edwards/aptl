"""Unit tests for the sidecar-owned Kali PTY broker."""

from __future__ import annotations

import base64
import importlib.util
import json
import stat
import sys
from pathlib import Path

import pytest

from aptl_techvault.evidence.techvault import (
    TranscriptFrame,
    transcript_chain_digest,
)

_BROKER_PATH = Path(__file__).parent.parent / "containers/kali-capture/broker.py"


def _load_broker():
    spec = importlib.util.spec_from_file_location("kali_capture_broker", _BROKER_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def broker():
    return _load_broker()


def test_activation_is_create_once_and_idempotent(broker, tmp_path):
    runtime = tmp_path / "runtime"
    first = broker.activate_authority(
        runtime,
        run_id="run-1",
        plan_id="capture-plan-1",
        binding_id="aptl.collector.redteam-session-transcript",
        now=lambda: "2026-09-14T10:00:00Z",
    )
    second = broker.activate_authority(
        runtime,
        run_id="run-1",
        plan_id="capture-plan-1",
        binding_id="aptl.collector.redteam-session-transcript",
        now=lambda: "2026-09-14T10:00:01Z",
    )

    assert first == second
    assert first["activated_at"] == "2026-09-14T10:00:00Z"
    assert stat.S_IMODE((runtime / "authority.json").stat().st_mode) == 0o600


def test_activation_refuses_changed_authority(broker, tmp_path):
    runtime = tmp_path / "runtime"
    broker.activate_authority(
        runtime,
        run_id="run-1",
        plan_id="capture-plan-1",
        binding_id="aptl.collector.redteam-session-transcript",
    )

    with pytest.raises(ValueError, match="authority conflict"):
        broker.activate_authority(
            runtime,
            run_id="run-2",
            plan_id="capture-plan-1",
            binding_id="aptl.collector.redteam-session-transcript",
        )


@pytest.mark.parametrize("value", ["", ".hidden", "../escape", "a/b", "a b"])
def test_activation_rejects_unsafe_ids(broker, tmp_path, value):
    with pytest.raises(ValueError):
        broker.activate_authority(
            tmp_path / "runtime",
            run_id=value,
            plan_id="capture-plan-1",
            binding_id="aptl.collector.redteam-session-transcript",
        )


def test_recorder_writes_ordered_directional_frames_and_chain(broker, tmp_path):
    authority = {
        "run_id": "run-1",
        "plan_id": "capture-plan-1",
        "binding_id": "aptl.collector.redteam-session-transcript",
        "activated_at": "2026-09-14T10:00:00Z",
    }
    instants = iter(
        (
            "2026-09-14T10:00:01Z",
            "2026-09-14T10:00:02Z",
            "2026-09-14T10:00:03Z",
            "2026-09-14T10:00:04Z",
        )
    )
    recorder = broker.SessionRecorder(
        tmp_path / "captures",
        authority,
        session_id="session-1",
        now=lambda: next(instants),
    )
    recorder.append("input", b"whoami\n")
    recorder.append("output", b"kali\r\n")
    recorder.finish("clean-exit")

    exported = broker.export_capture(tmp_path / "captures", authority)
    assert exported["accepted_session_ids"] == ["session-1"]
    session = exported["sessions"][0]
    assert session["close_reason"] == "clean-exit"
    assert [frame["direction"] for frame in session["frames"]] == [
        "input",
        "output",
    ]
    frames = tuple(
        TranscriptFrame(
            sequence=frame["sequence"],
            timestamp=frame["timestamp"],
            direction=frame["direction"],
            data=base64.b64decode(frame["data_b64"], validate=True),
        )
        for frame in session["frames"]
    )
    assert session["final_chain_digest"] == transcript_chain_digest(frames)
    assert (
        stat.S_IMODE(
            (tmp_path / "captures/run-1/sessions/session-1/metadata.json")
            .stat()
            .st_mode
        )
        == 0o600
    )


def test_export_refuses_accepted_session_without_final_metadata(broker, tmp_path):
    authority = {
        "run_id": "run-1",
        "plan_id": "capture-plan-1",
        "binding_id": "aptl.collector.redteam-session-transcript",
        "activated_at": "2026-09-14T10:00:00Z",
    }
    broker.SessionRecorder(tmp_path / "captures", authority, session_id="session-1")

    with pytest.raises(ValueError, match="not finalized"):
        broker.export_capture(tmp_path / "captures", authority)


def test_inner_ssh_command_uses_only_loopback_target_and_preserves_original_as_one_arg(
    broker,
):
    original = "printf '%s' 'hello world'"

    command = broker.inner_ssh_command(original)

    assert command[-2] == "kali@127.0.0.1"
    assert "2222" in command
    assert command[-1] == original
    assert command.count(original) == 1
    assert "StrictHostKeyChecking=yes" in command


def test_session_identity_preserves_mcp_correlation_ids(broker):
    authority = {"run_id": "run-1"}

    session_id = broker.session_identity_from_environment(
        authority,
        {
            "APTL_SESSION_ID": "session-1",
            "APTL_RUN_ID": "run-1",
            "APTL_TRACE_ID": "run-1",
        },
    )

    assert session_id == "session-1"


@pytest.mark.parametrize(
    "environment",
    [
        {
            "APTL_SESSION_ID": "session-1",
            "APTL_RUN_ID": "other-run",
            "APTL_TRACE_ID": "other-run",
        },
        {
            "APTL_SESSION_ID": "session-1",
            "APTL_RUN_ID": "run-1",
            "APTL_TRACE_ID": "other-run",
        },
        {
            "APTL_SESSION_ID": "../unsafe",
            "APTL_RUN_ID": "run-1",
            "APTL_TRACE_ID": "run-1",
        },
    ],
)
def test_session_identity_rejects_invalid_correlation(broker, environment):
    with pytest.raises(ValueError):
        broker.session_identity_from_environment({"run_id": "run-1"}, environment)


def test_broker_rejects_new_session_after_quiesce_closes_admission(
    broker, tmp_path, monkeypatch
):
    runtime = tmp_path / "runtime"
    captures = tmp_path / "captures"
    broker.activate_authority(
        runtime,
        run_id="run-1",
        plan_id="capture-plan-1",
        binding_id="aptl.collector.redteam-session-transcript",
    )
    broker.quiesce(runtime)
    monkeypatch.setattr(broker, "_RUNTIME_ROOT", runtime)
    monkeypatch.setattr(broker, "_CAPTURE_ROOT", captures)
    monkeypatch.setenv("APTL_SESSION_ID", "session-1")
    monkeypatch.setenv("APTL_RUN_ID", "run-1")
    monkeypatch.setenv("APTL_TRACE_ID", "run-1")
    monkeypatch.setattr(broker.signal, "signal", lambda *_args: None)

    with pytest.raises(ValueError, match="admission is closed"):
        broker.run_broker()

    assert not (captures / "run-1/accepted-sessions.jsonl").exists()


def test_broker_source_contains_no_shell_execution_or_legacy_capture_privileges():
    source = _BROKER_PATH.read_text(encoding="utf-8")

    assert "shell=True" not in source
    assert "auditd" not in source
    assert "tcpdump" not in source
    assert "accton" not in source


def test_export_payload_is_json_serializable(broker, tmp_path):
    authority = {
        "run_id": "run-1",
        "plan_id": "capture-plan-1",
        "binding_id": "aptl.collector.redteam-session-transcript",
        "activated_at": "2026-09-14T10:00:00Z",
    }
    recorder = broker.SessionRecorder(
        tmp_path / "captures", authority, session_id="session-1"
    )
    recorder.finish("remote-eof")

    json.dumps(broker.export_capture(tmp_path / "captures", authority))


def test_recorder_discloses_loss_instead_of_exceeding_run_quota(
    broker,
    tmp_path,
    monkeypatch,
):
    authority = {
        "run_id": "run-1",
        "plan_id": "capture-plan-1",
        "binding_id": "aptl.collector.redteam-session-transcript",
        "activated_at": "2026-09-14T10:00:00Z",
    }
    monkeypatch.setattr(broker, "_MAX_CAPTURE_BYTES", 1024)
    recorder = broker.SessionRecorder(
        tmp_path / "captures",
        authority,
        session_id="session-1",
    )

    recorder.append("output", b"one byte exceeds the reserved envelope")
    recorder.finish("clean-exit")

    session = broker.export_capture(tmp_path / "captures", authority)["sessions"][0]
    assert session["frames"] == []
    assert session["loss_count"] == 1


def test_leading_option_command_cannot_configure_inner_ssh(broker):
    import subprocess

    command = broker.inner_ssh_command("-oProxyCommand=printf option-injected")
    result = subprocess.run(
        [command[0], "-G", "-F", "none", *command[1:]],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "proxycommand printf option-injected" not in result.stdout


def _prepare_broker_session(broker, tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    broker.activate_authority(
        runtime,
        run_id="run-1",
        plan_id="plan-1",
        binding_id="aptl.collector.redteam-session-transcript",
    )
    monkeypatch.setattr(broker, "_RUNTIME_ROOT", runtime)
    monkeypatch.setattr(broker, "_CAPTURE_ROOT", tmp_path / "captures")
    for name, value in (
        ("APTL_SESSION_ID", "session-1"),
        ("APTL_RUN_ID", "run-1"),
        ("APTL_TRACE_ID", "run-1"),
    ):
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(broker.signal, "signal", lambda *_args: None)
    return runtime


def test_duplicate_session_preserves_original_pid_registration(
    broker, tmp_path, monkeypatch
):
    runtime = _prepare_broker_session(broker, tmp_path, monkeypatch)
    record = runtime / "sessions" / "session-1.pid"
    record.parent.mkdir(exist_ok=True)
    record.write_text("12345\n")
    with pytest.raises(FileExistsError):
        broker.run_broker()
    assert record.read_text() == "12345\n"


def test_broker_relays_characters_and_interrupt_bytes_and_restores_outer_terminal(
    broker, tmp_path, monkeypatch, mocker
):
    import os
    import pty
    import select
    import termios

    _prepare_broker_session(broker, tmp_path, monkeypatch)
    master, slave = pty.openpty()
    saved = termios.tcgetattr(slave)
    child = mocker.Mock()
    child.poll.return_value = 0
    monkeypatch.setattr(broker.subprocess, "Popen", lambda *_args, **_kwargs: child)
    monkeypatch.setattr(broker.sys, "stdin", mocker.Mock(fileno=lambda: slave))

    def relay(*_args):
        flags = termios.tcgetattr(slave)[3]
        assert not flags & (termios.ICANON | termios.ECHO | termios.ISIG)
        os.write(master, b"x\x03")
        assert select.select([slave], [], [], 1)[0]
        assert os.read(slave, 2) == b"x\x03"
        return 0

    monkeypatch.setattr(broker, "_relay", relay)
    try:
        assert broker.run_broker() == 0
        assert termios.tcgetattr(slave) == saved
    finally:
        os.close(master)
        os.close(slave)
