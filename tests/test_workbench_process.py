"""Real-subprocess coverage for bounded workbench invocations (#963).

Every program here is a harmless Python child that sleeps, prints or fills a
pipe. Helpers end themselves after a minute, and each test kills whatever it
started, so a failing assertion cannot leave work running.
"""

from __future__ import annotations

import contextlib
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from aptl.workbench.process import (
    BoundedProcessError,
    BoundedProcessRunner,
    ProcessResult,
    _PipeExchange,
)
from tests.test_participant_workbench_adapter import _poll_until_absent

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="process-group supervision is POSIX-only"
)

_ENVIRONMENT = {"PATH": "/usr/local/bin:/usr/bin:/bin"}
# Cleanup has three one-second phases: SIGTERM grace, reap and stream release.
_CLEANUP_BOUND = 3.0
# Absorbs interpreter start-up and scheduling on loaded CI runners.
_SLACK = 3.0
# Long enough for the parent and its helper to start before the deadline.
_HANG_DEADLINE = 5.0
# Covers interpreter start-up and writing a few pipe buffers of output.
_INPUT_DEADLINE = 3.0
_RESULT = b'{"ok": true}\n'

# Ignores SIGTERM, and publishes its pid by rename only after it does.
_HELPER = """
import os, pathlib, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
staged = pathlib.Path(sys.argv[1] + ".tmp")
staged.write_text(str(os.getpid()))
staged.replace(sys.argv[1])
time.sleep(60)
"""

# Like the helper, but records each SIGTERM in a marker file and keeps running,
# so a test can act while cleanup waits out its grace period.
_TERM_RECORDER = """
import os, pathlib, signal, sys, time
marker = pathlib.Path(sys.argv[1] + ".term")
signal.signal(signal.SIGTERM, lambda *_: marker.touch())
staged = pathlib.Path(sys.argv[1] + ".tmp")
staged.write_text(str(os.getpid()))
staged.replace(sys.argv[1])
time.sleep(60)
"""

# The direct child: start one helper, wait until it is ready, then end as told.
# The helper inherits the child's standard streams either way.
_PARENT = """
import os, pathlib, subprocess, sys, time
helper, pid_file, session, ending = sys.argv[1:]
subprocess.Popen(
    [sys.executable, "-c", helper, pid_file],
    start_new_session=session == "detached",
)
limit = time.monotonic() + 30
while not pathlib.Path(pid_file).exists() and time.monotonic() < limit:
    time.sleep(0.01)
if ending == "flood":
    sys.stdout.buffer.write(b"x" * 65536)
    sys.stdout.flush()
if ending == "exit":
    sys.stderr.write(os.environ.get("CANARY", ""))
    print('{"ok": true}')
    sys.exit(0)
time.sleep(60)
"""


def _parent(
    pid_file: Path, session: str, ending: str, helper: str = _HELPER
) -> tuple[str, ...]:
    return (sys.executable, "-c", _PARENT, helper, str(pid_file), session, ending)


def _run(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    timeout_seconds: float,
    stdin: bytes = b"",
    env: dict[str, str] | None = None,
    max_output_bytes: int = 1024,
) -> ProcessResult:
    """Run the real runner off-thread so that a broken bound fails, not hangs."""

    results: list[ProcessResult] = []
    errors: list[Exception] = []

    def invoke() -> None:
        try:
            results.append(
                BoundedProcessRunner.run(
                    argv,
                    env=env or dict(_ENVIRONMENT),
                    cwd=cwd,
                    stdin=stdin,
                    timeout_seconds=timeout_seconds,
                    max_output_bytes=max_output_bytes,
                )
            )
        except Exception as error:  # re-raised on the test thread below
            errors.append(error)

    worker = threading.Thread(target=invoke, daemon=True)
    worker.start()
    worker.join(timeout_seconds + _CLEANUP_BOUND + 30)
    assert not worker.is_alive(), "the runner outlived its deadline and cleanup"
    if errors:
        raise errors[0]
    return results[0]


def _outcome(
    argv: tuple[str, ...], *, cwd: Path, timeout_seconds: float
) -> ProcessResult | BoundedProcessError:
    try:
        return _run(argv, cwd=cwd, timeout_seconds=timeout_seconds)
    except BoundedProcessError as error:
        return error


def _wait_for(path: Path) -> bool:
    limit = time.monotonic() + 30
    while not path.exists() and time.monotonic() < limit:
        time.sleep(0.01)
    return path.exists()


def _published_pid(pid_file: Path) -> int:
    assert _wait_for(pid_file), "the helper never started"
    return int(pid_file.read_text(encoding="utf-8"))


def _confirm_gone(pid_file: Path) -> bool:
    """Whether the helper disappears; once it has, its pid is forgotten.

    A pid seen gone can be reused by an unrelated process, so the pid file is
    removed and ``_end_helper`` never signals that pid afterwards.
    """

    gone = _poll_until_absent(_published_pid(pid_file))
    if gone:
        pid_file.unlink()
    return gone


def _end_helper(pid_file: Path) -> None:
    """SIGKILL a helper that is still running; a no-op once it is gone."""

    with contextlib.suppress(OSError, ValueError):
        pid = int(pid_file.read_text(encoding="utf-8"))
        os.kill(pid, 0)
        os.kill(pid, signal.SIGKILL)


@pytest.fixture
def outside_service():
    """A long-lived service the invocation does not own, like a lab service."""

    service = subprocess.Popen(
        (sys.executable, "-c", "import time; time.sleep(60)"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    yield service
    service.kill()
    service.wait()


@pytest.mark.parametrize(
    ("program", "stdout_bytes"),
    [
        pytest.param("import time; time.sleep(60)", 0, id="never-reads-input"),
        pytest.param(
            "import sys, time; sys.stdout.buffer.write(b'x' * 262144);"
            " sys.stdout.flush(); time.sleep(60)",
            262144,
            id="fills-output-pipe",
        ),
    ],
)
def test_deadline_covers_launch_input_and_output(
    program: str, stdout_bytes: int, tmp_path: Path
) -> None:
    """Undeliverable input and a full output pipe cannot stall the deadline.

    The regression: the deadline started only after a blocking write of the
    whole input, so a child that never read 8 MiB of it hung the runner
    forever.
    """

    started = time.monotonic()
    with pytest.raises(BoundedProcessError, match="timeout") as raised:
        _run(
            (sys.executable, "-c", program),
            cwd=tmp_path,
            stdin=b"i" * (8 << 20),
            timeout_seconds=_INPUT_DEADLINE,
            max_output_bytes=1 << 20,
        )
    elapsed = time.monotonic() - started

    cleanup = raised.value.cleanup
    assert raised.value.stdout_bytes == stdout_bytes
    assert cleanup.residual == ()
    assert cleanup.seconds < _CLEANUP_BOUND + _SLACK
    assert elapsed - cleanup.seconds < _INPUT_DEADLINE + _SLACK


@pytest.mark.parametrize(
    ("ending", "timeout_seconds", "failure"),
    [
        pytest.param("exit", 30.0, None, id="success"),
        pytest.param("flood", 30.0, "output exceeded", id="error"),
        pytest.param("hang", _HANG_DEADLINE, "timeout", id="timeout"),
    ],
)
def test_cleanup_kills_owned_helpers_and_spares_outside_services(
    ending: str,
    timeout_seconds: float,
    failure: str | None,
    tmp_path: Path,
    outside_service: subprocess.Popen[bytes],
) -> None:
    """A SIGTERM-ignoring helper that outlives its parent never survives.

    The regression: success skipped group cleanup entirely, so the helper and
    the output streams it held outlived every successful request.
    """

    pid_file = tmp_path / "helper.pid"
    try:
        outcome = _outcome(
            _parent(pid_file, "owned", ending),
            cwd=tmp_path,
            timeout_seconds=timeout_seconds,
        )
        if failure is None:
            assert isinstance(outcome, ProcessResult)
            assert (outcome.returncode, outcome.stdout, outcome.stderr) == (
                0,
                _RESULT,
                b"",
            )
        else:
            assert isinstance(outcome, BoundedProcessError)
            assert failure in outcome.reason

        assert outcome.cleanup.residual == ()
        assert outcome.cleanup.seconds < _CLEANUP_BOUND + _SLACK
        assert _confirm_gone(pid_file), "a helper survived"
        assert outside_service.poll() is None, "cleanup reached a service"
    finally:
        _end_helper(pid_file)


def test_capture_after_exit_takes_only_what_is_already_waiting() -> None:
    """A descendant that never stops writing cannot extend the result.

    The pipe holds what the exited child wrote, and ``os.read`` is stubbed to
    keep returning more, the way the pipe looks to its reader while a
    descendant floods it. The regression: capture after the exit read for as
    long as the pipe stayed readable, so such a writer kept extending the
    result until the budget ran out and a successful request failed as an
    output overflow.
    """

    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    os.write(stdout_write, _RESULT)
    exited_child = SimpleNamespace(
        stdout=os.fdopen(stdout_read, "rb"),
        stderr=os.fdopen(stderr_read, "rb"),
        stdin=None,
    )
    try:
        with selectors.DefaultSelector() as selector:
            exchange = _PipeExchange(selector, b"", 1 << 20)
            exchange.attach(exited_child)
            with mock.patch(
                "aptl.workbench.process.os.read",
                side_effect=lambda _fd, size: b"x" * size,
            ):
                within_budget = exchange.drain()
    finally:
        for stream in (exited_child.stdout, exited_child.stderr):
            stream.close()
        os.close(stdout_write)
        os.close(stderr_write)

    assert within_budget, "the flood exhausted the output budget"
    assert (len(exchange.stdout), len(exchange.stderr)) == (len(_RESULT), 0)


def test_cleanup_signals_nothing_once_the_group_is_gone(tmp_path: Path) -> None:
    """A child that left nothing behind is never sent SIGTERM or SIGKILL.

    A group id that is free again can name a stranger's group, so cleanup
    signals only while the signal-0 probe still finds the group.
    """

    with mock.patch("aptl.workbench.process.os.killpg", wraps=os.killpg) as killpg:
        result = _run(
            (sys.executable, "-c", "print('{\"ok\": true}')"),
            cwd=tmp_path,
            timeout_seconds=30.0,
        )

    sent = {call.args[1] for call in killpg.call_args_list}
    assert result.stdout == _RESULT
    assert result.cleanup.residual == ()
    assert sent == {0}, "only the membership probe may reach the group"


def test_cancellation_still_cleans_up_and_notes_the_cleanup(
    tmp_path: Path,
    outside_service: subprocess.Popen[bytes],
) -> None:
    """A KeyboardInterrupt mid-request ends the invocation and propagates."""

    pid_file = tmp_path / "helper.pid"
    argv = _parent(pid_file, "owned", "hang")
    environment = dict(_ENVIRONMENT)

    def interrupt(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    def cancel_once_ready() -> None:
        if _wait_for(pid_file):
            os.kill(os.getpid(), signal.SIGUSR1)

    previous = signal.signal(signal.SIGUSR1, interrupt)
    try:
        threading.Thread(target=cancel_once_ready, daemon=True).start()
        with pytest.raises(KeyboardInterrupt) as raised:
            BoundedProcessRunner.run(
                argv,
                env=environment,
                cwd=tmp_path,
                stdin=b"",
                timeout_seconds=30.0,
                max_output_bytes=1024,
            )

        notes = "\n".join(getattr(raised.value, "__notes__", ()))
        assert "residual: none observed" in notes
        assert _confirm_gone(pid_file), "a helper survived"
        assert outside_service.poll() is None, "cleanup reached a service"
    finally:
        signal.signal(signal.SIGUSR1, previous)
        _end_helper(pid_file)


def test_a_second_interrupt_during_cleanup_still_kills_the_helper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pressing Ctrl-C again while cleanup waits out SIGTERM still escalates.

    The first interrupt cancels the request. The second lands in the grace
    period, after the helper has received SIGTERM and kept running; the grace
    period is lengthened so that the second interrupt cannot miss it. The
    regression: that interrupt abandoned cleanup between SIGTERM and SIGKILL,
    so the helper survived.
    """

    monkeypatch.setattr("aptl.workbench.process._TERM_GRACE_SECONDS", 30.0)
    pid_file = tmp_path / "helper.pid"
    argv = _parent(pid_file, "owned", "hang", helper=_TERM_RECORDER)
    environment = dict(_ENVIRONMENT)
    interrupts: list[float] = []

    def interrupt(_signum: int, _frame: object) -> None:
        interrupts.append(time.monotonic())
        raise KeyboardInterrupt

    def interrupt_twice() -> None:
        if _wait_for(pid_file):
            os.kill(os.getpid(), signal.SIGUSR1)
        if _wait_for(Path(f"{pid_file}.term")):
            os.kill(os.getpid(), signal.SIGUSR1)

    previous = signal.signal(signal.SIGUSR1, interrupt)
    try:
        threading.Thread(target=interrupt_twice, daemon=True).start()
        with pytest.raises(KeyboardInterrupt):
            BoundedProcessRunner.run(
                argv,
                env=environment,
                cwd=tmp_path,
                stdin=b"",
                timeout_seconds=30.0,
                max_output_bytes=1024,
            )

        assert len(interrupts) == 2, "the second interrupt missed cleanup"
        assert _confirm_gone(pid_file), "the helper survived interrupted cleanup"
    finally:
        signal.signal(signal.SIGUSR1, previous)
        _end_helper(pid_file)


def test_escaped_stream_holder_is_reported_without_secrets(tmp_path: Path) -> None:
    """A helper that left the process group is reported, not presumed gone.

    The regression: the runner waited one second per stream reader and then
    returned success while the helper still held the output streams.
    """

    pid_file = tmp_path / "helper.pid"
    argv = _parent(pid_file, "detached", "exit")
    canary = "canary-963-never-reported"
    try:
        with pytest.raises(BoundedProcessError) as raised:
            _run(
                argv,
                cwd=tmp_path,
                timeout_seconds=30.0,
                env={**_ENVIRONMENT, "CANARY": canary},
            )

        error = raised.value
        cleanup = error.cleanup
        assert cleanup.residual == ("output-streams-held",)
        assert cleanup.seconds < _CLEANUP_BOUND + _SLACK
        assert str(error) == (
            "agent process cleanup left residual processes; withheld captured "
            f"output (stdout {len(_RESULT)} bytes, stderr {len(canary)} bytes); "
            f"process group {cleanup.process_group} cleanup took "
            f"{cleanup.seconds:.2f}s; residual: output-streams-held"
        )
        helper = _published_pid(pid_file)
        assert not _poll_until_absent(helper, timeout=0.5), "outside the group"
    finally:
        _end_helper(pid_file)
