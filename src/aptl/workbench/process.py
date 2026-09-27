"""Bounded subprocess execution for the participant workbench."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class AgentExecutionError(RuntimeError):
    """The installed agent or one of its selected MCP servers failed safely."""


@dataclass(frozen=True)
class ProcessResult:
    """Bounded child result returned by the process runner."""

    returncode: int
    stdout: bytes
    stderr: bytes


class ProcessRunner(Protocol):
    """Execute one fixed agent request without a shell."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        env: dict[str, str],
        cwd: Path,
        stdin: bytes,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ProcessResult: ...


class BoundedProcessRunner:
    """Run a child process with bounded combined output and group teardown."""

    @staticmethod
    def run(
        argv: tuple[str, ...],
        *,
        env: dict[str, str],
        cwd: Path,
        stdin: bytes,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ProcessResult:
        """Execute a child with strict time and combined-output limits."""
        if timeout_seconds <= 0 or max_output_bytes <= 0:
            raise AgentExecutionError("agent process limits are invalid")
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout = bytearray()
        stderr = bytearray()
        overflow = threading.Event()
        budget = _OutputBudget(max_output_bytes)
        readers = [
            threading.Thread(
                target=_drain_bounded,
                args=(process.stdout, stdout, budget, overflow),
                daemon=True,
            ),
            threading.Thread(
                target=_drain_bounded,
                args=(process.stderr, stderr, budget, overflow),
                daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()
        _write_stdin(process, stdin)
        reason = _wait_for_process(process, timeout_seconds, overflow)
        if reason is not None:
            _terminate_process_group(process)
        for reader in readers:
            reader.join(timeout=1)
        if reason is not None:
            raise AgentExecutionError(reason)
        return ProcessResult(process.returncode, bytes(stdout), bytes(stderr))


class _OutputBudget:
    """Serialize a strict combined stdout/stderr byte budget."""

    def __init__(self, limit: int) -> None:
        self._remaining = limit
        self._lock = threading.Lock()

    def admit(self, chunk: bytes) -> tuple[bytes, bool]:
        """Admit bytes within the remaining combined-output budget."""
        with self._lock:
            admitted = chunk[: self._remaining]
            self._remaining -= len(admitted)
            return admitted, len(admitted) != len(chunk)


def _drain_bounded(
    pipe: object,
    target: bytearray,
    budget: _OutputBudget,
    overflow: threading.Event,
) -> None:
    """Drain a child stream until EOF or the shared budget is exhausted."""
    if pipe is None:
        return
    while chunk := pipe.read(8192):
        admitted, exceeded = budget.admit(chunk)
        target.extend(admitted)
        if exceeded:
            overflow.set()
            return


def _write_stdin(process: subprocess.Popen[bytes], data: bytes) -> None:
    """Write and close the child's standard input, tolerating early exit."""
    if process.stdin is None:
        return
    try:
        process.stdin.write(data)
        process.stdin.close()
    except BrokenPipeError:
        pass


def _wait_for_process(
    process: subprocess.Popen[bytes],
    timeout_seconds: float,
    overflow: threading.Event,
) -> str | None:
    """Wait for completion and return a bounded-execution failure reason."""
    deadline = time.monotonic() + timeout_seconds
    while process.poll() is None:
        if overflow.wait(0.02):
            return "agent output exceeded the configured limit"
        if time.monotonic() >= deadline:
            return "agent request exceeded the configured timeout"
    return None


def _signal_group(pid: int, number: int) -> None:
    """Signal a whole process group, best effort.

    Neither error this can raise is actionable, and neither is evidence about
    what survived. ``ProcessLookupError`` (ESRCH) means the group had no
    member left to signal. ``PermissionError`` (EPERM) means the platform
    could not signal any member: Darwin answers EPERM where Linux answers
    ESRCH once a group holds only unreaped zombies, because a zombie's
    credentials are already cleared. Reading either errno as "the group is
    gone" is what made teardown stop early. Escalation below runs on a fixed
    schedule instead, so both are swallowed here.
    """

    try:
        os.killpg(pid, number)
    except (ProcessLookupError, PermissionError):
        pass


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the entire child process group, escalating unconditionally.

    SIGTERM, then a bounded grace period for the direct child, then SIGKILL to
    the whole group whether or not the direct child has already gone.

    Escalating only when the *direct child* outlived the grace period was the
    defect: a descendant that ignores or outlives SIGTERM stayed alive
    whenever its parent died promptly, because nothing ever escalated to the
    group again. The runner's contract is that a bounded run leaves nothing
    behind, so the escalation cannot be conditional on the one process the
    runner happens to hold a handle for.

    The SIGKILL is sent before the child is reaped. While any member remains,
    the group id stays allocated and cannot name a stranger's group; once the
    group is empty the signal is a no-op that raises ESRCH or EPERM, both
    swallowed above.
    """

    _signal_group(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    _signal_group(process.pid, signal.SIGKILL)
    process.wait()
