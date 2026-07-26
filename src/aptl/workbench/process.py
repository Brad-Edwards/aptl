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


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the entire child process group, escalating when necessary."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=1)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
