"""Bounded subprocess execution for the participant workbench.

One invocation is one child started in a new session, so the child and every
descendant that stays in its process group are invocation-owned. The runner
keeps two separate bounds:

- **The deadline** is monotonic and starts before launch. It covers launch,
  standard-input delivery and output capture. Input and output move through
  non-blocking pipes, so a child that never reads its input, a full pipe, or a
  descendant that keeps the output streams open cannot hold the runner past
  it. Output ends when the runner sees the child exit: it keeps what is then
  waiting in the pipes, which is everything the child wrote.
- **Cleanup** follows every outcome: success, error, cancellation or timeout.
  It signals the whole process group while the group still exists, reaps the
  child and waits a bounded time for the output streams to close. It is timed
  and reported apart from the deadline.

Process supervision is not OS isolation. Cleanup reaches the process group and
nothing else, so processes outside it, such as scenario-owned persistent
services, keep their declared lifecycle. A descendant that leaves the group is
out of reach too; cleanup reports one only while it still holds the output
streams. Residue is what cleanup can observe without trusting an errno: a
child it could not reap, or output streams still held open. Reports name what
remains, never argv, environment or output.
"""

from __future__ import annotations

import contextlib
import os
import selectors
import signal
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

_POLL_SECONDS = 0.02
_CHUNK_BYTES = 65536

# Cleanup bounds, each applied once: the SIGTERM grace period for the group,
# reaping the child after SIGKILL, and waiting for the output streams to close.
_TERM_GRACE_SECONDS = 1.0
_REAP_SECONDS = 1.0
_RELEASE_SECONDS = 1.0

_TIMEOUT = "agent request exceeded the configured timeout"
_OVERFLOW = "agent output exceeded the configured limit"
_RESIDUE = "agent process cleanup left residual processes"
_RESIDUAL_AGENT_RUNNING = "agent-process-running"
_RESIDUAL_STREAMS_HELD = "output-streams-held"


class AgentExecutionError(RuntimeError):
    """The installed agent or one of its selected MCP servers failed safely."""


@dataclass(frozen=True)
class ProcessCleanup:
    """How cleanup of one invocation's process group ended.

    Timed apart from the invocation deadline. ``residual`` names what cleanup
    could still observe afterwards; it never carries argv, environment or
    output.
    """

    process_group: int
    seconds: float
    residual: tuple[str, ...] = ()

    def summary(self) -> str:
        """Describe the cleanup without any process content."""

        remaining = ", ".join(self.residual) or "none observed"
        return (
            f"process group {self.process_group} cleanup took "
            f"{self.seconds:.2f}s; residual: {remaining}"
        )


@dataclass(frozen=True)
class ProcessResult:
    """Bounded child result returned by the process runner."""

    returncode: int
    stdout: bytes
    stderr: bytes
    cleanup: ProcessCleanup | None = None


class BoundedProcessError(AgentExecutionError):
    """A bounded invocation stopped early or its cleanup left residue.

    Carries only safe facts: the reason, how much captured output was
    withheld, and the separately timed cleanup.
    """

    def __init__(
        self,
        reason: str,
        *,
        cleanup: ProcessCleanup,
        stdout_bytes: int,
        stderr_bytes: int,
    ) -> None:
        super().__init__(
            f"{reason}; withheld captured output (stdout {stdout_bytes} bytes, "
            f"stderr {stderr_bytes} bytes); {cleanup.summary()}"
        )
        self.reason = reason
        self.cleanup = cleanup
        self.stdout_bytes = stdout_bytes
        self.stderr_bytes = stderr_bytes


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
    """Run a child within one deadline, then clean up its whole process group."""

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
        deadline = time.monotonic() + timeout_seconds
        with selectors.DefaultSelector() as selector:
            exchange = _PipeExchange(selector, stdin, max_output_bytes)
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                exchange.attach(process)
                reason = _supervise(process, exchange, deadline)
            except BaseException as interrupted:
                # Cancellation or an unexpected error still ends the invocation.
                interrupted.add_note(_end_invocation(process, exchange).summary())
                raise
            cleanup = _end_invocation(process, exchange)
        if reason is None and cleanup.residual:
            reason = _RESIDUE
        if reason is not None:
            raise BoundedProcessError(
                reason,
                cleanup=cleanup,
                stdout_bytes=len(exchange.stdout),
                stderr_bytes=len(exchange.stderr),
            )
        return ProcessResult(
            process.returncode,
            bytes(exchange.stdout),
            bytes(exchange.stderr),
            cleanup,
        )


class _PipeExchange:
    """Deliver standard input and capture bounded output without blocking.

    Output streams are registered with their capture buffer as selector data;
    standard input is registered with ``None``.
    """

    def __init__(
        self,
        selector: selectors.BaseSelector,
        stdin: bytes,
        limit: int,
    ) -> None:
        self._selector = selector
        self._pending = memoryview(stdin)
        self._remaining = limit
        self._capturing = True
        self._process: subprocess.Popen[bytes] | None = None
        self.stdout = bytearray()
        self.stderr = bytearray()

    def attach(self, process: subprocess.Popen[bytes]) -> None:
        """Register the child's pipes in non-blocking mode."""

        self._process = process
        for stream, captured in (
            (process.stdout, self.stdout),
            (process.stderr, self.stderr),
        ):
            os.set_blocking(stream.fileno(), False)
            self._selector.register(stream, selectors.EVENT_READ, captured)
        if self._pending:
            os.set_blocking(process.stdin.fileno(), False)
            self._selector.register(process.stdin, selectors.EVENT_WRITE)
        else:
            self.close_input()

    def pump(self, timeout: float) -> bool:
        """Serve every ready pipe once; return False when output overflows."""

        for key, _events in self._selector.select(timeout):
            if key.data is None:
                self._send()
            elif not self._receive(key):
                return False
        return True

    def drain(self) -> bool:
        """Capture what the exited child left in the pipes; False on overflow.

        Reading stops at the bytes waiting now: everything the child wrote, and
        nothing a descendant writes later, so it cannot exhaust the budget.
        """

        for key in self._output_keys():
            if not self._take(key, _pending_bytes(key.fd)):
                return False
        return True

    def stop_capture(self) -> None:
        """Discard output from now on; it is no longer part of the result."""

        self._capturing = False

    def close_input(self) -> None:
        """Close the child's standard input if it is still open."""

        stdin = self._process.stdin if self._process is not None else None
        if stdin is None or stdin.closed:
            return
        self._pending = memoryview(b"")
        with contextlib.suppress(KeyError):
            self._selector.unregister(stdin)
        with contextlib.suppress(OSError):
            stdin.close()

    def release(self, until: float) -> bool:
        """Discard output until its holders close it; return whether one remains."""

        while self._outputs_open() and time.monotonic() < until:
            self.pump(_POLL_SECONDS)
        held = self._outputs_open()
        # Snapshot first: unregistering changes the selector's map.
        registered = [key.fileobj for key in self._selector.get_map().values()]
        for stream in registered:
            self._selector.unregister(stream)
        if self._process is not None:
            for stream in (
                self._process.stdin,
                self._process.stdout,
                self._process.stderr,
            ):
                with contextlib.suppress(OSError):
                    stream.close()
        return held

    def _send(self) -> None:
        """Write the next chunk of standard input, tolerating early exit."""

        try:
            sent = os.write(self._process.stdin.fileno(), self._pending[:_CHUNK_BYTES])
        except BlockingIOError:
            return
        except BrokenPipeError:
            self.close_input()
            return
        self._pending = self._pending[sent:]
        if not self._pending:
            self.close_input()

    def _receive(self, key: selectors.SelectorKey) -> bool:
        """Read one chunk; return False when it does not fit the budget."""

        try:
            chunk = os.read(key.fd, _CHUNK_BYTES)
        except BlockingIOError:
            return True
        if not chunk:
            self._selector.unregister(key.fileobj)
            key.fileobj.close()
        elif self._capturing:
            return self._admit(key.data, chunk)
        return True

    def _take(self, key: selectors.SelectorKey, count: int) -> bool:
        """Admit up to ``count`` waiting bytes of one stream; False on overflow."""

        while count > 0:
            chunk = os.read(key.fd, min(count, _CHUNK_BYTES))
            if not chunk:
                return True
            if not self._admit(key.data, chunk):
                return False
            count -= len(chunk)
        return True

    def _admit(self, captured: bytearray, chunk: bytes) -> bool:
        """Admit bytes within the remaining combined-output budget."""

        admitted = chunk[: self._remaining]
        self._remaining -= len(admitted)
        captured.extend(admitted)
        return len(admitted) == len(chunk)

    def _output_keys(self) -> list[selectors.SelectorKey]:
        """Return the output streams that are still registered."""

        return [
            key for key in self._selector.get_map().values() if key.data is not None
        ]

    def _outputs_open(self) -> bool:
        """Whether any output stream is still open at its other end."""

        return bool(self._output_keys())


def _pending_bytes(fd: int) -> int:
    """Return how many bytes the pipe at ``fd`` holds right now (FIONREAD)."""

    # POSIX-only like the runner, so imported here: this module imports anywhere.
    import fcntl
    import termios

    waiting = fcntl.ioctl(fd, termios.FIONREAD, struct.pack("i", 0))
    return struct.unpack("i", waiting)[0]


def _supervise(
    process: subprocess.Popen[bytes],
    exchange: _PipeExchange,
    deadline: float,
) -> str | None:
    """Exchange input and output until the child exits or a limit is reached."""

    while process.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _TIMEOUT
        if not exchange.pump(min(remaining, _POLL_SECONDS)):
            return _OVERFLOW
    exchange.close_input()
    return None if exchange.drain() else _OVERFLOW


def _end_invocation(
    process: subprocess.Popen[bytes],
    exchange: _PipeExchange,
) -> ProcessCleanup:
    """Clean up the invocation's process group within its own fixed bound."""

    started = time.monotonic()
    exchange.stop_capture()
    exchange.close_input()
    _terminate_process_group(process, exchange)
    held = exchange.release(time.monotonic() + _RELEASE_SECONDS)
    observed = (
        (_RESIDUAL_AGENT_RUNNING, process.returncode is None),
        (_RESIDUAL_STREAMS_HELD, held),
    )
    return ProcessCleanup(
        process_group=process.pid,
        seconds=round(time.monotonic() - started, 3),
        residual=tuple(code for code, present in observed if present),
    )


def _signal_group(pid: int, number: int) -> None:
    """Signal a whole process group, best effort.

    Neither error this can raise is actionable, and neither is evidence about
    what survived. ``ProcessLookupError`` (ESRCH) means the group had no
    member left to signal. ``PermissionError`` (EPERM) means the platform
    could not signal any member: Darwin answers EPERM once a group holds only
    unreaped zombies, because a zombie's credentials are already cleared,
    while Linux still answers 0 for them. Reading either errno as "the group
    is gone" is what made teardown stop early. Escalation below decides from
    a separate probe that trusts only ESRCH, so both are swallowed here.
    """

    try:
        os.killpg(pid, number)
    except (ProcessLookupError, PermissionError):
        pass


def _group_exists(group: int) -> bool:
    """Whether any process, live or not yet reaped, may still hold ``group``.

    Signal 0 delivers nothing, and only ESRCH proves the group is gone: Linux
    answers 0 for an unreaped zombie and Darwin EPERM, which can also mean a
    live member this process may not signal. Cleanup therefore waits for
    orphaned members to be reaped by the process that adopts them.
    """

    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    return True


def _group_ended(process: subprocess.Popen[bytes]) -> bool:
    """Whether the child is reaped and nothing else holds its group id."""

    return process.poll() is not None and not _group_exists(process.pid)


def _await_group_exit(
    process: subprocess.Popen[bytes],
    exchange: _PipeExchange | None,
    until: float,
) -> bool:
    """Wait until the group has ended; return False if ``until`` passes first.

    The child is reaped as soon as it exits, because an unreaped child still
    holds the group id. Output is drained meanwhile, so that a member blocked
    on a full pipe can still act on a signal.
    """

    while not _group_ended(process):
        if time.monotonic() >= until:
            return False
        if exchange is None:
            time.sleep(_POLL_SECONDS)
        else:
            exchange.pump(_POLL_SECONDS)
    return True


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    exchange: _PipeExchange | None = None,
) -> None:
    """Terminate the child's whole process group while the group exists.

    SIGTERM, a bounded grace period, then SIGKILL to the whole group if it has
    not ended, whether or not the direct child has gone, then a bounded reap.
    An interrupted grace period, such as a second KeyboardInterrupt, still
    sends the SIGKILL before the interruption propagates.

    Escalating only when the *direct child* outlived the grace period was the
    defect: a descendant that ignores or outlives SIGTERM stayed alive
    whenever its parent died promptly, because nothing ever escalated to the
    group again. The runner's contract is that a bounded run leaves nothing
    behind, so escalation depends on the group, never on the one process the
    runner happens to hold a handle for.

    Nothing is signalled once the group is proven gone. A remaining member
    keeps the id allocated, so a stranger could get a signal only if the
    kernel reused a freed id in the milliseconds before the next probe.
    """

    if _group_ended(process):
        return
    ended = False
    try:
        _signal_group(process.pid, signal.SIGTERM)
        grace_ends = time.monotonic() + _TERM_GRACE_SECONDS
        ended = _await_group_exit(process, exchange, grace_ends)
    finally:
        if not ended:
            _signal_group(process.pid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=_REAP_SECONDS)
