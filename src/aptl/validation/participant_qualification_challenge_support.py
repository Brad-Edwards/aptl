"""Controlled providers and state retained by boundary qualification checks."""

from __future__ import annotations

import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.backends.raes_participant_apparatus import ParticipantApparatus
from aptl.backends.raes_participant_driver import AptlParticipantControlPlane
from aptl.backends.raes_participant_provider import ParticipantDecisionSolicitation
from aptl.workbench.process import AgentExecutionError, BoundedProcessRunner

if TYPE_CHECKING:
    from raes_processor.models import ExecutionPlan
    from raes_runtime.registry import RuntimeTarget

    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.runstore import RunStorageBackend


class StaticResponseProvider:
    """Controlled invalid provider used only by qualification challenges."""

    implementation_name = "aptl-controlled-challenge-fixture"
    implementation_version = "1.0.0"
    provider_name = "deterministic"
    model = None

    def __init__(self, response: str) -> None:
        """Retain one controlled provider response."""

        self._response = response

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        """Return the controlled malformed or out-of-surface payload."""

        del solicitation
        return self._response


# The bounded run has to time out *after* the fixture has established what the
# challenge measures: a live descendant whose pid was recorded. The runner's
# clock starts at ``Popen``, so this budget has to cover interpreter startup in
# the child, the grandchild spawn, and the pid write -- none of which the
# fixture can front-load, because the pid does not exist until the grandchild
# does.
#
# Measured on a 16-core Linux host, that setup takes p50 22 ms / max 30 ms
# idle and p50 61 ms / max 77 ms with every core busy. With the CPU 2x
# oversubscribed, as a parallel test run on a CI runner can be, the old 0.1 s
# budget lost the race in 9 of 60 trials, recording no pid at all -- which
# reads as a containment failure even though teardown did its job; 5 s lost it
# in 0 of 10. No Darwin measurement was available, and Darwin spawns processes
# more slowly, so this is deliberately generous rather than fitted, and still
# far below the 30 s the child sleeps, so the timeout fires on every run.
#
# The wall cost is paid once per qualification pass and buys a check that
# actually exercises the boundary every time instead of intermittently
# exercising nothing.
_TIMEOUT_CHALLENGE_BUDGET_SECONDS = 5.0


class TimeoutSelectionProvider:
    """Exercise bounded process-group teardown through the provider operation."""

    implementation_name = "aptl-timeout-challenge-fixture"
    implementation_version = "1.0.0"
    provider_name = "deterministic"
    model = None

    def __init__(self) -> None:
        """Initialize child-process observation state."""

        self.child_pid: int | None = None

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        """Start a child process and force the bounded runner to time out."""

        del solicitation
        runner = BoundedProcessRunner()
        with tempfile.TemporaryDirectory(
            prefix="aptl-participant-timeout-"
        ) as directory:
            pid_path = Path(directory) / "child.pid"
            # Write the pid through a temporary file and rename it into place.
            # ``write_text`` truncates on open, so a SIGKILL landing between the
            # open and the write leaves an empty ``child.pid``; parsing that
            # raised ValueError from the ``finally`` below, which the caller's
            # ``except ValueError`` then recorded as a correctly rejected
            # provider operation. A rename is atomic, so the file is either
            # absent or complete.
            program = (
                "import os,pathlib,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import time; time.sleep(30)']);"
                f"tmp=pathlib.Path({str(pid_path)!r}+'.tmp');"
                "tmp.write_text(str(child.pid));"
                f"os.replace(tmp, {str(pid_path)!r});"
                "time.sleep(30)"
            )
            try:
                runner.run(
                    (sys.executable, "-c", program),
                    env={
                        "PATH": "/usr/local/bin:/usr/bin:/bin",
                        "NO_COLOR": "1",
                    },
                    cwd=Path(directory),
                    stdin=b"",
                    timeout_seconds=_TIMEOUT_CHALLENGE_BUDGET_SECONDS,
                    max_output_bytes=4096,
                )
            finally:
                self.child_pid = _recorded_child_pid(pid_path)
        raise AgentExecutionError("timeout challenge did not time out")


def _recorded_child_pid(pid_path: Path) -> int | None:
    """Return the descendant pid the fixture recorded, or nothing.

    Never raises: this runs in a ``finally`` on the timeout path, where an
    exception would displace the ``AgentExecutionError`` the challenge is there
    to observe.
    """

    try:
        recorded = pid_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return int(recorded) if recorded.isdigit() else None


@dataclass
class ChallengeContext:
    """Retain the isolated state for one boundary challenge."""

    run_id: str
    target: RuntimeTarget
    plan: ExecutionPlan
    backend: DeploymentBackend
    control: AptlParticipantControlPlane
    participant_address: str
    behavior_address: str
    apparatus: ParticipantApparatus
    run_store: RunStorageBackend
