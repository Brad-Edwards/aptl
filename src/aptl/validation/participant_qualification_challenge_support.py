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

    def __init__(self, response: str) -> None:
        """Retain one controlled provider response."""

        self._response = response

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        """Return the controlled malformed or out-of-surface payload."""

        del solicitation
        return self._response


class TimeoutSelectionProvider:
    """Exercise bounded process-group teardown through the provider operation."""

    implementation_name = "aptl-timeout-challenge-fixture"
    implementation_version = "1.0.0"

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
            program = (
                "import pathlib,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import time; time.sleep(30)']);"
                f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid));"
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
                    timeout_seconds=0.1,
                    max_output_bytes=4096,
                )
            finally:
                if pid_path.exists():
                    self.child_pid = int(pid_path.read_text(encoding="utf-8"))
        raise AgentExecutionError("timeout challenge did not time out")


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
