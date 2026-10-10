"""Run pending host-side cleanup after an explicit lab volume reset.

``aptl lab stop -v`` removes the project's Docker volumes first; host state
that described those volumes must then be cleared too. Each pending record
names a stable action. APTL-owned actions run here, in core, with whatever
APTL version is installed now. Pack-owned actions dispatch to the one
installed handler the startup seam authorizes for the exact admitted pack.

Every action is idempotent and treats already-absent state as done, so a crash
between an effect and its completion marker is safe: the next reset repeats
the effect and records the completion exactly once. A failed, unauthorized,
unsupported, or unreadable record is never retired or removed; it is reported
with a bounded reason and retried by the next ``aptl lab stop -v`` or
``aptl lab reset``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aptl.core.startup_reset_state import (
    ACTION_CLEAR_WAZUH_ENROLLMENT_BASELINE,
    ACTION_PACK_RESET,
    CleanupAction,
    PendingCleanup,
    complete_pending_cleanup,
    load_pending_cleanup,
)
from aptl.utils.logging import get_logger
from aptl.utils.pathsafe import PathContainmentError, remove_contained_nofollow

log = get_logger("lifecycle-cleanup")

#: APTL-owned realization state recording each Wazuh agent's enrollment id.
#: It describes identities held in the lab's volumes, so an explicit volume
#: reset must clear it with them.
WAZUH_ENROLLMENT_BASELINE_RELPATH = Path(
    ".aptl/realization/wazuh-agent-identity/baseline.json"
)

REASON_HOST_STATE_UNSAFE = "host-state-unsafe"
REASON_HOST_STATE_UNAVAILABLE = "host-state-unavailable"
REASON_COMPLETION_FAILED = "completion-record-failed"
REASON_STATE_UNAVAILABLE = "cleanup-state-unavailable"

RETRY_COMMAND = "aptl lab stop -v --yes"


class CleanupActionError(RuntimeError):
    """A cleanup action did not complete; ``str()`` is a stable reason code."""


@dataclass(frozen=True)
class PendingCleanupFailure:
    """One cleanup record that remains pending after this attempt."""

    record: str
    action: str
    subject: str
    reason: str

    def describe(self) -> str:
        """Return a bounded, secret-free description for operators."""

        return f"{self.action} for {self.subject} ({self.record}): {self.reason}"


@dataclass(frozen=True)
class CleanupReport:
    """Outcome of one pass over the pending cleanup records."""

    completed: int
    pending: tuple[PendingCleanupFailure, ...]

    @property
    def ok(self) -> bool:
        """Return whether no cleanup remains pending."""

        return not self.pending


def clear_wazuh_enrollment_baseline(project_dir: Path) -> None:
    """Remove the enrollment baseline under the lab project, if present."""

    try:
        remove_contained_nofollow(project_dir, WAZUH_ENROLLMENT_BASELINE_RELPATH)
    except PathContainmentError as exc:
        raise CleanupActionError(REASON_HOST_STATE_UNSAFE) from exc
    except OSError as exc:
        raise CleanupActionError(REASON_HOST_STATE_UNAVAILABLE) from exc


def _run_pack_reset(action: CleanupAction, backend: object) -> None:
    """Dispatch one pack-owned reset to its authorized installed handler."""

    from aptl.backends.scenario_startup import (
        ScenarioStartupProviderError,
        StartupHookContext,
        StartupProviderProvenance,
        run_persisted_startup_reset,
    )
    from aptl.core.scenario_bundle import PackIdentity

    try:
        run_persisted_startup_reset(
            PackIdentity(action.pack_id, action.pack_version, action.pack_set_digest),
            StartupProviderProvenance(
                action.distribution,
                action.distribution_version,
                action.entry_point,
            ),
            StartupHookContext(backend),
            action_version=action.action_version,
        )
    except ScenarioStartupProviderError as exc:
        raise CleanupActionError(str(exc)) from None


def _run_action(project_dir: Path, pending: PendingCleanup, backend: object) -> None:
    """Run one supported action; the loader already rejected unknown ones."""

    if pending.action.action == ACTION_CLEAR_WAZUH_ENROLLMENT_BASELINE:
        clear_wazuh_enrollment_baseline(project_dir)
    elif pending.action.action == ACTION_PACK_RESET:
        _run_pack_reset(pending.action, backend)
    else:
        # load_pending_cleanup admits only known actions; refuse defensively.
        raise CleanupActionError("cleanup-action-unsupported")


def _failure(pending: PendingCleanup, reason: str) -> PendingCleanupFailure:
    """Describe one runnable record that stays pending for ``reason``."""

    return PendingCleanupFailure(
        pending.record, pending.action.action, pending.action.subject, reason
    )


def run_pending_cleanup(project_dir: Path, backend: object) -> CleanupReport:
    """Run every pending cleanup record once, retiring only successes.

    The caller must hold the project lifecycle lock and must already have
    removed the project's Docker volumes.
    """

    try:
        runnable, rejected = load_pending_cleanup(project_dir)
    except ValueError:
        log.warning("pending cleanup state could not be read")
        return CleanupReport(
            0,
            (
                PendingCleanupFailure(
                    ".aptl/lifecycle", "cleanup state", "APTL", REASON_STATE_UNAVAILABLE
                ),
            ),
        )
    failures = [
        PendingCleanupFailure(item.record, "unreadable record", "unknown", item.reason)
        for item in rejected
    ]
    completed = 0
    for pending in runnable:
        try:
            _run_action(project_dir, pending, backend)
        except CleanupActionError as exc:
            log.warning(
                "pending cleanup failed: action=%s record=%s reason=%s",
                pending.action.action,
                pending.record,
                exc,
            )
            failures.append(_failure(pending, str(exc)))
            continue
        try:
            complete_pending_cleanup(project_dir, pending)
        except (OSError, ValueError, PathContainmentError) as exc:
            log.warning(
                "pending cleanup completion not recorded: record=%s exception=%s",
                pending.record,
                type(exc).__name__,
            )
            failures.append(_failure(pending, REASON_COMPLETION_FAILED))
            continue
        completed += 1
    return CleanupReport(completed, tuple(failures))


def _count(number: int, noun: str) -> str:
    """Return ``number`` with ``noun`` pluralized for operator messages."""

    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def pending_cleanup_message(
    report: CleanupReport, *, retry_command: str = RETRY_COMMAND
) -> str:
    """Explain host cleanup that remains after verified Docker teardown.

    ``retry_command`` is the command that failed, which the operator reruns.
    """

    remains = "remains" if len(report.pending) == 1 else "remain"
    details = "; ".join(item.describe() for item in report.pending)
    return (
        "[lifecycle-host-cleanup-pending] Docker teardown completed and the "
        "project volumes were removed, but "
        f"{_count(len(report.pending), 'host-side cleanup action')} {remains} "
        f"pending: {details}. The pending records were kept. Resolve the cause, "
        f"then retry with `{retry_command}`."
    )


def docker_teardown_failed_message(
    project_dir: Path, docker_error: str, *, retry_command: str = RETRY_COMMAND
) -> str:
    """Explain a Docker teardown failure and the host cleanup it deferred.

    ``retry_command`` is the command that failed, which the operator reruns.
    """

    try:
        runnable, rejected = load_pending_cleanup(project_dir)
        pending = f"{_count(len(runnable) + len(rejected), 'action')}"
        remains = "remains" if len(runnable) + len(rejected) == 1 else "remain"
        deferred = f"{pending} {remains} pending"
    except ValueError:
        deferred = "the pending cleanup state could not be read"
    return (
        "[lifecycle-docker-teardown-failed] Docker teardown failed: "
        f"{docker_error.rstrip('.')}. Host-side cleanup "
        f"was not attempted; {deferred}. Resolve the Docker failure, then "
        f"retry with `{retry_command}`."
    )


__all__ = [
    "RETRY_COMMAND",
    "WAZUH_ENROLLMENT_BASELINE_RELPATH",
    "CleanupActionError",
    "CleanupReport",
    "PendingCleanupFailure",
    "clear_wazuh_enrollment_baseline",
    "docker_teardown_failed_message",
    "pending_cleanup_message",
    "run_pending_cleanup",
]
