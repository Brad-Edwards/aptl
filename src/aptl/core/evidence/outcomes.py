"""Terminal-outcome and reason-code taxonomy for evidence acquisition
(EXP-010 / issue #752 preflight "Lifecycle and terminal semantics").

The preflight requires **stable diagnostic/reason codes** that distinguish
missing source, startup failure, mid-run loss, truncation, clock skew,
timeout, and finalization failure "even where ACES terminal statuses
coincide". This module owns that vocabulary as an enum plus a small set of
capture-domain diagnostic codes, and the coordinator's overall
:class:`AcquisitionDisposition` mapping. Collector failures are typed outcome
DATA projected into ACES diagnostics — there is no second public exception
hierarchy (preflight / ADR-047 "Error envelope").
"""

from __future__ import annotations

from enum import Enum

from aces_contracts.diagnostics import Diagnostic, Severity

from aptl.utils.redaction import redact

#: Diagnostic domain for evidence-acquisition failures — distinct from
#: EXP-002's ``experiment-admission`` domain so a consumer can tell an
#: admission rejection from a capture/acquisition problem.
EVIDENCE_CAPTURE_DOMAIN = "experiment-capture"

#: Safe stage label for rendering acquisition diagnostics (mirrors
#: ``errors.EXPERIMENT_ADMISSION_STAGE_LABEL``).
EVIDENCE_CAPTURE_STAGE_LABEL = "Experiment evidence acquisition failed"


class CollectorStatus(str, Enum):
    """The distinct per-collector outcomes an adapter must preserve.

    The empty-on-error collapse that ``collectors.py`` / MCP / sidecar
    harvesters use for best-effort work is explicitly forbidden here: a
    conformant adapter never reports :attr:`OK`/:attr:`EMPTY_OK` for a
    failure. :attr:`EMPTY_OK` (a source that legitimately produced zero
    events) is a SUCCESS distinct from every failure below.
    """

    OK = "ok"
    EMPTY_OK = "empty-ok"
    SOURCE_UNAVAILABLE = "source-unavailable"
    STARTUP_FAILURE = "startup-failure"
    MID_RUN_LOSS = "mid-run-loss"
    TRUNCATION = "truncation"
    CLOCK_SKEW = "clock-skew"
    TIMEOUT = "timeout"
    FINALIZATION_FAILURE = "finalization-failure"


#: The statuses that represent a successfully captured (or legitimately
#: empty) collector — everything else is a failure/limitation the coordinator
#: must disposition explicitly.
SUCCESS_STATUSES: frozenset[CollectorStatus] = frozenset(
    {CollectorStatus.OK, CollectorStatus.EMPTY_OK}
)

#: One stable capture-domain diagnostic code per failure status. The raw
#: value is never echoed; only these fixed codes reach a diagnostic.
STATUS_DIAGNOSTIC_CODES: dict[CollectorStatus, str] = {
    CollectorStatus.SOURCE_UNAVAILABLE: "aptl.experiment-capture.source-unavailable",
    CollectorStatus.STARTUP_FAILURE: "aptl.experiment-capture.collector-startup-failure",
    CollectorStatus.MID_RUN_LOSS: "aptl.experiment-capture.mid-run-loss",
    CollectorStatus.TRUNCATION: "aptl.experiment-capture.truncation",
    CollectorStatus.CLOCK_SKEW: "aptl.experiment-capture.clock-skew",
    CollectorStatus.TIMEOUT: "aptl.experiment-capture.timeout",
    CollectorStatus.FINALIZATION_FAILURE: "aptl.experiment-capture.finalization-failure",
}


class AcquisitionDisposition(str, Enum):
    """The overall acquisition outcome for one trial's capture set.

    Maps onto ACES ``ExperimentRunModel`` run/outcome status without creating
    a second controller state machine:

    * :attr:`SEALED_READY` — every required capture succeeded and finalized;
      only this is ready for the #444 sealing handoff.
    * :attr:`COMPLETED_PARTIAL` — a required capture degraded, but the
      degradation was explicitly accepted by policy and carries loss /
      limitation / comparability disclosures.
    * :attr:`INVALIDATED` — a required mid-run loss, unacceptable truncation
      or clock uncertainty, or a required finalization failure; unsealed.
    * :attr:`INCONCLUSIVE` — a required source was unavailable or a collector
      failed to start, aborting the attempt before participant action.
    """

    SEALED_READY = "sealed-ready"
    COMPLETED_PARTIAL = "completed-partial"
    INVALIDATED = "invalidated"
    INCONCLUSIVE = "inconclusive"


def capture_diagnostic(code: str, address: str, message: str) -> Diagnostic:
    """Build one redacted evidence-capture :class:`Diagnostic`.

    Mirrors ``errors.diagnostic`` but fixed to
    :data:`EVIDENCE_CAPTURE_DOMAIN`. ``message`` is passed through
    :func:`redact` as defense in depth; callers construct it from safe,
    non-source-derived text (stable codes, IDs, counts) only.
    """
    return Diagnostic(
        code=code,
        domain=EVIDENCE_CAPTURE_DOMAIN,
        address=address,
        message=redact(message),
        severity=Severity.ERROR,
    )
