"""Shared lab lifecycle data classes.

Lives in a leaf module so deployment backends (which are imported
during ``aptl.core.lab`` module load) can reference these types
without importing the full ``aptl.core.lab`` module — that direction
created a circular import (``lab.py`` -> snapshot -> deployment
package -> backend.py / docker_compose.py -> ``aptl.core.lab``
mid-load).

``aptl.core.lab`` re-exports the public names for backward
compatibility, so callers that already import from ``aptl.core.lab``
keep working.
"""

from dataclasses import dataclass, field
from enum import Enum

from aptl.core.execution_boundary import ExecutionBoundaryObservation


class StartupOutcome(str, Enum):
    """Closed set of lab-start outcomes (ADR-030).

    The string values are stable wire identifiers — they appear in
    ``LabActionResponse.outcome`` (API), in CLI output, and in the
    TypeScript mirror at ``web/src/lib/types.ts``. Renaming a value
    breaks the contract; add a new member instead.
    """

    READY = "ready"
    DEGRADED_USABLE = "degraded_usable"
    DEGRADED_UNUSABLE = "degraded_unusable"
    FAILED = "failed"


class DiagnosticImpact(str, Enum):
    """What a startup diagnostic actually affects (ADR-030).

    ``cosmetic`` — no functional or telemetry impact (e.g. an image
    pre-pull skipped; compose will pull on demand later).
    ``telemetry`` — reduces evidence trail / SIEM ingest fidelity but
    scenarios still run.
    ``capability`` — affects scenario or platform features (MCPs not
    built, SOC tools not seeded, MCP credentials not refreshed).
    ``readiness`` — affects SSH or control-plane reach to a lab service
    (red/blue/victim containers unreachable, etc.).

    Mapping rules to ``StartupOutcome`` live in
    :func:`aptl.core.lab.derive_startup_outcome` — keep them in sync.
    """

    COSMETIC = "cosmetic"
    TELEMETRY = "telemetry"
    CAPABILITY = "capability"
    READINESS = "readiness"


class DiagnosticSeverity(str, Enum):
    """Operator-action level for a startup diagnostic (ADR-030).

    Independent of impact: a ``cosmetic`` issue is usually ``info``,
    but a ``capability`` step might be ``warning`` or ``error``
    depending on whether retries are still possible.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class StartupDiagnostic:
    """One structured note emitted by a startup step (ADR-030).

    Step bodies emit these via ``aptl.core.lab._emit_diagnostic`` so the
    redaction / message-shape guardrails live in one place. Free-form
    messages must obey ADR-029 redaction: no .env values, no command
    lines, no raw subprocess stderr — narrow labels and elapsed times
    only.
    """

    step: str
    impact: "DiagnosticImpact"
    severity: "DiagnosticSeverity"
    message: str
    component: str = ""
    operator_action: str = ""


# The project-scoped recovery routes for a range that stays up, with what each
# does to lab data (#952). Start failures and the existing-range refusal name
# the same two commands.
STOP_RECOVERY_ROUTES: tuple[tuple[str, str], ...] = (
    (
        "aptl lab stop",
        "removes the project's containers and networks and keeps its volumes, "
        "so lab data survives",
    ),
    ("aptl lab stop -v", "also removes the volumes and destroys all lab data"),
)


def describe_project_runtime(container_count: int, network_count: int) -> str:
    """Name project runtime counts for an operator, such as ``3 containers``."""

    def count(number: int, noun: str) -> str:
        return f"{number} {noun}" if number == 1 else f"{number} {noun}s"

    return f"{count(container_count, 'container')} and {count(network_count, 'network')}"


@dataclass(frozen=True)
class StartResidue:
    """Project containers and networks a failed lab start left behind (#952).

    The counts are what the backend observed right after the failure, or
    ``None`` when that observation itself failed. ``teardown_requested``
    records ``--teardown-on-failure``; ``torn_down`` is True only when the
    project-scoped stop ran without volume removal and the backend then
    observed no project containers or networks. When a teardown leaves
    something behind, the counts are what remains.
    """

    container_count: int | None
    network_count: int | None
    teardown_requested: bool = False
    torn_down: bool = False

    def describe(self) -> str | None:
        """Return the observed counts for an operator, or ``None`` if unknown."""

        if self.container_count is None or self.network_count is None:
            return None
        return describe_project_runtime(self.container_count, self.network_count)


@dataclass
class LabResult:
    """Result of a lab lifecycle operation.

    ``outcome`` and ``diagnostics`` are the structured surface added by
    ADR-030; ``success`` is retained as a compatibility field and is
    derived from the outcome (True iff outcome is not
    ``StartupOutcome.FAILED``). Callers that only need the boolean keep
    working without changes; callers that need partial-readiness detail
    read ``outcome`` and ``diagnostics``.

    Normalization (``__post_init__``):

    - ``success=False`` with no explicit outcome → ``outcome=FAILED``.
      Otherwise legacy callers (the Docker Compose backend, ``_step_*``
      bodies that return ``LabResult(success=False, error=...)``) would
      surface a failed run as ``outcome=ready``, which both the CLI
      renderer and the API projection would misclassify.
    - ``outcome=FAILED`` with ``success=True`` → ``success=False``.
      ``FAILED`` is the unambiguous signal; the two fields cannot
      legitimately disagree.
    """

    success: bool
    message: str = ""
    error: str = ""
    outcome: "StartupOutcome" = StartupOutcome.READY
    diagnostics: list[StartupDiagnostic] = field(default_factory=list)
    # Published host ports after conflict resolution (host_ports.ResolvedPort),
    # populated on lab start so the CLI can report the real host port each
    # service landed on when a default was already in use. Empty for other ops.
    resolved_ports: list[object] = field(default_factory=list)
    # The selected daemon observed during this exact startup attempt. A missing
    # observation is rendered explicitly as unknown, including on early failure.
    execution_boundary: ExecutionBoundaryObservation | None = None
    # Seconds lab start spent admitting (parsing and planning) the scenario,
    # or None when the attempt never reached admission (#953).
    admission_seconds: float | None = None
    # What a failed start left in the project, or None when it left nothing
    # or failed before it could create anything (#952).
    residue: StartResidue | None = None

    def __post_init__(self) -> None:
        # Make the invariant total: ``outcome`` is the authoritative
        # field; ``success`` is derived (True iff outcome is not FAILED).
        # The one legacy tolerance: a caller that passes only
        # ``success=False`` (without setting outcome) means a failure;
        # promote it to ``outcome=FAILED`` so the boundary stays
        # consistent. After that, ``success`` is always derived so
        # contradictory combinations like
        # ``LabResult(success=False, outcome=DEGRADED_USABLE)`` cannot
        # leak through the DTO (codex review #202 cycle 3).
        if not self.success and self.outcome is StartupOutcome.READY:
            self.outcome = StartupOutcome.FAILED
        self.success = self.outcome is not StartupOutcome.FAILED


@dataclass
class LabStatus:
    """Current status of the lab environment."""

    running: bool
    containers: list[dict[str, object]] = field(default_factory=list)
    error: str = ""
