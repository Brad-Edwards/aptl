"""Shared models and outcome helpers for the live scenario gate."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path

from aptl.backends.identity import (
    APTL_RAES_TARGET_NAME,
    APTL_RAES_TARGET_VERSION,
    BackendIdentity,
)
from aptl.validation.scenario_verification import (
    ScenarioIdentity,
    VerificationCheck,
    VerificationReport,
    VerificationStatus,
)

DEFAULT_PROFILE = "full-remote-control-plane"

CATEGORY_RAES_SPECIFICATION = "raes_specification"
CATEGORY_BACKEND_INTERPRETATION = "backend_interpretation"
CATEGORY_BACKEND_INSTANTIATION = "backend_instantiation"
CATEGORY_DEFENSIVE_STACK_READINESS = "defensive_stack_readiness"
CATEGORY_KALI_REACHABILITY = "kali_reachability"
CATEGORY_EVIDENCE_CAPTURE = "evidence_capture"

FAILURE_CATEGORIES: tuple[str, ...] = (
    CATEGORY_RAES_SPECIFICATION,
    CATEGORY_BACKEND_INTERPRETATION,
    CATEGORY_BACKEND_INSTANTIATION,
    CATEGORY_DEFENSIVE_STACK_READINESS,
    CATEGORY_KALI_REACHABILITY,
    CATEGORY_EVIDENCE_CAPTURE,
)

CHECK_CATEGORY: dict[str, str] = {
    "static_prerequisite": CATEGORY_RAES_SPECIFICATION,
    "boot_inputs_match_public_path": CATEGORY_BACKEND_INSTANTIATION,
    "raes_driven_boot": CATEGORY_BACKEND_INSTANTIATION,
    "defensive_stack_readiness": CATEGORY_DEFENSIVE_STACK_READINESS,
    "kali_reachability": CATEGORY_KALI_REACHABILITY,
    "telemetry_evidence_path": CATEGORY_EVIDENCE_CAPTURE,
    "runtime_orchestration_containment": CATEGORY_BACKEND_INSTANTIATION,
    "run_archive_manifest": CATEGORY_EVIDENCE_CAPTURE,
    "scenario_variation": CATEGORY_BACKEND_INTERPRETATION,
}


@dataclass(frozen=True)
class LiveGateCheck(object):
    """One named live-gate check, its failure category, and outcome."""

    name: str
    category: str
    status: VerificationStatus | bool
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Normalize compatibility booleans into the shared status vocabulary."""

        if isinstance(self.status, bool):
            object.__setattr__(
                self,
                "status",
                VerificationStatus.PASSED if self.status else VerificationStatus.FAILED,
            )

    @property
    def passed(self) -> bool:
        """Return whether this check reached the sole successful outcome."""

        return self.status is VerificationStatus.PASSED


def aggregate_status(checks: tuple[LiveGateCheck, ...]) -> VerificationStatus:
    """Return the authoritative aggregate outcome for operational checks."""

    status = VerificationStatus.PASSED
    if any(check.status is VerificationStatus.BLOCKED for check in checks):
        status = VerificationStatus.BLOCKED
    elif any(check.status is VerificationStatus.FAILED for check in checks):
        status = VerificationStatus.FAILED
    return status


def canonical_checks(
    checks: tuple[LiveGateCheck, ...],
) -> tuple[VerificationCheck, ...]:
    """Convert legacy operational checks at the shared report boundary."""

    return tuple(
        VerificationCheck(
            check_id=check.name,
            category=check.category,
            status=check.status,
            diagnostic="; ".join(check.diagnostics),
        )
        for check in checks
    )


def make_live_gate_report(
    scenario: str,
    profile: str,
    run_id: str,
    checks: tuple[LiveGateCheck, ...],
) -> VerificationReport:
    """Compatibility constructor for the one shared verification report shape."""

    return VerificationReport(
        status=aggregate_status(checks),
        scenario=ScenarioIdentity(
            identity=scenario,
            content_digest="sha256:"
            + hashlib.sha256(scenario.encode("utf-8")).hexdigest(),
            source_kind="project-tree",
            version="project-tree",
        ),
        backend=BackendIdentity(
            target_name=APTL_RAES_TARGET_NAME,
            target_version=APTL_RAES_TARGET_VERSION,
            profile=profile,
            provider="unknown",
            transport="unknown",
        ),
        run_id=run_id,
        attempt_id=run_id,
        checks=canonical_checks(checks),
    )


LiveGateReport = make_live_gate_report


@dataclass(frozen=True)
class LiveGateOptions(object):
    """Tunable inputs for the live validation gate."""

    profile: str = DEFAULT_PROFILE
    run_id: str | None = None
    clean_volumes: bool = True
    skip_clean_boot: bool = False
    static_check_imports: bool = False
    event_window_seconds: int = 180
    fixtures_root: Path | None = None
    profiles_root: Path | None = None


@dataclass
class LiveGateState(object):
    """Mutable scratchpad threaded through the live-gate checks."""

    realization_details: dict | None = None
    deployment_spec: object | None = None
    selected_profiles: list[str] = field(default_factory=list)
    snapshot: dict | None = None
    evidence: dict | None = None
    diagnostics_seen: int = 0
