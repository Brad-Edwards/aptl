"""Machine-readable models for bounded participant qualification."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class ParticipantQualificationCheck:
    """One machine-readable pre-capture qualification result."""

    check_id: str
    passed: bool
    summary: str
    run_id: str
    evidence_paths: tuple[str, ...] = ()
    details: Mapping[str, object] | None = None

    def to_payload(self) -> dict[str, object]:
        """Serialize one qualification check."""

        return {
            "check_id": self.check_id,
            "passed": self.passed,
            "summary": self.summary,
            "run_id": self.run_id,
            "evidence_paths": list(self.evidence_paths),
            "details": dict(self.details or {}),
        }


@dataclass(frozen=True)
class ParticipantQualificationReport:
    """Complete deterministic and optional installed-provider readiness."""

    passed: bool
    run_id: str
    scenario_source_sha256: str
    compiled_model_sha256: str
    covered_action_contracts: tuple[str, ...]
    checks: tuple[ParticipantQualificationCheck, ...]
    installed_provider: str | None = None
    installed_model: str | None = None
    official_capture_started: bool = False

    def to_payload(self) -> dict[str, object]:
        """Serialize the secret-free qualification report."""

        return {
            "schema": "aptl.participant-agency-qualification/v3",
            "passed": self.passed,
            "run_id": self.run_id,
            "scenario_source_sha256": self.scenario_source_sha256,
            "compiled_model_sha256": self.compiled_model_sha256,
            "covered_action_contracts": list(self.covered_action_contracts),
            "checks": [check.to_payload() for check in self.checks],
            "installed_provider": self.installed_provider,
            "installed_model": self.installed_model,
            "official_capture_started": self.official_capture_started,
        }

    def render(self) -> str:
        """Render a concise qualification summary."""

        lines = [
            (
                "participant agency qualification: "
                + ("PASS" if self.passed else "FAIL")
            ),
            f"run id: {self.run_id}",
            f"scenario source sha256: {self.scenario_source_sha256}",
            f"compiled model sha256: {self.compiled_model_sha256}",
            f"action coverage: {len(self.covered_action_contracts)}/26",
            f"installed provider: {self.installed_provider or 'not requested'}",
            f"installed model: {self.installed_model or 'not applicable'}",
            "official capture: not started",
        ]
        lines.extend(
            f"{check.check_id}: {'PASS' if check.passed else 'FAIL'} — {check.summary}"
            for check in self.checks
        )
        return "\n".join(lines)
