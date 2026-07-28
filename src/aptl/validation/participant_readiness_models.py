"""Request and report models for pre-capture participant readiness."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.backends.raes_participant_provider import ParticipantSelectionProvider

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.runstore import RunStorageBackend


@dataclass(frozen=True)
class ParticipantReadinessRequest:
    """All inputs required for one bounded readiness trajectory."""

    project_dir: Path
    config: AptlConfig
    run_store: RunStorageBackend
    provider_name: str
    behavior_name: str
    turns: int
    run_id: str | None = None
    backend: DeploymentBackend | None = None
    provider_override: ParticipantSelectionProvider | None = None


@dataclass(frozen=True)
class ParticipantReadinessReport:
    """Secret-free result of one pre-capture participant trajectory."""

    passed: bool
    run_id: str
    provider: str
    model: str | None
    behavior: str
    participant_address: str
    selected_actions: tuple[str, ...]
    completed_turns: int
    diagnostics: tuple[str, ...]
    terminal_outcomes: tuple[Mapping[str, object], ...] = ()
    scenario_source_sha256: str = ""
    compiled_model_sha256: str = ""
    episode_terminal_reason: str = ""
    official_capture_started: bool = False

    def to_payload(self) -> dict[str, object]:
        """Serialize the readiness outcome without provider secrets."""

        return {
            "schema": "aptl.participant-agency-readiness/v2",
            "passed": self.passed,
            "run_id": self.run_id,
            "provider": self.provider,
            "model": self.model,
            "behavior": self.behavior,
            "participant_address": self.participant_address,
            "selected_actions": list(self.selected_actions),
            "completed_turns": self.completed_turns,
            "diagnostics": list(self.diagnostics),
            "terminal_outcomes": [dict(outcome) for outcome in self.terminal_outcomes],
            "scenario_source_sha256": self.scenario_source_sha256 or None,
            "compiled_model_sha256": self.compiled_model_sha256 or None,
            "episode_terminal_reason": self.episode_terminal_reason or None,
            "official_capture_started": self.official_capture_started,
        }

    def render(self) -> str:
        """Render a concise human-readable readiness report."""

        status = "PASS" if self.passed else "FAIL"
        actions = ", ".join(self.selected_actions) or "none"
        terminal_statuses = (
            ", ".join(str(outcome["status"]) for outcome in self.terminal_outcomes)
            or "none"
        )
        lines = [
            f"participant agency readiness: {status}",
            f"run id: {self.run_id}",
            f"provider: {self.provider}",
            f"model: {self.model or 'not applicable'}",
            f"behavior: {self.behavior}",
            f"turns: {self.completed_turns}",
            f"selected actions: {actions}",
            f"terminal outcomes: {terminal_statuses}",
            f"scenario source sha256: {self.scenario_source_sha256 or 'unavailable'}",
            f"compiled model sha256: {self.compiled_model_sha256 or 'unavailable'}",
            (
                "episode terminal reason: "
                f"{self.episode_terminal_reason or 'unavailable'}"
            ),
            "official capture: not started",
        ]
        lines.extend(f"diagnostic: {item}" for item in self.diagnostics)
        return "\n".join(lines)
