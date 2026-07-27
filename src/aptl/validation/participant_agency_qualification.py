"""Full pre-capture qualification for bounded RAES participant agency."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from aptl.backends.raes import _plan_scenario
from aptl.backends.raes_participant_provider import (
    ParticipantDecisionSolicitation,
)
from aptl.core.deployment import get_backend
from aptl.validation.participant_agency_readiness import (
    BEHAVIOR_ADDRESSES,
    SCENARIO_RELATIVE_PATH,
    ParticipantReadinessReport,
    ParticipantReadinessRequest,
    validate_participant_agency_readiness,
)
from aptl.validation.participant_qualification_boundaries import (
    run_boundary_challenge,
)
from aptl.validation.participant_qualification_models import (
    ParticipantQualificationCheck as ParticipantQualificationCheck,
    ParticipantQualificationReport as ParticipantQualificationReport,
)

if TYPE_CHECKING:
    from raes_processor.models import ExecutionPlan

    from aptl.backends.raes_participant_driver import ParticipantPlanAuthority
    from aptl.core.config import AptlConfig
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.runstore import RunStorageBackend

_CONTROL_EVIDENCE_PATH = "evaluator/participant-control-evidence.jsonl"
_ACTION_EVIDENCE_PATH = "evaluator/participant-action-evidence.jsonl"
_BOUNDARY_CHALLENGES = tuple(f"BC-{ordinal:02d}" for ordinal in range(1, 11))
_INSTALLED_BEHAVIORS = (
    "green-normal-session",
    "red-public-service",
    "blue-triage",
)


class _SequentialSelectionProvider:
    """Select each authored candidate in its compiled behavior order."""

    implementation_name = "aptl-deterministic-sequence-fixture"
    implementation_version = "1.0.0"

    def __init__(self) -> None:
        """Initialize one fresh authored-sequence cursor."""

        self._selected_action_addresses: set[str] = set()

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        """Select the first candidate not already used in this behavior."""

        for candidate in solicitation.candidate_selections:
            action_address = candidate.get("action_contract_address")
            if (
                isinstance(action_address, str)
                and action_address not in self._selected_action_addresses
            ):
                self._selected_action_addresses.add(action_address)
                return json.dumps(candidate, separators=(",", ":"), sort_keys=True)
        raise ValueError(
            "deterministic sequence exhausted its delivered action surface"
        )


@dataclass(frozen=True)
class _QualificationContext:
    """Shared exact-plan coordinates for every qualification check."""

    project_dir: Path
    config: AptlConfig
    run_store: RunStorageBackend
    run_id: str
    backend: DeploymentBackend
    plan: ExecutionPlan
    authority: ParticipantPlanAuthority


def validate_participant_agency_qualification(
    *,
    project_dir: Path,
    config: AptlConfig,
    run_store: RunStorageBackend,
    run_id: str | None = None,
    backend: DeploymentBackend | None = None,
    installed_provider: str | None = None,
    installed_turns: int = 8,
) -> ParticipantQualificationReport:
    """Run the complete readiness contract without starting study capture."""

    _validate_qualification_options(installed_provider, installed_turns)
    selected_run_id = run_id or f"participant-qualification-{uuid4().hex}"
    run_store.create_run(selected_run_id)
    deployment = backend or get_backend(config, project_dir)
    target, plan = _plan_scenario(
        project_dir,
        config,
        deployment,
        project_dir / SCENARIO_RELATIVE_PATH,
        None,
    )
    authority = target.participant_runtime.plan_authority
    if authority is None:
        raise ValueError("participant plan authority is unavailable")
    context = _QualificationContext(
        project_dir=project_dir,
        config=config,
        run_store=run_store,
        run_id=selected_run_id,
        backend=deployment,
        plan=plan,
        authority=authority,
    )
    checks = [_static_plan_check(context)]
    if not checks[0].passed:
        return _persist_qualification_report(
            run_store,
            _qualification_report(context, checks, set(), installed_provider),
        )
    positive_checks, covered_actions = _positive_trajectory_checks(context)
    checks.extend(positive_checks)
    checks.append(_action_coverage_check(context, covered_actions))
    checks.extend(
        run_boundary_challenge(
            challenge_id,
            project_dir=project_dir,
            config=config,
            run_store=run_store,
            parent_run_id=selected_run_id,
            backend=deployment,
        )
        for challenge_id in _BOUNDARY_CHALLENGES
    )
    checks.extend(
        _installed_provider_checks(
            context,
            installed_provider,
            installed_turns,
        )
    )
    report = _qualification_report(
        context,
        checks,
        covered_actions,
        installed_provider,
    )
    return _persist_qualification_report(run_store, report)


def _validate_qualification_options(
    installed_provider: str | None,
    installed_turns: int,
) -> None:
    """Reject unsupported installed providers and unbounded turn counts."""

    if installed_provider not in {None, "claude", "codex"}:
        raise ValueError("installed qualification provider must be claude or codex")
    if installed_turns < 1 or installed_turns > 8:
        raise ValueError("installed qualification turns must be between 1 and 8")


def _static_plan_check(
    context: _QualificationContext,
) -> ParticipantQualificationCheck:
    """Require the exact RAES plan to have no blocking diagnostics."""

    blocking = [item for item in context.plan.diagnostics if item.is_error]
    return ParticipantQualificationCheck(
        check_id="STATIC-PLAN",
        passed=not blocking,
        summary="exact RAES plan has no blocking diagnostics",
        run_id=context.run_id,
        details={"blocking_diagnostic_count": len(blocking)},
    )


def _positive_trajectory_checks(
    context: _QualificationContext,
) -> tuple[list[ParticipantQualificationCheck], set[str]]:
    """Execute every authored behavior and collect complete action coverage."""

    checks: list[ParticipantQualificationCheck] = []
    covered_actions: set[str] = set()
    for behavior_name, behavior_address in BEHAVIOR_ADDRESSES.items():
        behavior = context.plan.model.behavior_specifications[behavior_address]
        trajectory = validate_participant_agency_readiness(
            ParticipantReadinessRequest(
                project_dir=context.project_dir,
                config=context.config,
                run_store=context.run_store,
                provider_name="deterministic-sequence",
                behavior_name=behavior_name,
                turns=len(behavior.action_contract_addresses),
                run_id=f"{context.run_id}-positive-{behavior_name}",
                backend=context.backend,
                provider_override=_SequentialSelectionProvider(),
            )
        )
        covered_actions.update(trajectory.selected_actions)
        checks.append(_positive_check(behavior_name, trajectory))
    return checks, covered_actions


def _positive_check(
    behavior_name: str,
    trajectory: ParticipantReadinessReport,
) -> ParticipantQualificationCheck:
    """Require an authored behavior to produce succeeded terminal outcomes."""

    all_succeeded = bool(trajectory.terminal_outcomes) and all(
        outcome["status"] == "succeeded" for outcome in trajectory.terminal_outcomes
    )
    return ParticipantQualificationCheck(
        check_id=f"POSITIVE-{behavior_name.upper()}",
        passed=trajectory.passed and all_succeeded,
        summary=(
            f"authored {behavior_name} action sequence completed with "
            "typed terminal outcomes"
        ),
        run_id=trajectory.run_id,
        evidence_paths=(
            "participant/readiness-report.json",
            "participant/observations.jsonl",
            _CONTROL_EVIDENCE_PATH,
            _ACTION_EVIDENCE_PATH,
        ),
        details={
            "completed_turns": trajectory.completed_turns,
            "selected_actions": list(trajectory.selected_actions),
        },
    )


def _action_coverage_check(
    context: _QualificationContext,
    covered_actions: set[str],
) -> ParticipantQualificationCheck:
    """Require every compiled action to be admitted through RAES v2."""

    compiled_actions = set(context.plan.model.action_contracts)
    return ParticipantQualificationCheck(
        check_id="ACTION-COVERAGE",
        passed=covered_actions == compiled_actions,
        summary="every compiled action was admitted through RAES v2",
        run_id=context.run_id,
        details={
            "covered": len(covered_actions),
            "compiled": len(compiled_actions),
        },
    )


def _installed_provider_checks(
    context: _QualificationContext,
    installed_provider: str | None,
    installed_turns: int,
) -> list[ParticipantQualificationCheck]:
    """Run representative green, red, and blue installed-provider episodes."""

    if installed_provider is None:
        return []
    checks: list[ParticipantQualificationCheck] = []
    for behavior_name in _INSTALLED_BEHAVIORS:
        child_run_id = f"{context.run_id}-{installed_provider}-{behavior_name}"
        trajectory = validate_participant_agency_readiness(
            ParticipantReadinessRequest(
                project_dir=context.project_dir,
                config=context.config,
                run_store=context.run_store,
                provider_name=installed_provider,
                behavior_name=behavior_name,
                turns=installed_turns,
                run_id=child_run_id,
                backend=context.backend,
            )
        )
        checks.append(
            ParticipantQualificationCheck(
                check_id=(
                    f"INSTALLED-{installed_provider.upper()}-{behavior_name.upper()}"
                ),
                passed=trajectory.passed,
                summary=(
                    "installed implementation completed one bounded "
                    f"{behavior_name} episode"
                ),
                run_id=child_run_id,
                evidence_paths=(
                    "participant/readiness-report.json",
                    _CONTROL_EVIDENCE_PATH,
                    _ACTION_EVIDENCE_PATH,
                ),
                details={
                    "completed_turns": trajectory.completed_turns,
                    "terminal_statuses": [
                        outcome["status"] for outcome in trajectory.terminal_outcomes
                    ],
                },
            )
        )
    return checks


def _qualification_report(
    context: _QualificationContext,
    checks: list[ParticipantQualificationCheck],
    covered_actions: set[str],
    installed_provider: str | None,
) -> ParticipantQualificationReport:
    """Build the complete secret-free qualification report."""

    return ParticipantQualificationReport(
        passed=all(check.passed for check in checks),
        run_id=context.run_id,
        scenario_source_sha256=context.authority.scenario_source_sha256,
        compiled_model_sha256=context.authority.compiled_model_sha256,
        covered_action_contracts=tuple(sorted(covered_actions)),
        checks=tuple(checks),
        installed_provider=installed_provider,
    )


def _persist_qualification_report(
    run_store: RunStorageBackend,
    report: ParticipantQualificationReport,
) -> ParticipantQualificationReport:
    """Persist the complete pre-capture qualification report."""

    run_store.write_json(
        report.run_id,
        "participant/readiness-suite-report.json",
        report.to_payload(),
    )
    return report
