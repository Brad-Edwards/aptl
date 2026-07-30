"""Environment preparation and evidence checks for boundary qualification."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING

from raes_contracts.runtime_state import OperationState

from aptl.backends.raes import _plan_scenario
from aptl.backends.raes_participant_apparatus import build_participant_apparatus
from aptl.backends.raes_participant_driver import AptlParticipantControlPlane
from aptl.backends.raes_participant_fixture import participant_episode_state_dir
from aptl.backends.raes_realization import interpret_provisioning_plan
from aptl.core.scenario_bundle import project_tree_bundle
from aptl.validation.participant_agency_readiness import (
    BEHAVIOR_ADDRESSES,
    SCENARIO_RELATIVE_PATH,
    _verify_live_materialization,
)
from aptl.validation.participant_qualification_challenge_support import (
    ChallengeContext,
)
from aptl.validation.participant_qualification_models import (
    ParticipantQualificationCheck,
)

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.runstore import RunStorageBackend

ACTION_EVIDENCE_PATH = "evaluator/participant-action-evidence.jsonl"
BOUNDARY_CHALLENGE_PATH = "evaluator/boundary-challenge.json"


def prepare_challenge_context(
    *,
    project_dir: Path,
    config: AptlConfig,
    run_store: RunStorageBackend,
    run_id: str,
    backend: DeploymentBackend,
    behavior_name: str,
) -> ChallengeContext:
    """Prepare an isolated, exact-state participant episode."""

    run_store.create_run(run_id)
    scenario_path = project_dir / SCENARIO_RELATIVE_PATH
    target, plan = _plan_scenario(
        project_dir,
        config,
        backend,
        scenario_path,
        None,
    )
    if any(diagnostic.is_error for diagnostic in plan.diagnostics):
        raise ValueError("boundary challenge scenario planning failed")
    bundle = project_tree_bundle(project_dir, scenario_path)
    realization = interpret_provisioning_plan(
        plan=plan.provisioning,
        config=config,
        bundle=bundle,
    )
    if _verify_live_materialization(backend, realization):
        raise ValueError("boundary challenge lab materialization is unavailable")
    authority = target.participant_runtime.plan_authority
    if authority is None:
        raise ValueError("boundary challenge plan authority is unavailable")
    authority.bind_runtime_context(
        realization.details(),
        run_store=run_store,
        run_id=run_id,
    )
    behavior_address = BEHAVIOR_ADDRESSES[behavior_name]
    participant_address = plan.model.behavior_specifications[
        behavior_address
    ].participant_addresses[0]
    control = AptlParticipantControlPlane(
        target,
        behavior_specifications=plan.model.behavior_specifications,
    )
    initialization = control.initialize_participant_episode(
        participant_address,
        episode_id=f"{run_id}-{behavior_name}",
    )
    status = control.get_operation(initialization.operation_id)
    if status is None or status.state is not OperationState.SUCCEEDED:
        raise ValueError("boundary challenge episode initialization failed")
    return ChallengeContext(
        run_id=run_id,
        target=target,
        plan=plan,
        backend=backend,
        control=control,
        participant_address=participant_address,
        behavior_address=behavior_address,
        apparatus=build_participant_apparatus(
            participant_address=participant_address,
            implementation_name="aptl-controlled-challenge-fixture",
            implementation_version="1.0.0",
            provider_name="deterministic",
            model=None,
            run_id=run_id,
        ),
        run_store=run_store,
    )


def episode_state_is_absent(context: ChallengeContext) -> bool:
    """Check every realized target for absence of challenge episode state."""

    episode_id = f"{context.run_id}-{_behavior_name(context.behavior_address)}"
    path = participant_episode_state_dir(context.participant_address, episode_id)
    readiness = context.target.participant_runtime.plan_authority.readiness
    absent = readiness is not None
    if readiness is not None:
        for _, container in readiness.target_containers:
            try:
                result = context.backend.container_exec(
                    container,
                    ["test", "!", "-e", path],
                    timeout=10,
                )
            except (OSError, subprocess.SubprocessError):
                result = None
            if (
                not isinstance(result, subprocess.CompletedProcess)
                or result.returncode != 0
            ):
                absent = False
                break
    return absent


def action_evidence_count(context: ChallengeContext) -> int:
    """Count authoritative action-evidence projections for the challenge."""

    path = context.run_store.get_run_path(context.run_id) / ACTION_EVIDENCE_PATH
    return len(path.read_text(encoding="utf-8").splitlines()) if path.exists() else 0


def persist_boundary_check(
    context: ChallengeContext,
    check: ParticipantQualificationCheck,
) -> None:
    """Persist the machine-readable boundary challenge result."""

    context.run_store.write_json(
        context.run_id,
        BOUNDARY_CHALLENGE_PATH,
        {
            "schema": "aptl.participant-boundary-challenge/v1",
            **check.to_payload(),
            "official_capture_started": False,
        },
    )


def wait_until_process_absent(pid: int) -> bool:
    """Wait briefly for the timed-out provider's child process to disappear."""

    deadline = time.monotonic() + 2
    absent = False
    while time.monotonic() < deadline and not absent:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            absent = True
        except PermissionError:
            break
        if not absent:
            time.sleep(0.02)
    return absent


def _behavior_name(behavior_address: str) -> str:
    """Resolve the authored behavior name for an address."""

    return next(
        name
        for name, address in BEHAVIOR_ADDRESSES.items()
        if address == behavior_address
    )
