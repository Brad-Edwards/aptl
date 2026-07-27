"""Small result and identity helpers for participant realization execution."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from raes_contracts.contracts import ParticipantActionResultModel
from raes_contracts.participant_binding import (
    ParticipantActionAdmissionRequest,
    ParticipantNativeActionExecution,
)
from raes_contracts.runtime_state import ApplyResult, RuntimeSnapshot


def rejected_native_execution(
    request: ParticipantActionAdmissionRequest,
    snapshot: RuntimeSnapshot,
    episode_id: str,
    message: str,
    *,
    failure_class: str,
) -> ParticipantNativeActionExecution:
    """Return a terminal action failure without mutating runtime state."""

    result = ParticipantActionResultModel(
        status="failed",
        participant_address=request.participant_address,
        episode_id=episode_id,
        action_instance_id=request.action_instance_id,
        action_contract_address=request.action_contract_address,
        observation_point=observation_point(request),
        failure_class=failure_class,
        observations=["bounded action realization was unavailable"],
        diagnostics=[message],
    )
    return ParticipantNativeActionExecution(
        apply_result=ApplyResult(success=True, snapshot=snapshot),
        action_result=result,
        post_state_digest="sha256:unavailable",
    )


def observation_point(request: ParticipantActionAdmissionRequest) -> str:
    """Resolve the action result's participant observation point."""

    if request.temporal_contexts:
        return request.temporal_contexts[0].observation_point
    return f"episode-step:{request.action_instance_id}:terminal"


def mapping_digest(value: Mapping[str, Any]) -> str:
    """Hash normalized governed arguments using canonical JSON coordinates."""

    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def evidence_token(value: str) -> str:
    """Normalize an action identity for an evidence reference."""

    return value.replace(":", "-").replace("/", "-").replace(" ", "-")
