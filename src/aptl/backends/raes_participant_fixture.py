"""Closed dispatch for truthful synthetic bounded participant operations."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING

from aptl.backends.raes_participant_fixture_blue import BLUE_HANDLERS
from aptl.backends.raes_participant_fixture_core import (
    _OperationContext,
    VerifiedParticipantOperation,
    _ensure_fixture,
    _failed,
    participant_episode_state_dir,
)
from aptl.backends.raes_participant_fixture_green import GREEN_HANDLERS
from aptl.backends.raes_participant_fixture_red import RED_HANDLERS

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

__all__ = [
    "VerifiedParticipantOperation",
    "execute_verified_participant_operation",
    "participant_episode_state_dir",
    "semantic_handler_addresses",
]

_Handler = Callable[[_OperationContext], VerifiedParticipantOperation]
_HANDLERS: Mapping[str, _Handler] = {
    **GREEN_HANDLERS,
    **RED_HANDLERS,
    **BLUE_HANDLERS,
}


def execute_verified_participant_operation(
    *,
    backend: "DeploymentBackend",
    container_by_node: Mapping[str, str],
    action_contract_address: str,
    arguments: Mapping[str, object],
    participant_address: str,
    episode_id: str,
    target_nodes: tuple[str, ...],
) -> VerifiedParticipantOperation:
    """Execute one closed operation and report independently verified facts."""

    handler = _HANDLERS.get(action_contract_address)
    if handler is None:
        return _failed("action has no semantic realization", "unsupported_action")
    context = _OperationContext(
        backend=backend,
        containers=container_by_node,
        state_dir=participant_episode_state_dir(participant_address, episode_id),
        arguments=arguments,
    )
    try:
        _ensure_fixture(context, target_nodes)
        return handler(context)
    except (KeyError, OSError, subprocess.SubprocessError, ValueError) as exc:
        return _failed(
            f"trusted semantic operation failed: {type(exc).__name__}",
            "backend_error",
        )


def semantic_handler_addresses() -> frozenset[str]:
    """Return the exact closed action surface implemented by this backend."""

    return frozenset(_HANDLERS)
