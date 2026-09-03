"""Closed APTL realizations for governed RAES participant actions.

The registry is backend implementation data.  RAES remains the authority for
which action contracts and governed arguments are eligible in an episode;
these records only declare how APTL can realize an already-admitted address.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from raes_contracts.diagnostics import Diagnostic
from raes_contracts.participant_binding import (
    ParticipantActionAdmissionRequest,
    ParticipantNativeActionExecution,
)
from raes_contracts.runtime_state import RuntimeSnapshot

from aptl.backends.raes_participant_fixture import semantic_handler_addresses

if TYPE_CHECKING:
    from aptl.backends.raes_participant_driver import ParticipantPlanAuthority
    from aptl.core.deployment.backend import DeploymentBackend

_AUTHENTICATE_ACTION = "participant.action-contract.authenticate-synthetic-user"
_INSPECT_ALERT_ACTION = "participant.action-contract.inspect-assigned-alert"


class ParticipantRealizationReadinessError(ValueError):
    """The admitted model cannot be truthfully realized by this backend."""


class ParticipantOperation(str, Enum):
    """Closed native operation families used by the TechVault realization."""

    PORTAL_OBSERVATION = "portal-observation"
    SYNTHETIC_SESSION = "synthetic-session"
    CUSTOMER_STATE = "customer-state"
    SUPPORT_STATE = "support-state"
    PUBLIC_HTTP = "public-http"
    SYNTHETIC_AUTH = "synthetic-auth"
    OBJECTIVE_DISCOVERY = "objective-discovery"
    ALERT_OBSERVATION = "alert-observation"
    ALERT_STATE = "alert-state"
    RESPONSE_STATE = "response-state"


@dataclass(frozen=True)
class ParticipantActionRealization:
    """One compiled action address bound to fixed realized TechVault nodes."""

    action_contract_address: str
    operation: ParticipantOperation
    target_nodes: tuple[str, ...]
    mutates_state: bool
    allows_idempotent_stutter: bool
    observer_kind: str


@dataclass(frozen=True)
class ParticipantRealizationReadiness:
    """Validated, complete action realization surface for one admitted model."""

    action_contract_addresses: tuple[str, ...]
    target_containers: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ParticipantRealizationExecution:
    """Native result plus evidence staged until the RAES commit succeeds."""

    native: ParticipantNativeActionExecution
    evaluator_record: Mapping[str, object] | None = None
    participant_record: Mapping[str, object] | None = None


def _action(
    name: str,
    operation: ParticipantOperation,
    nodes: tuple[str, ...],
    *,
    mutates_state: bool = False,
    allows_idempotent_stutter: bool = False,
    observer: str = "bounded-observation",
) -> ParticipantActionRealization:
    """Build the internal operation for the bounded participant workflow."""
    address = f"participant.action-contract.{name}"
    return ParticipantActionRealization(
        action_contract_address=address,
        operation=operation,
        target_nodes=nodes,
        mutates_state=mutates_state,
        allows_idempotent_stutter=allows_idempotent_stutter,
        observer_kind=observer,
    )


_BPA_ACTIONS = (
    _action("inspect-portal", ParticipantOperation.PORTAL_OBSERVATION, ("webapp",)),
    _action(
        "authenticate-synthetic-user",
        ParticipantOperation.SYNTHETIC_SESSION,
        ("webapp", "db"),
        mutates_state=True,
        allows_idempotent_stutter=True,
        observer="session-pre-post",
    ),
    _action("view-permitted-account", ParticipantOperation.CUSTOMER_STATE, ("db",)),
    _action(
        "sign-out-session",
        ParticipantOperation.SYNTHETIC_SESSION,
        ("webapp",),
        mutates_state=True,
        observer="session-pre-post",
    ),
    _action("inspect-own-profile", ParticipantOperation.CUSTOMER_STATE, ("db",)),
    _action(
        "update-own-profile",
        ParticipantOperation.CUSTOMER_STATE,
        ("db",),
        mutates_state=True,
        allows_idempotent_stutter=True,
        observer="profile-and-protected-fields-pre-post",
    ),
    _action(
        "verify-own-state",
        ParticipantOperation.CUSTOMER_STATE,
        ("db", "webapp"),
    ),
    _action("browse-help", ParticipantOperation.PORTAL_OBSERVATION, ("webapp",)),
    _action(
        "create-support-request",
        ParticipantOperation.SUPPORT_STATE,
        ("db",),
        mutates_state=True,
        allows_idempotent_stutter=True,
        observer="support-request-pre-post",
    ),
    _action("inspect-own-support-request", ParticipantOperation.SUPPORT_STATE, ("db",)),
    _action(
        "append-support-note",
        ParticipantOperation.SUPPORT_STATE,
        ("db",),
        mutates_state=True,
        allows_idempotent_stutter=True,
        observer="support-note-pre-post",
    ),
    _action(
        "inspect-public-surface", ParticipantOperation.PUBLIC_HTTP, ("kali", "webapp")
    ),
    _action(
        "probe-permitted-endpoint",
        ParticipantOperation.PUBLIC_HTTP,
        ("kali", "webapp"),
        mutates_state=True,
        allows_idempotent_stutter=True,
        observer="request-and-response-pre-post",
    ),
    _action("inspect-response-metadata", ParticipantOperation.PUBLIC_HTTP, ("kali",)),
    _action(
        "submit-bounded-auth-attempt",
        ParticipantOperation.SYNTHETIC_AUTH,
        ("kali", "webapp", "defender-console"),
        mutates_state=True,
        allows_idempotent_stutter=True,
        observer="authentication-and-telemetry-pre-post",
    ),
    _action("inspect-auth-outcome", ParticipantOperation.SYNTHETIC_AUTH, ("kali",)),
    _action(
        "discover-synthetic-objective",
        ParticipantOperation.OBJECTIVE_DISCOVERY,
        ("kali", "webapp"),
    ),
    _action(
        "retrieve-synthetic-marker",
        ParticipantOperation.OBJECTIVE_DISCOVERY,
        ("kali", "webapp"),
    ),
    _action(
        "list-assigned-alerts",
        ParticipantOperation.ALERT_OBSERVATION,
        ("defender-console",),
    ),
    _action(
        "inspect-assigned-alert",
        ParticipantOperation.ALERT_OBSERVATION,
        ("defender-console",),
    ),
    _action(
        "query-allowed-context",
        ParticipantOperation.ALERT_OBSERVATION,
        ("defender-console",),
    ),
    _action(
        "classify-alert",
        ParticipantOperation.ALERT_STATE,
        ("event-store",),
        mutates_state=True,
        allows_idempotent_stutter=True,
        observer="alert-classification-pre-post",
    ),
    _action(
        "inspect-actor-event-set",
        ParticipantOperation.ALERT_OBSERVATION,
        ("event-store",),
    ),
    _action(
        "correlate-selected-evidence",
        ParticipantOperation.ALERT_OBSERVATION,
        ("event-store", "defender-console"),
    ),
    _action(
        "apply-scoped-response",
        ParticipantOperation.RESPONSE_STATE,
        ("webapp", "event-store"),
        mutates_state=True,
        allows_idempotent_stutter=True,
        observer="response-target-and-unrelated-state-pre-post",
    ),
    _action(
        "verify-response-effect",
        ParticipantOperation.RESPONSE_STATE,
        ("webapp", "event-store"),
    ),
)

BPA_ACTION_REALIZATIONS: Mapping[str, ParticipantActionRealization] = {
    action.action_contract_address: action for action in _BPA_ACTIONS
}

_REQUIRED_PRIOR_ACTIONS: Mapping[str, tuple[str, ...]] = {
    "participant.action-contract.view-permitted-account": (_AUTHENTICATE_ACTION,),
    "participant.action-contract.sign-out-session": (_AUTHENTICATE_ACTION,),
    "participant.action-contract.inspect-own-profile": (_AUTHENTICATE_ACTION,),
    "participant.action-contract.update-own-profile": (_AUTHENTICATE_ACTION,),
    "participant.action-contract.inspect-own-support-request": (
        "participant.action-contract.create-support-request",
    ),
    "participant.action-contract.append-support-note": (
        "participant.action-contract.create-support-request",
    ),
    "participant.action-contract.inspect-response-metadata": (
        "participant.action-contract.probe-permitted-endpoint",
    ),
    "participant.action-contract.inspect-auth-outcome": (
        "participant.action-contract.submit-bounded-auth-attempt",
    ),
    "participant.action-contract.discover-synthetic-objective": (
        "participant.action-contract.probe-permitted-endpoint",
    ),
    "participant.action-contract.retrieve-synthetic-marker": (
        "participant.action-contract.discover-synthetic-objective",
    ),
    _INSPECT_ALERT_ACTION: ("participant.action-contract.list-assigned-alerts",),
    "participant.action-contract.query-allowed-context": (_INSPECT_ALERT_ACTION,),
    "participant.action-contract.classify-alert": (_INSPECT_ALERT_ACTION,),
    "participant.action-contract.inspect-actor-event-set": (_INSPECT_ALERT_ACTION,),
    "participant.action-contract.correlate-selected-evidence": (
        "participant.action-contract.inspect-actor-event-set",
        "participant.action-contract.query-allowed-context",
    ),
    "participant.action-contract.apply-scoped-response": (
        "participant.action-contract.classify-alert",
    ),
    "participant.action-contract.verify-response-effect": (
        "participant.action-contract.apply-scoped-response",
    ),
}
REQUIRED_PRIOR_ACTIONS = _REQUIRED_PRIOR_ACTIONS
_FRESH_REQUIRED_PRIOR_ACTIONS: Mapping[str, tuple[str, ...]] = {
    "participant.action-contract.sign-out-session": (_AUTHENTICATE_ACTION,),
}


def unmet_required_prior_actions(
    action_contract_address: str,
    successful_action_sequence: tuple[str, ...],
) -> tuple[str, ...]:
    """Return missing or consumed successful-observation prerequisites."""

    required = _REQUIRED_PRIOR_ACTIONS.get(action_contract_address, ())
    completed = set(successful_action_sequence)
    unmet = [address for address in required if address not in completed]
    for address in _FRESH_REQUIRED_PRIOR_ACTIONS.get(
        action_contract_address,
        (),
    ):
        prior_index = _last_index(successful_action_sequence, address)
        action_index = _last_index(
            successful_action_sequence,
            action_contract_address,
        )
        if prior_index <= action_index and address not in unmet:
            unmet.append(address)
    return tuple(unmet)


def _last_index(values: tuple[str, ...], expected: str) -> int:
    """Return the last matching index, or -1 when absent."""

    return next(
        (
            index
            for index in range(len(values) - 1, -1, -1)
            if values[index] == expected
        ),
        -1,
    )


def _node_containers(realization_details: Mapping[str, object]) -> dict[str, str]:
    """Handle containers for the bounded participant workflow."""
    raw_nodes = realization_details.get("nodes", ())
    if not isinstance(raw_nodes, list | tuple):
        raise ParticipantRealizationReadinessError(
            "realization details do not carry a node list"
        )
    containers: dict[str, str] = {}
    for raw_node in raw_nodes:
        if not isinstance(raw_node, Mapping):
            continue
        name = raw_node.get("name")
        container = raw_node.get("container_name")
        if isinstance(name, str) and name and isinstance(container, str) and container:
            containers[name] = container
    return containers


def validate_participant_realizations(
    runtime_model: object,
    realization_details: Mapping[str, object],
    *,
    registry: Mapping[str, ParticipantActionRealization],
) -> ParticipantRealizationReadiness:
    """Fail closed unless every compiled action has one usable typed handler."""

    compiled, compiled_addresses = _compiled_action_surface(runtime_model, registry)
    _validate_semantic_handler_surface(compiled_addresses)
    _validate_semantic_claims(compiled, compiled_addresses)
    containers = _node_containers(realization_details)
    action_nodes = {
        node
        for address in compiled_addresses
        for node in registry[address].target_nodes
    }
    missing_nodes = sorted(action_nodes - set(containers))
    if missing_nodes:
        raise ParticipantRealizationReadinessError(
            "participant action targets are not realized: " + ", ".join(missing_nodes)
        )
    return ParticipantRealizationReadiness(
        action_contract_addresses=compiled_addresses,
        target_containers=tuple(
            (node, containers[node]) for node in sorted(action_nodes)
        ),
    )


def _compiled_action_surface(
    runtime_model: object,
    registry: Mapping[str, ParticipantActionRealization],
) -> tuple[Mapping[str, object], tuple[str, ...]]:
    """Validate registry equality and return the compiled action surface."""

    compiled = getattr(runtime_model, "action_contracts", None)
    if not isinstance(compiled, Mapping):
        raise ParticipantRealizationReadinessError(
            "admitted runtime model does not carry action contracts"
        )
    compiled_addresses = tuple(sorted(str(address) for address in compiled))
    missing = tuple(
        address for address in compiled_addresses if address not in registry
    )
    if missing:
        raise ParticipantRealizationReadinessError(
            "missing participant action realizations: " + ", ".join(missing)
        )
    extras = tuple(sorted(set(registry) - set(compiled_addresses)))
    if extras:
        raise ParticipantRealizationReadinessError(
            "participant realization registry exceeds the admitted action surface: "
            + ", ".join(extras)
        )
    return compiled, compiled_addresses


def _validate_semantic_handler_surface(
    compiled_addresses: tuple[str, ...],
) -> None:
    """Require semantic handler equality with the compiled action surface."""

    semantic_handlers = semantic_handler_addresses()
    missing_handlers = tuple(
        address for address in compiled_addresses if address not in semantic_handlers
    )
    extra_handlers = tuple(sorted(semantic_handlers - set(compiled_addresses)))
    if missing_handlers or extra_handlers:
        raise ParticipantRealizationReadinessError(
            "participant semantic handler surface does not equal the admitted "
            "action surface"
        )


def _validate_semantic_claims(
    compiled: Mapping[str, object],
    compiled_addresses: tuple[str, ...],
) -> None:
    """Require each compiled action to declare observable semantic claims."""

    for address in compiled_addresses:
        contract = compiled[address]
        precondition_ids = {
            str(item.get("precondition_id"))
            for item in contract.spec.get("preconditions", ())
            if isinstance(item, Mapping)
        }
        effect_ids = {
            str(item.get("effect_id"))
            for item in contract.spec.get("effects", ())
            if isinstance(item, Mapping)
        }
        if not precondition_ids or not effect_ids:
            raise ParticipantRealizationReadinessError(
                f"participant action {address} lacks verifiable semantic claims"
            )


def execute_verified_participant_operation(
    **coordinates: object,
) -> object:
    """Retain the patchable semantic-operation seam used by runtime tests."""

    from aptl.backends.raes_participant_fixture import (
        execute_verified_participant_operation as execute,
    )

    return execute(**coordinates)


def execute_participant_realization(
    *,
    request: ParticipantActionAdmissionRequest,
    snapshot: RuntimeSnapshot,
    episode_id: str,
    authority: ParticipantPlanAuthority,
    deployment_backend: DeploymentBackend,
) -> ParticipantRealizationExecution:
    """Execute one RAES-admitted action through its closed native handler."""

    from aptl.backends.raes_participant_realization_execution import (
        execute_participant_realization as execute,
    )

    return execute(
        request=request,
        snapshot=snapshot,
        episode_id=episode_id,
        authority=authority,
        deployment_backend=deployment_backend,
    )


def _persist_action_evidence(
    authority: ParticipantPlanAuthority,
    *,
    evaluator_record: Mapping[str, object],
    participant_record: Mapping[str, object],
) -> tuple[Diagnostic, ...]:
    """Publish an atomic source record, then its recoverable JSONL projections."""

    from aptl.backends.raes_participant_realization_execution import (
        persist_action_evidence,
    )

    return persist_action_evidence(
        authority,
        evaluator_record=evaluator_record,
        participant_record=participant_record,
    )
