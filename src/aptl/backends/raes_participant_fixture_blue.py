"""Security-analyst operations for the bounded participant fixture."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from aptl.backends.raes_participant_fixture_core import (
    _ASSESSOR_CONTAINMENT,
    _RESPONSE_LATEST,
    _WEBAPP_ASSESSOR_ACCESS,
    _WEBAPP_BENIGN_ACCESS,
    _OperationContext,
    VerifiedParticipantOperation,
    _combined_values,
    _failed,
    _many,
    _scalar,
    _values,
    _verified,
    _write_value,
)


def _list_alerts(context: _OperationContext) -> VerifiedParticipantOperation:
    """List alerts for the bounded participant workflow."""
    if _scalar(context.arguments, "queue") != "alerts.blue.assigned":
        return _failed("alert queue is outside the realized domain")
    limit = int(_scalar(context.arguments, "limit"))
    if not 1 <= limit <= 3:
        return _failed("alert limit is outside the realized domain")
    names = ("alert.auth-001", "alert.actor-001", "alert.response-001")[:limit]
    pre = _values(context, "defender-console", names)
    post = _values(context, "defender-console", names)
    return _verified(
        bool(post) and all(value.endswith("|assigned") for value in post.values()),
        "assigned synthetic alert queue read from the defender target",
        pre,
        post,
        "queue-assigned",
        "alert-list-observed",
    )


def _inspect_alert(context: _OperationContext) -> VerifiedParticipantOperation:
    """Inspect alert for the bounded participant workflow."""
    alert = _scalar(context.arguments, "alert")
    fields = _many(context.arguments, "fields")
    name = alert.removeprefix("alerts.")
    field_names = (
        "event-type",
        "actor",
        "source",
        "target",
        "timestamp",
        "status",
    )
    if name not in {"auth-001", "actor-001", "response-001"} or (
        not fields
        or len(fields) > 4
        or len(set(fields)) != len(fields)
        or not set(fields) <= set(field_names)
    ):
        return _failed("alert selection is outside the realized domain")
    pre_raw = _values(context, "defender-console", (f"alert.{name}",))
    post_raw = _values(context, "defender-console", (f"alert.{name}",))
    try:
        pre_values = dict(
            zip(
                field_names,
                pre_raw[f"defender-console.alert.{name}"].split("|"),
                strict=True,
            )
        )
        post_values = dict(
            zip(
                field_names,
                post_raw[f"defender-console.alert.{name}"].split("|"),
                strict=True,
            )
        )
    except ValueError:
        return _failed("stored alert does not have the realized field shape")
    pre = {
        f"defender-console.alert.{name}.{field}": pre_values[field] for field in fields
    }
    post = {
        f"defender-console.alert.{name}.{field}": post_values[field] for field in fields
    }
    return _verified(
        post_values["status"] == "assigned"
        and set(post) == {f"defender-console.alert.{name}.{field}" for field in fields},
        "selected assigned alert fields read from the defender target",
        pre,
        post,
        "alert-assigned",
        "alert-observed",
    )


def _query_context(context: _OperationContext) -> VerifiedParticipantOperation:
    """Query context for the bounded participant workflow."""
    reference = _scalar(context.arguments, "context")
    if reference not in {
        "context.host.webapp",
        "context.identity.benign-customer",
        "context.identity.synthetic-assessor",
    }:
        return _failed("context reference is outside the realized domain")
    pre = _values(context, "defender-console", (reference,))
    post = _values(context, "defender-console", (reference,))
    return _verified(
        bool(next(iter(post.values()))),
        "authorized synthetic context read from the defender target",
        pre,
        post,
        "context-authorized",
        "context-observed",
    )


def _classify_alert(context: _OperationContext) -> VerifiedParticipantOperation:
    """Classify alert for the bounded participant workflow."""
    alert = _scalar(context.arguments, "alert")
    classification = _scalar(context.arguments, "classification")
    confidence = _scalar(context.arguments, "confidence")
    if (
        alert not in {"alerts.auth-001", "alerts.actor-001", "alerts.response-001"}
        or classification not in {"benign", "suspicious", "confirmed"}
        or confidence not in {"low", "medium", "high"}
    ):
        return _failed("classification arguments are outside the realized domain")
    name = f"classification.{alert}"
    pre = _values(context, "event-store", (name,))
    record = f"{classification}|{confidence}"
    _write_value(
        context.backend,
        context.container("event-store"),
        context.path(name),
        record,
    )
    post = _values(context, "event-store", (name,))
    return _verified(
        post[f"event-store.{name}"] == record,
        "synthetic alert classification recorded and read back",
        pre,
        post,
        "classification-authorized",
        "classification-recorded",
    )


def _inspect_actor_events(
    context: _OperationContext,
) -> VerifiedParticipantOperation:
    """Inspect actor events for the bounded participant workflow."""
    actor = _scalar(context.arguments, "actor")
    limit = int(_scalar(context.arguments, "limit"))
    if actor not in {
        "identities.benign-customer",
        "identities.synthetic-assessor",
    }:
        return _failed("actor is outside the realized domain")
    if not 1 <= limit <= 5:
        return _failed("actor event limit is outside the realized domain")
    name = f"events.{actor}"
    pre_raw = _values(context, "event-store", (name,))
    post_raw = _values(context, "event-store", (name,))
    pre_events = pre_raw[f"event-store.{name}"].split("|")[:limit]
    post_events = post_raw[f"event-store.{name}"].split("|")[:limit]
    pre = {
        f"event-store.{name}.event-{index}": event
        for index, event in enumerate(pre_events, start=1)
    }
    post = {
        f"event-store.{name}.event-{index}": event
        for index, event in enumerate(post_events, start=1)
    }
    return _verified(
        len(post) == limit and all(post.values()),
        f"bounded actor event set read with limit {limit}",
        pre,
        post,
        "actor-scope-authorized",
        "actor-events-observed",
    )


def _correlate_evidence(
    context: _OperationContext,
) -> VerifiedParticipantOperation:
    """Correlate evidence for the bounded participant workflow."""
    references = _many(context.arguments, "evidence")
    if not references:
        return _failed("correlation evidence is empty")
    observed: dict[str, str] = {}
    for reference in references:
        if reference.startswith("alerts."):
            name = f"alert.{reference.removeprefix('alerts.')}"
            observed.update(_values(context, "defender-console", (name,)))
        elif reference.startswith("context."):
            observed.update(_values(context, "defender-console", (reference,)))
        else:
            return _failed("correlation evidence is outside the realized domain")
    return _verified(
        all(observed.values()),
        "selected previously visible evidence correlated without expanding scope",
        observed,
        dict(observed),
        "evidence-observed",
        "correlation-observed",
    )


def _apply_response(context: _OperationContext) -> VerifiedParticipantOperation:
    """Apply response for the bounded participant workflow."""
    response = _scalar(context.arguments, "response_target")
    allowed = {
        "response.dismiss:alerts.response-001",
        "response.annotate:alerts.response-001",
        "response.escalate:alerts.response-001",
        _ASSESSOR_CONTAINMENT,
    }
    if response not in allowed:
        return _failed("response target is outside the realized domain")
    pre = _combined_values(
        context,
        (
            ("event-store", (_RESPONSE_LATEST,)),
            ("webapp", ("assessor-access", "benign-access")),
        ),
    )
    _write_value(
        context.backend,
        context.container("event-store"),
        context.path(_RESPONSE_LATEST),
        response,
    )
    if response == _ASSESSOR_CONTAINMENT:
        _write_value(
            context.backend,
            context.container("webapp"),
            context.path("assessor-access"),
            "blocked",
        )
    post = _combined_values(
        context,
        (
            ("event-store", (_RESPONSE_LATEST,)),
            ("webapp", ("assessor-access", "benign-access")),
        ),
    )
    expected_assessor = (
        "blocked" if response == _ASSESSOR_CONTAINMENT else pre[_WEBAPP_ASSESSOR_ACCESS]
    )
    ok = (
        post["event-store.response.latest"] == response
        and post[_WEBAPP_ASSESSOR_ACCESS] == expected_assessor
        and post[_WEBAPP_BENIGN_ACCESS] == pre[_WEBAPP_BENIGN_ACCESS]
    )
    return _verified(
        ok,
        "scoped synthetic response applied with unrelated benign access unchanged",
        pre,
        post,
        "response-authorized",
        "response-applied",
        "unrelated-state-unchanged",
    )


def _verify_response(context: _OperationContext) -> VerifiedParticipantOperation:
    """Verify response for the bounded participant workflow."""
    if _scalar(context.arguments, "response") != "responses.blue.latest":
        return _failed("response reference is outside the realized domain")
    pre = _combined_values(
        context,
        (
            ("event-store", (_RESPONSE_LATEST,)),
            ("webapp", ("assessor-access", "benign-access")),
        ),
    )
    post = _combined_values(
        context,
        (
            ("event-store", (_RESPONSE_LATEST,)),
            ("webapp", ("assessor-access", "benign-access")),
        ),
    )
    return _verified(
        post["event-store.response.latest"] != "none"
        and post[_WEBAPP_BENIGN_ACCESS] == "allowed",
        "latest scoped response and bounded access effect read back",
        pre,
        post,
        "response-exists",
        "response-result-observed",
    )


BLUE_HANDLERS: Mapping[
    str, Callable[[_OperationContext], VerifiedParticipantOperation]
] = {
    "participant.action-contract.list-assigned-alerts": _list_alerts,
    "participant.action-contract.inspect-assigned-alert": _inspect_alert,
    "participant.action-contract.query-allowed-context": _query_context,
    "participant.action-contract.classify-alert": _classify_alert,
    "participant.action-contract.inspect-actor-event-set": _inspect_actor_events,
    "participant.action-contract.correlate-selected-evidence": _correlate_evidence,
    "participant.action-contract.apply-scoped-response": _apply_response,
    "participant.action-contract.verify-response-effect": _verify_response,
}
