"""Security-assessor operations for the bounded participant fixture."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from aptl.backends.raes_participant_fixture_core import (
    _DEBUG_ENDPOINT,
    _KALI_LAST_AUTH_OUTCOME,
    _LOGIN_ENDPOINT,
    _RESPONSE_CONTENT_LENGTH,
    _RESPONSE_CONTENT_TYPE,
    _RESPONSE_LOCATION,
    _RESPONSE_STATUS,
    _WEBAPP_ASSESSOR_ACCESS,
    _OperationContext,
    VerifiedParticipantOperation,
    _combined_values,
    _failed,
    _http_response_metadata,
    _http_status,
    _many,
    _read_absolute,
    _scalar,
    _values,
    _verified,
    _write_value,
)

_PUBLIC_ENDPOINTS = {
    "landing": "/",
    "robots": "/robots.txt",
    "diagnostics": _DEBUG_ENDPOINT,
}


def _inspect_public_surface(
    context: _OperationContext,
) -> VerifiedParticipantOperation:
    """Inspect public surface for the bounded participant workflow."""
    surface = _scalar(context.arguments, "surface")
    endpoint = _PUBLIC_ENDPOINTS.get(surface)
    if endpoint is None:
        return _failed("public surface is outside the realized domain")
    pre_status = _http_status(context, "kali", endpoint, "GET")
    pre = {
        **_values(context, "webapp", ("assessor-access",)),
        f"kali.public-surface.{surface}.status": pre_status,
    }
    post_status = _http_status(context, "kali", endpoint, "GET")
    post = {
        **_values(context, "webapp", ("assessor-access",)),
        f"kali.public-surface.{surface}.status": post_status,
    }
    return _verified(
        pre_status == post_status == "200"
        and post[_WEBAPP_ASSESSOR_ACCESS] == "allowed",
        f"approved {surface} surface returned HTTP {post_status}",
        pre,
        post,
        "public-surface-authorized",
        "public-surface-observed",
    )


def _probe_endpoint(context: _OperationContext) -> VerifiedParticipantOperation:
    """Handle endpoint for the bounded participant workflow."""
    endpoint = _scalar(context.arguments, "endpoint")
    method = _scalar(context.arguments, "method", default="GET")
    if endpoint not in {"/", "/login", "/robots.txt", _DEBUG_ENDPOINT}:
        return _failed("endpoint is outside the realized domain")
    if method not in {"GET", "HEAD"}:
        return _failed("method is outside the realized domain")
    response_names = (
        "last-response",
        _RESPONSE_STATUS,
        _RESPONSE_CONTENT_TYPE,
        _RESPONSE_CONTENT_LENGTH,
        _RESPONSE_LOCATION,
    )
    pre = _values(context, "kali", response_names)
    status, content_type, content_length, location = _http_response_metadata(
        context,
        "kali",
        endpoint,
        method,
    )
    record = f"{method}|{endpoint}"
    _write_value(
        context.backend,
        context.container("kali"),
        context.path("last-response"),
        record,
    )
    for name, value in {
        _RESPONSE_STATUS: status,
        _RESPONSE_CONTENT_TYPE: content_type,
        _RESPONSE_CONTENT_LENGTH: content_length,
        _RESPONSE_LOCATION: location,
    }.items():
        _write_value(
            context.backend,
            context.container("kali"),
            context.path(name),
            value,
        )
    post = _values(context, "kali", response_names)
    return _verified(
        post["kali.last-response"] == record
        and post["kali.response.status"] == "200"
        and all(
            post[f"kali.response.{name}"] != "none"
            for name in (
                "content-type",
                "content-length",
                "location",
            )
        ),
        f"bounded {method} request to {endpoint} returned HTTP {status}",
        pre,
        post,
        "endpoint-in-scope",
        "endpoint-probed",
        "endpoint-result-observed",
    )


def _inspect_response_metadata(
    context: _OperationContext,
) -> VerifiedParticipantOperation:
    """Inspect response metadata for the bounded participant workflow."""
    fields = _many(context.arguments, "fields")
    allowed = {"status", "content-type", "content-length", "location"}
    if not fields or not set(fields) <= allowed:
        return _failed("response metadata selection is outside the realized domain")
    names = tuple(f"response.{field}" for field in fields)
    pre = _values(context, "kali", names)
    post = _values(context, "kali", names)
    expected_keys = {f"kali.response.{field}" for field in fields}
    return _verified(
        set(post) == expected_keys and all(value != "none" for value in post.values()),
        "selected metadata fields read from the preceding bounded response",
        pre,
        post,
        "response-exists",
        "response-metadata-observed",
    )


def _submit_auth_attempt(
    context: _OperationContext,
) -> VerifiedParticipantOperation:
    """Submit auth attempt for the bounded participant workflow."""
    identity_ref = _scalar(context.arguments, "identity")
    credential_ref = _scalar(context.arguments, "credential_candidate")
    attempt = _scalar(context.arguments, "attempt_number")
    identities = {
        "identities.synthetic-user-a": "synthetic-user-a",
        "identities.synthetic-user-b": "synthetic-user-b",
    }
    credentials = {
        "credentials.synthetic-candidate-1": "candidate-1",
        "credentials.synthetic-candidate-2": "candidate-2",
    }
    if identity_ref not in identities or credential_ref not in credentials:
        return _failed("authentication candidate is outside the realized domain")
    if not attempt.isdigit() or not 1 <= int(attempt) <= 3:
        return _failed("authentication attempt is outside the realized budget")
    pre = _combined_values(
        context,
        (("kali", ("last-auth-outcome",)), ("defender-console", ("auth-event",))),
    )
    status = _http_status(
        context,
        "kali",
        _LOGIN_ENDPOINT,
        "GET",
    )
    outcome = f"{identity_ref}|{credential_ref}|attempt-{attempt}|http-{status}"
    _write_value(
        context.backend,
        context.container("kali"),
        context.path("last-auth-outcome"),
        outcome,
    )
    _write_value(
        context.backend,
        context.container("defender-console"),
        context.path("auth-event"),
        outcome,
    )
    post = _combined_values(
        context,
        (("kali", ("last-auth-outcome",)), ("defender-console", ("auth-event",))),
    )
    return _verified(
        post[_KALI_LAST_AUTH_OUTCOME] == outcome
        and post["defender-console.auth-event"] == outcome,
        f"bounded authentication attempt returned HTTP {status} and retained telemetry",
        pre,
        post,
        "auth-budget-available",
        "authentication-attempted",
        "auth-event-retained",
    )


def _inspect_auth_outcome(
    context: _OperationContext,
) -> VerifiedParticipantOperation:
    """Inspect auth outcome for the bounded participant workflow."""
    if _scalar(context.arguments, "outcome") != "observations.red.latest-auth-outcome":
        return _failed("authentication outcome is outside the realized domain")
    pre = _values(context, "kali", ("last-auth-outcome",))
    post = _values(context, "kali", ("last-auth-outcome",))
    return _verified(
        post[_KALI_LAST_AUTH_OUTCOME] != "none",
        "preceding bounded authentication outcome read back",
        pre,
        post,
        "auth-outcome-exists",
        "auth-outcome-observed",
    )


def _discover_objective(context: _OperationContext) -> VerifiedParticipantOperation:
    """Discover objective for the bounded participant workflow."""
    clue = _scalar(context.arguments, "clue")
    allowed = {
        "observations.red.latest-response": "kali.last-response",
        "observations.red.latest-auth-outcome": _KALI_LAST_AUTH_OUTCOME,
    }
    if clue not in allowed:
        return _failed("objective clue is outside the realized domain")
    node, name = allowed[clue].split(".", maxsplit=1)
    pre = _values(context, node, (name,))
    robots = _read_absolute(
        context.backend,
        context.container("webapp"),
        "/srv/bounded-participant/robots.txt",
    )
    post = _values(context, node, (name,))
    return _verified(
        next(iter(post.values())) != "none" and _DEBUG_ENDPOINT in robots,
        "synthetic objective reference discovered from an observed clue",
        pre,
        post,
        "clue-observed",
        "marker-reference-discovered",
    )


def _retrieve_marker(context: _OperationContext) -> VerifiedParticipantOperation:
    """Retrieve marker for the bounded participant workflow."""
    if _scalar(context.arguments, "marker") != "content.synthetic-red-marker":
        return _failed("objective marker is outside the realized domain")
    pre = _values(context, "webapp", ("assessor-access",))
    status = _http_status(context, "kali", _DEBUG_ENDPOINT, "GET")
    marker = _read_absolute(
        context.backend,
        context.container("webapp"),
        "/srv/bounded-participant/debug",
    )
    post = _values(context, "webapp", ("assessor-access",))
    return _verified(
        status == "200" and marker.strip() == "BPA-SYNTHETIC-MARKER",
        "declared synthetic objective marker retrieved and read back",
        pre,
        post,
        "marker-discovered",
        "marker-observed",
    )


RED_HANDLERS: Mapping[
    str, Callable[[_OperationContext], VerifiedParticipantOperation]
] = {
    "participant.action-contract.inspect-public-surface": _inspect_public_surface,
    "participant.action-contract.probe-permitted-endpoint": _probe_endpoint,
    "participant.action-contract.inspect-response-metadata": _inspect_response_metadata,
    "participant.action-contract.submit-bounded-auth-attempt": _submit_auth_attempt,
    "participant.action-contract.inspect-auth-outcome": _inspect_auth_outcome,
    "participant.action-contract.discover-synthetic-objective": _discover_objective,
    "participant.action-contract.retrieve-synthetic-marker": _retrieve_marker,
}
