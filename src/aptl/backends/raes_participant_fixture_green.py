"""Benign-user operations for the bounded participant fixture."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from aptl.backends.raes_participant_fixture_core import (
    _BENIGN_ACCOUNT_ACTIVE,
    _DB_SUPPORT_REQUEST,
    _LOGIN_ENDPOINT,
    _PROFILE_CONTACT_EMAIL,
    _PROFILE_DEPARTMENT,
    _PROFILE_PROTECTED_ACCOUNT_ID,
    _SUPPORT_NOTE,
    _SUPPORT_REQUEST,
    _WEBAPP_SESSION,
    _OperationContext,
    VerifiedParticipantOperation,
    _combined_values,
    _failed,
    _http_status,
    _many,
    _read_absolute,
    _scalar,
    _values,
    _verified,
    _write_value,
)


def _inspect_portal(context: _OperationContext) -> VerifiedParticipantOperation:
    """Inspect portal for the bounded participant workflow."""
    if _scalar(context.arguments, "surface") != "nodes.webapp.services.http":
        return _failed("portal surface is outside the realized domain")
    pre = _values(context, "webapp", ("benign-access",))
    status = _http_status(context, "webapp", "/", "GET")
    content = _read_absolute(
        context.backend,
        context.container("webapp"),
        "/srv/bounded-participant/index.html",
    )
    post = _values(context, "webapp", ("benign-access",))
    ok = status == "200" and "TechVault bounded participant" in content
    return _verified(
        ok,
        f"portal HTTP status {status} with independently read content",
        pre,
        post,
        "portal-authorized",
        "portal-observed",
    )


def _authenticate_user(context: _OperationContext) -> VerifiedParticipantOperation:
    """Authenticate user for the bounded participant workflow."""
    if _scalar(context.arguments, "identity") != "identities.benign-customer":
        return _failed("synthetic identity is outside the realized domain")
    pre = _combined_values(
        context,
        (("webapp", ("session",)), ("db", ("account",))),
    )
    status = _http_status(
        context,
        "webapp",
        _LOGIN_ENDPOINT,
        "GET",
    )
    if status == "200":
        _write_value(
            context.backend,
            context.container("webapp"),
            context.path("session"),
            "active:benign-customer",
        )
    post = _combined_values(
        context,
        (("webapp", ("session",)), ("db", ("account",))),
    )
    ok = (
        post[_WEBAPP_SESSION] == "active:benign-customer"
        and post["db.account"] == _BENIGN_ACCOUNT_ACTIVE
    )
    return _verified(
        ok,
        "synthetic customer session created and read back",
        pre,
        post,
        "identity-assigned",
        "session-created",
        "authentication-observed",
    )


def _view_account(context: _OperationContext) -> VerifiedParticipantOperation:
    """Inspect account for the bounded participant workflow."""
    if _scalar(context.arguments, "account") != "accounts.benign-customer":
        return _failed("account is outside the realized domain")
    pre = _values(context, "db", ("account",))
    post = _values(context, "db", ("account",))
    return _verified(
        post["db.account"] == _BENIGN_ACCOUNT_ACTIVE,
        "assigned synthetic account read from the database target",
        pre,
        post,
        "own-account-only",
        "own-account-observed",
    )


def _sign_out(context: _OperationContext) -> VerifiedParticipantOperation:
    """Terminate out for the bounded participant workflow."""
    if _scalar(context.arguments, "session") != "sessions.benign-current":
        return _failed("session is outside the realized domain")
    pre = _values(context, "webapp", ("session",))
    _write_value(
        context.backend,
        context.container("webapp"),
        context.path("session"),
        "inactive",
    )
    post = _values(context, "webapp", ("session",))
    return _verified(
        pre[_WEBAPP_SESSION].startswith("active:")
        and post[_WEBAPP_SESSION] == "inactive",
        "participant-owned synthetic session ended and read back",
        pre,
        post,
        "session-owned",
        "session-ended",
    )


def _inspect_profile(context: _OperationContext) -> VerifiedParticipantOperation:
    """Inspect profile for the bounded participant workflow."""
    requested = _many(context.arguments, "fields")
    allowed = {"contact_email", "department"}
    if not requested or not set(requested) <= allowed:
        return _failed("profile field selection is outside the realized domain")
    names = tuple(f"profile.{field}" for field in requested)
    pre = _values(context, "db", names)
    post = _values(context, "db", names)
    return _verified(
        all(post.values()),
        "requested permitted profile fields read from the database target",
        pre,
        post,
        "profile-owned",
        "permitted-profile-observed",
    )


def _update_profile(context: _OperationContext) -> VerifiedParticipantOperation:
    """Update profile for the bounded participant workflow."""
    pre = _values(
        context,
        "db",
        (
            _PROFILE_CONTACT_EMAIL,
            _PROFILE_DEPARTMENT,
            _PROFILE_PROTECTED_ACCOUNT_ID,
        ),
    )
    change = _scalar(context.arguments, "change")
    allowed = {
        "department:Research": (_PROFILE_DEPARTMENT, "Research"),
        "contact_email:green.user+validated@techvault.local": (
            _PROFILE_CONTACT_EMAIL,
            "green.user+validated@techvault.local",
        ),
    }
    if change not in allowed:
        return _failed("profile change is outside the realized domain")
    field, value = allowed[change]
    _write_value(
        context.backend,
        context.container("db"),
        context.path(field),
        value,
    )
    post = _values(
        context,
        "db",
        (
            _PROFILE_CONTACT_EMAIL,
            _PROFILE_DEPARTMENT,
            _PROFILE_PROTECTED_ACCOUNT_ID,
        ),
    )
    ok = (
        post[f"db.{field}"] == value
        and post["db.profile.protected_account_id"]
        == pre["db.profile.protected_account_id"]
    )
    return _verified(
        ok,
        "one permitted profile field changed and the protected field did not",
        pre,
        post,
        "field-change-authorized",
        "profile-field-updated",
        "protected-fields-unchanged",
    )


def _verify_own_state(context: _OperationContext) -> VerifiedParticipantOperation:
    """Verify own state for the bounded participant workflow."""
    resource = _scalar(context.arguments, "resource")
    names_by_resource = {
        "profiles.benign-customer": (
            "db",
            (_PROFILE_CONTACT_EMAIL, _PROFILE_DEPARTMENT),
        ),
        "support.benign-assigned": (
            "db",
            (_SUPPORT_REQUEST, _SUPPORT_NOTE),
        ),
        "sessions.benign-current": ("webapp", ("session",)),
    }
    if resource not in names_by_resource:
        return _failed("owned resource is outside the realized domain")
    node, names = names_by_resource[resource]
    pre = _values(context, node, names)
    post = _values(context, node, names)
    return _verified(
        all(value != "none" for value in post.values()),
        "participant-owned synthetic state read back",
        pre,
        post,
        "resource-owned",
        "owned-state-observed",
    )


def _browse_help(context: _OperationContext) -> VerifiedParticipantOperation:
    """Inspect help for the bounded participant workflow."""
    topic = _scalar(context.arguments, "topic")
    if topic not in {"account-access", "profile-corrections", "support-requests"}:
        return _failed("help topic is outside the realized domain")
    pre = _values(context, "webapp", (f"help.{topic}",))
    post = _values(context, "webapp", (f"help.{topic}",))
    return _verified(
        bool(next(iter(post.values()))),
        "approved public help topic read from the portal target",
        pre,
        post,
        "help-public",
        "help-observed",
    )


def _create_support_request(
    context: _OperationContext,
) -> VerifiedParticipantOperation:
    """Create support request for the bounded participant workflow."""
    template = _scalar(context.arguments, "request_template")
    if template not in {
        "account-access-question",
        "profile-correction-confirmation",
    }:
        return _failed("support template is outside the realized domain")
    pre = _values(context, "db", (_SUPPORT_REQUEST,))
    _write_value(
        context.backend,
        context.container("db"),
        context.path(_SUPPORT_REQUEST),
        f"open:{template}",
    )
    post = _values(context, "db", (_SUPPORT_REQUEST,))
    return _verified(
        post[_DB_SUPPORT_REQUEST] == f"open:{template}",
        "assigned synthetic support request created and read back",
        pre,
        post,
        "request-authorized",
        "support-request-created",
    )


def _inspect_support_request(
    context: _OperationContext,
) -> VerifiedParticipantOperation:
    """Inspect support request for the bounded participant workflow."""
    if _scalar(context.arguments, "request") != "support.benign-assigned":
        return _failed("support request is outside the realized domain")
    pre = _values(context, "db", (_SUPPORT_REQUEST,))
    post = _values(context, "db", (_SUPPORT_REQUEST,))
    return _verified(
        post[_DB_SUPPORT_REQUEST].startswith("open:"),
        "participant-owned support request read from the database target",
        pre,
        post,
        "request-owned",
        "support-request-observed",
    )


def _append_support_note(context: _OperationContext) -> VerifiedParticipantOperation:
    """Append support note for the bounded participant workflow."""
    template = _scalar(context.arguments, "note_template")
    if template not in {"confirm-details", "request-status"}:
        return _failed("support note template is outside the realized domain")
    pre = _values(context, "db", (_SUPPORT_REQUEST, _SUPPORT_NOTE))
    if not pre[_DB_SUPPORT_REQUEST].startswith("open:"):
        return _failed(
            "assigned support request does not exist", "precondition_unsatisfied"
        )
    _write_value(
        context.backend,
        context.container("db"),
        context.path(_SUPPORT_NOTE),
        template,
    )
    post = _values(context, "db", (_SUPPORT_REQUEST, _SUPPORT_NOTE))
    return _verified(
        post["db.support.note"] == template
        and post[_DB_SUPPORT_REQUEST] == pre[_DB_SUPPORT_REQUEST],
        "approved note appended to the assigned support request",
        pre,
        post,
        "note-authorized",
        "support-note-appended",
    )


GREEN_HANDLERS: Mapping[
    str, Callable[[_OperationContext], VerifiedParticipantOperation]
] = {
    "participant.action-contract.inspect-portal": _inspect_portal,
    "participant.action-contract.authenticate-synthetic-user": _authenticate_user,
    "participant.action-contract.view-permitted-account": _view_account,
    "participant.action-contract.sign-out-session": _sign_out,
    "participant.action-contract.inspect-own-profile": _inspect_profile,
    "participant.action-contract.update-own-profile": _update_profile,
    "participant.action-contract.verify-own-state": _verify_own_state,
    "participant.action-contract.browse-help": _browse_help,
    "participant.action-contract.create-support-request": _create_support_request,
    "participant.action-contract.inspect-own-support-request": _inspect_support_request,
    "participant.action-contract.append-support-note": _append_support_note,
}
