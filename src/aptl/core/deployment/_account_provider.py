"""Provider-agnostic account realization logic (issue #577, ADR-046 addendum).

Pure functions — no I/O. Three responsibilities:

* resolve the account-materializer binding for a resolved backend service;
* validate a whole account batch *before* any mutation (fail closed); and
* build the ``samba-tool`` argv lists the Compose account mixin runs through
  ``container_exec``.

A credential never appears in any argv this module builds: user creation uses
``samba-tool user create <name> --random-password`` so the secret is generated
inside the target boundary and never disclosed. Identity values (username,
group, mail, SPN) travel as discrete argv tokens, never interpolated into a
shell string; the validation below additionally rejects control characters and
leading dashes so an untrusted value cannot become an option or shell syntax
(ADR-046 addendum §"Provider validation is defense in depth").
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from aptl.core.deployment.realization import (
    DeploymentAccountRealization,
    DeploymentNodeRealization,
)

SAMBA_AD = "samba-ad"

# Provider-native identity grammars. These reject the list separator (`,`) that
# ``samba-tool group addmembers`` would otherwise expand into several principals,
# plus DN/query metacharacters and control characters, so an untrusted SDL value
# cannot become an option, a second principal, or shell/LDAP syntax. Usernames,
# SPNs, and mail are single tokens; AD group display names may contain spaces
# (e.g. "Domain Admins"), so only groups admit an internal space.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._$-]*$")
_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
_MAIL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]*$")
_SPN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]*$")

# Code-owned binding: backend service name -> account provider kind. Adding a
# new account-capable service is one entry here (ADR-046 §Extensibility), never
# a scenario-name branch. This is the single source of truth the interpret-time
# gate (``aces_account_realization``) and the realize-time materializer share.
_PROVIDER_BINDINGS: Mapping[str, str] = {"ad": SAMBA_AD}

# Bound on a single identity token. Usernames, group names, mail, and SPNs are
# ACES-owned and short; this is a defensive cap against an unbounded value
# reaching argv or a log field.
_MAX_IDENTIFIER_LEN = 256


def resolve_account_provider(service_name: str | None) -> str | None:
    """Return the account provider kind bound to a backend service, or None."""

    if service_name is None:
        return None
    return _PROVIDER_BINDINGS.get(service_name)


def account_provider_services() -> frozenset[str]:
    """Return the set of backend services with a registered account provider."""

    return frozenset(_PROVIDER_BINDINGS)


@dataclass(frozen=True)
class AccountTarget(object):
    """A validated account batch bound to one resolved target container."""

    container_name: str
    provider: str
    accounts: tuple[DeploymentAccountRealization, ...]


@dataclass(frozen=True)
class AccountPlanError(object):
    """A fail-closed rejection of one account placement, by stable reason."""

    address: str
    reason: str


def plan_account_targets(
    accounts: Sequence[DeploymentAccountRealization],
    nodes: Sequence[DeploymentNodeRealization],
) -> tuple[list[AccountTarget], list[AccountPlanError]]:
    """Resolve + validate the whole account batch before any mutation.

    Returns ``(targets, errors)``. When ``errors`` is non-empty the caller must
    not mutate anything: validation is a batch gate, not per-account.
    """

    by_address = _nodes_by_address(nodes)
    errors: list[AccountPlanError] = []
    grouped: dict[str, list[DeploymentAccountRealization]] = {}
    provider_for: dict[str, str] = {}
    seen: dict[tuple[str, str], DeploymentAccountRealization] = {}

    for account in accounts:
        resolved = _resolve_target(account, by_address)
        if isinstance(resolved, AccountPlanError):
            errors.append(resolved)
            continue
        container_name, provider = resolved
        field_error = _validate_account_fields(account)
        if field_error is not None:
            errors.append(field_error)
            continue
        conflict = _conflict(seen, container_name, account)
        if conflict is not None:
            errors.append(conflict)
            continue
        seen[(container_name, canonical_principal(account.username))] = account
        grouped.setdefault(container_name, []).append(account)
        provider_for[container_name] = provider

    if errors:
        # Batch-atomic: a single rejected placement blocks the whole batch so
        # no account is mutated before validation passes (ADR-046 addendum).
        return [], errors

    targets = [
        AccountTarget(
            container_name=container_name,
            provider=provider_for[container_name],
            accounts=tuple(batch),
        )
        for container_name, batch in grouped.items()
    ]
    return targets, errors


def _nodes_by_address(
    nodes: Sequence[DeploymentNodeRealization],
) -> dict[str, DeploymentNodeRealization | None]:
    """Map node address -> node, marking duplicate addresses ambiguous (None)."""

    by_address: dict[str, DeploymentNodeRealization | None] = {}
    for node in nodes:
        by_address[node.address] = None if node.address in by_address else node
    return by_address


_MISSING_NODE = object()


def _resolve_target(
    account: DeploymentAccountRealization,
    by_address: Mapping[str, DeploymentNodeRealization | None],
) -> tuple[str, str] | AccountPlanError:
    """Resolve one account to ``(container_name, provider)`` or a plan error."""

    node = by_address.get(account.target_address, _MISSING_NODE)
    provider = resolve_account_provider(
        node.service_name if isinstance(node, DeploymentNodeRealization) else None
    )
    reason = _target_reason(node, provider)
    if reason is not None:
        return AccountPlanError(account.address, reason)
    return node.container_name, provider  # type: ignore[union-attr]


def _target_reason(
    node: DeploymentNodeRealization | None | object,
    provider: str | None,
) -> str | None:
    """Return the first fail-closed reason a resolved target is unusable, or None."""

    checks = (
        ("unresolved-target-node", node is _MISSING_NODE),
        ("ambiguous-target-node", node is None),
        (
            "target-node-has-no-container",
            isinstance(node, DeploymentNodeRealization) and node.container_name is None,
        ),
        ("no-account-provider-for-service", provider is None),
    )
    return next((reason for reason, failed in checks if failed), None)


def _validate_account_fields(
    account: DeploymentAccountRealization,
) -> AccountPlanError | None:
    """Reject provider-unsafe identity values before any mutation."""

    reason = _field_error_reason(account)
    return AccountPlanError(account.address, reason) if reason is not None else None


def _field_error_reason(account: DeploymentAccountRealization) -> str | None:
    """Return the first provider-unsafe identity field's reason, or None."""

    checks = (
        ("invalid-username", _matches(_USERNAME_RE, account.username)),
        ("invalid-group", all(_matches(_GROUP_RE, g) for g in account.groups)),
        ("invalid-mail", not account.mail or _matches(_MAIL_RE, account.mail)),
        ("invalid-spn", not account.spn or _matches(_SPN_RE, account.spn)),
    )
    return next((reason for reason, ok in checks if not ok), None)


def _matches(pattern: re.Pattern[str], value: str) -> bool:
    """Return whether a bounded value matches a provider-native grammar."""

    return (
        bool(value) and len(value) <= _MAX_IDENTIFIER_LEN and bool(pattern.match(value))
    )


def canonical_principal(username: str) -> str:
    """Canonicalize a principal name (AD account names are case-insensitive).

    Shared by duplicate detection and read-after-write membership verification so
    the two agree on identity: ``Former.Employee`` and ``former.employee`` are one
    account.
    """

    return username.casefold()


def _conflict(
    seen: Mapping[tuple[str, str], DeploymentAccountRealization],
    container_name: str,
    account: DeploymentAccountRealization,
) -> AccountPlanError | None:
    """Reject a duplicate principal on one target with conflicting attributes.

    Keyed on the canonical (case-insensitive) principal name because AD treats
    ``Former.Employee`` and ``former.employee`` as the same account: two
    declarations that disagree on any non-name attribute would otherwise both
    mutate the one principal.
    """

    prior = seen.get((container_name, canonical_principal(account.username)))
    if prior is None or _same_declaration(prior, account):
        return None
    return AccountPlanError(account.address, "conflicting-duplicate-account")


def _same_declaration(
    a: DeploymentAccountRealization,
    b: DeploymentAccountRealization,
) -> bool:
    """Whether two same-principal declarations request identical non-name state."""

    return (a.groups, a.spn, a.mail, a.disabled) == (
        b.groups,
        b.spn,
        b.mail,
        b.disabled,
    )


def dedupe_groups(
    accounts: Sequence[DeploymentAccountRealization],
) -> tuple[str, ...]:
    """Return the sorted, de-duplicated group names declared across a batch."""

    groups = {group for account in accounts for group in account.groups}
    return tuple(sorted(groups))


# --- samba-tool argv builders (pure) --------------------------------------
#
# Each returns a discrete argv list for container_exec. No builder emits a
# credential: user creation delegates password generation to the target with
# --random-password.


# The AD entrypoint (containers/ad/setup-ad.sh) writes this marker AFTER its
# baseline account provisioner (provision-users.sh) finishes, and it persists on
# the ad_data volume. It is the samba-ad provider's explicit "baseline
# provisioning complete" signal — the generic AD-DC marker, not a scenario branch.
_SAMBA_PROVISIONED_MARKER = "/var/lib/samba/private/.provisioned"


def samba_domain_info() -> list[str]:
    """Bounded readiness probe: the AD provider answers domain info."""

    return ["samba-tool", "domain", "info", "127.0.0.1"]


def samba_provisioning_complete_probe() -> list[str]:
    """Probe the marker proving the AD baseline provisioner has finished.

    Gating account realization on this (in addition to ``domain info``) makes the
    provisioner-complete ordering explicit: the backend must not observe an
    account as absent and create it while the service-owned provisioner is still
    installing that same account with its designed fixture credential.
    """

    return ["test", "-f", _SAMBA_PROVISIONED_MARKER]


def samba_group_show(group: str) -> list[str]:
    """Argv to check whether a group exists (rc 0 when present)."""

    return ["samba-tool", "group", "show", group]


def samba_group_add(group: str) -> list[str]:
    """Argv to create a group."""

    return ["samba-tool", "group", "add", group]


def samba_group_addmembers(group: str, user: str) -> list[str]:
    """Argv to add one user to a group (idempotent)."""

    return ["samba-tool", "group", "addmembers", group, user]


def samba_group_listmembers(group: str) -> list[str]:
    """Argv to list a group's members, one per line (read-after-write verify)."""

    return ["samba-tool", "group", "listmembers", group]


def samba_user_show(user: str) -> list[str]:
    """Argv to read a user's attributes (rc 0 when the account exists)."""

    return ["samba-tool", "user", "show", user]


def samba_user_create(user: str, *, mail: str = "") -> list[str]:
    """Create a user with a target-side-generated password (never a secret argv)."""

    cmd = ["samba-tool", "user", "create", user, "--random-password"]
    if mail:
        cmd.append(f"--mail-address={mail}")
    return cmd


def samba_user_set_mail(user: str, mail: str) -> list[str]:
    """Converge an existing user's mail without renaming or touching its secret.

    ``samba-tool user rename`` updates the passed attributes and only renames
    when a new username is supplied, so passing just ``--mail-address`` is the
    supported non-interactive way to set mail on an already-existing account.
    """

    return ["samba-tool", "user", "rename", user, f"--mail-address={mail}"]


def samba_user_enable(user: str) -> list[str]:
    """Argv to enable an account (idempotent)."""

    return ["samba-tool", "user", "enable", user]


def samba_user_disable(user: str) -> list[str]:
    """Argv to disable an account (idempotent)."""

    return ["samba-tool", "user", "disable", user]


def samba_spn_list(user: str) -> list[str]:
    """Argv to list a user's SPNs (read-after-write verify)."""

    return ["samba-tool", "spn", "list", user]


def samba_spn_add(spn: str, user: str) -> list[str]:
    """Argv to add one SPN to a user."""

    return ["samba-tool", "spn", "add", spn, user]
