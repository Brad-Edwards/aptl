"""Static SDL<->provisioner account parity check (ADR-046 TechVault addendum, #689).

Split out of ``_gate_checks.py`` to keep that module under the file-length
gate: this module owns ``check_account_provisioner_parity``, the sole
consumer of the provisioner-script scraping logic.
``techvault_gate.validate_scenario`` calls it here directly (step 7).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from aces_sdl.accounts import Account
from aces_sdl.scenario import Scenario

from aptl.utils.redaction import redact
from aptl.validation.techvault_gate import GateCheck

# Static SDL<->provisioner account parity (ADR-046 TechVault addendum,
# issue #689): the checked-in AD account provisioner the `ad` container's
# entrypoint always runs. A declared SDL account is honest only when this
# script actually creates it.
_PROVISION_USERS_SCRIPT = Path("containers") / "ad" / "provision-users.sh"
_SAMBA_USER_CREATE_RE = re.compile(r"samba-tool\s+user\s+create\s+(\S+)")
_SAMBA_MAIL_RE = re.compile(r'--mail="([^"]*)"')
_SAMBA_GROUP_ADDMEMBERS_RE = re.compile(
    r'samba-tool\s+group\s+addmembers\s+("[^"]+"|\S+)\s+(\S+)'
)
_SAMBA_SPN_ADD_RE = re.compile(r"samba-tool\s+spn\s+add\s+(\S+)\s+(\S+)")
_SAMBA_USER_DISABLE_RE = re.compile(r"samba-tool\s+user\s+disable\s+(\S+)")


@dataclass(frozen=True)
class _ProvisionerFacts(object):
    """Per-user facts statically scraped from ``provision-users.sh``.

    Each field records what the provisioner script actually,
    machine-checkably does for a given username — the authoritative
    boundary account realization evidence must match (issue #689).
    """

    users: frozenset[str] = frozenset()
    mail_by_user: Mapping[str, str] = field(default_factory=dict)
    groups_by_user: Mapping[str, frozenset[str]] = field(default_factory=dict)
    spns_by_user: Mapping[str, frozenset[str]] = field(default_factory=dict)
    disabled_users: frozenset[str] = frozenset()


def _parse_provisioner_facts(script_text: str) -> _ProvisionerFacts:
    """Statically scan the AD provisioner script for per-user account facts.

    ``user create`` commands use ``\\``-newline continuations to spread
    flags (including ``--mail=``) across lines; collapse those first so a
    continuation-line flag is still captured on the logical command line.
    """
    collapsed = script_text.replace("\\\n", " ")
    users: set[str] = set()
    mail_by_user: dict[str, str] = {}
    groups_by_user: dict[str, set[str]] = {}
    spns_by_user: dict[str, set[str]] = {}
    disabled_users: set[str] = set()

    for line in collapsed.splitlines():
        create_match = _SAMBA_USER_CREATE_RE.search(line)
        if create_match is not None:
            username = create_match.group(1)
            users.add(username)
            mail_match = _SAMBA_MAIL_RE.search(line)
            if mail_match is not None:
                mail_by_user[username] = mail_match.group(1)
            continue

        group_match = _SAMBA_GROUP_ADDMEMBERS_RE.search(line)
        if group_match is not None:
            group = group_match.group(1).strip('"')
            username = group_match.group(2)
            groups_by_user.setdefault(username, set()).add(group)
            continue

        spn_match = _SAMBA_SPN_ADD_RE.search(line)
        if spn_match is not None:
            spn, username = spn_match.groups()
            spns_by_user.setdefault(username, set()).add(spn)
            continue

        disable_match = _SAMBA_USER_DISABLE_RE.search(line)
        if disable_match is not None:
            disabled_users.add(disable_match.group(1))

    return _ProvisionerFacts(
        users=frozenset(users),
        mail_by_user=mail_by_user,
        groups_by_user={k: frozenset(v) for k, v in groups_by_user.items()},
        spns_by_user={k: frozenset(v) for k, v in spns_by_user.items()},
        disabled_users=frozenset(disabled_users),
    )


def check_account_provisioner_parity(
    *, scenario: Scenario, project_dir: Path
) -> GateCheck:
    """Confirm every SDL-declared account attribute is provisioner-authoritative.

    Account declarations are honest only when the clean-start path actually
    creates them, with the same groups/mail/SPN/disabled state, through an
    existing service-owned provisioner (ADR-046 TechVault Operational Standup
    Addendum, issue #689). This never runs Docker or ``samba-tool``; it
    statically scans the checked-in provisioner script the ``ad`` container's
    entrypoint always runs (``containers/ad/provision-users.sh``), so
    SDL<->provisioner drift is caught before ``aptl lab start`` rather than
    discovered live.

    Each SDL account (``scenario.accounts``) is checked against the
    provisioner's per-user facts:

    - ``username`` must have a matching ``samba-tool user create``.
    - every declared ``group`` must be a subset of the groups the
      provisioner actually adds that user to via
      ``samba-tool group addmembers``.
    - a non-empty declared ``mail`` must equal the ``--mail=`` value on
      that user's ``user create`` command.
    - a non-empty declared ``spn`` must be one the provisioner actually
      sets for that user via ``samba-tool spn add``.
    - declared ``disabled`` must equal whether the provisioner runs
      ``samba-tool user disable`` for that user (absent means not
      disabled).

    The check is one-directional (the provisioner may create more users,
    groups, or SPNs than the SDL declares; a phantom SDL account or a
    phantom SDL-declared attribute still fails).
    """
    script_path = project_dir / _PROVISION_USERS_SCRIPT
    if not script_path.exists():
        return GateCheck(
            "account_provisioner_parity",
            False,
            (f"AD account provisioner script missing at {script_path}",),
        )
    try:
        script_text = script_path.read_text(encoding="utf-8")
    except OSError as exc:
        return GateCheck(
            "account_provisioner_parity",
            False,
            (redact(f"AD account provisioner script unreadable: {exc}"),),
        )

    facts = _parse_provisioner_facts(script_text)
    diagnostics: list[str] = []
    for name, account in scenario.accounts.items():
        diagnostics.extend(_account_parity_diagnostics(name, account, facts))
    return GateCheck("account_provisioner_parity", *_outcome(diagnostics))


def _account_parity_diagnostics(
    name: str, account: Account, facts: _ProvisionerFacts
) -> list[str]:
    """Check one SDL account's attributes against the provisioner's facts."""
    username = account.username
    label = f"SDL account {name!r} (username={username!r})"
    if username not in facts.users:
        return [_missing_user_diagnostic(label)]
    return [
        *_group_parity_diagnostics(label, account, username, facts),
        *_mail_parity_diagnostics(label, account, username, facts),
        *_spn_parity_diagnostics(label, account, username, facts),
        *_disabled_parity_diagnostics(label, account, username, facts),
    ]


def _missing_user_diagnostic(label: str) -> str:
    """Report an SDL account with no matching provisioner user create."""
    return redact(
        f"{label} has no matching `samba-tool user create` in "
        f"{_PROVISION_USERS_SCRIPT.name}; declared accounts must "
        "be honest, clean-start-realized fixtures"
    )


def _group_parity_diagnostics(
    label: str, account: Account, username: str, facts: _ProvisionerFacts
) -> list[str]:
    """Report SDL-declared groups the provisioner never adds this user to."""
    missing_groups = set(account.groups) - facts.groups_by_user.get(username, frozenset())
    if not missing_groups:
        return []
    return [
        redact(
            f"{label} declares group(s) {sorted(missing_groups)} that "
            f"{_PROVISION_USERS_SCRIPT.name} never adds via "
            "`samba-tool group addmembers`"
        )
    ]


def _mail_parity_diagnostics(
    label: str, account: Account, username: str, facts: _ProvisionerFacts
) -> list[str]:
    """Report a declared mail address that doesn't match the provisioner's."""
    declared_mail = account.mail
    if not declared_mail:
        return []
    actual_mail = facts.mail_by_user.get(username)
    if actual_mail == declared_mail:
        return []
    return [
        redact(
            f"{label} declares mail {declared_mail!r} but "
            f"{_PROVISION_USERS_SCRIPT.name} sets {actual_mail!r} "
            "via `--mail=`"
        )
    ]


def _spn_parity_diagnostics(
    label: str, account: Account, username: str, facts: _ProvisionerFacts
) -> list[str]:
    """Report a declared SPN the provisioner never sets for this user."""
    declared_spn = account.spn
    if not declared_spn or declared_spn in facts.spns_by_user.get(username, frozenset()):
        return []
    return [
        redact(
            f"{label} declares spn {declared_spn!r} that "
            f"{_PROVISION_USERS_SCRIPT.name} never sets via "
            "`samba-tool spn add`"
        )
    ]


def _disabled_parity_diagnostics(
    label: str, account: Account, username: str, facts: _ProvisionerFacts
) -> list[str]:
    """Report a declared disabled state that doesn't match the provisioner's."""
    declared_disabled = bool(account.disabled)
    actual_disabled = username in facts.disabled_users
    if declared_disabled == actual_disabled:
        return []
    return [
        redact(
            f"{label} declares disabled={declared_disabled} but "
            f"{_PROVISION_USERS_SCRIPT.name} "
            + (
                "never runs `samba-tool user disable` for this user"
                if declared_disabled
                else "runs `samba-tool user disable` for this user"
            )
        )
    ]


def _outcome(diagnostics: list[str]) -> tuple[bool, tuple[str, ...]]:
    """Pack diagnostics into a ``(passed, diagnostics)`` pair for ``GateCheck``."""
    return (not diagnostics, tuple(diagnostics))
