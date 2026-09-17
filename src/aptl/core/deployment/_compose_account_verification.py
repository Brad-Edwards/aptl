"""Read-after-write verification of realized account placements.

A zero exit code from ``samba-tool`` says the directory accepted a write, not
that the declared state is true. This module reads each realized account back
and certifies the declared, explicitly-authored non-secret state — attributes,
group memberships, SPNs — against what the scenario asked for, and speaks the
bounded :class:`LabResult` vocabulary the realization path fails closed with.

Split out of ``_compose_account_realization`` so neither half outgrows a file
a reader can hold in their head.
"""

from __future__ import annotations

from collections.abc import Sequence

from aptl.core.deployment import _account_provider as provider
from aptl.core.deployment.realization import DeploymentAccountRealization
from aptl.core.lab_types import LabResult
from aptl.utils.redaction import redact


class ComposeAccountVerificationMixin(object):
    """Certify that a realized account matches its declaration."""

    def _verify_accounts(
        self,
        container: str,
        accounts: Sequence[DeploymentAccountRealization],
        *,
        timeout: int,
    ) -> LabResult | None:
        """Read-after-write: confirm declared non-secret state actually landed."""

        for account in accounts:
            reason = self._verify_account(container, account, timeout=timeout)
            if reason is not None:
                return _failure(account.address, reason)
        return None

    def _verify_account(
        self,
        container: str,
        account: DeploymentAccountRealization,
        *,
        timeout: int,
    ) -> str | None:
        """Return a stable failure reason for one account, or None when verified.

        Each aspect is verified by an exact, field-aware read; ``or`` short-circuits
        so a later read only runs once the earlier ones pass.
        """

        shown = self.container_exec(
            container, provider.samba_user_show(account.username), timeout=timeout
        )
        if shown.returncode != 0:
            return "user-not-found-after-realize"
        reason = _verify_attributes(shown.stdout or "", account)
        reason = reason or self._verify_memberships(container, account, timeout=timeout)
        return reason or self._verify_spn(container, account, timeout=timeout)

    def _verify_memberships(
        self,
        container: str,
        account: DeploymentAccountRealization,
        *,
        timeout: int,
    ) -> str | None:
        """Verify exact, case-insensitive membership in every declared group."""

        member = provider.canonical_principal(account.username)
        for group in account.groups:
            members = self.container_exec(
                container, provider.samba_group_listmembers(group), timeout=timeout
            )
            if members.returncode != 0 or member not in _parse_members(
                members.stdout or ""
            ):
                return "declared-group-membership-missing"
        return None

    def _verify_spn(
        self,
        container: str,
        account: DeploymentAccountRealization,
        *,
        timeout: int,
    ) -> str | None:
        """Verify the declared SPN is present by exact match (when one is declared)."""

        if not account.spn:
            return None
        listed = self.container_exec(
            container, provider.samba_spn_list(account.username), timeout=timeout
        )
        if listed.returncode != 0 or account.spn not in _parse_spns(
            listed.stdout or ""
        ):
            return "declared-spn-not-set"
        return None


def _verify_attributes(
    user_show_stdout: str,
    account: DeploymentAccountRealization,
) -> str | None:
    """Verify the declared, explicitly-authored non-secret attributes from `user show`."""

    if account.mail and _show_attr(user_show_stdout, "mail") != account.mail:
        return "declared-mail-not-set"
    if (
        account.disabled is not None
        and _parse_disabled(user_show_stdout) != account.disabled
    ):
        return "declared-disabled-state-not-set"
    return None


# ACCOUNTDISABLE bit in the AD userAccountControl attribute (512 = enabled
# NORMAL_ACCOUNT, 514 = disabled). samba-tool has no direct enabled/disabled
# read-out, so the verifier parses this value from `samba-tool user show`.
_ACCOUNTDISABLE = 0x2


def _parse_disabled(user_show_stdout: str) -> bool | None:
    """Return the account's disabled state from `samba-tool user show`, or None."""

    raw = _show_attr(user_show_stdout, "userAccountControl")
    if raw is None:
        return None
    try:
        return bool(int(raw) & _ACCOUNTDISABLE)
    except ValueError:
        return None


def _show_attr(user_show_stdout: str, attr: str) -> str | None:
    """Return the exact value of one attribute from `samba-tool user show`.

    Parses the ``attr: value`` line and returns the value verbatim, so
    verification compares an exact field rather than searching raw stdout (which
    would let a superstring or an unrelated attribute falsely certify state).
    """

    for line in user_show_stdout.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip().casefold() == attr.casefold():
            return value.strip()
    return None


def _parse_members(listmembers_stdout: str) -> set[str]:
    """Return the canonical membership set from `samba-tool group listmembers`.

    Each output line is exactly one member's account name, so membership is an
    exact per-line match (case-insensitive) — never a whitespace-token search,
    which would let a requested ``Admin`` match a member ``Alice Admin``.
    """

    return {
        line.strip().casefold()
        for line in listmembers_stdout.splitlines()
        if line.strip()
    }


def _parse_spns(spn_list_stdout: str) -> set[str]:
    """Return the exact SPN set from `samba-tool spn list`.

    SPN lines carry a ``service/host`` form; the DN/header lines do not contain
    ``/``. Exact-matching each SPN keeps a declared ``MSSQLSvc/db:1433`` from being
    certified by an unrelated ``MSSQLSvc/db:14330`` (Kerberos treats a superstring
    as a different principal).
    """

    return {line.strip() for line in spn_list_stdout.splitlines() if "/" in line}


def _rejected(error: provider.AccountPlanError) -> LabResult:
    """Bounded fail-closed result for a batch-validation rejection."""

    return LabResult(
        success=False,
        error=redact(
            f"Account realization rejected at {error.address}: {error.reason}"
        ),
    )


def _failure(address: str, reason: str) -> LabResult:
    """Bounded fail-closed result naming the placement address and stable reason."""

    return LabResult(
        success=False,
        error=redact(f"Account realization failed at {address}: {reason}"),
    )
