"""Docker Compose account-placement realization (issue #577, ADR-046 addendum).

Consumes ``DeploymentRealizationSpec.accounts`` and makes the declared
identity true on the resolved target through ``container_exec``: it ensures
declared groups, creates or reconciles each user, applies supported non-secret
attributes, reconciles group memberships, and then verifies the resulting
non-secret state by read-after-write. A zero exit code alone is not success.

Security posture (ADR-029 + ADR-046 addendum):

* the whole batch is validated before the first mutation (fail closed);
* credentials are generated inside the target boundary (``--random-password``)
  and never read back, logged, or placed on argv/env — an already-existing
  account is never re-created, so its provisioner-owned password is preserved;
* failures return a bounded :class:`LabResult` naming the placement address and
  a stable reason, never raw provider stdout/stderr.
"""

from __future__ import annotations

from collections.abc import Sequence

from aptl.core.deployment import _account_provider as provider
from aptl.core.deployment.realization import (
    DeploymentAccountRealization,
    DeploymentNodeRealization,
)
from aptl.core.lab_types import LabResult
from aptl.core.services import wait_for_service
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

log = get_logger("deployment.account_realization")

# The AD provider's healthcheck is `samba-tool domain info`; realization waits
# for the same bounded readiness before mutating. Generous because a fresh AD
# provisions its domain on first boot.
_READINESS_TIMEOUT = 300
_READINESS_INTERVAL = 5

# Per-command timeout for a single samba-tool invocation through container_exec.
_ACCOUNT_CMD_TIMEOUT = 60


class ComposeRealizationAccountMixin(object):
    """Realize typed ACES account placements through Docker Compose."""

    def realize_accounts(
        self,
        accounts: Sequence[DeploymentAccountRealization],
        nodes: Sequence[DeploymentNodeRealization],
        *,
        timeout: int | None = None,
    ) -> LabResult | None:
        """Realize account placements onto their resolved target nodes.

        Returns ``None`` on success (or when there is nothing to realize), so
        the caller's ``result is None`` chain continues — matching the
        image/network/content step shape. Returns a fail-closed
        :class:`LabResult` on validation, readiness, or verification failure.
        """

        if not accounts:
            return None
        targets, errors = provider.plan_account_targets(accounts, nodes)
        if errors:
            return _rejected(errors[0])
        return self._realize_targets(targets, timeout=timeout or _ACCOUNT_CMD_TIMEOUT)

    def _realize_targets(
        self,
        targets: Sequence[provider.AccountTarget],
        *,
        timeout: int,
    ) -> LabResult | None:
        """Realize each validated target batch; stop at the first failure."""

        for target in targets:
            result = self._realize_account_target(target, timeout=timeout)
            if result is not None:
                return result
        return None

    def _realize_account_target(
        self,
        target: provider.AccountTarget,
        *,
        timeout: int,
    ) -> LabResult | None:
        """Realize one validated batch against a single target container."""

        container = target.container_name
        if not self._account_provider_ready(container, timeout=timeout):
            return _failure(container, "account-provider-not-ready")
        self._ensure_groups(container, target.accounts, timeout=timeout)
        for account in target.accounts:
            reason = self._reconcile_account(container, account, timeout=timeout)
            if reason is not None:
                return _failure(account.address, reason)
        return self._verify_accounts(container, target.accounts, timeout=timeout)

    def _account_provider_ready(self, container: str, *, timeout: int) -> bool:
        """Wait until the AD provider is up AND its baseline provisioner is done.

        Two conditions, both required: the directory answers ``domain info`` (the
        service is serving) and the provisioning-complete marker exists (the
        service-owned baseline provisioner has finished). The second closes the
        clean-start race where the backend could otherwise create an account the
        provisioner is still installing, discarding the designed fixture
        credential this reconcile path promises to preserve.
        """

        def probe() -> bool:
            """True only when the directory serves AND baseline provisioning is done."""

            return self._probe_rc(
                container, provider.samba_domain_info(), timeout
            ) and self._probe_rc(
                container, provider.samba_provisioning_complete_probe(), timeout
            )

        result = wait_for_service(
            probe,
            _READINESS_TIMEOUT,
            _READINESS_INTERVAL,
            f"account-provider:{container}",
        )
        return result.ready

    def _probe_rc(self, container: str, cmd: list[str], timeout: int) -> bool:
        """Return True when a probe command returns a zero exit code."""

        return self.container_exec(container, cmd, timeout=timeout).returncode == 0

    def _ensure_groups(
        self,
        container: str,
        accounts: Sequence[DeploymentAccountRealization],
        *,
        timeout: int,
    ) -> None:
        """Create every declared group once, before any membership reconcile."""

        for group in provider.dedupe_groups(accounts):
            exists = self.container_exec(
                container, provider.samba_group_show(group), timeout=timeout
            )
            if exists.returncode != 0:
                self.container_exec(
                    container, provider.samba_group_add(group), timeout=timeout
                )

    def _reconcile_account(
        self,
        container: str,
        account: DeploymentAccountRealization,
        *,
        timeout: int,
    ) -> str | None:
        """Create-if-absent then converge the account's declared attributes.

        Returns a stable failure reason (stopping before any membership or
        attribute mutation) when the user could not be ensured, else ``None``.
        Only explicitly authored attributes are materialized (SEM-218): an
        omitted ``disabled`` / ``mail`` is left untouched so a benign placement
        cannot flip an existing account's state.
        """

        created, reason = self._ensure_user(container, account, timeout=timeout)
        if reason is not None:
            return reason
        self._apply_mail(container, account, created=created, timeout=timeout)
        self._apply_disabled(container, account, timeout=timeout)
        self._apply_spn(container, account, timeout=timeout)
        for group in account.groups:
            self.container_exec(
                container,
                provider.samba_group_addmembers(group, account.username),
                timeout=timeout,
            )
        return None

    def _ensure_user(
        self,
        container: str,
        account: DeploymentAccountRealization,
        *,
        timeout: int,
    ) -> tuple[bool, str | None]:
        """Create the user only when absent — never clobber an existing secret.

        Returns ``(created, reason)``: ``created`` is True when this call created
        the user (so ``mail`` was set atomically at create). ``reason`` is a
        stable failure key when the user does not exist after the create attempt
        — the caller must then stop before any membership mutation, so a failed
        or expanded create can never leave unauthorized state behind.
        """

        exists = self.container_exec(
            container, provider.samba_user_show(account.username), timeout=timeout
        )
        if exists.returncode == 0:
            return False, None
        self.container_exec(
            container,
            provider.samba_user_create(account.username, mail=account.mail),
            timeout=timeout,
        )
        confirmed = self.container_exec(
            container, provider.samba_user_show(account.username), timeout=timeout
        )
        if confirmed.returncode != 0:
            return False, "user-create-failed"
        return True, None

    def _apply_mail(
        self,
        container: str,
        account: DeploymentAccountRealization,
        *,
        created: bool,
        timeout: int,
    ) -> None:
        """Converge declared mail on an existing account (create already set it)."""

        if not account.mail or created:
            return
        self.container_exec(
            container,
            provider.samba_user_set_mail(account.username, account.mail),
            timeout=timeout,
        )

    def _apply_disabled(
        self,
        container: str,
        account: DeploymentAccountRealization,
        *,
        timeout: int,
    ) -> None:
        """Converge enabled/disabled state ONLY when the author declared it.

        When ``disabled`` was omitted (``None``) the account's state is left
        exactly as-is — an unrelated placement must never re-enable a suspended
        account or disable an active one.
        """

        if account.disabled is None:
            return
        command = (
            provider.samba_user_disable(account.username)
            if account.disabled
            else provider.samba_user_enable(account.username)
        )
        self.container_exec(container, command, timeout=timeout)

    def _apply_spn(
        self,
        container: str,
        account: DeploymentAccountRealization,
        *,
        timeout: int,
    ) -> None:
        """Add the declared SPN when it is not already present (idempotent)."""

        if not account.spn:
            return
        listed = self.container_exec(
            container, provider.samba_spn_list(account.username), timeout=timeout
        )
        already_present = listed.returncode == 0 and account.spn in _parse_spns(
            listed.stdout or ""
        )
        if not already_present:
            self.container_exec(
                container,
                provider.samba_spn_add(account.spn, account.username),
                timeout=timeout,
            )

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
