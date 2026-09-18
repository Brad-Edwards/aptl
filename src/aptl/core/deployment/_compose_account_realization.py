"""Docker Compose account-placement realization (issue #577, ADR-046 addendum).

Consumes ``DeploymentRealizationSpec.accounts`` and makes the declared
identity true on the resolved target through ``container_exec``: it ensures
declared groups, creates or reconciles each user, applies supported non-secret
attributes, reconciles group memberships, and then verifies the resulting
non-secret state by read-after-write. A zero exit code alone is not success.

Security posture (ADR-029 + ADR-046 addendum):

* the whole batch is validated before the first mutation (fail closed);
* a ``strong`` account's credential is generated inside the target boundary
  (``--random-password``) and never read back or logged, and an already-existing
  account is never re-created, so its provisioner-owned password is preserved;
* a ``weak`` or ``medium`` account gets a backend-minted credential of the
  declared class, proved by authenticating as that account and disclosed only to
  the operator's range-private directory — the scenario declares that credential
  as the surface an attacker is meant to find (issue #1006);
* failures return a bounded :class:`LabResult` naming the placement address and
  a stable reason, never raw provider stdout/stderr.
"""

from __future__ import annotations

from collections.abc import Sequence

from aptl.core.deployment import _account_credentials as credentials
from aptl.core.deployment import _account_provider as provider
from aptl.core.deployment._compose_account_verification import (
    ComposeAccountVerificationMixin,
    _failure,
    _parse_spns,
    _rejected,
)
from aptl.core.deployment.realization import (
    DeploymentAccountRealization,
    DeploymentNodeRealization,
)
from aptl.core.lab_types import LabResult
from aptl.core.services import wait_for_service
from aptl.utils.logging import get_logger

log = get_logger("deployment.account_realization")

# The AD provider's healthcheck is `samba-tool domain info`; realization waits
# for the same bounded readiness before mutating. Generous because a fresh AD
# provisions its domain on first boot.
_READINESS_TIMEOUT = 300
_READINESS_INTERVAL = 5

# Per-command timeout for a single samba-tool invocation through container_exec.
_ACCOUNT_CMD_TIMEOUT = 60


class ComposeRealizationAccountMixin(ComposeAccountVerificationMixin):
    """Realize typed RAES account placements through Docker Compose."""

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
        unprepared = self._prepare_account_target(target, timeout=timeout)
        if unprepared is not None:
            return unprepared
        for account in target.accounts:
            reason = self._reconcile_account(container, account, timeout=timeout)
            if reason is not None:
                return _failure(account.address, reason)
        return self._verify_accounts(container, target.accounts, timeout=timeout)

    def _prepare_account_target(
        self,
        target: provider.AccountTarget,
        *,
        timeout: int,
    ) -> LabResult | None:
        """Ready the target: provider up, policy permitting, groups present."""

        container = target.container_name
        if not self._account_provider_ready(container, timeout=timeout):
            return _failure(container, "account-provider-not-ready")
        reason = self._permit_declared_weak_credentials(
            container, target.accounts, timeout=timeout
        )
        if reason is not None:
            return _failure(container, reason)
        self._ensure_groups(container, target.accounts, timeout=timeout)
        return None

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

    def _permit_declared_weak_credentials(
        self,
        container: str,
        accounts: Sequence[DeploymentAccountRealization],
        *,
        timeout: int,
    ) -> str | None:
        """Relax the domain policy only when the batch declares a weak credential.

        Samba's default policy can refuse the credentials a scenario declares as
        its guessing surface, so without this the declared weak class cannot be
        made true. It is applied once per target and only for a declared `weak`
        account: medium credentials already satisfy the default policy, so a
        medium or strong batch never weakens the domain (issue #1006).
        """

        if not any(account.password_strength == credentials.WEAK for account in accounts):
            return None
        applied = self.container_exec(
            container, provider.samba_domain_relax_password_policy(), timeout=timeout
        )
        if applied.returncode != 0:
            return "account-password-policy-not-applied"
        return None

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
        reason = self._apply_password(
            container, account, created=created, timeout=timeout
        )
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

    def _apply_password(
        self,
        container: str,
        account: DeploymentAccountRealization,
        *,
        created: bool,
        timeout: int,
    ) -> str | None:
        """Make the account's declared credential class true, or fail closed.

        A ``strong`` account keeps the target-generated secret from create. A
        ``weak`` or ``medium`` account is the scenario's declared credential
        surface, so the backend mints a password of that class, sets it, and
        proves it by authenticating as the account.

        An existing account is left alone only when the backend can still prove
        the declared class is true of it — the disclosed credential says that
        class and still authenticates. Skipping on existence alone accepted an
        unknown, strong, or unusable secret as the declared attack surface, and
        made a partial failure permanent: if the set succeeded but the proof or
        the disclosure did not, the account existed, so every later run skipped
        it and reported success over a credential nobody held (issue #1105).
        """

        strength = account.password_strength
        if strength not in credentials.BACKEND_MINTED_STRENGTHS:
            return None
        if not created and self._retained_credential_is_current(
            container, account, strength, timeout=timeout
        ):
            return None
        password = credentials.password_for_strength(strength)
        unproven = self._set_and_prove_password(
            container, account, password, timeout=timeout
        )
        if unproven is not None:
            return unproven
        return self._disclose_password(account, password, strength)

    def _retained_credential_is_current(
        self,
        container: str,
        account: DeploymentAccountRealization,
        strength: str,
        *,
        timeout: int,
    ) -> bool:
        """Whether the disclosed credential still proves the declared class.

        Evidence, not assumption: the disclosed record has to name the declared
        class and the secret has to still authenticate as the account. Anything
        else — no record, a record of another class, a secret the directory now
        refuses — means the declared class is not established, so the caller
        realizes it rather than inheriting whatever is there.
        """

        retained = credentials.read_disclosed_credential(
            self.realization_root,
            node=account.target_address,
            username=account.username,
        )
        if retained is None or retained[0] != strength:
            return False
        proof = self.container_exec_with_input(
            container,
            provider.samba_user_authenticate(),
            provider.samba_authenticate_input(account.username, retained[1]),
            timeout=timeout,
        )
        return proof.returncode == 0

    def _set_and_prove_password(
        self,
        container: str,
        account: DeploymentAccountRealization,
        password: str,
        *,
        timeout: int,
    ) -> str | None:
        """Set the minted password, then prove it authenticates as the account.

        Both halves send the secret on stdin. Through ``container_exec`` it
        would also land in the host's ``docker exec ...`` argv, where
        ``/proc/<pid>/cmdline`` is world-readable (issue #1105).
        """

        applied = self.container_exec_with_input(
            container,
            provider.samba_user_setpassword(account.username),
            provider.samba_setpassword_input(password),
            timeout=timeout,
        )
        if applied.returncode != 0:
            return "account-password-not-applied"
        proof = self.container_exec_with_input(
            container,
            provider.samba_user_authenticate(),
            provider.samba_authenticate_input(account.username, password),
            timeout=timeout,
        )
        if proof.returncode != 0:
            # The directory accepted the write but the credential does not
            # authenticate, so the declared account is not actually usable.
            return "account-password-not-authenticable"
        return None

    def _disclose_password(
        self,
        account: DeploymentAccountRealization,
        password: str,
        strength: str,
    ) -> str | None:
        """Write the minted credential where only the operator can read it."""

        try:
            credentials.disclose_account_credential(
                self.realization_root,
                node=account.target_address,
                username=account.username,
                password=password,
                strength=strength,
            )
        except (OSError, ValueError):
            return "account-credential-not-disclosed"
        return None

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
