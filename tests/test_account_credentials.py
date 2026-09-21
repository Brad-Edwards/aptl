"""Declared credential classes must be realized, not silently substituted.

TechVault declares ``password_strength`` per account: seven weak, four medium,
three strong. Those are in-world facts — the weak ones are the credential
surface the scenario's attack path is built on. Realizing all fourteen with
``--random-password`` produces a range in which that surface does not exist,
and nothing failed to say so (issue #1006).
"""

from __future__ import annotations

import re
import stat

import pytest
from raes_contracts.planning import PlannedResource, RuntimeDomain

from aptl.backends.raes_account_realization import resolve_account_placement
from aptl.core.deployment import _account_credentials as credentials
from aptl.core.deployment import _account_provider as provider


def _resolve(spec: dict):
    resource = PlannedResource(
        address="provision.account-placement.x",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="account-placement",
        payload={"spec": spec},
    )
    return resolve_account_placement(
        resource=resource,
        payload={"spec": spec},
        target_address="scenario.node.ad",
        target_service="ad",
    )


class TestDeclaredStrengthSurvivesLowering:
    def test_declared_strength_reaches_the_realization_record(self):
        account, diagnostics = _resolve(
            {"username": "u", "node": "scenario.ad", "password_strength": "weak"}
        )
        assert diagnostics == []
        assert account is not None
        assert account.password_strength == "weak"
        # And it is reported back in the placement projection, so the declared
        # and realized class are visible to the runtime, not just to the backend.
        assert account.details()["password_strength"] == "weak"

    def test_absent_strength_takes_the_raes_default(self):
        account, diagnostics = _resolve({"username": "u", "node": "scenario.ad"})
        assert diagnostics == []
        assert account is not None
        assert account.password_strength == credentials.DEFAULT_PASSWORD_STRENGTH

    def test_unrealizable_strength_fails_closed(self):
        """`none` is a real RAES value this backend cannot make true."""
        account, diagnostics = _resolve(
            {"username": "u", "node": "scenario.ad", "password_strength": "none"}
        )
        assert account is None
        assert len(diagnostics) == 1
        assert "account-password-strength-unrealizable" in diagnostics[0].message

    def test_unknown_strength_fails_closed(self):
        account, diagnostics = _resolve(
            {"username": "u", "node": "scenario.ad", "password_strength": "medium-ish"}
        )
        assert account is None
        assert diagnostics


class TestMintedPasswordMatchesDeclaredClass:
    def test_weak_password_is_actually_weak(self):
        """A weak credential must fall to a wordlist plus a small mutation."""
        for _ in range(50):
            password = credentials.password_for_strength("weak")
            assert len(password) <= 12
            # A dictionary word with at most a short numeric or single-symbol
            # suffix — the shape a guessing attack actually finds.
            assert re.fullmatch(r"[A-Z][a-z]+(?:\d{1,4}|!)", password), password

    def test_medium_password_resists_a_plain_wordlist(self):
        for _ in range(50):
            password = credentials.password_for_strength("medium")
            assert len(password) >= 10
            assert re.search(r"\d", password)
            assert re.search(r"[^A-Za-z0-9]", password)
            # Not a bare dictionary word, so a plain wordlist misses it.
            assert not re.fullmatch(r"[A-Za-z]+\d{0,4}", password)

    def test_weak_and_medium_are_distinguishable(self):
        weak = {credentials.password_for_strength("weak") for _ in range(30)}
        medium = {credentials.password_for_strength("medium") for _ in range(30)}
        assert not (weak & medium)

    def test_strong_is_not_minted_here(self):
        """Strong stays target-generated, so this module refuses to invent one."""
        assert "strong" not in credentials.BACKEND_MINTED_STRENGTHS
        with pytest.raises(ValueError):
            credentials.password_for_strength("strong")


class TestCredentialDisclosure:
    def test_credential_is_written_range_private(self, tmp_path):
        password = credentials.password_for_strength("weak")

        target = credentials.disclose_account_credential(
            tmp_path,
            node="scenario.node.ad",
            username="michael.thompson",
            password=password,
            strength="weak",
        )

        assert target.read_text(encoding="utf-8") == f"weak\n{password}\n"
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700

    def test_path_traversal_in_an_identity_is_refused(self, tmp_path):
        with pytest.raises(ValueError):
            credentials.disclose_account_credential(
                tmp_path,
                node="../../etc",
                username="root",
                password="x",
                strength="weak",
            )


class TestProviderArgv:
    """Argv shape, exercised with a password the module under test minted.

    The value is minted rather than written here for two reasons: a
    credential-shaped literal in tracked source is a secret-scanner finding
    however fake it is, and a minted one is the value these helpers actually
    carry in a realized range.

    These assertions used to require the secret to BE in argv, as a discrete
    token. That keeps it out of shell syntax but not out of
    `/proc/<pid>/cmdline`, which is world-readable on the host through
    `docker exec ...` and readable by any process in the target. The contract
    is now the opposite: no argv element may carry it (issue #1105).
    """

    def test_setpassword_carries_no_secret_in_argv(self):
        password = credentials.password_for_strength("medium")

        argv = provider.samba_user_setpassword("bob")

        assert argv == ["samba-tool", "user", "setpassword", "bob"]
        assert all(password not in part for part in argv)

    def test_setpassword_answers_both_prompts_on_stdin(self):
        """samba-tool asks for the value and then asks again to confirm."""
        password = credentials.password_for_strength("medium")

        assert provider.samba_setpassword_input(password) == (
            f"{password}\n{password}\n"
        )

    def test_authentication_probe_carries_no_secret_in_argv(self):
        password = credentials.password_for_strength("medium")

        argv = provider.samba_user_authenticate()

        assert argv[0] == "smbclient"
        # The identity and its secret arrive through the authentication file.
        assert "-A" in argv
        assert argv[argv.index("-A") + 1] == "/dev/stdin"
        assert all(password not in part and "bob%" not in part for part in argv)

    def test_authentication_input_is_the_credentials_file_smbclient_reads(self):
        password = credentials.password_for_strength("weak")

        body = provider.samba_authenticate_input("bob", password)

        assert body == f"username=bob\npassword={password}\n"

    def test_realm_still_reaches_the_probe(self):
        argv = provider.samba_user_authenticate("TECHVAULT.LOCAL")

        assert argv[argv.index("-W") + 1] == "TECHVAULT.LOCAL"

    def test_policy_relaxation_permits_the_declared_weak_class(self):
        argv = provider.samba_domain_relax_password_policy()
        assert argv[:4] == ["samba-tool", "domain", "passwordsettings", "set"]
        assert "--complexity=off" in argv
        assert any(part.startswith("--min-pwd-length=") for part in argv)
