"""Unit tests for the pure account-provider logic (issue #577).

Covers provider binding resolution, batch validation before any mutation,
and the ``samba-tool`` argv builders. The central security invariant — no
credential ever appears in a built argv — is asserted directly: user creation
uses ``--random-password`` (target-side generation), never a positional secret.
"""

from __future__ import annotations

import pytest

from aptl.core.deployment import _account_provider as provider
from aptl.core.deployment.realization import (
    DeploymentAccountRealization,
    DeploymentNetworkAttachment,
    DeploymentNodeRealization,
)


def _node(
    *,
    address: str,
    name: str = "scenario.ad",
    service_name: str | None = "ad",
    container_name: str | None = "aptl-ad",
) -> DeploymentNodeRealization:
    return DeploymentNodeRealization(
        address=address,
        name=name,
        service_name=service_name,
        container_name=container_name,
        networks=(),
        network_attachments=(),
    )


def _account(
    *,
    address: str = "provision.account-placement.jessica",
    target_address: str = "scenario.node.ad",
    username: str = "jessica.williams",
    groups: tuple[str, ...] = (),
    spn: str = "",
    mail: str = "",
    disabled: bool = False,
) -> DeploymentAccountRealization:
    return DeploymentAccountRealization(
        address=address,
        target_address=target_address,
        username=username,
        groups=groups,
        spn=spn,
        mail=mail,
        disabled=disabled,
    )


class TestProviderBinding:
    def test_ad_service_binds_to_samba(self):
        assert provider.resolve_account_provider("ad") == provider.SAMBA_AD

    def test_unknown_service_has_no_provider(self):
        assert provider.resolve_account_provider("db") is None

    def test_none_service_has_no_provider(self):
        assert provider.resolve_account_provider(None) is None

    def test_interpret_time_service_set_matches_binding(self):
        # The interpret-time gate and the realize-time binding must share one
        # source of truth (ADR-046 §Extensibility): a single code-owned map.
        assert provider.account_provider_services() == frozenset({"ad"})


class TestPlanAccountTargets:
    def test_resolves_target_and_groups_by_container(self):
        node = _node(address="scenario.node.ad")
        accounts = (
            _account(username="jessica.williams", target_address="scenario.node.ad"),
            _account(
                address="provision.account-placement.emily",
                username="emily.chen",
                target_address="scenario.node.ad",
            ),
        )
        targets, errors = provider.plan_account_targets(accounts, (node,))
        assert errors == []
        assert len(targets) == 1
        assert targets[0].container_name == "aptl-ad"
        assert targets[0].provider == provider.SAMBA_AD
        assert {a.username for a in targets[0].accounts} == {
            "jessica.williams",
            "emily.chen",
        }

    def test_unresolved_target_node_fails_closed(self):
        node = _node(address="scenario.node.ad")
        accounts = (_account(target_address="scenario.node.missing"),)
        targets, errors = provider.plan_account_targets(accounts, (node,))
        assert targets == []
        assert [e.reason for e in errors] == ["unresolved-target-node"]
        assert errors[0].address == "provision.account-placement.jessica"

    def test_service_without_provider_fails_closed(self):
        node = _node(
            address="scenario.node.db", service_name="db", container_name="aptl-db"
        )
        accounts = (_account(target_address="scenario.node.db"),)
        targets, errors = provider.plan_account_targets(accounts, (node,))
        assert targets == []
        assert [e.reason for e in errors] == ["no-account-provider-for-service"]

    def test_node_without_container_fails_closed(self):
        node = _node(address="scenario.node.ad", container_name=None)
        accounts = (_account(target_address="scenario.node.ad"),)
        targets, errors = provider.plan_account_targets(accounts, (node,))
        assert targets == []
        assert [e.reason for e in errors] == ["target-node-has-no-container"]

    def test_ambiguous_target_address_fails_closed(self):
        nodes = (
            _node(address="scenario.node.ad", container_name="aptl-ad"),
            _node(address="scenario.node.ad", container_name="aptl-ad-2"),
        )
        accounts = (_account(target_address="scenario.node.ad"),)
        targets, errors = provider.plan_account_targets(accounts, nodes)
        assert targets == []
        assert [e.reason for e in errors] == ["ambiguous-target-node"]

    @pytest.mark.parametrize(
        "field_kwargs, reason",
        [
            ({"username": ""}, "invalid-username"),
            ({"username": "bad\x00user"}, "invalid-username"),
            ({"username": "bad\nuser"}, "invalid-username"),
            ({"username": "-injected"}, "invalid-username"),
            # Samba `group addmembers` reads its member arg as a comma-separated
            # list: a comma would expand one placement into several principals.
            ({"username": "weakuser,Administrator"}, "invalid-username"),
            ({"username": "has space"}, "invalid-username"),
            ({"groups": ("Sales", "bad\x01group")}, "invalid-group"),
            ({"groups": ("-opt",)}, "invalid-group"),
            ({"groups": ("A,B",)}, "invalid-group"),
            ({"mail": "a\x00b@x"}, "invalid-mail"),
            ({"mail": "a,b@x"}, "invalid-mail"),
            ({"spn": "-x/y"}, "invalid-spn"),
            ({"spn": "svc/a,svc/b"}, "invalid-spn"),
        ],
    )
    def test_rejects_unsafe_identity_values(self, field_kwargs, reason):
        node = _node(address="scenario.node.ad")
        accounts = (_account(target_address="scenario.node.ad", **field_kwargs),)
        targets, errors = provider.plan_account_targets(accounts, (node,))
        assert targets == []
        assert [e.reason for e in errors] == [reason]

    @pytest.mark.parametrize(
        "field_kwargs",
        [
            {"groups": ("Domain Admins",)},  # AD group names may contain spaces
            {"username": "svc-sql"},
            {"username": "jessica.williams"},
            {"mail": "jessica.williams@techvault.local"},
            {"spn": "MSSQLSvc/db.techvault.local:1433"},
        ],
    )
    def test_accepts_valid_provider_identifiers(self, field_kwargs):
        node = _node(address="scenario.node.ad")
        accounts = (_account(target_address="scenario.node.ad", **field_kwargs),)
        targets, errors = provider.plan_account_targets(accounts, (node,))
        assert errors == []
        assert len(targets) == 1

    def test_conflicting_duplicate_username_fails_closed(self):
        node = _node(address="scenario.node.ad")
        accounts = (
            _account(username="dup", mail="a@x", target_address="scenario.node.ad"),
            _account(
                address="provision.account-placement.dup2",
                username="dup",
                mail="b@x",
                target_address="scenario.node.ad",
            ),
        )
        targets, errors = provider.plan_account_targets(accounts, (node,))
        assert targets == []
        assert [e.reason for e in errors] == ["conflicting-duplicate-account"]

    def test_case_insensitive_conflicting_duplicate_fails_closed(self):
        # AD principal names are case-insensitive: Former.Employee and
        # former.employee are the same account, so conflicting declarations
        # under different case must be caught, not silently both applied.
        node = _node(address="scenario.node.ad")
        accounts = (
            _account(
                username="Former.Employee",
                disabled=True,
                target_address="scenario.node.ad",
            ),
            _account(
                address="provision.account-placement.fe2",
                username="former.employee",
                disabled=False,
                target_address="scenario.node.ad",
            ),
        )
        targets, errors = provider.plan_account_targets(accounts, (node,))
        assert targets == []
        assert [e.reason for e in errors] == ["conflicting-duplicate-account"]

    def test_identical_duplicate_username_is_not_a_conflict(self):
        node = _node(address="scenario.node.ad")
        acct = _account(username="dup", target_address="scenario.node.ad")
        targets, errors = provider.plan_account_targets((acct, acct), (node,))
        assert errors == []
        assert len(targets) == 1


class TestSambaCommandBuilders:
    def test_user_create_uses_random_password_never_positional_secret(self):
        cmd = provider.samba_user_create("jessica.williams")
        assert cmd == [
            "samba-tool",
            "user",
            "create",
            "jessica.williams",
            "--random-password",
        ]

    def test_user_create_sets_mail_when_declared(self):
        cmd = provider.samba_user_create(
            "emily.chen", mail="emily.chen@techvault.local"
        )
        assert cmd == [
            "samba-tool",
            "user",
            "create",
            "emily.chen",
            "--random-password",
            "--mail-address=emily.chen@techvault.local",
        ]

    def test_user_set_mail_updates_existing_without_rename_or_secret(self):
        cmd = provider.samba_user_set_mail("jessica.williams", "j@techvault.local")
        assert cmd == [
            "samba-tool",
            "user",
            "rename",
            "jessica.williams",
            "--mail-address=j@techvault.local",
        ]
        # No new username positional and no password token: mail-only update.
        assert all(not t.startswith("--random-password") for t in cmd)

    def test_group_and_membership_builders(self):
        assert provider.samba_group_show("Sales") == [
            "samba-tool",
            "group",
            "show",
            "Sales",
        ]
        assert provider.samba_group_add("Sales") == [
            "samba-tool",
            "group",
            "add",
            "Sales",
        ]
        assert provider.samba_group_addmembers("Sales", "jessica.williams") == [
            "samba-tool",
            "group",
            "addmembers",
            "Sales",
            "jessica.williams",
        ]
        assert provider.samba_group_listmembers("Sales") == [
            "samba-tool",
            "group",
            "listmembers",
            "Sales",
        ]

    def test_user_show_disable_enable_and_spn_builders(self):
        assert provider.samba_user_show("svc-sql") == [
            "samba-tool",
            "user",
            "show",
            "svc-sql",
        ]
        assert provider.samba_user_disable("former.employee") == [
            "samba-tool",
            "user",
            "disable",
            "former.employee",
        ]
        assert provider.samba_user_enable("former.employee") == [
            "samba-tool",
            "user",
            "enable",
            "former.employee",
        ]
        assert provider.samba_spn_add("MSSQLSvc/db:1433", "svc-sql") == [
            "samba-tool",
            "spn",
            "add",
            "MSSQLSvc/db:1433",
            "svc-sql",
        ]
        assert provider.samba_spn_list("svc-sql") == [
            "samba-tool",
            "spn",
            "list",
            "svc-sql",
        ]

    def test_domain_info_probe_builder(self):
        assert provider.samba_domain_info() == [
            "samba-tool",
            "domain",
            "info",
            "127.0.0.1",
        ]

    def test_provisioning_complete_probe_builder(self):
        # Explicit provisioner-complete gate: the marker setup-ad.sh writes
        # AFTER provision-users.sh, so a still-absent account is authoritative.
        assert provider.samba_provisioning_complete_probe() == [
            "test",
            "-f",
            "/var/lib/samba/private/.provisioned",
        ]

    def test_no_builder_output_carries_a_password_token(self):
        # Defense in depth: none of the builders may emit a credential. The
        # weak fixture passwords live only in provision-users.sh; realization
        # never reproduces them.
        weak_passwords = {"password123", "Summer2024", "Welcome1!", "SqlService2024!"}
        built = [
            provider.samba_user_create("jessica.williams", mail="j@x"),
            provider.samba_group_add("Sales"),
            provider.samba_group_addmembers("Sales", "jessica.williams"),
            provider.samba_spn_add("MSSQLSvc/db:1433", "svc-sql"),
            provider.samba_user_disable("former.employee"),
        ]
        for cmd in built:
            for token in cmd:
                assert token not in weak_passwords
                assert "--password" not in token
