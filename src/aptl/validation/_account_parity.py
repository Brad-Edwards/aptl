"""SDL<->provisioner account parity check (ADR-046 TechVault addendum, #689).

Split out of ``_gate_checks.py`` to keep that module under the file-length
gate. ``techvault_gate.validate_scenario`` calls it here directly (step 6).

Parity is checked against the admitted provisioning realization. It used to
have a second path that scraped a checked-in ``provision-users.sh`` from the
``ad`` image, but the pack no longer declares that image and nothing builds
it, so there is no checked-in script to compare against (issue #1006).
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from raes.accounts import Account
from raes.scenario import Scenario

from aptl.utils.redaction import redact
from aptl.validation.techvault_gate import GateCheck



def check_account_provisioner_parity(
    *,
    scenario: Scenario,
    project_dir: Path,
    realization_details: Mapping[str, object] | None = None,
) -> GateCheck:
    """Confirm every SDL-declared account attribute is realization-authoritative.

    Account declarations are honest only when the clean-start path actually
    creates them, with the same groups/mail/SPN/disabled state (ADR-046
    TechVault Operational Standup Addendum, issue #689). This never runs
    Docker or ``samba-tool``: it compares each authored account against the
    admitted provisioning realization, so SDL<->realization drift is caught
    before ``aptl lab start`` rather than discovered live.

    Each SDL account (``scenario.accounts``) must have an admitted
    account placement on its declared node whose ``username``, ``groups``,
    ``mail``, ``spn`` and ``disabled`` match the declaration.

    Without an admitted realization there is nothing to compare against, so
    the check fails closed rather than passing silently.
    """
    if realization_details is None:
        return GateCheck(
            "account_provisioner_parity",
            False,
            (
                "no admitted provisioning realization to check accounts against; "
                f"account parity is unverifiable for {project_dir}",
            ),
        )

    diagnostics = _realized_account_parity(scenario, realization_details)
    return GateCheck("account_provisioner_parity", *_outcome(diagnostics))


def _realized_account_parity(
    scenario: Scenario, realization_details: Mapping[str, object]
) -> list[str]:
    """Compare authored accounts with the admitted backend account placements."""

    placements = realization_details.get("placements")
    rows = placements if isinstance(placements, list) else []
    by_name = {
        str(row.get("name")): row
        for row in rows
        if isinstance(row, dict)
        and row.get("resource_type") == "account-placement"
        and isinstance(row.get("account"), dict)
    }
    diagnostics: list[str] = []
    for name, account in scenario.accounts.items():
        diagnostics.extend(
            _realized_account_diagnostics(name, account, by_name.get(name))
        )
    return diagnostics


def _realized_account_diagnostics(
    name: str, account: Account, row: object
) -> list[str]:
    """Compare one authored account to its admitted placement projection."""

    if not isinstance(row, dict):
        return [redact(f"SDL account {name!r} has no admitted account placement")]
    realized = row["account"]
    assert isinstance(realized, dict)
    expected = {
        "username": account.username,
        "groups": sorted(account.groups),
        "mail": account.mail,
        "spn": account.spn,
        "disabled": bool(account.disabled),
    }
    actual = {
        "username": realized.get("username"),
        "groups": sorted(realized.get("groups") or []),
        "mail": realized.get("mail"),
        "spn": realized.get("spn"),
        "disabled": realized.get("disabled"),
    }
    diagnostics = []
    if row.get("target_node") != f"provision.node.{account.node}":
        diagnostics.append(
            redact(
                f"SDL account {name!r} has a mismatched admitted account-placement target_node"
            )
        )
    diagnostics.extend(
        redact(
            f"SDL account {name!r} has a mismatched admitted "
            f"account-placement field {field_name!r}"
        )
        for field_name, expected_value in expected.items()
        if actual[field_name] != expected_value
    )
    return diagnostics


def _outcome(diagnostics: list[str]) -> tuple[bool, tuple[str, ...]]:
    """Pack diagnostics into a ``(passed, diagnostics)`` pair for ``GateCheck``."""
    return (not diagnostics, tuple(diagnostics))
