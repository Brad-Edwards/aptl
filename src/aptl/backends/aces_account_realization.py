"""Resolve ACES account-placement payloads into typed realization records.

An `account-placement` resource lowers into a typed
:class:`DeploymentAccountRealization` here, or fails closed with an error
diagnostic when its target node has no registered account provider. This is the
interpret-time half of account realization: #577 (ADR-046 Account and Identity
Realization Addendum) makes the record load-bearing — the deployment backend's
``realize_accounts`` operation ensures the declared groups, users, memberships,
and non-secret attributes on the resolved target and verifies them by
read-after-write. The record carries non-secret identity only; the concrete
credential is generated inside the target/provider boundary and never crosses
this record (ADR-029). The set of services that have an account provider is
owned by a single code-owned binding (:mod:`aptl.core.deployment._account_provider`),
so this gate and the materializer never diverge.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aces_contracts.diagnostics import Diagnostic
from aces_contracts.planning import PlannedResource

from aptl.backends.aces_diagnostics import diagnostic
from aptl.backends.aces_realization_values import (
    account_groups as _account_groups,
    optional_bool as _optional_bool,
    optional_string as _optional_string,
    placement_spec as _placement_spec,
)
from aptl.core.deployment._account_provider import account_provider_services
from aptl.core.deployment.realization import DeploymentAccountRealization

# Backend services with a registered account provider. Single source of truth
# with the realize-time materializer's binding (ADR-046 §Extensibility): adding
# a new account-capable service is one entry in ``_account_provider``, never a
# scenario-name branch here.
_ACCOUNT_PROVISIONER_SERVICES = account_provider_services()


def resolve_account_placement(
    *,
    resource: PlannedResource,
    payload: Mapping[str, Any],
    target_address: str,
    target_service: str | None,
) -> tuple[DeploymentAccountRealization | None, list[Diagnostic]]:
    """Lower one account-placement resource or return fail-closed diagnostics."""

    spec = _placement_spec(payload)
    username = _optional_string(spec, "username") if spec is not None else None
    reason = _account_placement_rejection(spec, username, target_service)

    account: DeploymentAccountRealization | None = None
    diagnostics: list[Diagnostic] = []
    if reason is not None:
        diagnostics = [_reject(resource.address, reason)]
    else:
        account = DeploymentAccountRealization(
            address=resource.address,
            target_address=target_address,
            username=username,
            groups=_account_groups(spec),
            spn=_optional_string(spec, "spn") or "",
            mail=_optional_string(spec, "mail") or "",
            # Preserve author explicitness (SEM-218, ADR-046 addendum): None when
            # the author omitted `disabled`, so the backend never flips an
            # existing account's enabled state on an unrelated placement.
            disabled=_optional_bool(spec, "disabled"),
        )
    return account, diagnostics


def _account_placement_rejection(
    spec: Mapping[str, Any] | None,
    username: str | None,
    target_service: str | None,
) -> str | None:
    """Return the first fail-closed rejection reason for an account placement.

    None means the placement passed every policy check.
    """

    reason = None
    if spec is None:
        reason = "invalid-account-spec"
    elif username is None:
        reason = "account-missing-username"
    elif target_service is None or target_service not in _ACCOUNT_PROVISIONER_SERVICES:
        reason = "no-account-provisioner-for-target"
    return reason


def _reject(address: str, reason_code: str) -> Diagnostic:
    """Build a fail-closed account realization diagnostic."""

    return diagnostic(
        "aptl.provisioner.account-placement-rejected",
        address,
        (
            "ACES account placement was rejected by the APTL account "
            f"realization policy (reason={reason_code})."
        ),
    )
