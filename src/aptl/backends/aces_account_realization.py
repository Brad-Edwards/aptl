"""Resolve ACES account-placement payloads into deployment account evidence.

Issue #689 / ADR-046's TechVault addendum: an `account-placement` resource
must lower into typed realization evidence (:class:`DeploymentAccountRealization`)
or fail closed with an error diagnostic. Unlike content, accounts carry no
secret material and need no new backend operation — the concrete credential
stays owned by the target node's service-owned provisioner
(``containers/ad/provision-users.sh``, which already runs unconditionally as
part of the `ad` container's entrypoint). Realization here is a narrow,
honest claim: the declared account's target node resolves to a backend
service APTL knows actually provisions accounts. A placement that targets
any other node is unrealizable and fails closed before the account is
recorded as realized.
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
from aptl.core.deployment.realization import DeploymentAccountRealization

# Backend services with an existing service-owned account provisioner.
# Adding a new account-capable service is one new entry here, not a
# scenario-name branch (ADR-046 §Extensibility).
_ACCOUNT_PROVISIONER_SERVICES = frozenset({"ad"})


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
            disabled=bool(_optional_bool(spec, "disabled")),
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
