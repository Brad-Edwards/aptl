"""Management-only, session-scoped credential leases for the workbench."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from aptl.utils.placeholders import contains_placeholder
from aptl.workbench.profiles import ProfileId

_MODEL_CREDENTIAL = "ANTHROPIC_API_KEY"


class WorkbenchCredentialError(ValueError):
    """A selected profile cannot obtain a complete, non-placeholder lease."""


class EphemeralCredentialBroker:
    """Issue minimal per-profile leases from a management-owned secret source."""

    def __init__(self, secret_source: Mapping[str, str]) -> None:
        self._secret_source = dict(secret_source)
        self._leases: dict[tuple[ProfileId, str], dict[str, str]] = {}

    def prepare(
        self, profile: ProfileId, run_id: str, aliases: tuple[str, ...]
    ) -> Mapping[str, str]:
        """Create one lease containing model auth and selected service aliases."""
        names = (_MODEL_CREDENTIAL, *aliases)
        values: dict[str, str] = {}
        for name in names:
            value = self._secret_source.get(name)
            if not value or contains_placeholder(value):
                raise WorkbenchCredentialError(
                    f"missing or placeholder workbench credential: {name}"
                )
            values[name] = value
        key = (profile, run_id)
        if key in self._leases:
            raise WorkbenchCredentialError("credential lease already exists")
        self._leases[key] = values
        return MappingProxyType(values)

    def lease(self, profile: ProfileId, run_id: str) -> Mapping[str, str]:
        """Return an existing lease without widening it."""
        try:
            return MappingProxyType(self._leases[(profile, run_id)])
        except KeyError as exc:
            raise WorkbenchCredentialError("no active credential lease") from exc

    def destroy(self, profile: ProfileId, run_id: str) -> None:
        """Drop all references held by the active profile lease."""
        lease = self._leases.pop((profile, run_id), None)
        if lease is not None:
            lease.clear()
