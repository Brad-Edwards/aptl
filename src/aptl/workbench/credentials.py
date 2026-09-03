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
        self._leases: dict[tuple[object, str], dict[str, str]] = {}

    def prepare(
        self, profile: ProfileId, run_id: str, aliases: tuple[str, ...]
    ) -> Mapping[str, str]:
        """Create one lease containing model auth and selected service aliases."""
        return self.prepare_named(
            profile,
            run_id,
            (_MODEL_CREDENTIAL, *aliases),
        )

    def prepare_named(
        self,
        subject: object,
        run_id: str,
        names: tuple[str, ...],
    ) -> Mapping[str, str]:
        """Create one lease for an exact, caller-declared credential set."""

        if not names or len(set(names)) != len(names):
            raise WorkbenchCredentialError(
                "credential lease names must be unique and non-empty"
            )
        values: dict[str, str] = {}
        for name in names:
            if not isinstance(name, str) or not name:
                raise WorkbenchCredentialError(
                    "credential lease names must be unique and non-empty"
                )
            value = self._secret_source.get(name)
            if not value or contains_placeholder(value):
                raise WorkbenchCredentialError(
                    f"missing or placeholder workbench credential: {name}"
                )
            values[name] = value
        key = (subject, run_id)
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
        self.destroy_named(profile, run_id)

    def destroy_named(self, subject: object, run_id: str) -> None:
        """Drop a provider or profile lease without widening its identity."""

        lease = self._leases.pop((subject, run_id), None)
        if lease is not None:
            lease.clear()
