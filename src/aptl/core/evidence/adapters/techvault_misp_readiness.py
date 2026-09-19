"""Native MISP authenticated-readiness evidence for the TechVault scenario.

The released pack's ``misp-authenticated-api-readiness`` requirement asks for
four separate facts on a clean realization: the canonical URL MISP is reached
at and whether its certificate verified, an authenticated API write followed by
a read of what was written, the declared database identity reached through the
declared application role, and authenticated access to the cache together with
the persistence policy the pack declared for it.

They are separate on purpose. A login page proves none of them; an
authenticated API call proves the application and its credential but not the
stores behind it; a reachable cache proves neither authentication nor policy.
This source refuses to collapse them, and refuses to report readiness when any
one is missing, anonymous, substituted or self-contradictory.

"Substituted" is the reason the observed identities are compared with the
admitted ones rather than merely checked for content. A database reached as
some other role, or a cache running some other eviction policy, is a service
that answers -- it is just not the service the scenario admitted, and reporting
it as ready would hide exactly the drift this evidence exists to catch.

Only bounded statuses, stable identities and correlation ids leave this
boundary. No credential value, configuration body, certificate path or native
response payload is recorded.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from aptl.core.evidence.adapters.sources import SourceResult
from aptl.core.evidence.outcomes import CollectorStatus

_MAX_READINESS_BYTES = 256 * 1024

#: Every fact the pack's scope requires, and the type each one must carry. A
#: payload missing a key, or carrying the wrong shape for one, is contradictory
#: rather than partially ready.
_REQUIRED_FIELDS: Mapping[str, type | tuple[type, ...]] = {
    "canonical_url": str,
    "certificate_verified": bool,
    "api_write_read_ok": bool,
    "api_correlation_id": str,
    "database_identity": str,
    "database_role": str,
    "database_role_access_ok": bool,
    "cache_authenticated": bool,
    "cache_persistence_policy": str,
    "cache_eviction_policy": str,
}

#: The facts that must all be true before readiness is reported. A false value
#: here is a definite negative, not a missing observation, so it fails closed
#: rather than degrading.
_REQUIRED_TRUE = (
    "certificate_verified",
    "api_write_read_ok",
    "database_role_access_ok",
    "cache_authenticated",
)

#: Facts that must be present but have no admitted counterpart to compare with:
#: the correlation id is generated per capture, by definition.
_NON_EMPTY = ("api_correlation_id",)


@dataclass(frozen=True)
class AdmittedMispState:
    """The values the admitted plan says the probes must observe.

    Every field is compared exactly. These come from the realization and the
    released pack, never from a default in this module, so a scenario that
    admits different values is checked against those.
    """

    canonical_url: str
    database_identity: str
    database_role: str
    cache_persistence_policy: str
    cache_eviction_policy: str

    def mismatches(self, observed: Mapping[str, object]) -> tuple[str, ...]:
        """Return the names of every observed value that is not the admitted one."""

        return tuple(
            name
            for name, expected in (
                ("canonical_url", self.canonical_url),
                ("database_identity", self.database_identity),
                ("database_role", self.database_role),
                ("cache_persistence_policy", self.cache_persistence_policy),
                ("cache_eviction_policy", self.cache_eviction_policy),
            )
            if str(observed.get(name, "")) != expected
        )


class MispAuthenticatedApiReadinessSource:
    """Project one bounded MISP/database/cache readiness observation."""

    def __init__(
        self,
        query: Callable[[str, str], Mapping[str, object] | None],
        admitted: AdmittedMispState,
    ) -> None:
        """Bind the trusted query owner and the state the plan admitted."""

        self._query = query
        self._admitted = admitted

    def fetch(self, start_iso: str, end_iso: str) -> SourceResult:
        payload = self._query(start_iso, end_iso)
        raw = _readiness_document(payload, self._admitted)
        if raw is None:
            status = (
                CollectorStatus.SOURCE_UNAVAILABLE
                if payload is None
                else CollectorStatus.MID_RUN_LOSS
            )
            return _failure(status)
        return SourceResult(
            status=CollectorStatus.OK,
            chunks=(raw,),
            media_type="application/json",
            source_pipeline={
                "source_refs": [
                    {"ref_kind": "other", "ref_id": ref}
                    for ref in (
                        "nodes.misp.runtime.platform_applications."
                        "misp-threat-intelligence",
                        "nodes.misp-db.runtime.database_services.misp-db",
                        "nodes.misp-redis.runtime.datastore_services.misp-redis",
                    )
                ]
            },
        )


def _readiness_document(
    payload: Mapping[str, object] | None, admitted: AdmittedMispState
) -> bytes | None:
    """Encode one complete, admitted readiness payload within its bound."""

    if (
        payload is None
        or not _valid_readiness_payload(payload)
        or admitted.mismatches(payload)
    ):
        return None
    document = {
        "misp_authenticated_api_ready": True,
        **{name: payload[name] for name in sorted(_REQUIRED_FIELDS)},
    }
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return raw if len(raw) <= _MAX_READINESS_BYTES else None


def _valid_readiness_payload(payload: Mapping[str, object]) -> bool:
    """Return whether every required fact is present, typed and affirmative."""

    for name, expected in _REQUIRED_FIELDS.items():
        value = payload.get(name)
        # bool is a subclass of int, so a str field must not accept True.
        if not isinstance(value, expected):
            return False
    if any(not str(payload[name]).strip() for name in _NON_EMPTY):
        return False
    return all(payload[name] is True for name in _REQUIRED_TRUE)


def _failure(status: CollectorStatus = CollectorStatus.MID_RUN_LOSS) -> SourceResult:
    """Return one bounded, secret-free failure with no partial evidence."""

    return SourceResult(status=status, chunks=(), media_type="application/json")


__all__ = ("AdmittedMispState", "MispAuthenticatedApiReadinessSource")
