"""Participant-implementation provenance (REP-003 / issue #452).

Records the participant implementation and model identity that the run
ACTUALLY used, taken from the accepted
:class:`~aptl.backends.raes_participant_apparatus_models.ParticipantApparatus`
that :func:`~aptl.backends.raes_participant_apparatus.build_participant_apparatus`
produced at selection time.

This is deliberately not a reconstruction from current configuration. The
research protocol requires model identity to be frozen and reconstructable, so
an absent model is recorded as ``None`` rather than being back-filled from
whatever the configuration says today — a guessed default would silently
misreport which agent ran.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from aptl.core.provenance.identity import (
    ProvenanceIdentityError,
    ProvenanceLeaf,
    derive_identity,
    validate_logical_id,
)
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.protocol import ProvenanceContext, ProvenanceResult

log = logging.getLogger(__name__)

#: The code-owned provider id for participant apparatus.
PARTICIPANT_PROVIDER_ID = "participant"

#: Identity domain for a participant's accepted selection.
_DOMAIN = "participant"


def _selection_projection(apparatus: object) -> dict[str, object]:
    """Return one participant's accepted selection identity.

    Provider and model are non-secret identity. Credentials never appear here:
    the participant credential path is an ephemeral broker
    (``EphemeralCredentialBroker``), and nothing in that path is read.
    """
    return {
        "implementation_selection_ref": getattr(apparatus, "implementation_selection_ref", None),
        "manifest_ref": getattr(apparatus, "manifest_ref", None),
        "provider": getattr(apparatus, "provider", None),
        "model": getattr(apparatus, "model", None),
    }


class ParticipantApparatusProvider:
    """Collects each installed participant's accepted implementation selection."""

    provider_id = PARTICIPANT_PROVIDER_ID

    def __init__(self, apparatus_by_address: Mapping[str, object]):
        self._apparatus_by_address = dict(apparatus_by_address)

    def collect(self, context: ProvenanceContext) -> ProvenanceResult:
        """Project every accepted participant selection into a leaf."""
        if not self._apparatus_by_address:
            return ProvenanceResult(
                provider_id=self.provider_id,
                status=ProvenanceStatus.UNAVAILABLE,
                detail="source not present",
            )

        if len(self._apparatus_by_address) > context.max_entries:
            return ProvenanceResult(
                provider_id=self.provider_id,
                status=ProvenanceStatus.TRUNCATED,
                detail="entry limit reached",
            )

        leaves: list[ProvenanceLeaf] = []
        participants: dict[str, object] = {}
        try:
            for address, apparatus in self._apparatus_by_address.items():
                # The address becomes a record key, so it is validated with the
                # same rule every logical id obeys rather than trusted.
                safe_address = validate_logical_id(address)
                projection = _selection_projection(apparatus)
                leaves.append(
                    ProvenanceLeaf(safe_address, derive_identity(_DOMAIN, projection))
                )
                participants[safe_address] = projection
        except (ProvenanceIdentityError, TypeError, ValueError):
            log.warning("run-provenance: participant apparatus projection was rejected")
            return ProvenanceResult(
                provider_id=self.provider_id,
                status=ProvenanceStatus.FAILED,
                detail="owner reported failure",
            )

        if context.expired():
            return ProvenanceResult(
                provider_id=self.provider_id,
                status=ProvenanceStatus.TIMED_OUT,
                detail="deadline exceeded",
            )

        return ProvenanceResult(
            provider_id=self.provider_id,
            status=ProvenanceStatus.COLLECTED,
            leaves=tuple(sorted(leaves)),
            payload={"participants": participants},
        )
