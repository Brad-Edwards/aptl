"""Participant-visibility projection of acquired evidence (EXP-010 / issue
#752 preflight "Visibility boundary").

Capture authorization is a SEPARATE projection from participant visibility:
storage or evaluator authorization never implies a participant may see the
evidence. This module is the server-side filter — participant-facing surfaces
(responses, logs, a future API) get ONLY the participant-visible and disclosed
evidence; hidden, evaluator-only, and apparatus-only evidence is retained in
the archive but never enters the participant projection.
"""

from __future__ import annotations

from collections.abc import Sequence

from aptl.core.evidence._persist import EvidenceRef
from aptl.core.experiment.capture_registry import CaptureVisibility

#: Visibility classes a participant is allowed to observe. Everything else
#: (evaluator-only, apparatus-only) is dropped from the participant projection.
_PARTICIPANT_VISIBLE_CLASSES: frozenset[str] = frozenset(
    {CaptureVisibility.PARTICIPANT_VISIBLE.value, CaptureVisibility.DISCLOSED.value}
)


def is_participant_visible(ref: EvidenceRef) -> bool:
    """Return whether an evidence reference may enter a participant projection."""
    return ref.visibility_class in _PARTICIPANT_VISIBLE_CLASSES


def project_for_participant(refs: Sequence[EvidenceRef]) -> tuple[EvidenceRef, ...]:
    """Return only the participant-visible / disclosed subset of ``refs``.

    The retained archive keeps every reference; this projection is what a
    participant-facing surface is allowed to see. Hidden / evaluator-only /
    apparatus-only references are never included even though the coordinator
    was authorized to retain them.
    """
    return tuple(ref for ref in refs if is_participant_visible(ref))
