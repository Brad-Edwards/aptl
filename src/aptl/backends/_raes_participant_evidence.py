"""Evidence collection and durable records for participant delivery."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from aptl.backends._raes_participant_models import (
    ParticipantInjectTurn,
    ParticipantTurnResult,
)
from aptl.core.evidence._persist import EvidenceRef
from aptl.core.evidence.outcomes import CollectorStatus
from aptl.core.evidence.protocol import CollectorContext, CollectorOutcome
from aptl.workbench.process import AgentExecutionError

if TYPE_CHECKING:
    from aptl.backends._raes_participant_transport import (
        ClaudeCodeHostParticipantAdapter,
    )


class _ParticipantDeliveryCollector:
    """Run one provider turn inside the public evidence lifecycle."""

    def __init__(self, registration_id: str) -> None:
        """Initialize one collector for an admitted registration."""

        self._registration_id = registration_id
        self._context: CollectorContext | None = None
        self._started_at = ""
        self._payload: dict[str, object] = {}
        self.result: ParticipantTurnResult | None = None
        self._failed = False

    @property
    def registration_id(self) -> str:
        """Return the admitted collector registration identifier."""

        return self._registration_id

    def start(self, context: CollectorContext) -> object:
        """Start collection within the public evidence lifecycle."""

        self._context = context
        self._started_at = context.clock.now()
        return self

    def deliver(
        self,
        adapter: "ClaudeCodeHostParticipantAdapter",
        **kwargs: object,
    ) -> None:
        """Invoke the transport and retain its result."""

        try:
            self.result = adapter.deliver(**kwargs)  # type: ignore[arg-type]
        except Exception:
            self._failed = True
            raise

    def mark_failed(self) -> None:
        """Mark the trial as failed before evidence finalization."""

        self._failed = True

    def stop(self, handle: object) -> CollectorOutcome:
        """Finalize the provider result as one bounded evidence payload."""

        if handle is not self or self._context is None:
            raise AgentExecutionError(
                "participant delivery collector handle is invalid"
            )
        now = self._context.clock.now()
        if self._failed or self.result is None:
            return CollectorOutcome(
                status=CollectorStatus.MID_RUN_LOSS,
                started_at=self._started_at,
                finished_at=now,
                detail="participant provider delivery failed",
            )
        result = self.result
        provider_metadata = {
            key: value
            for key, value in result.provider_payload.items()
            if key != "result"
        }
        payload = {
            "delivery_address": self._payload["delivery_address"],
            "participant_address": self._payload["participant_address"],
            "realization_profile_ref": self._payload["realization_profile_ref"],
            "instruction": self._payload["instruction"],
            "response": result.response,
            "provider_metadata": provider_metadata,
            "model": self._payload["model"],
            "session_id": result.session_id,
            "delivery_status": "delivered",
            "observation_status": "not-asserted",
        }
        return CollectorOutcome(
            status=CollectorStatus.OK,
            started_at=self._started_at,
            finished_at=now,
            chunks=(json.dumps(payload, sort_keys=True).encode("utf-8"),),
            media_type="application/json",
            event_count=1,
            observer_effect="participant instruction delivered through installed provider",
            source_pipeline={
                "realization_profile_ref": payload["realization_profile_ref"],
                "delivery_address": payload["delivery_address"],
            },
        )

    def bind_payload(self, turn: ParticipantInjectTurn, model: str) -> None:
        """Bind authored delivery coordinates before the trial starts."""

        self._payload = {
            "delivery_address": turn.address,
            "participant_address": turn.participant_address,
            "realization_profile_ref": turn.realization_profile_ref,
            "instruction": turn.instruction,
            "model": model,
        }


def _delivery_record(
    sequence: int,
    turn: ParticipantInjectTurn,
    result: ParticipantTurnResult,
    model: str,
    evidence_ref: EvidenceRef,
) -> dict[str, object]:
    """Build one content-addressed delivery index record."""

    instruction_sha256 = hashlib.sha256(turn.instruction.encode()).hexdigest()
    response_sha256 = hashlib.sha256(result.response.encode()).hexdigest()
    return {
        "schema_version": "aptl-participant-inject-delivery/v1",
        "sequence": sequence,
        "delivery_address": turn.address,
        "participant_address": turn.participant_address,
        "profile": turn.profile.value,
        "realization_profile_ref": turn.realization_profile_ref,
        "source_item_ref": turn.source_item_ref,
        "instruction_sha256": f"sha256:{instruction_sha256}",
        "response_sha256": f"sha256:{response_sha256}",
        "model": model,
        "conversation_continuity_sha256": (
            "sha256:" + hashlib.sha256(result.session_id.encode()).hexdigest()
        ),
        "inject_address": turn.inject_address,
        "event_address": turn.event_address,
        "script_address": turn.script_address,
        "story_address": turn.story_address,
        "observation_boundary_address": turn.observation_boundary_address,
        "temporal_constraint_address": turn.temporal_constraint_address,
        "clock_address": turn.clock_address,
        "tick": turn.tick,
        "control_transition_address": turn.control_transition_address,
        "control_effective_order": turn.control_effective_order,
        "controller_address": turn.controller_address,
        "evidence_requirement_addresses": list(turn.evidence_requirement_addresses),
        "failure_disposition": turn.failure_disposition,
        "delivery_status": "delivered",
        "observation_status": "not-asserted",
        "evidence_record_id": evidence_ref.evidence_record_id,
        "evidence_content_digest": evidence_ref.content_digest,
        "capture_spec_id": evidence_ref.capture_spec_id,
        "capture_requirement_id": evidence_ref.requirement_id,
        "capture_registration_id": evidence_ref.registration_id,
    }
