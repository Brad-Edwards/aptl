"""Decision-only provider boundary for governed RAES participants."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from raes_contracts.contracts import ParticipantDecisionSurfaceSelectionV2Model

from aptl.workbench.runtime import ManagedAgentAdapter


@dataclass(frozen=True)
class ParticipantDecisionSolicitation:
    """The only material made available to an installed participant agent."""

    participant_address: str
    episode_id: str
    solicitation_id: str
    participant_view: Mapping[str, object]
    rendered_context: tuple[Mapping[str, object], ...]
    observation_history: tuple[Mapping[str, object], ...]
    candidate_selections: tuple[Mapping[str, object], ...]


class ParticipantSelectionProvider(Protocol):
    """Select one complete RAES proposal without executing its action."""

    @property
    def implementation_name(self) -> str: ...

    @property
    def implementation_version(self) -> str: ...

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str: ...


class DeterministicSelectionProvider:
    """Test/readiness provider that selects from a declared candidate order."""

    implementation_name = "aptl-deterministic-selection-fixture"
    implementation_version = "1.0.0"

    def __init__(self, *, candidate_index: int = 0) -> None:
        self._candidate_index = candidate_index

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        try:
            candidate = solicitation.candidate_selections[
                self._candidate_index
            ]
        except IndexError as exc:
            raise ValueError(
                "deterministic provider candidate index is outside the surface"
            ) from exc
        return json.dumps(candidate, separators=(",", ":"), sort_keys=True)


class ManagedAgentSelectionProvider:
    """Use an installed managed agent to choose one delivered candidate."""

    def __init__(
        self,
        *,
        adapter: ManagedAgentAdapter,
        handle: object,
        implementation_name: str,
        implementation_version: str,
    ) -> None:
        self._adapter = adapter
        self._handle = handle
        self._implementation_name = implementation_name
        self._implementation_version = implementation_version

    @property
    def implementation_name(self) -> str:
        return self._implementation_name

    @property
    def implementation_version(self) -> str:
        return self._implementation_version

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        prompt = json.dumps(
            {
                "instruction": (
                    "Choose one candidate that advances the visible task. "
                    "Return exactly that candidate JSON object with no prose, "
                    "markdown, or additional keys. You do not execute actions."
                ),
                "participant_view": dict(solicitation.participant_view),
                "rendered_context": [
                    dict(item) for item in solicitation.rendered_context
                ],
                "observation_history": [
                    dict(item) for item in solicitation.observation_history
                ],
                "candidate_selections": [
                    dict(candidate)
                    for candidate in solicitation.candidate_selections
                ],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        return self._adapter.respond(self._handle, prompt)

    def close(self) -> None:
        self._adapter.close(self._handle)


def parse_provider_selection(
    raw: str,
) -> ParticipantDecisionSurfaceSelectionV2Model:
    """Parse hostile provider output as exactly one RAES v2 selection."""

    if not isinstance(raw, str) or not raw or len(raw) > 128_000:
        raise ValueError("participant provider returned an invalid result envelope")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "participant provider did not return valid JSON"
        ) from exc
    if not isinstance(payload, Mapping):
        raise ValueError("participant provider selection must be one JSON object")
    return ParticipantDecisionSurfaceSelectionV2Model.model_validate(payload)


def candidate_payloads(
    candidates: Sequence[ParticipantDecisionSurfaceSelectionV2Model],
) -> tuple[Mapping[str, object], ...]:
    """Return defensive JSON projections for the provider boundary."""

    return tuple(
        candidate.model_dump(mode="json") for candidate in candidates
    )
