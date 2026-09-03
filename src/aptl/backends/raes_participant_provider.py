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
    def provider_name(self) -> str: ...

    @property
    def model(self) -> str | None: ...

    @property
    def implementation_name(self) -> str: ...

    @property
    def implementation_version(self) -> str: ...

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str: ...


class DeterministicSelectionProvider:
    """Test/readiness provider that selects from a declared candidate order."""

    implementation_name = "aptl-deterministic-selection-fixture"
    implementation_version = "1.0.0"
    provider_name = "deterministic"
    model = None

    def __init__(self, *, candidate_index: int = 0) -> None:
        self._candidate_index = candidate_index

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        try:
            candidate = solicitation.candidate_selections[self._candidate_index]
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
        provider_name: str,
        model: str,
        implementation_name: str,
        implementation_version: str,
    ) -> None:
        self._adapter = adapter
        self._handle = handle
        self._provider_name = provider_name
        self._model = model
        self._implementation_name = implementation_name
        self._implementation_version = implementation_version

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def model(self) -> str:
        return self._model

    @property
    def implementation_name(self) -> str:
        return self._implementation_name

    @property
    def implementation_version(self) -> str:
        return self._implementation_version

    def select(self, solicitation: ParticipantDecisionSolicitation) -> str:
        prompt, aliases = _compact_selection_prompt(solicitation)
        raw_selection = self._adapter.respond(
            self._handle,
            prompt,
            response_schema=_compact_selection_schema(len(aliases)),
        )
        candidate_number = _parse_compact_selection(
            raw_selection,
            candidate_count=len(aliases),
        )
        proposal_ref = aliases[candidate_number]
        candidate = solicitation.candidate_selections[candidate_number]
        if candidate.get("proposal_ref") != proposal_ref:
            raise ValueError(
                "compact participant selection did not resolve to its "
                "delivered proposal"
            )
        return json.dumps(candidate, separators=(",", ":"), sort_keys=True)

    def close(self) -> None:
        self._adapter.close(self._handle)


def _compact_selection_prompt(
    solicitation: ParticipantDecisionSolicitation,
) -> tuple[str, tuple[str, ...]]:
    """Render every delivered choice without repeating trusted coordinates."""

    actions: list[str] = []
    action_indexes: dict[str, int] = {}
    candidates: list[list[object]] = []
    aliases: list[str] = []
    alias_set: set[str] = set()
    for candidate_number, candidate in enumerate(solicitation.candidate_selections):
        address = candidate.get("action_contract_address")
        proposal_ref = candidate.get("proposal_ref")
        arguments = candidate.get("arguments")
        if (
            not isinstance(address, str)
            or not address
            or not isinstance(proposal_ref, str)
            or not proposal_ref
            or not isinstance(arguments, Mapping)
            or proposal_ref in alias_set
        ):
            raise ValueError(
                "compact participant selection candidates are invalid or ambiguous"
            )
        action_number = action_indexes.get(address)
        if action_number is None:
            action_number = len(actions)
            action_indexes[address] = action_number
            actions.append(address)
        aliases.append(proposal_ref)
        alias_set.add(proposal_ref)
        candidates.append(
            [
                candidate_number,
                action_number,
                dict(arguments),
            ]
        )
    if not candidates:
        raise ValueError("compact participant selection has no candidates")
    prompt = json.dumps(
        {
            "instruction": (
                "Choose one candidate that advances the visible task. "
                'Return exactly {"candidate":N}, where N is one candidate '
                "number from the delivered list. Return no prose, markdown, "
                "or additional keys. You do not execute actions."
            ),
            "participant_view": dict(solicitation.participant_view),
            "rendered_context": [dict(item) for item in solicitation.rendered_context],
            "observation_history": [
                dict(item) for item in solicitation.observation_history
            ],
            "candidate_encoding": [
                "candidate",
                "action",
                "arguments",
            ],
            "actions": actions,
            "candidates": candidates,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return prompt, tuple(aliases)


def _compact_selection_schema(candidate_count: int) -> Mapping[str, object]:
    """Constrain structured output to the current delivered candidate range."""

    if candidate_count <= 0:
        raise ValueError("compact participant selection has no candidates")
    return {
        "type": "object",
        "properties": {
            "candidate": {
                "type": "integer",
                "minimum": 0,
                "maximum": candidate_count - 1,
            }
        },
        "required": ["candidate"],
        "additionalProperties": False,
    }


def _parse_compact_selection(raw: str, *, candidate_count: int) -> int:
    """Parse exactly one transient alias into the delivered candidate tuple."""

    if not isinstance(raw, str) or not raw or len(raw) > 128_000:
        raise ValueError("compact participant selection envelope is invalid")
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_json_object)
    except ValueError as exc:
        raise ValueError("compact participant selection is not valid JSON") from exc
    if not isinstance(payload, Mapping) or set(payload) != {"candidate"}:
        raise ValueError("compact participant selection must contain one candidate")
    candidate_number = payload["candidate"]
    if (
        type(candidate_number) is not int
        or candidate_number < 0
        or candidate_number >= candidate_count
    ):
        raise ValueError("compact participant selection candidate is out of range")
    return candidate_number


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON members before an alias can become authority."""

    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("compact participant selection contains duplicate keys")
        result[name] = value
    return result


def parse_provider_selection(
    raw: str,
) -> ParticipantDecisionSurfaceSelectionV2Model:
    """Parse hostile provider output as exactly one RAES v2 selection."""

    if not isinstance(raw, str) or not raw or len(raw) > 128_000:
        raise ValueError("participant provider returned an invalid result envelope")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("participant provider did not return valid JSON") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("participant provider selection must be one JSON object")
    return ParticipantDecisionSurfaceSelectionV2Model.model_validate(payload)


def candidate_payloads(
    candidates: Sequence[ParticipantDecisionSurfaceSelectionV2Model],
) -> tuple[Mapping[str, object], ...]:
    """Return defensive JSON projections for the provider boundary."""

    return tuple(candidate.model_dump(mode="json") for candidate in candidates)
