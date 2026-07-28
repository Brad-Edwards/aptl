"""Admission for the bounded participant decision response schema."""

from __future__ import annotations

import json
from collections.abc import Mapping

from aptl.workbench.process import AgentExecutionError
from aptl.workbench.runtime import AgentLaunch, DecisionAgentLaunch

_INVALID_RESPONSE_SCHEMA = "agent response schema is invalid"


def admit_decision_response_schema(
    launch: AgentLaunch,
    response_schema: Mapping[str, object] | None,
) -> str | None:
    """Admit only the exact bounded candidate-index schema for decisions."""

    if not isinstance(launch, DecisionAgentLaunch):
        if response_schema is not None:
            raise AgentExecutionError(
                "agent response schema is limited to decision launches"
            )
        return None
    properties = _candidate_properties(response_schema)
    _validate_candidate(properties.get("candidate"))
    return json.dumps(response_schema, separators=(",", ":"), sort_keys=True)


def _candidate_properties(
    response_schema: Mapping[str, object] | None,
) -> Mapping[str, object]:
    """Return the sole candidate property from an exact response envelope."""

    if (
        not isinstance(response_schema, Mapping)
        or set(response_schema)
        != {"type", "properties", "required", "additionalProperties"}
        or response_schema.get("type") != "object"
        or response_schema.get("required") != ["candidate"]
        or response_schema.get("additionalProperties") is not False
    ):
        raise AgentExecutionError(_INVALID_RESPONSE_SCHEMA)
    properties = response_schema.get("properties")
    if not isinstance(properties, Mapping) or set(properties) != {"candidate"}:
        raise AgentExecutionError(_INVALID_RESPONSE_SCHEMA)
    return properties


def _validate_candidate(candidate: object) -> None:
    """Require one bounded, zero-based integer candidate index."""

    if (
        not isinstance(candidate, Mapping)
        or set(candidate) != {"type", "minimum", "maximum"}
        or candidate.get("type") != "integer"
        or type(candidate.get("minimum")) is not int
        or candidate.get("minimum") != 0
        or type(candidate.get("maximum")) is not int
        or candidate["maximum"] < 0
    ):
        raise AgentExecutionError(_INVALID_RESPONSE_SCHEMA)
