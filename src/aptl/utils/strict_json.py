"""Unambiguous JSON decoding for signed and security-sensitive documents."""

from __future__ import annotations

import json
from typing import Any


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def loads_strict(payload: bytes | str) -> Any:
    """Decode JSON while rejecting duplicate keys and non-finite numbers."""

    return json.loads(
        payload,
        object_pairs_hook=_closed_object,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"invalid JSON constant: {value}")
        ),
    )


def model_validate_json_strict(model_type: Any, payload: bytes | str) -> Any:
    """Reject ambiguous JSON, then retain Pydantic's JSON-aware strict coercion."""

    loads_strict(payload)
    return model_type.model_validate_json(payload)
