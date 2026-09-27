"""Unambiguous JSON decoding for signed and security-sensitive documents."""

from __future__ import annotations

import json
from typing import NoReturn, TypeAlias, TypeVar

from pydantic import BaseModel

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)
ModelT = TypeVar("ModelT", bound=BaseModel)
def _closed_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    """Build one object while rejecting ambiguous duplicate member names."""

    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    """Reject non-finite JSON constants accepted by Python's decoder."""

    raise ValueError(f"invalid JSON constant: {value}")


def loads_strict(payload: bytes | str) -> JsonValue:
    """Decode JSON while rejecting duplicate keys and non-finite numbers."""

    return json.loads(
        payload,
        object_pairs_hook=_closed_object,
        parse_constant=_reject_constant,
    )


def model_validate_json_strict(
    model_type: type[ModelT], payload: bytes | str
) -> ModelT:
    """Reject ambiguous JSON, then retain Pydantic's JSON-aware strict coercion."""

    loads_strict(payload)
    return model_type.model_validate_json(payload)
