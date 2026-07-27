"""Canonical, versioned serialization of compiled RAES runtime models."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import TYPE_CHECKING

import rfc8785

if TYPE_CHECKING:
    from raes_processor.models import RuntimeModel

COMPILED_RUNTIME_MODEL_ARTIFACT_SCHEMA = "aptl.raes-runtime-model-artifact/v1"


def compiled_runtime_model_bytes(runtime_model: RuntimeModel) -> bytes:
    """Render the versioned RFC 8785 model artifact used by the freeze."""

    payload = {
        "schema": COMPILED_RUNTIME_MODEL_ARTIFACT_SCHEMA,
        "runtime_model": _canonical_runtime_value(runtime_model),
    }
    return rfc8785.dumps(payload) + b"\n"


def compiled_runtime_model_sha256(runtime_model: RuntimeModel) -> str:
    """Return the content digest of the deterministic compiled-model artifact."""

    return hashlib.sha256(compiled_runtime_model_bytes(runtime_model)).hexdigest()


def _canonical_runtime_value(value: object) -> object:
    """Normalize the complete runtime model without lossy string coercion."""

    normalized: object
    if isinstance(value, Enum):
        normalized = _canonical_runtime_value(value.value)
    elif value is None or isinstance(value, str | bool | int | float):
        normalized = value
    elif is_dataclass(value) and not isinstance(value, type):
        normalized = {
            item.name: _canonical_runtime_value(getattr(value, item.name))
            for item in fields(value)
        }
    elif callable(model_dump := getattr(value, "model_dump", None)):
        normalized = _canonical_runtime_value(model_dump(mode="json"))
    elif isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("compiled runtime model mappings require string keys")
        normalized = {
            key: _canonical_runtime_value(item) for key, item in value.items()
        }
    elif isinstance(value, list | tuple):
        normalized = [_canonical_runtime_value(item) for item in value]
    elif isinstance(value, set | frozenset):
        items = [_canonical_runtime_value(item) for item in value]
        normalized = sorted(items, key=rfc8785.dumps)
    else:
        raise TypeError(
            "compiled runtime model contains an unsupported canonical value: "
            f"{type(value).__name__}"
        )
    return normalized
