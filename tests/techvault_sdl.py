"""Shared helpers for the modular TechVault SDL test surface."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any


TECHVAULT_NAMESPACE = "techvault"


def namespaced(name: str) -> str:
    return f"{TECHVAULT_NAMESPACE}.{name}"


def provision_node(name: str) -> str:
    return f"provision.node.{namespaced(name)}"


@lru_cache(maxsize=4)
def load_expanded_techvault_sdl(path: str) -> dict[str, Any]:
    from aces_sdl import parse_sdl_file

    return parse_sdl_file(Path(path)).model_dump(mode="json", by_alias=True)


@lru_cache(maxsize=4)
def load_legacy_techvault_sdl(path: str) -> dict[str, Any]:
    data = load_expanded_techvault_sdl(path)
    known_prefixed = {
        key
        for section in data.values()
        if isinstance(section, dict)
        for key in section
        if isinstance(key, str) and key.startswith(f"{TECHVAULT_NAMESPACE}.")
    }
    section_prefixes = (
        "nodes",
        "infrastructure",
        "features",
        "conditions",
        "vulnerabilities",
        "metrics",
        "evaluations",
        "tlos",
        "goals",
        "entities",
        "injects",
        "events",
        "scripts",
        "stories",
        "content",
        "accounts",
        "relationships",
        "agents",
        "objectives",
        "workflows",
    )

    def strip_value(value: Any) -> Any:
        if isinstance(value, dict):
            return {strip_key(key): strip_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [strip_value(item) for item in value]
        if isinstance(value, str):
            if value in known_prefixed:
                return value.removeprefix(f"{TECHVAULT_NAMESPACE}.")
            for section in section_prefixes:
                value = value.replace(f"{section}.{TECHVAULT_NAMESPACE}.", f"{section}.")
            value = value.replace(f"provision.node.{TECHVAULT_NAMESPACE}.", "provision.node.")
        return value

    def strip_key(key: Any) -> Any:
        if isinstance(key, str) and key in known_prefixed:
            return key.removeprefix(f"{TECHVAULT_NAMESPACE}.")
        return key

    return strip_value(data)
