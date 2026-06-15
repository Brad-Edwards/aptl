"""SDL parser — YAML loading with key normalization and shorthand expansion.

Provides ``parse_sdl()`` as the primary entry point. Handles:
- Case-insensitive key normalization (``Name`` → ``name``)
- Hyphen-to-underscore conversion (``min-score`` → ``min_score``)
- Shorthand expansion (``source: "pkg"`` → ``{name: "pkg", version: "*"}``)
"""

from __future__ import annotations

from collections.abc import Hashable
from pathlib import Path
from typing import TypeAlias

import yaml
from pydantic import ValidationError

from aptl.core.sdl._errors import SDLParseError, SDLValidationError
from aptl.core.sdl._base import is_variable_ref
from aptl.core.sdl.scenario import Scenario
from aptl.core.sdl.validator import SemanticValidator


# A value as produced by ``yaml.safe_load``: scalars, lists and mappings
# nested to arbitrary depth. Mapping keys may be non-string scalars, so the
# alias is recursive on both keys and values.
YAMLValue: TypeAlias = (
    "None | bool | int | float | str "
    "| list[YAMLValue] | dict[Hashable, YAMLValue]"
)

# A normalized SDL mapping: top-level YAML document after key normalization.
YAMLMapping: TypeAlias = "dict[Hashable, YAMLValue]"


# Top-level sections that are HashMaps of user-defined identifiers.
# Keys inside these are scenario-author names (e.g., "web-server")
# and must NOT be transformed.
_HASHMAP_SECTIONS = frozenset({
    "nodes", "infrastructure", "features", "conditions",
    "vulnerabilities", "metrics", "evaluations", "tlos",
    "goals", "entities", "injects", "events", "scripts", "stories",
    "content", "accounts", "relationships", "agents", "objectives",
    "workflows",
    "variables",
})

# Fields within struct models that are also HashMaps of user-defined keys.
_NESTED_HASHMAP_FIELDS = frozenset({
    # VM.features (dict[str, str])
    "features",
    # VM.conditions (dict[str, str])
    "conditions",
    # VM.injects (dict[str, str])
    "injects",
    # Node.roles (dict[str, Role])
    "roles",
    # Entity.facts (dict[str, str])
    "facts",
    # Entity.entities (dict[str, Entity])
    "entities",
    # Script.events (dict[str, int])
    "events",
    # Workflow.steps (dict[str, WorkflowStep])
    "steps",
})


def _child_is_hashmap_field(key: str, value: YAMLValue) -> bool:
    """Return whether the children of ``key`` are user-defined hashmap keys."""
    if key in _HASHMAP_SECTIONS or key in _NESTED_HASHMAP_FIELDS:
        return True
    # Complex properties use list items like ``[{switch-name: "10.0.0.10"}]``.
    return key == "properties" and isinstance(value, list)


def _normalize_field_key(k: Hashable) -> Hashable:
    """Normalize a Pydantic field key: lowercase + hyphens to underscores."""
    if isinstance(k, str):
        return k.lower().replace("-", "_")
    return k


def _normalize_keys(data: YAMLValue, is_hashmap: bool = False) -> YAMLValue:
    """Normalize dict keys for Pydantic field matching.

    Pydantic struct field keys are lowercased with hyphens converted to
    underscores. User-defined HashMap keys (node names, feature names,
    entity names, etc.) are preserved as-is so cross-references remain
    consistent.
    """
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if is_hashmap:
                # This key is a user-defined identifier — preserve it
                norm_k = k
                child_is_hashmap = False
            else:
                norm_k = _normalize_field_key(k)
                # Check if this field's children are user-defined HashMap keys
                child_key = norm_k if isinstance(norm_k, str) else str(norm_k)
                child_is_hashmap = _child_is_hashmap_field(child_key, v)
            result[norm_k] = _normalize_keys(v, is_hashmap=child_is_hashmap)
        return result
    if isinstance(data, list):
        # List items inherit the hashmap flag — if the parent dict had
        # user-defined keys, list items within it do too.
        return [_normalize_keys(item, is_hashmap=is_hashmap) for item in data]
    return data


def _reject_mapping_key_if_variable(
    key: Hashable,
    *,
    path: str,
    is_hashmap: bool,
) -> None:
    """Raise if ``key`` is a ``${var}`` placeholder in a symbol position."""
    if not (is_hashmap and is_variable_ref(key)):
        return
    key_path = f"{path}.{key}" if path else str(key)
    raise SDLParseError(
        "Variable placeholders are not allowed in "
        f"user-defined mapping keys: '{key_path}'"
    )


def _reject_in_mapping(
    data: dict[Hashable, YAMLValue],
    *,
    path: str,
    is_hashmap: bool,
) -> None:
    """Recurse over a mapping, rejecting variable placeholders in its keys."""
    for k, v in data.items():
        _reject_mapping_key_if_variable(k, path=path, is_hashmap=is_hashmap)

        child_key = k if isinstance(k, str) else str(k)
        child_path = f"{path}.{child_key}" if path else child_key
        child_is_hashmap = (
            False if is_hashmap else _child_is_hashmap_field(child_key, v)
        )
        _reject_variable_mapping_keys(
            v,
            path=child_path,
            is_hashmap=child_is_hashmap,
        )


def _reject_in_sequence(
    data: list[YAMLValue],
    *,
    path: str,
    is_hashmap: bool,
) -> None:
    """Recurse over a sequence, propagating the hashmap flag to items."""
    for index, item in enumerate(data):
        _reject_variable_mapping_keys(
            item,
            path=f"{path}[{index}]",
            is_hashmap=is_hashmap,
        )


def _reject_variable_mapping_keys(
    data: YAMLValue,
    *,
    path: str = "",
    is_hashmap: bool = False,
) -> None:
    """Reject ``${var}`` placeholders in symbol-defining mapping keys."""
    if isinstance(data, dict):
        _reject_in_mapping(data, path=path, is_hashmap=is_hashmap)
    elif isinstance(data, list):
        _reject_in_sequence(data, path=path, is_hashmap=is_hashmap)


def _expand_source(value: YAMLValue) -> YAMLValue:
    """Expand shorthand source: 'pkg-name' → {name: 'pkg-name', version: '*'}."""
    if isinstance(value, str):
        return {"name": value, "version": "*"}
    return value


def _expand_infrastructure(
    infra: dict[Hashable, YAMLValue],
) -> dict[Hashable, YAMLValue]:
    """Expand infrastructure shorthand: {node: 3} → {node: {count: 3}}."""
    result = {}
    for name, value in infra.items():
        if isinstance(value, int) or is_variable_ref(value):
            result[name] = {"count": value}
        else:
            result[name] = value
    return result


def _expand_roles(
    roles: dict[Hashable, YAMLValue],
) -> dict[Hashable, YAMLValue]:
    """Expand role shorthand: {admin: 'username'} → {admin: {username: 'username'}}."""
    result = {}
    for name, value in roles.items():
        if isinstance(value, str):
            result[name] = {"username": value}
        else:
            result[name] = value
    return result


def _expand_min_score(value: YAMLValue) -> YAMLValue:
    """Expand min-score shorthand: 50 → {percentage: 50}."""
    if isinstance(value, int) or is_variable_ref(value):
        return {"percentage": value}
    return value


# Sections where "source" is a plain string reference, NOT a Source package.
_SOURCE_SKIP_SECTIONS = frozenset({"relationships", "agents"})


def _expand_sources_scoped(
    obj: YAMLValue,
    *,
    is_hashmap: bool = False,
    skip: bool = False,
) -> YAMLValue:
    """Recursively expand ``source`` shorthand outside of skipped sections."""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if is_hashmap:
                result[k] = _expand_sources_scoped(
                    v,
                    is_hashmap=False,
                    skip=skip,
                )
                continue

            child_skip = skip or k in _SOURCE_SKIP_SECTIONS
            child_is_hashmap = _child_is_hashmap_field(k, v)

            if k == "source" and not skip:
                result[k] = _expand_source(v)
            else:
                result[k] = _expand_sources_scoped(
                    v,
                    is_hashmap=child_is_hashmap,
                    skip=child_skip,
                )
        return result
    if isinstance(obj, list):
        return [
            _expand_sources_scoped(
                item,
                is_hashmap=is_hashmap,
                skip=skip,
            )
            for item in obj
        ]
    return obj


def _expand_node_shorthands(nodes: dict[Hashable, YAMLValue]) -> None:
    """Expand roles and feature/condition/inject list shorthands within nodes."""
    for node_data in nodes.values():
        if isinstance(node_data, dict):
            if "roles" in node_data:
                node_data["roles"] = _expand_roles(node_data["roles"])
            # G6: features/conditions/injects as list -> dict with empty role
            for field in ("features", "conditions", "injects"):
                if field in node_data and isinstance(node_data[field], list):
                    node_data[field] = dict.fromkeys(node_data[field], "")


def _expand_evaluation_shorthands(evaluations: dict[Hashable, YAMLValue]) -> None:
    """Expand min_score shorthand in evaluations."""
    for eval_data in evaluations.values():
        if isinstance(eval_data, dict) and "min_score" in eval_data:
            eval_data["min_score"] = _expand_min_score(
                eval_data["min_score"]
            )


def _expand_shorthands(data: YAMLMapping) -> YAMLMapping:
    """Apply all shorthand expansions to normalized data."""
    data = _expand_sources_scoped(data)

    # Expand infrastructure shorthand
    if "infrastructure" in data and isinstance(data["infrastructure"], dict):
        data["infrastructure"] = _expand_infrastructure(data["infrastructure"])

    # Expand roles and feature/condition/inject list shorthands within nodes
    if "nodes" in data and isinstance(data["nodes"], dict):
        _expand_node_shorthands(data["nodes"])

    # Expand min_score in evaluations
    if "evaluations" in data and isinstance(data["evaluations"], dict):
        _expand_evaluation_shorthands(data["evaluations"])

    return data


def parse_sdl(
    content: str,
    path: Path | None = None,
    *,
    skip_semantic_validation: bool = False,
) -> Scenario:
    """Parse an SDL YAML string into a validated Scenario.

    Handles SDL documents with ``name`` at the top level. Runs
    structural validation (Pydantic) and semantic validation
    (cross-references, cycles, etc.).

    Args:
        content: Raw YAML string.
        path: Optional file path for error messages.
        skip_semantic_validation: If True, only run Pydantic structural
            validation (useful for partial scenarios during development).

    Returns:
        Validated Scenario object.

    Raises:
        SDLParseError: If YAML parsing fails or the data isn't a dict.
        SDLValidationError: If semantic validation finds errors.
    """
    content = content.strip()
    if not content:
        raise SDLParseError("SDL content is empty", path=path)

    try:
        raw = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise SDLParseError(f"Invalid YAML: {e}", path=path) from e

    if not isinstance(raw, dict):
        raise SDLParseError(
            "SDL must be a YAML mapping (not a scalar or list)", path=path
        )

    # Normalize keys (case-insensitive, hyphens to underscores)
    data = _normalize_keys(raw)

    # User-defined mapping keys define the SDL symbol table and must be concrete.
    _reject_variable_mapping_keys(data)

    # Expand shorthands
    data = _expand_shorthands(data)

    # Construct the Pydantic model (structural validation)
    try:
        scenario = Scenario(**data)
    except ValidationError as e:
        raise SDLParseError(str(e), path=path) from e

    # Semantic validation
    if not skip_semantic_validation:
        validator = SemanticValidator(scenario)
        try:
            validator.validate()
        except SDLValidationError as e:
            e.path = path
            raise
        scenario._set_advisories(validator.warnings)
    else:
        scenario._set_advisories([])

    return scenario


def parse_sdl_file(path: Path, **kwargs: bool) -> Scenario:
    """Parse an SDL YAML file into a validated Scenario.

    Convenience wrapper around ``parse_sdl()`` that reads from a file.
    """
    if not path.exists():
        raise FileNotFoundError(f"SDL file not found: {path}")

    content = path.read_text(encoding="utf-8")
    return parse_sdl(content, path=path, **kwargs)
