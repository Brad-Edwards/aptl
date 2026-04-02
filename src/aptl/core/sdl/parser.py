"""SDL parser — YAML loading with key normalization and shorthand expansion.

Provides ``parse_sdl()`` as the primary entry point. Handles:
- Case-insensitive key normalization (``Name`` → ``name``)
- Hyphen-to-underscore conversion (``min-score`` → ``min_score``)
- Shorthand expansion (``source: "pkg"`` → ``{name: "pkg", version: "*"}``)
"""

import textwrap
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from aptl.core.sdl._errors import SDLParseError, SDLValidationError
from aptl.core.sdl._base import is_variable_ref
from aptl.core.sdl.scenario import ExpandedScenario, Scenario
from aptl.core.sdl.validator import SemanticValidator


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
    "features",            # VM.features (dict[str, str])
    "conditions",          # VM.conditions (dict[str, str])
    "injects",             # VM.injects (dict[str, str])
    "roles",               # Node.roles (dict[str, Role])
    "facts",               # Entity.facts (dict[str, str])
    "entities",            # Entity.entities (dict[str, Entity])
    "events",              # Script.events (dict[str, int])
    "steps",               # Workflow.steps (dict[str, WorkflowStep])
})


def _child_is_hashmap_field(key: str, value: Any) -> bool:
    """Return whether the children of ``key`` are user-defined hashmap keys."""
    if key in _HASHMAP_SECTIONS or key in _NESTED_HASHMAP_FIELDS:
        return True
    # Complex properties use list items like ``[{switch-name: "10.0.0.10"}]``.
    return key == "properties" and isinstance(value, list)


def _normalize_field_key(k: Any) -> Any:
    """Normalize a Pydantic field key: lowercase + hyphens to underscores."""
    if isinstance(k, str):
        return k.lower().replace("-", "_")
    return k


def _normalize_keys(data: Any, is_hashmap: bool = False) -> Any:
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


def _reject_variable_mapping_keys(
    data: Any,
    *,
    path: str = "",
    is_hashmap: bool = False,
) -> None:
    """Reject ``${var}`` placeholders in symbol-defining mapping keys."""
    if isinstance(data, dict):
        for k, v in data.items():
            if is_hashmap and is_variable_ref(k):
                key_path = f"{path}.{k}" if path else str(k)
                raise SDLParseError(
                    "Variable placeholders are not allowed in "
                    f"user-defined mapping keys: '{key_path}'"
                )

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
        return

    if isinstance(data, list):
        for index, item in enumerate(data):
            child_path = f"{path}[{index}]"
            _reject_variable_mapping_keys(
                item,
                path=child_path,
                is_hashmap=is_hashmap,
            )


def _expand_source(value: Any) -> Any:
    """Expand shorthand source: 'pkg-name' → {name: 'pkg-name', version: '*'}."""
    if isinstance(value, str):
        return {"name": value, "version": "*"}
    return value


def _expand_infrastructure(infra: dict[str, Any]) -> dict[str, Any]:
    """Expand infrastructure shorthand: {node: 3} → {node: {count: 3}}."""
    result = {}
    for name, value in infra.items():
        if isinstance(value, int) or is_variable_ref(value):
            result[name] = {"count": value}
        else:
            result[name] = value
    return result


def _expand_roles(roles: dict[str, Any]) -> dict[str, Any]:
    """Expand role shorthand: {admin: 'username'} → {admin: {username: 'username'}}."""
    result = {}
    for name, value in roles.items():
        if isinstance(value, str):
            result[name] = {"username": value}
        else:
            result[name] = value
    return result


def _expand_min_score(value: Any) -> Any:
    """Expand min-score shorthand: 50 → {percentage: 50}."""
    if isinstance(value, int) or is_variable_ref(value):
        return {"percentage": value}
    return value


def _expand_shorthands(data: dict[str, Any]) -> dict[str, Any]:
    """Apply all shorthand expansions to normalized data."""
    # Sections where "source" is a plain string reference, NOT a Source package.
    _SOURCE_SKIP_SECTIONS = frozenset({"relationships", "agents"})

    def expand_sources_scoped(
        obj: Any,
        *,
        is_hashmap: bool = False,
        skip: bool = False,
    ) -> Any:
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                if is_hashmap:
                    result[k] = expand_sources_scoped(
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
                    result[k] = expand_sources_scoped(
                        v,
                        is_hashmap=child_is_hashmap,
                        skip=child_skip,
                    )
            return result
        if isinstance(obj, list):
            return [
                expand_sources_scoped(
                    item,
                    is_hashmap=is_hashmap,
                    skip=skip,
                )
                for item in obj
            ]
        return obj

    data = expand_sources_scoped(data)

    # Expand infrastructure shorthand
    if "infrastructure" in data and isinstance(data["infrastructure"], dict):
        data["infrastructure"] = _expand_infrastructure(data["infrastructure"])

    # Expand roles and feature/condition/inject list shorthands within nodes
    if "nodes" in data and isinstance(data["nodes"], dict):
        for node_data in data["nodes"].values():
            if isinstance(node_data, dict):
                if "roles" in node_data:
                    node_data["roles"] = _expand_roles(node_data["roles"])
                # G6: features/conditions/injects as list -> dict with empty role
                for field in ("features", "conditions", "injects"):
                    if field in node_data and isinstance(node_data[field], list):
                        node_data[field] = {
                            name: "" for name in node_data[field]
                        }

    # Expand min_score in evaluations
    if "evaluations" in data and isinstance(data["evaluations"], dict):
        for eval_data in data["evaluations"].values():
            if isinstance(eval_data, dict) and "min_score" in eval_data:
                eval_data["min_score"] = _expand_min_score(
                    eval_data["min_score"]
                )

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
    data = _load_normalized_data(content, path=path)
    if data.get("imports"):
        if path is None:
            raise SDLParseError(
                "SDL imports require file-backed parsing via parse_sdl_file()",
                path=path,
            )
        from aptl.core.sdl.composition import expand_sdl_modules

        data, namespaces = expand_sdl_modules(data, path=path)
        scenario_cls = ExpandedScenario if namespaces else Scenario
    else:
        scenario_cls = Scenario

    # Construct the Pydantic model (structural validation)
    try:
        scenario = scenario_cls(**data)
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
        scenario._set_semantic_validated(True)
    else:
        scenario._set_advisories([])
        scenario._set_semantic_validated(False)
    if isinstance(scenario, ExpandedScenario):
        scenario._set_module_namespaces(locals().get("namespaces", {}))

    return scenario


def parse_sdl_file(path: Path, **kwargs: Any) -> Scenario:
    """Parse an SDL YAML file into a validated Scenario.

    Convenience wrapper around ``parse_sdl()`` that reads from a file.
    """
    if not path.exists():
        raise FileNotFoundError(f"SDL file not found: {path}")

    content = path.read_text(encoding="utf-8")
    data = _load_normalized_data(content, path=path)
    namespaces: dict[str, str] = {}
    if data.get("imports"):
        from aptl.core.sdl.composition import expand_sdl_modules

        data, namespaces = expand_sdl_modules(data, path=path)
    scenario_cls = ExpandedScenario if namespaces else Scenario
    try:
        scenario = scenario_cls(**data)
    except ValidationError as e:
        raise SDLParseError(str(e), path=path) from e

    skip_semantic_validation = bool(kwargs.pop("skip_semantic_validation", False))
    if not skip_semantic_validation:
        validator = SemanticValidator(scenario)
        try:
            validator.validate()
        except SDLValidationError as e:
            e.path = path
            raise
        scenario._set_advisories(validator.warnings)
        scenario._set_semantic_validated(True)
    else:
        scenario._set_advisories([])
        scenario._set_semantic_validated(False)
    if isinstance(scenario, ExpandedScenario):
        scenario._set_module_namespaces(namespaces)
    return scenario


def _load_normalized_data(
    content: str,
    *,
    path: Path | None = None,
) -> dict[str, Any]:
    content = textwrap.dedent(content).strip()
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

    data = _normalize_keys(raw)
    _reject_variable_mapping_keys(data)
    return _expand_shorthands(data)
