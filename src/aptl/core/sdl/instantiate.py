"""Canonical scenario instantiation.

The SDL parser preserves `${var}` placeholders structurally. This module owns
the repo-level instantiation phase that turns a parsed ``Scenario`` into a
fully concrete ``InstantiatedScenario`` before compilation/runtime planning.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from aptl.core.sdl._base import extract_variable_name
from aptl.core.sdl._errors import SDLInstantiationError, SDLValidationError
from aptl.core.sdl.scenario import InstantiatedScenario, Scenario
from aptl.core.sdl.validator import SemanticValidator
from aptl.core.sdl.variables import Variable, VariableType

_VARIABLE_TOKEN_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_-]*)\}")

JSONScalar = str | int | float | bool | None
JSONLike = JSONScalar | list["JSONLike"] | dict[str, "JSONLike"]


def _matches_value_type(value: object, variable: Variable) -> bool:
    if variable.type == VariableType.STRING:
        return isinstance(value, str)
    if variable.type == VariableType.INTEGER:
        return isinstance(value, int) and not isinstance(value, bool)
    if variable.type == VariableType.BOOLEAN:
        return isinstance(value, bool)
    if variable.type == VariableType.NUMBER:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def _resolve_variable_values(
    scenario: Scenario,
    parameters: Mapping[str, JSONLike],
) -> tuple[dict[str, JSONLike], list[str]]:
    resolved: dict[str, JSONLike] = {}
    errors: list[str] = []

    for name, variable in scenario.variables.items():
        if name in parameters:
            value = parameters[name]
        elif variable.default is not None:
            value = variable.default
        elif variable.required:
            errors.append(
                f"Variable '{name}' is required and has no provided value or default."
            )
            continue
        else:
            continue

        if not _matches_value_type(value, variable):
            errors.append(
                f"Variable '{name}' expects type '{variable.type.value}', got "
                f"{type(value).__name__}."
            )
            continue
        if variable.allowed_values and value not in variable.allowed_values:
            errors.append(
                f"Variable '{name}' must be one of {variable.allowed_values!r}; "
                f"got {value!r}."
            )
            continue
        resolved[name] = value

    undeclared = sorted(name for name in parameters if name not in scenario.variables)
    for name in undeclared:
        errors.append(f"Instantiation parameter '{name}' is not a declared variable.")

    return resolved, errors


def _substitute_value(
    value: Any,
    *,
    variable_values: Mapping[str, JSONLike],
    unresolved_refs: set[str],
) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _substitute_value(
                nested_value,
                variable_values=variable_values,
                unresolved_refs=unresolved_refs,
            )
            for key, nested_value in value.items()
        }
    if isinstance(value, list):
        return [
            _substitute_value(
                nested_value,
                variable_values=variable_values,
                unresolved_refs=unresolved_refs,
            )
            for nested_value in value
        ]
    if not isinstance(value, str):
        return value

    full_variable_name = extract_variable_name(value)
    if full_variable_name is not None:
        if full_variable_name not in variable_values:
            unresolved_refs.add(full_variable_name)
            return value
        return variable_values[full_variable_name]

    def replace_token(match: re.Match[str]) -> str:
        variable_name = match.group(1)
        if variable_name not in variable_values:
            unresolved_refs.add(variable_name)
            return match.group(0)
        return str(variable_values[variable_name])

    return _VARIABLE_TOKEN_RE.sub(replace_token, value)


def instantiate_scenario(
    raw_scenario: Scenario,
    parameters: Mapping[str, JSONLike] | None = None,
    profile: str | None = None,
    *,
    validate_semantics: bool | None = None,
) -> InstantiatedScenario:
    """Return a fully concrete scenario ready for compilation.

    Instantiation applies parameter values and variable defaults, rejects
    unresolved placeholders, rebuilds the Pydantic model, and reruns semantic
    validation on the concrete result.
    """

    effective_parameters = dict(parameters or {})
    variable_values, errors = _resolve_variable_values(raw_scenario, effective_parameters)
    if errors:
        raise SDLInstantiationError(errors)

    raw_payload = raw_scenario.model_dump(mode="python", by_alias=True)
    unresolved_refs: set[str] = set()
    substituted_payload = _substitute_value(
        raw_payload,
        variable_values=variable_values,
        unresolved_refs=unresolved_refs,
    )
    if unresolved_refs:
        unresolved_list = ", ".join(sorted(unresolved_refs))
        raise SDLInstantiationError(
            [
                "Scenario contains unresolved variable references after "
                f"instantiation: {unresolved_list}."
            ]
        )

    try:
        instantiated = InstantiatedScenario.model_validate(substituted_payload)
    except ValidationError as exc:
        raise SDLInstantiationError([str(exc)]) from exc

    should_validate_semantics = (
        raw_scenario.semantic_validated
        if validate_semantics is None
        else validate_semantics
    )
    if should_validate_semantics:
        validator = SemanticValidator(instantiated)
        try:
            validator.validate()
        except SDLValidationError as exc:
            raise SDLInstantiationError(exc.errors) from exc
        instantiated._set_advisories(validator.warnings)
        instantiated._set_semantic_validated(True)
    else:
        instantiated._set_advisories(list(raw_scenario.advisories))
        instantiated._set_semantic_validated(False)
    instantiated._set_instantiation_context(
        parameters=variable_values,
        profile=profile,
    )
    return instantiated
