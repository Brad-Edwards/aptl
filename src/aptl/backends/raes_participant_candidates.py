"""Finite governed-choice enumeration for participant surfaces."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from itertools import combinations, product

import rfc8785
from raes_contracts.contracts import (
    ParticipantDecisionSurfaceSelectionV2Model,
    ParticipantDecisionSurfaceV2Model,
)

from aptl.backends.raes_participant_apparatus_models import reference_token

_MAX_CANDIDATE_VARIANTS_PER_ACTION = 4096


def candidate_selections(
    surface: ParticipantDecisionSurfaceV2Model,
    runtime_model: object,
    *,
    completed_action_sequence: tuple[str, ...],
) -> tuple[ParticipantDecisionSurfaceSelectionV2Model, ...]:
    """Resolve choices whose native prerequisites hold at this state cut."""

    from aptl.backends.raes_participant_realizations import (
        unmet_required_prior_actions,
    )

    assert surface.delivery is not None
    candidates: list[ParticipantDecisionSurfaceSelectionV2Model] = []
    for entry in surface.participant_view.action_entries:
        if unmet_required_prior_actions(
            entry.action_contract_address,
            completed_action_sequence,
        ):
            continue
        contract = runtime_model.action_contracts[entry.action_contract_address]
        for arguments in _governed_argument_variants(contract.argument_definitions):
            variant_digest = hashlib.sha256(rfc8785.dumps(arguments)).hexdigest()[:16]
            candidates.append(
                ParticipantDecisionSurfaceSelectionV2Model(
                    surface_id=surface.participant_view.surface_id,
                    decision_epoch=surface.participant_view.decision_epoch,
                    participant_view_digest=surface.assurance.participant_view_digest,
                    delivery_ref=surface.delivery.delivery_ref,
                    action_contract_address=entry.action_contract_address,
                    argument_shape_ref=entry.selection_shape_ref,
                    proposal_ref=(
                        f"participant-proposals."
                        f"{surface.participant_view.episode_id}."
                        f"epoch-{surface.participant_view.decision_epoch}."
                        f"{reference_token(entry.action_contract_address)}."
                        f"arguments-{variant_digest}"
                    ),
                    arguments=arguments,
                )
            )
    return tuple(candidates)


def _governed_argument_variants(
    definitions: Sequence[Mapping[str, object]],
) -> tuple[dict[str, object], ...]:
    """Enumerate every finite semantic choice admitted by an argument shape."""

    named_options: list[tuple[str, tuple[object, ...]]] = []
    for definition in definitions:
        named_option = _argument_options(definition)
        if named_option is not None:
            named_options.append(named_option)

    variant_count = 1
    for _, options in named_options:
        variant_count *= len(options)
        if variant_count > _MAX_CANDIDATE_VARIANTS_PER_ACTION:
            raise ValueError(
                "compiled action argument domain exceeds the bounded "
                f"candidate limit of {_MAX_CANDIDATE_VARIANTS_PER_ACTION}"
            )
    if not named_options:
        return ({},)
    return tuple(
        {
            name: value
            for (name, _), value in zip(
                named_options,
                selected,
                strict=True,
            )
        }
        for selected in product(*(options for _, options in named_options))
    )


def _argument_options(
    definition: Mapping[str, object],
) -> tuple[str, tuple[object, ...]] | None:
    """Resolve one finite argument domain, or an explicitly omitted argument."""

    name = definition.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("compiled action argument definition has no name")
    allowed = definition.get("allowed_values")
    minimum = definition.get("minimum")
    maximum = definition.get("maximum")
    result: tuple[str, tuple[object, ...]] | None
    if _is_allowed_value_sequence(allowed):
        result = (name, _allowed_value_options(name, definition, allowed))
    elif (
        definition.get("value_type") == "integer"
        and isinstance(minimum, int)
        and isinstance(maximum, int)
        and maximum >= minimum
    ):
        result = (name, tuple(range(minimum, maximum + 1)))
    elif definition.get("value_type") == "boolean":
        result = (name, (False, True))
    elif (
        definition.get("default") is not None
        and definition.get("omission") == "use_default"
    ):
        result = (name, (definition["default"],))
    elif definition.get("omission") == "omit":
        result = None
    else:
        raise ValueError(
            f"cannot enumerate a finite governed domain for argument {name!r}"
        )
    return result


def _is_allowed_value_sequence(value: object) -> bool:
    """Return whether a value is a nonempty, non-string sequence."""

    return (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes))
        and bool(value)
    )


def _allowed_value_options(
    name: str,
    definition: Mapping[str, object],
    allowed: Sequence[object],
) -> tuple[object, ...]:
    """Expand a finite single- or many-valued allowed-value declaration."""

    options: tuple[object, ...]
    if definition.get("cardinality") == "many":
        minimum = definition.get("min_items")
        maximum = definition.get("max_items")
        if (
            not isinstance(minimum, int)
            or not isinstance(maximum, int)
            or minimum < 0
            or maximum < minimum
            or maximum > len(allowed)
        ):
            raise ValueError(f"argument {name!r} has no finite valid cardinality")
        options = tuple(
            list(selection)
            for count in range(minimum, maximum + 1)
            for selection in combinations(allowed, count)
        )
    else:
        options = tuple(allowed)
    return options
