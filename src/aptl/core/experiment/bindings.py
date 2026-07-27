"""RAES-owned cross-plane experiment binding admission (EXP-005)."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass

import rfc8785
from pydantic import BaseModel
from raes import Scenario
from raes_contracts.bounded_domains import scalar_in_domain
from raes.variables import VariableType
from raes.variation import ParameterVariationPoint
from raes_backend_protocols.capabilities import BackendManifest
from raes_contracts.contracts import (
    BackendManifestV2Model,
    BindingOwnerModel,
    BindingScalarType,
    ExperimentBindingDescriptorModel,
    ExperimentBindingDescriptorSetModel,
    ExperimentSpecModel,
    LiteralBindingValueModel,
    ParticipantConfigurationResultModel,
    ParticipantImplementationBindingTargetModel,
    ParticipantImplementationManifestModel,
    RealizedBindingProvenanceModel,
    ScenarioBindingTargetModel,
)
from raes_contracts.experiment_bindings import (
    ApparatusManifestKey,
    ParticipantManifestKey,
    ScenarioBindingResolution,
    validate_experiment_binding_targets,
)
from raes_contracts.participant_configuration import (
    ConfigurationOverrideModel,
    realize_participant_configuration,
)

from aptl.backends.raes_manifest import (
    APTL_EXPERIMENT_ACTION_TIMEOUT_TARGET,
    create_aptl_binding_manifest_model,
)
from aptl.core.config import AptlConfig
from aptl.utils.redaction import is_secret_shaped_value, is_sensitive_key

ParticipantManifestMap = Mapping[
    ParticipantManifestKey,
    "ParticipantManifestBinding",
]

_SCENARIO_OWNER = BindingOwnerModel(
    contract_id="sdl-authoring-input-v1",
    contract_version="1",
    validator_id="raes-sdl-instantiation",
    validator_version="1",
)

_PYTHON_ENTRYPOINT_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_.]*$"
)
_WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True)
class ParticipantManifestBinding:
    """Selected participant manifest plus its portable identity coordinates."""

    manifest: ParticipantImplementationManifestModel
    manifest_ref: str
    manifest_digest: str


@dataclass(frozen=True)
class AdmittedConditionBindings:
    """One condition's immutable, owner-validated binding results."""

    scenario_parameters: tuple[tuple[str, object], ...]
    participant_configurations: tuple[ParticipantConfigurationResultModel, ...]
    apparatus_config: AptlConfig
    apparatus_projection: tuple[tuple[str, object], ...]
    realized_bindings: tuple[RealizedBindingProvenanceModel, ...]


class ScenarioVariableTargetResolver:
    """Resolve parameter variation points against one admitted RAES scenario."""

    def __init__(self, scenario: Scenario) -> None:
        self._scenario = scenario

    def resolve(
        self,
        scenario_family_id: str,
        variation_point_id: str,
        supplied_target_id: str,
    ) -> ScenarioBindingResolution:
        if scenario_family_id != self._scenario.name:
            raise ValueError("unknown scenario family")
        point = self._scenario.variation_points.get(variation_point_id)
        if not isinstance(point, ParameterVariationPoint):
            raise ValueError("unknown or unsupported scenario variation point")
        variable_name = point.target.variable
        expected_target = f"variables.{variable_name}"
        if supplied_target_id != expected_target:
            raise ValueError("unknown scenario variation target")
        variable = self._scenario.variables.get(variable_name)
        if variable is None:
            raise ValueError("scenario variation target variable is not declared")
        return ScenarioBindingResolution(
            canonical_target_id=expected_target,
            value_type=_binding_type(variable.type),
            allowed_value_kinds=["literal"],
            sensitivity="public",
            owner=_SCENARIO_OWNER,
        )


def _binding_type(variable_type: VariableType) -> BindingScalarType:
    """Map a RAES scenario variable type to its binding scalar type."""

    return {
        VariableType.STRING: BindingScalarType.STRING,
        VariableType.INTEGER: BindingScalarType.INTEGER,
        VariableType.NUMBER: BindingScalarType.NUMBER,
        VariableType.BOOLEAN: BindingScalarType.BOOLEAN,
    }[variable_type]


def _unsafe_literal(value: object) -> bool:
    """Return whether a literal could encode a secret or executable locator."""

    if is_secret_shaped_value(value):
        return True
    if not isinstance(value, str):
        return False
    lowered = value.casefold()
    return (
        is_sensitive_key(value)
        or "\x00" in value
        or value.startswith(("/", "\\"))
        or ".." in value.replace("\\", "/").split("/")
        or any(token in value for token in ("$(", "`", "\n", "\r", ";", "&&", "||"))
        or lowered.startswith(("python:", "module:", "file:", "env:"))
        or bool(_PYTHON_ENTRYPOINT_RE.fullmatch(value))
        or bool(_WINDOWS_ABSOLUTE_PATH_RE.match(value))
    )


def _validate_literal_safety(descriptors: ExperimentBindingDescriptorSetModel) -> None:
    """Reject every descriptor whose literal crosses the safe-data boundary."""

    for descriptor in descriptors.descriptors:
        if isinstance(descriptor.value, LiteralBindingValueModel) and _unsafe_literal(
            descriptor.value.value
        ):
            raise ValueError("binding descriptor contains an unsafe literal value")


def _validate_scenario_domains(
    descriptors: ExperimentBindingDescriptorSetModel,
    scenario: Scenario,
) -> None:
    """Require each scenario literal to belong to its selected point's domain."""

    for descriptor in descriptors.descriptors:
        target = descriptor.target
        if not isinstance(target, ScenarioBindingTargetModel):
            continue
        point = scenario.variation_points.get(target.variation_point_id)
        if not isinstance(point, ParameterVariationPoint):
            continue
        if not isinstance(descriptor.value, LiteralBindingValueModel):
            raise ValueError("scenario bindings require literal values")
        if not scalar_in_domain(descriptor.value.value, point.domain):
            raise ValueError(
                "scenario binding value is outside the variation-point domain"
            )


def _participant_manifest_models(
    bindings: ParticipantManifestMap,
) -> dict[ParticipantManifestKey, ParticipantImplementationManifestModel]:
    """Project selected participant bindings to the RAES validator input."""

    return {key: binding.manifest for key, binding in bindings.items()}


def _apparatus_manifest_models(
    manifest: BackendManifest,
) -> dict[ApparatusManifestKey, BackendManifestV2Model]:
    """Project the active APTL backend manifest to its RAES apparatus key."""

    model = create_aptl_binding_manifest_model(manifest)
    key: ApparatusManifestKey = (
        "backend",
        model.identity.name,
        model.identity.version,
        model.schema_version,
    )
    return {key: model}


def _condition_descriptors(
    descriptors: ExperimentBindingDescriptorSetModel,
) -> dict[str, tuple[ExperimentBindingDescriptorModel, ...]]:
    """Group descriptors by condition with stable binding-ID ordering."""

    by_condition: dict[str, list[ExperimentBindingDescriptorModel]] = defaultdict(list)
    for descriptor in descriptors.descriptors:
        by_condition[descriptor.source_condition_id].append(descriptor)
    return {
        condition_id: tuple(sorted(items, key=lambda item: item.binding_id))
        for condition_id, items in by_condition.items()
    }


def _scenario_parameters(
    descriptors: tuple[ExperimentBindingDescriptorModel, ...],
) -> tuple[tuple[str, object], ...]:
    """Return stable scenario variable/value pairs for one condition."""

    parameters: list[tuple[str, object]] = []
    for descriptor in descriptors:
        if not isinstance(descriptor.target, ScenarioBindingTargetModel):
            continue
        if not isinstance(descriptor.value, LiteralBindingValueModel):
            raise ValueError("scenario bindings require literal values")
        variable_name = descriptor.target.target_id.removeprefix("variables.")
        parameters.append((variable_name, descriptor.value.value))
    return tuple(sorted(parameters))


def _participant_configurations(
    descriptors: tuple[ExperimentBindingDescriptorModel, ...],
    participant_manifests: ParticipantManifestMap,
) -> tuple[
    tuple[ParticipantConfigurationResultModel, ...],
    dict[str, str],
]:
    """Realize participant-owned configuration results for one condition."""

    grouped: dict[ParticipantManifestKey, list[ExperimentBindingDescriptorModel]] = defaultdict(list)
    for descriptor in descriptors:
        target = descriptor.target
        if isinstance(target, ParticipantImplementationBindingTargetModel):
            grouped[
                (
                    target.participant_address,
                    target.implementation_name,
                    target.implementation_version,
                    target.manifest_version,
                )
            ].append(descriptor)

    results: list[ParticipantConfigurationResultModel] = []
    digests_by_binding: dict[str, str] = {}
    for key in sorted(grouped):
        manifest_binding = participant_manifests[key]
        group = sorted(grouped[key], key=lambda item: item.binding_id)
        result = realize_participant_configuration(
            participant_address=key[0],
            manifest=manifest_binding.manifest,
            manifest_ref=manifest_binding.manifest_ref,
            manifest_digest=manifest_binding.manifest_digest,
            overrides=[
                ConfigurationOverrideModel(
                    target_id=descriptor.target.target_id,
                    value=descriptor.value,
                )
                for descriptor in group
            ],
        )
        results.append(result)
        for descriptor in group:
            digests_by_binding[descriptor.binding_id] = result.configuration_digest
    return tuple(results), digests_by_binding


def _apparatus_configuration(
    descriptors: tuple[ExperimentBindingDescriptorModel, ...],
    base_config: AptlConfig,
) -> tuple[AptlConfig, tuple[tuple[str, object], ...], str | None, set[str]]:
    """Apply the closed APTL apparatus projection and derive its digest."""

    values: list[tuple[str, object]] = []
    binding_ids: set[str] = set()
    for descriptor in descriptors:
        if descriptor.target.plane != "apparatus":
            continue
        if descriptor.target.target_id != APTL_EXPERIMENT_ACTION_TIMEOUT_TARGET:
            raise ValueError("unknown APTL apparatus target")
        if not isinstance(descriptor.value, LiteralBindingValueModel):
            raise ValueError("APTL apparatus targets require literal values")
        values.append((descriptor.target.target_id, descriptor.value.value))
        binding_ids.add(descriptor.binding_id)
    projection = tuple(sorted(values))
    if not projection:
        return base_config, (), None, binding_ids
    if len(projection) != 1:
        raise ValueError("duplicate APTL apparatus target")
    payload = base_config.model_dump(mode="python")
    payload["experiment"]["participant_action_timeout_seconds"] = projection[0][1]
    realized = AptlConfig.model_validate(payload)
    digest_projection = {
        "schema": "aptl-experiment-apparatus-configuration/v1",
        "values": dict(projection),
    }
    digest = (
        f"sha256:{hashlib.sha256(rfc8785.dumps(digest_projection)).hexdigest()}"
    )
    return realized, projection, digest, binding_ids


def _realized_provenance(
    descriptors: tuple[ExperimentBindingDescriptorModel, ...],
    participant_digests: Mapping[str, str],
    apparatus_digest: str | None,
    apparatus_binding_ids: set[str],
) -> tuple[RealizedBindingProvenanceModel, ...]:
    """Attach owner-derived configuration digests to realized bindings."""

    realized: list[RealizedBindingProvenanceModel] = []
    for descriptor in descriptors:
        configuration_digest = participant_digests.get(descriptor.binding_id)
        origin = "selection"
        if descriptor.binding_id in apparatus_binding_ids:
            configuration_digest = apparatus_digest
            origin = "override"
        elif isinstance(descriptor.target, ParticipantImplementationBindingTargetModel):
            origin = "override"
        realized.append(
            RealizedBindingProvenanceModel(
                descriptor=descriptor,
                origin=origin,
                configuration_digest=configuration_digest,
            )
        )
    return tuple(realized)


def admit_experiment_bindings(
    spec: ExperimentSpecModel,
    *,
    scenario: Scenario,
    backend_manifest: BackendManifest,
    participant_manifests: ParticipantManifestMap,
    base_config: AptlConfig,
) -> dict[str, AdmittedConditionBindings]:
    """Validate and realize every explicit binding before trial planning."""

    descriptors = spec.binding_descriptors
    if descriptors is None:
        return {}
    _validate_literal_safety(descriptors)
    _validate_scenario_domains(descriptors, scenario)
    apparatus_manifests = (
        _apparatus_manifest_models(backend_manifest)
        if any(
            descriptor.target.plane == "apparatus"
            for descriptor in descriptors.descriptors
        )
        else {}
    )
    admitted = validate_experiment_binding_targets(
        descriptors,
        scenario_resolver=ScenarioVariableTargetResolver(scenario),
        participant_manifests=_participant_manifest_models(participant_manifests),
        apparatus_manifests=apparatus_manifests,
    )
    results: dict[str, AdmittedConditionBindings] = {}
    for condition_id, condition_items in _condition_descriptors(admitted).items():
        participant_results, participant_digests = _participant_configurations(
            condition_items,
            participant_manifests,
        )
        apparatus_config, apparatus_projection, apparatus_digest, apparatus_ids = (
            _apparatus_configuration(condition_items, base_config)
        )
        results[condition_id] = AdmittedConditionBindings(
            scenario_parameters=_scenario_parameters(condition_items),
            participant_configurations=participant_results,
            apparatus_config=apparatus_config,
            apparatus_projection=apparatus_projection,
            realized_bindings=_realized_provenance(
                condition_items,
                participant_digests,
                apparatus_digest,
                apparatus_ids,
            ),
        )
    return results


def scenario_for_explicit_bindings(
    scenario: Scenario,
    bindings: Mapping[str, AdmittedConditionBindings],
) -> Scenario:
    """Return a parameter-only scenario family ready for RAES instantiation."""

    if not scenario.variation_points:
        return scenario
    variable_by_point: dict[str, str] = {}
    for point_id, point in scenario.variation_points.items():
        if not isinstance(point, ParameterVariationPoint):
            raise ValueError("explicit experiment binding supports only parameter variation points")
        variable_by_point[point_id] = point.target.variable
    required_variables = set(variable_by_point.values())
    for condition_id, condition in bindings.items():
        supplied_variables = {name for name, _value in condition.scenario_parameters}
        if supplied_variables != required_variables:
            raise ValueError(
                f"condition {condition_id!r} does not bind the complete scenario variation set"
            )
    return scenario.model_copy(update={"variation_points": {}})


def binding_projection(binding: BaseModel) -> dict[str, object]:
    """Return one RAES binding/configuration model as JSON-ready data."""

    return binding.model_dump(mode="json", exclude_none=True)


__all__ = [
    "AdmittedConditionBindings",
    "ParticipantManifestBinding",
    "ParticipantManifestMap",
    "ScenarioVariableTargetResolver",
    "admit_experiment_bindings",
    "binding_projection",
    "scenario_for_explicit_bindings",
]
