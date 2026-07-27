"""Safe cross-plane experiment binding admission (EXP-005 / issue #441)."""

from __future__ import annotations

import dataclasses
import json

import pytest
from raes import parse_sdl
from raes_contracts.contracts import (
    ExperimentRunModel,
    ExperimentSpecModel,
    ParticipantImplementationManifestModel,
)
from raes_contracts.corpus import FIXTURES, corpus_family_root

from aptl.backends.raes_manifest import (
    create_aptl_binding_manifest_model,
    create_aptl_manifest,
)
from aptl.core.config import AptlConfig
from aptl.core.experiment.bindings import (
    ParticipantManifestBinding,
    ScenarioVariableTargetResolver,
    admit_experiment_bindings,
)
from aptl.core.experiment.policy import default_admission_policy
from aptl.core.experiment.trial_plan import expand_trial_plan


def _scenario():
    return parse_sdl(
        """
name: factorial-binding
variables:
  red_tactic:
    type: string
    allowed_values: [aggressive, stealthy]
variation_points:
  red-tactic:
    kind: parameter
    target: {kind: variable, variable: red_tactic}
    domain: {kind: enum, values: [aggressive, stealthy]}
content: {}
"""
    )


def _participant_manifest(
    *, include_secret_target: bool = False
) -> ParticipantImplementationManifestModel:
    payload = {
        "schema_version": "participant-implementation-manifest/v1",
        "identity": {"name": "reference-red-agent", "version": "2.0.0"},
        "implementation_kind": "agent",
        "supported_contract_versions": [
            "participant-implementation-manifest-v1",
            "participant-implementation-provenance-v1",
            "experiment-binding-descriptors-v1",
            "participant-configuration-result-v1",
            "participant-episode-state-envelope-v1",
        ],
        "compatibility": {
            "participant_runtimes": ["aptl"],
            "processors": [],
            "backends": ["aptl"],
        },
        "concept_bindings": [
            {"scope": "implementation_kind", "family": "apparatus-declarations"},
            {
                "scope": "capabilities.supported_participant_contracts",
                "family": "apparatus-declarations",
            },
            {
                "scope": "capabilities.supported_decision_surface_modes",
                "family": "apparatus-declarations",
            },
            {
                "scope": "capabilities.tool_affordance_expectations",
                "family": "tools-and-artifacts",
            },
            {
                "scope": "capabilities.exposure_policy_kinds",
                "family": "provenance-and-evidence",
            },
        ],
        "capabilities": {
            "supported_participant_contracts": [
                "participant-episode-state-envelope-v1"
            ],
            "supported_decision_surface_modes": ["policy-directed"],
            "tool_affordance_expectations": ["shell"],
            "exposure_policy_kinds": ["task-statement"],
        },
        "configuration_registry": {
            "owner": {
                "contract_id": "participant-implementation-manifest/v1",
                "contract_version": "1",
                "validator_id": "reference-red-agent-configuration",
                "validator_version": "1",
            },
            "targets": {
                "policy.mode": {
                    "target_id": "policy.mode",
                    "value_type": "string",
                    "aliases": ["mode"],
                    "allowed_value_kinds": ["literal"],
                    "sensitivity": "internal",
                    "default": {"kind": "literal", "value": "balanced"},
                },
                "policy.retries": {
                    "target_id": "policy.retries",
                    "value_type": "integer",
                    "aliases": [],
                    "allowed_value_kinds": ["literal"],
                    "sensitivity": "internal",
                    "default": {"kind": "literal", "value": 2},
                }
            },
        },
    }
    if include_secret_target:
        payload["configuration_registry"]["targets"]["credentials.api"] = {
            "target_id": "credentials.api",
            "value_type": "string",
            "aliases": [],
            "allowed_value_kinds": ["secret-reference"],
            "sensitivity": "secret",
        }
    return ParticipantImplementationManifestModel.model_validate(payload)


def _descriptor(
    *,
    binding_id: str,
    condition_id: str,
    factor_id: str,
    level_id: str,
    target: dict[str, object],
    value_type: str,
    value: object,
    owner: dict[str, str],
) -> dict[str, object]:
    return {
        "binding_id": binding_id,
        "source_factor_id": factor_id,
        "source_factor_level_id": level_id,
        "source_condition_id": condition_id,
        "target": target,
        "value_type": value_type,
        "value": {"kind": "literal", "value": value},
        "owner": owner,
    }


def _explicit_spec(*, include_secret_reference: bool = False) -> ExperimentSpecModel:
    scenario_owner = {
        "contract_id": "sdl-authoring-input-v1",
        "contract_version": "1",
        "validator_id": "raes-sdl-instantiation",
        "validator_version": "1",
    }
    participant_owner = {
        "contract_id": "participant-implementation-manifest/v1",
        "contract_version": "1",
        "validator_id": "reference-red-agent-configuration",
        "validator_version": "1",
    }
    apparatus_owner = {
        "contract_id": "backend-manifest/v2",
        "contract_version": "1",
        "validator_id": "aptl-configuration",
        "validator_version": "1",
    }
    descriptors: list[dict[str, object]] = []
    for condition_id, tactic, timeout in (
        ("cond-aggressive", "aggressive", 90),
        ("cond-stealthy", "stealthy", 180),
    ):
        descriptors.extend(
            [
                _descriptor(
                    binding_id=f"binding.{condition_id}.scenario",
                    condition_id=condition_id,
                    factor_id="red-tactic",
                    level_id=tactic,
                    target={
                        "plane": "scenario",
                        "scenario_family_id": "factorial-binding",
                        "variation_point_id": "red-tactic",
                        "target_id": "variables.red_tactic",
                    },
                    value_type="string",
                    value=tactic,
                    owner=scenario_owner,
                ),
                _descriptor(
                    binding_id=f"binding.{condition_id}.participant",
                    condition_id=condition_id,
                    factor_id="red-tactic",
                    level_id=tactic,
                    target={
                        "plane": "participant-implementation",
                        "participant_address": "participants.red",
                        "implementation_name": "reference-red-agent",
                        "implementation_version": "2.0.0",
                        "manifest_version": "participant-implementation-manifest/v1",
                        "target_id": "mode",
                    },
                    value_type="string",
                    value=tactic,
                    owner=participant_owner,
                ),
                _descriptor(
                    binding_id=f"binding.{condition_id}.apparatus",
                    condition_id=condition_id,
                    factor_id="action-timeout",
                    level_id=str(timeout),
                    target={
                        "plane": "apparatus",
                        "component_kind": "backend",
                        "component_name": "aptl",
                        "component_version": "0.1.0",
                        "manifest_version": "backend-manifest/v2",
                        "target_id": "participant-runtime.action-timeout-seconds",
                    },
                    value_type="integer",
                    value=timeout,
                    owner=apparatus_owner,
                ),
            ]
        )
        if include_secret_reference:
            descriptors.append(
                {
                    "binding_id": f"binding.{condition_id}.participant-secret",
                    "source_factor_id": "credential-ref",
                    "source_factor_level_id": tactic,
                    "source_condition_id": condition_id,
                    "target": {
                        "plane": "participant-implementation",
                        "participant_address": "participants.red",
                        "implementation_name": "reference-red-agent",
                        "implementation_version": "2.0.0",
                        "manifest_version": "participant-implementation-manifest/v1",
                        "target_id": "credentials.api",
                    },
                    "value_type": "string",
                    "value": {
                        "kind": "secret-reference",
                        "reference_id": f"operator-secret.{tactic}-api",
                    },
                    "owner": participant_owner,
                }
            )
    factors = {
        "red-tactic": {
            "name": "Red tactic",
            "factor_kind": "treatment",
            "levels": ["aggressive", "stealthy"],
        },
        "action-timeout": {
            "name": "Action timeout",
            "factor_kind": "apparatus",
            "levels": ["90", "180"],
        },
    }
    if include_secret_reference:
        factors["credential-ref"] = {
            "name": "Credential reference",
            "factor_kind": "apparatus",
            "levels": ["aggressive", "stealthy"],
        }
    condition_factor_levels = {
        "cond-aggressive": {
            "red-tactic": "aggressive",
            "action-timeout": "90",
        },
        "cond-stealthy": {
            "red-tactic": "stealthy",
            "action-timeout": "180",
        },
    }
    if include_secret_reference:
        condition_factor_levels["cond-aggressive"]["credential-ref"] = "aggressive"
        condition_factor_levels["cond-stealthy"]["credential-ref"] = "stealthy"
    return ExperimentSpecModel.model_validate(
        {
            "schema_version": "experiment-authoring-input/v1",
            "spec_id": "factorial-bindings",
            "spec_version": "1.0.0",
            "title": "Factorial bindings",
            "description": "Representative cross-plane factorial design.",
            "task_ref": {"ref_kind": "task", "ref_id": "task-factorial"},
            "factors": factors,
            "run_plan": {
                "stochastic_controls": [
                    {"control_id": "episode-seed", "role": "seed", "value": 1}
                ],
                "episode_control": {
                    "turn_order": "sequential",
                    "max_steps": 10,
                    "termination_rule": "fixed horizon",
                },
                "allocation": {
                    "allocation_unit": "run",
                    "allocation_method": "balanced",
                    "compared_conditions": ["cond-aggressive", "cond-stealthy"],
                    "condition_assignments": {
                        "cond-aggressive": {
                            "condition_id": "cond-aggressive",
                            "factor_levels": condition_factor_levels[
                                "cond-aggressive"
                            ],
                            "required_refs": [
                                {"ref_kind": "profile", "ref_id": "profile.aggressive"}
                            ],
                        },
                        "cond-stealthy": {
                            "condition_id": "cond-stealthy",
                            "factor_levels": condition_factor_levels[
                                "cond-stealthy"
                            ],
                            "required_refs": [
                                {"ref_kind": "profile", "ref_id": "profile.stealthy"}
                            ],
                        },
                    },
                    "target_runs_per_condition": 1,
                    "replication_policy": "independent",
                },
            },
            "binding_semantics": "explicit-required",
            "binding_descriptors": {
                "schema_version": "experiment-binding-descriptors/v1",
                "descriptors": descriptors,
            },
        }
    )


def test_factorial_bindings_are_isolated_by_condition_and_plane() -> None:
    manifest = _participant_manifest()
    admitted = _admitted_bindings(manifest)

    aggressive = admitted["cond-aggressive"]
    stealthy = admitted["cond-stealthy"]
    assert aggressive.scenario_parameters == (("red_tactic", "aggressive"),)
    assert stealthy.scenario_parameters == (("red_tactic", "stealthy"),)
    assert aggressive.participant_configurations[0].configuration.values[0].value.value == "aggressive"
    assert stealthy.participant_configurations[0].configuration.values[0].value.value == "stealthy"
    participant_values = {
        value.target_id: value.origin
        for value in aggressive.participant_configurations[0].configuration.values
    }
    assert participant_values == {
        "policy.mode": "override",
        "policy.retries": "default",
    }
    assert aggressive.apparatus_config.experiment.participant_action_timeout_seconds == 90
    assert stealthy.apparatus_config.experiment.participant_action_timeout_seconds == 180
    assert len(aggressive.realized_bindings) == 3


def test_aptl_manifest_publishes_one_closed_experiment_target() -> None:
    manifest = create_aptl_binding_manifest_model()

    assert "experiment-binding-descriptors-v1" in manifest.supported_contract_versions
    assert manifest.configuration_registry is not None
    assert set(manifest.configuration_registry.targets) == {
        "participant-runtime.action-timeout-seconds"
    }


def test_aptl_binding_registry_rejects_a_foreign_backend_identity() -> None:
    manifest = create_aptl_manifest()
    foreign = dataclasses.replace(
        manifest,
        identity=dataclasses.replace(manifest.identity, name="foreign"),
    )

    with pytest.raises(ValueError, match="canonical APTL backend"):
        create_aptl_binding_manifest_model(foreign)


def _admitted_bindings(
    manifest: ParticipantImplementationManifestModel | None = None,
    spec: ExperimentSpecModel | None = None,
):
    manifest = manifest or _participant_manifest()
    return admit_experiment_bindings(
        spec or _explicit_spec(),
        scenario=_scenario(),
        backend_manifest=create_aptl_manifest(),
        participant_manifests={
            (
                "participants.red",
                "reference-red-agent",
                "2.0.0",
                "participant-implementation-manifest/v1",
            ): ParticipantManifestBinding(
                manifest=manifest,
                manifest_ref="manifests/reference-red-agent.json",
                manifest_digest="sha256:" + "1" * 64,
            )
        },
        base_config=AptlConfig(),
    )


def test_explicit_bindings_are_pinned_in_immutable_trial_plan() -> None:
    plan = expand_trial_plan(
        _explicit_spec(),
        source_set_digest="sha256:" + "a" * 64,
        condition_snapshot_digests={
            "cond-aggressive": "sha256:" + "b" * 64,
            "cond-stealthy": "sha256:" + "c" * 64,
        },
        admitted_bindings=_admitted_bindings(),
        policy=default_admission_policy(),
    )

    aggressive, stealthy = plan.trials
    assert aggressive.parameter_bindings == (("red_tactic", "aggressive"),)
    assert stealthy.parameter_bindings == (("red_tactic", "stealthy"),)
    assert len(aggressive.realized_bindings) == 3
    assert aggressive.apparatus_configuration == (
        ("participant-runtime.action-timeout-seconds", 90),
    )
    assert aggressive.participant_configurations[0].configuration_digest.startswith("sha256:")
    assert all(
        binding.configuration_digest is not None
        for binding in aggressive.realized_bindings
    )
    assert b"sk-" not in plan.canonical_bytes


def test_secret_reference_and_realized_digests_round_trip_without_secret_value() -> None:
    spec = _explicit_spec(include_secret_reference=True)
    manifest = _participant_manifest(include_secret_target=True)
    plan = expand_trial_plan(
        spec,
        source_set_digest="sha256:" + "d" * 64,
        admitted_bindings=_admitted_bindings(manifest, spec),
        policy=default_admission_policy(),
    )
    realized = [
        binding.model_dump(mode="json", exclude_none=True)
        for binding in plan.trials[0].realized_bindings
    ]
    run_path = (
        corpus_family_root(FIXTURES)
        / "experiment-core"
        / "experiment-run-v1"
        / "valid"
        / "reference.json"
    )
    run_payload = json.loads(run_path.read_text())
    run_payload["realized_bindings"] = realized

    run = ExperimentRunModel.model_validate(run_payload)
    serialized = run.model_dump_json()

    assert "operator-secret.aggressive-api" in serialized
    assert "sk-super-secret" not in serialized
    assert any(binding.configuration_digest for binding in run.realized_bindings)


def test_participant_manifest_rejects_alias_collision_before_resolution() -> None:
    payload = json.loads(_participant_manifest().model_dump_json())
    payload["configuration_registry"]["targets"]["policy.other"] = {
        "target_id": "policy.other",
        "value_type": "string",
        "aliases": ["mode"],
        "allowed_value_kinds": ["literal"],
        "sensitivity": "internal",
        "default": {"kind": "literal", "value": "other"},
    }

    with pytest.raises(ValueError, match="collides"):
        ParticipantImplementationManifestModel.model_validate(payload)


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "sk-super-secret-injected-token-98765",
        "../../etc/passwd",
        "$(touch /tmp/injected)",
        "module:function",
    ],
)
def test_unsafe_literal_is_rejected_before_binding_realization(unsafe_value: str) -> None:
    payload = json.loads(_explicit_spec().model_dump_json())
    payload["binding_descriptors"]["descriptors"][0]["value"]["value"] = unsafe_value
    spec = ExperimentSpecModel.model_validate(payload)
    scenario = _scenario()
    backend_manifest = create_aptl_manifest()
    base_config = AptlConfig()

    with pytest.raises(ValueError, match="unsafe literal"):
        admit_experiment_bindings(
            spec,
            scenario=scenario,
            backend_manifest=backend_manifest,
            participant_manifests={},
            base_config=base_config,
        )


def test_binding_realization_is_independent_of_authoring_map_order() -> None:
    spec = _explicit_spec()
    payload = json.loads(spec.model_dump_json())
    payload["factors"] = dict(reversed(list(payload["factors"].items())))
    allocation = payload["run_plan"]["allocation"]
    allocation["condition_assignments"] = dict(
        reversed(list(allocation["condition_assignments"].items()))
    )
    payload["binding_descriptors"]["descriptors"].reverse()
    reordered = ExperimentSpecModel.model_validate(payload)

    expected_bindings = _admitted_bindings(spec=spec)
    actual_bindings = _admitted_bindings(spec=reordered)
    assert actual_bindings == expected_bindings

    snapshots = {
        "cond-aggressive": "sha256:" + "b" * 64,
        "cond-stealthy": "sha256:" + "c" * 64,
    }
    expected_plan = expand_trial_plan(
        spec,
        source_set_digest="sha256:" + "a" * 64,
        condition_snapshot_digests=snapshots,
        admitted_bindings=expected_bindings,
        policy=default_admission_policy(),
    )
    actual_plan = expand_trial_plan(
        reordered,
        source_set_digest="sha256:" + "a" * 64,
        condition_snapshot_digests=snapshots,
        admitted_bindings=actual_bindings,
        policy=default_admission_policy(),
    )
    assert actual_plan.canonical_bytes == expected_plan.canonical_bytes


def test_benign_colon_literal_is_not_treated_as_an_entrypoint() -> None:
    payload = json.loads(_explicit_spec().model_dump_json())
    payload["binding_descriptors"]["descriptors"][1]["value"]["value"] = (
        "urn:example:value"
    )
    spec = ExperimentSpecModel.model_validate(payload)

    admitted = _admitted_bindings(spec=spec)

    assert (
        admitted["cond-aggressive"]
        .participant_configurations[0]
        .configuration.values[0]
        .value.value
        == "urn:example:value"
    )


def test_declared_type_mismatch_is_rejected_by_the_target_owner() -> None:
    payload = json.loads(_explicit_spec().model_dump_json())
    payload["binding_descriptors"]["descriptors"][0]["value_type"] = "integer"
    payload["binding_descriptors"]["descriptors"][0]["value"]["value"] = 7
    spec = ExperimentSpecModel.model_validate(payload)

    with pytest.raises(ValueError):
        _admitted_bindings(spec=spec)


def test_scenario_binding_outside_variation_point_domain_is_rejected() -> None:
    scenario = parse_sdl(
        """
name: factorial-binding
variables:
  red_tactic:
    type: string
    allowed_values: [aggressive, stealthy, destructive]
variation_points:
  red-tactic:
    kind: parameter
    target: {kind: variable, variable: red_tactic}
    domain: {kind: enum, values: [aggressive, stealthy]}
content: {}
"""
    )
    payload = json.loads(_explicit_spec().model_dump_json())
    payload["binding_descriptors"]["descriptors"][0]["value"]["value"] = (
        "destructive"
    )
    spec = ExperimentSpecModel.model_validate(payload)
    backend_manifest = create_aptl_manifest()
    base_config = AptlConfig()

    with pytest.raises(ValueError, match="variation-point domain"):
        admit_experiment_bindings(
            spec,
            scenario=scenario,
            backend_manifest=backend_manifest,
            participant_manifests={},
            base_config=base_config,
        )


from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@pytest.mark.fuzz
@settings(max_examples=40, deadline=None)
@given(st.permutations(tuple(range(6))))
def test_descriptor_order_never_changes_realized_parameter_maps(
    permutation: tuple[int, ...],
) -> None:
    spec = _explicit_spec()
    payload = json.loads(spec.model_dump_json())
    descriptors = payload["binding_descriptors"]["descriptors"]
    payload["binding_descriptors"]["descriptors"] = [
        descriptors[index] for index in permutation
    ]
    reordered = ExperimentSpecModel.model_validate(payload)

    assert _admitted_bindings(spec=reordered) == _admitted_bindings(spec=spec)


@pytest.mark.fuzz
@settings(max_examples=40, deadline=None)
@given(
    st.one_of(
        st.just("variables.red_tactic"),
        st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"),
                whitelist_characters="._-",
            ),
            min_size=1,
            max_size=40,
        ).filter(lambda value: value != "variables.red_tactic"),
    )
)
def test_scenario_target_resolution_is_closed(target_id: str) -> None:
    resolver = ScenarioVariableTargetResolver(_scenario())
    if target_id == "variables.red_tactic":
        resolved = resolver.resolve(
            "factorial-binding",
            "red-tactic",
            target_id,
        )
        assert resolved.canonical_target_id == target_id
    else:
        with pytest.raises(ValueError, match="unknown scenario variation target"):
            resolver.resolve(
                "factorial-binding",
                "red-tactic",
                target_id,
            )
