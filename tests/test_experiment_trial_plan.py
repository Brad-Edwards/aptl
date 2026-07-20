"""Tests for ``aptl.core.experiment.trial_plan`` (ADR-047 "Deterministic
immutable trial plan").

The trial plan is a PURE expander: no I/O, no persistence (Stage 5 wires
the result through ``LocalRunStore.create_json_once``). Determinism is the
whole point — two expansions of the same admitted spec, regardless of
process, host, dict-insertion order, or ``PYTHONHASHSEED``, must produce
byte-identical ``TrialPlan.canonical_bytes`` (ADR-047 "Gotchas": no
``hash()``, UUIDs, timestamps, ambient RNG, or set/dict traversal leaking
into the result).

Uses the installed ACES fixture corpus
(``aces_contracts.corpus.corpus_family_root(FIXTURES)``) for a realistic
condition allocation, plus hand-built minimal specs for flat allocation and
for map-order-independence at the factor-level granularity (the corpus
fixture's conditions each carry only one factor level, which is not enough
to exercise dict-key reordering).
"""

from __future__ import annotations

import copy
import inspect
import json
import subprocess
import sys
import textwrap

import pytest
from aces_contracts.corpus import FIXTURES, corpus_family_root
from aces_contracts.experiment_spec import ExperimentSpecModel

from aptl.core.experiment.errors import EXPERIMENT_ADMISSION_DOMAIN, AdmissionRejection
from aptl.core.experiment.policy import (
    AdmissionPolicy,
    OrderingKind,
    default_admission_policy,
)
from aptl.core.experiment import trial_plan
from aptl.core.experiment.trial_plan import (
    PlannedTrial,
    TrialPlan,
    compute_source_set_digest,
    expand_trial_plan,
)

CORPUS_ROOT = corpus_family_root(FIXTURES)
SOURCE_SET_DIGEST = "sha256:" + "ab" * 32


def _read_corpus_reference() -> dict:
    path = CORPUS_ROOT / "experiment-core" / "experiment-authoring-input-v1" / "valid" / "reference.json"
    return json.loads(path.read_text())


def _condition_reference_spec() -> ExperimentSpecModel:
    return ExperimentSpecModel.model_validate(_read_corpus_reference())


def _flat_spec_payload(
    *,
    target_run_count: int = 5,
    stochastic_controls: list[dict] | None = None,
    capture_spec_refs: list[dict] | None = None,
) -> dict:
    payload = {
        "schema_version": "experiment-authoring-input/v1",
        "spec_id": "spec-flat-test-v1",
        "spec_version": "1.0.0",
        "title": "Flat test spec",
        "description": "Flat allocation test fixture.",
        "task_ref": {"ref_kind": "task", "ref_id": "task-x", "ref_version": "1.0.0"},
        "run_plan": {
            "stochastic_controls": (
                stochastic_controls
                if stochastic_controls is not None
                else [{"control_id": "seed-a", "role": "seed", "value": 1}]
            ),
            "episode_control": {
                "turn_order": "sequential",
                "max_steps": 10,
                "termination_rule": "fixed horizon",
            },
            "target_run_count": target_run_count,
        },
    }
    if capture_spec_refs is not None:
        payload["capture_spec_refs"] = capture_spec_refs
    return payload


def _flat_spec(**kwargs) -> ExperimentSpecModel:
    return ExperimentSpecModel.model_validate(_flat_spec_payload(**kwargs))


def _condition_assignment(condition_id: str, factor_levels: dict, param_value: str) -> dict:
    return {
        "condition_id": condition_id,
        "factor_levels": factor_levels,
        "required_parameters": [
            {"name": "p", "value": param_value, "value_kind": "protocol"},
        ],
    }


def _condition_spec_payload(
    *,
    condition_assignments: dict,
    compared_conditions: list[str],
    target_runs_per_condition: int = 3,
    allocation_method: str = "balanced",
    stochastic_controls: list[dict] | None = None,
) -> dict:
    return {
        "schema_version": "experiment-authoring-input/v1",
        "spec_id": "spec-condition-test-v1",
        "spec_version": "1.0.0",
        "title": "Condition test spec",
        "description": "Condition allocation test fixture.",
        "task_ref": {"ref_kind": "task", "ref_id": "task-x", "ref_version": "1.0.0"},
        "run_plan": {
            "stochastic_controls": (
                stochastic_controls
                if stochastic_controls is not None
                else [{"control_id": "seed-a", "role": "seed", "value": 1}]
            ),
            "episode_control": {
                "turn_order": "sequential",
                "max_steps": 10,
                "termination_rule": "fixed horizon",
            },
            "allocation": {
                "allocation_unit": "run",
                "allocation_method": allocation_method,
                "compared_conditions": compared_conditions,
                "condition_assignments": condition_assignments,
                "target_runs_per_condition": target_runs_per_condition,
                "replication_policy": "n independent runs",
            },
        },
    }


def _two_factor_condition_spec(*, condition_dict_order=("cond-a", "cond-b"), factor_dict_order=("factor-x", "factor-y")):
    def _factor_levels(level_a, level_b):
        ordered_keys = factor_dict_order
        values = {"factor-x": level_a, "factor-y": level_b}
        return {key: values[key] for key in ordered_keys}

    assignments_in_order = {
        "cond-a": _condition_assignment("cond-a", _factor_levels("a1", "a2"), "a1"),
        "cond-b": _condition_assignment("cond-b", _factor_levels("b1", "b2"), "b1"),
    }
    condition_assignments = {key: assignments_in_order[key] for key in condition_dict_order}

    payload = _condition_spec_payload(
        condition_assignments=condition_assignments,
        compared_conditions=["cond-a", "cond-b"],
    )
    return ExperimentSpecModel.model_validate(payload)


# ---------------------------------------------------------------------------
# compute_source_set_digest
# ---------------------------------------------------------------------------


class TestComputeSourceSetDigest:
    def test_returns_a_sha256_prefixed_digest(self):
        digest = compute_source_set_digest({"a": 1, "b": 2})
        assert digest.startswith("sha256:")
        assert len(digest) == len("sha256:") + 64

    def test_is_stable_across_calls(self):
        projection = {"task": {"ref_id": "t", "digest": "sha256:" + "0" * 64}}
        assert compute_source_set_digest(projection) == compute_source_set_digest(projection)

    def test_is_independent_of_key_insertion_order(self):
        d1 = compute_source_set_digest({"a": 1, "b": 2, "c": {"x": 1, "y": 2}})
        d2 = compute_source_set_digest({"c": {"y": 2, "x": 1}, "b": 2, "a": 1})
        assert d1 == d2

    def test_different_content_yields_different_digest(self):
        d1 = compute_source_set_digest({"a": 1})
        d2 = compute_source_set_digest({"a": 2})
        assert d1 != d2


# ---------------------------------------------------------------------------
# Flat expansion
# ---------------------------------------------------------------------------


class TestFlatExpansion:
    def test_trial_count_matches_target_run_count(self):
        spec = _flat_spec(target_run_count=7)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert len(plan.trials) == 7

    def test_ordinals_are_zero_based_contiguous(self):
        spec = _flat_spec(target_run_count=4)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert [t.replication_ordinal for t in plan.trials] == [0, 1, 2, 3]

    def test_ordering_index_matches_ordinal(self):
        spec = _flat_spec(target_run_count=4)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert [t.ordering_index for t in plan.trials] == [0, 1, 2, 3]

    def test_condition_id_is_none_for_every_trial(self):
        spec = _flat_spec(target_run_count=3)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert all(t.condition_id is None for t in plan.trials)

    def test_factor_levels_and_parameter_bindings_are_empty(self):
        spec = _flat_spec(target_run_count=2)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        for trial in plan.trials:
            assert trial.factor_levels == ()
            assert trial.parameter_bindings == ()

    def test_ordering_kind_is_flat(self):
        spec = _flat_spec(target_run_count=2)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert plan.ordering_kind is OrderingKind.FLAT

    def test_capture_spec_refs_propagate_to_every_trial(self):
        spec = _flat_spec(
            target_run_count=2,
            capture_spec_refs=[{"ref_kind": "capture-spec", "ref_id": "cap-1", "ref_version": "1.0.0"}],
        )
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        for trial in plan.trials:
            assert trial.capture_spec_refs == ("cap-1",)

    def test_scenario_snapshot_digest_is_none_when_no_mapping_supplied(self):
        spec = _flat_spec(target_run_count=2)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert all(t.scenario_snapshot_digest is None for t in plan.trials)


# ---------------------------------------------------------------------------
# Condition expansion
# ---------------------------------------------------------------------------


class TestConditionExpansionUsesCorpusFixture:
    def test_total_trial_count_matches_conditions_times_replications(self):
        spec = _condition_reference_spec()
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        allocation = spec.run_plan.allocation
        expected = len(allocation.compared_conditions) * allocation.target_runs_per_condition
        assert len(plan.trials) == expected

    def test_trials_follow_authored_condition_order_then_replication_ordinal(self):
        spec = _condition_reference_spec()
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        allocation = spec.run_plan.allocation

        expected_sequence = [
            (condition_id, ordinal)
            for condition_id in allocation.compared_conditions
            for ordinal in range(allocation.target_runs_per_condition)
        ]
        actual_sequence = [(t.condition_id, t.replication_ordinal) for t in plan.trials]
        assert actual_sequence == expected_sequence

    def test_ordering_index_is_contiguous_zero_based(self):
        spec = _condition_reference_spec()
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert [t.ordering_index for t in plan.trials] == list(range(len(plan.trials)))

    def test_ordering_kind_is_condition_major_replication(self):
        spec = _condition_reference_spec()
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert plan.ordering_kind is OrderingKind.CONDITION_MAJOR_REPLICATION

    def test_factor_levels_come_from_the_matching_condition_assignment(self):
        spec = _condition_reference_spec()
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        by_condition = {}
        for trial in plan.trials:
            by_condition.setdefault(trial.condition_id, trial.factor_levels)
        assert by_condition["cond-aggressive"] == (("red-tactic", "aggressive"),)
        assert by_condition["cond-stealthy"] == (("red-tactic", "stealthy"),)

    def test_parameter_bindings_come_from_required_parameters(self):
        spec = _condition_reference_spec()
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        first_aggressive = next(t for t in plan.trials if t.condition_id == "cond-aggressive")
        assert first_aggressive.parameter_bindings == (("red_tactic", "aggressive"),)

    def test_scenario_snapshot_digest_from_condition_snapshot_digests(self):
        spec = _condition_reference_spec()
        digests = {"cond-aggressive": "sha256:" + "1" * 64, "cond-stealthy": "sha256:" + "2" * 64}
        plan = expand_trial_plan(
            spec,
            source_set_digest=SOURCE_SET_DIGEST,
            condition_snapshot_digests=digests,
            policy=default_admission_policy(),
        )
        for trial in plan.trials:
            assert trial.scenario_snapshot_digest == digests[trial.condition_id]

    def test_scenario_snapshot_digest_is_none_without_a_mapping(self):
        spec = _condition_reference_spec()
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert all(t.scenario_snapshot_digest is None for t in plan.trials)


# ---------------------------------------------------------------------------
# Authored condition order (never silently sorted)
# ---------------------------------------------------------------------------


class TestConditionOrderIsAuthoredNotSorted:
    """DISCRIMINATING test for the "authored order vs. silent sorted()"
    coverage gap: every other ``compared_conditions`` fixture in this module
    happens to already be in ascending order, so a hypothetical
    ``sorted(allocation.compared_conditions)`` in ``_expand_condition``
    would pass unnoticed. ``compared_conditions`` here is authored in the
    exact REVERSE of sorted order, so this test FAILS if ``_expand_condition``
    ever sorted instead of iterating authored order.
    """

    def test_trial_sequence_and_ordering_index_follow_authored_not_sorted_order(self):
        payload = _condition_spec_payload(
            condition_assignments={
                "cond-a-second": _condition_assignment("cond-a-second", {"f": "a"}, "a"),
                "cond-z-first": _condition_assignment("cond-z-first", {"f": "z"}, "z"),
            },
            # Authored order is the REVERSE of sorted(["cond-a-second",
            # "cond-z-first"]) == ["cond-a-second", "cond-z-first"].
            compared_conditions=["cond-z-first", "cond-a-second"],
            target_runs_per_condition=2,
        )
        spec = ExperimentSpecModel.model_validate(payload)

        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())

        # sorted() would yield cond-a-second's trials first; authored order
        # (the correct behavior) yields cond-z-first's trials first.
        actual_sequence = [(t.condition_id, t.replication_ordinal) for t in plan.trials]
        assert actual_sequence == [
            ("cond-z-first", 0),
            ("cond-z-first", 1),
            ("cond-a-second", 0),
            ("cond-a-second", 1),
        ]
        # ordering_index reflects the same authored-order coordinate, not a
        # sorted one.
        assert [t.ordering_index for t in plan.trials] == [0, 1, 2, 3]


# ---------------------------------------------------------------------------
# max_allocation_size fail-closed
# ---------------------------------------------------------------------------


class TestMaxAllocationSizeFailClosed:
    def test_flat_allocation_over_the_limit_is_rejected(self):
        spec = _flat_spec(target_run_count=50)
        policy = AdmissionPolicy(max_allocation_size=10)

        with pytest.raises(AdmissionRejection) as excinfo:
            expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)

        assert excinfo.value.diagnostics
        assert all(d.domain == EXPERIMENT_ADMISSION_DOMAIN for d in excinfo.value.diagnostics)
        assert all(d.is_error for d in excinfo.value.diagnostics)

    def test_condition_allocation_over_the_limit_is_rejected(self):
        spec = _condition_reference_spec()  # 2 conditions * 100 replications = 200
        policy = AdmissionPolicy(max_allocation_size=50)

        with pytest.raises(AdmissionRejection):
            expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)

    def test_allocation_within_the_limit_is_accepted(self):
        spec = _flat_spec(target_run_count=10)
        policy = AdmissionPolicy(max_allocation_size=10)

        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        assert len(plan.trials) == 10


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_flat_expansion_is_byte_identical_across_two_calls(self):
        spec = _flat_spec(target_run_count=6)
        policy = default_admission_policy()
        plan1 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan2 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)

        assert plan1.canonical_bytes == plan2.canonical_bytes
        assert plan1.plan_digest == plan2.plan_digest
        assert plan1.plan_id == plan2.plan_id

    def test_condition_expansion_is_byte_identical_across_two_calls(self):
        spec = _condition_reference_spec()
        policy = default_admission_policy()
        plan1 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan2 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)

        assert plan1.canonical_bytes == plan2.canonical_bytes
        assert plan1.plan_digest == plan2.plan_digest
        assert plan1.plan_id == plan2.plan_id

    def test_plan_digest_is_the_sha256_of_canonical_bytes(self):
        import hashlib

        spec = _flat_spec(target_run_count=3)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert plan.plan_digest == "sha256:" + hashlib.sha256(plan.canonical_bytes).hexdigest()

    def test_plan_id_is_filesystem_safe(self):
        import re

        spec = _flat_spec(target_run_count=3)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert re.fullmatch(r"[\w.-]+", plan.plan_id)
        assert ".." not in plan.plan_id

    def test_a_different_source_set_digest_changes_the_plan_digest(self):
        spec = _flat_spec(target_run_count=3)
        policy = default_admission_policy()
        plan1 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan2 = expand_trial_plan(spec, source_set_digest="sha256:" + "ff" * 32, policy=policy)
        assert plan1.plan_digest != plan2.plan_digest

    def test_module_source_never_references_nondeterministic_primitives(self):
        """ADR-047 Gotchas: no Python ``hash()``, UUIDs, timestamps, or
        ambient/library RNG may influence plan bytes. A plan built with any
        of these can look stable within one process and still drift across
        hosts or retries."""
        source = inspect.getsource(trial_plan)
        forbidden_substrings = [
            "uuid",
            "random.",
            "import random",
            "time.time",
            "datetime.now",
            "datetime.utcnow",
            " hash(",
            "(hash(",
        ]
        for token in forbidden_substrings:
            assert token not in source, f"forbidden nondeterministic token found: {token!r}"

    def test_plan_digest_is_stable_across_separate_processes_with_different_hash_seeds(self):
        """A same-process double-call cannot catch a stray Python ``hash()``
        call, because ``PYTHONHASHSEED`` is fixed for the lifetime of one
        process. Run the expansion in two subprocesses with different hash
        seeds and confirm the digest still matches."""
        script = textwrap.dedent(
            """
            from aces_contracts.experiment_spec import ExperimentSpecModel
            from aptl.core.experiment.policy import default_admission_policy
            from aptl.core.experiment.trial_plan import expand_trial_plan

            payload = {
                "schema_version": "experiment-authoring-input/v1",
                "spec_id": "spec-flat-test-v1",
                "spec_version": "1.0.0",
                "title": "Flat test spec",
                "description": "Flat allocation test fixture.",
                "task_ref": {"ref_kind": "task", "ref_id": "task-x", "ref_version": "1.0.0"},
                "run_plan": {
                    "stochastic_controls": [
                        {"control_id": "seed-a", "role": "seed", "value": 1},
                        {"control_id": "seed-b", "role": "randomization", "value": 2},
                    ],
                    "episode_control": {
                        "turn_order": "sequential",
                        "max_steps": 10,
                        "termination_rule": "fixed horizon",
                    },
                    "target_run_count": 6,
                },
            }
            spec = ExperimentSpecModel.model_validate(payload)
            plan = expand_trial_plan(
                spec, source_set_digest="sha256:" + "ab" * 32, policy=default_admission_policy()
            )
            print(plan.plan_digest)
            """
        )
        digests = set()
        for seed in ("0", "1", "3391772699"):
            _os = __import__("os")
            _src = _os.path.join(
                _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"
            )
            result = subprocess.run(
                [sys.executable, "-c", script],
                env={
                    **_os.environ,
                    "PYTHONHASHSEED": seed,
                    "PYTHONPATH": _src + _os.pathsep + _os.environ.get("PYTHONPATH", ""),
                },
                capture_output=True,
                text=True,
                check=True,
            )
            digests.add(result.stdout.strip())
        assert len(digests) == 1


# ---------------------------------------------------------------------------
# Map-order independence
# ---------------------------------------------------------------------------


class TestMapOrderIndependence:
    def test_reordering_condition_assignments_dict_keys_does_not_change_canonical_bytes(self):
        policy = default_admission_policy()
        spec_a = _two_factor_condition_spec(condition_dict_order=("cond-a", "cond-b"))
        spec_b = _two_factor_condition_spec(condition_dict_order=("cond-b", "cond-a"))

        plan_a = expand_trial_plan(spec_a, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan_b = expand_trial_plan(spec_b, source_set_digest=SOURCE_SET_DIGEST, policy=policy)

        assert plan_a.canonical_bytes == plan_b.canonical_bytes
        assert plan_a.plan_digest == plan_b.plan_digest

    def test_reordering_factor_levels_dict_keys_does_not_change_canonical_bytes(self):
        policy = default_admission_policy()
        spec_a = _two_factor_condition_spec(factor_dict_order=("factor-x", "factor-y"))
        spec_b = _two_factor_condition_spec(factor_dict_order=("factor-y", "factor-x"))

        plan_a = expand_trial_plan(spec_a, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan_b = expand_trial_plan(spec_b, source_set_digest=SOURCE_SET_DIGEST, policy=policy)

        assert plan_a.canonical_bytes == plan_b.canonical_bytes
        assert plan_a.plan_digest == plan_b.plan_digest

    def test_reordering_the_reference_fixture_json_top_level_keys_does_not_change_canonical_bytes(self):
        policy = default_admission_policy()
        original = _read_corpus_reference()
        reordered = dict(reversed(list(original.items())))
        assert list(reordered.keys()) != list(original.keys())  # sanity: the reorder is real

        spec_a = ExperimentSpecModel.model_validate(original)
        spec_b = ExperimentSpecModel.model_validate(reordered)

        plan_a = expand_trial_plan(spec_a, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan_b = expand_trial_plan(spec_b, source_set_digest=SOURCE_SET_DIGEST, policy=policy)

        assert plan_a.canonical_bytes == plan_b.canonical_bytes


# ---------------------------------------------------------------------------
# planned_trial_id uniqueness and reproducibility
# ---------------------------------------------------------------------------


class TestPlannedTrialIdUniquenessAndReproducibility:
    def test_ids_are_unique_within_a_flat_plan(self):
        spec = _flat_spec(target_run_count=25)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        ids = [t.planned_trial_id for t in plan.trials]
        assert len(set(ids)) == len(ids)

    def test_ids_are_unique_within_a_condition_plan(self):
        spec = _condition_reference_spec()
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        ids = [t.planned_trial_id for t in plan.trials]
        assert len(set(ids)) == len(ids)

    def test_ids_are_reproducible_across_expansions(self):
        spec = _condition_reference_spec()
        policy = default_admission_policy()
        plan1 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan2 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        assert [t.planned_trial_id for t in plan1.trials] == [t.planned_trial_id for t in plan2.trials]

    def test_ids_are_filesystem_safe(self):
        import re

        spec = _condition_reference_spec()
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        for trial in plan.trials:
            assert re.fullmatch(r"[\w.-]+", trial.planned_trial_id)
            assert ".." not in trial.planned_trial_id

    def test_a_different_source_set_digest_changes_every_id(self):
        spec = _flat_spec(target_run_count=3)
        policy = default_admission_policy()
        plan1 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan2 = expand_trial_plan(spec, source_set_digest="sha256:" + "ff" * 32, policy=policy)
        ids1 = {t.planned_trial_id for t in plan1.trials}
        ids2 = {t.planned_trial_id for t in plan2.trials}
        assert ids1.isdisjoint(ids2)


# ---------------------------------------------------------------------------
# Seed determinism + domain separation
# ---------------------------------------------------------------------------


class TestSeedDeterminismAndDomainSeparation:
    def test_same_coordinates_produce_the_same_seed_across_calls(self):
        spec = _flat_spec(target_run_count=3)
        policy = default_admission_policy()
        plan1 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan2 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        assert [t.stochastic_seeds for t in plan1.trials] == [t.stochastic_seeds for t in plan2.trials]

    def test_different_replication_ordinal_yields_a_different_seed(self):
        spec = _flat_spec(target_run_count=3)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        seeds = [dict(t.stochastic_seeds)["seed-a"] for t in plan.trials]
        assert len(set(seeds)) == len(seeds)

    def test_different_condition_id_yields_a_different_seed(self):
        spec = _condition_reference_spec()
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        first_replication_by_condition = {
            t.condition_id: dict(t.stochastic_seeds)["episode-seed"]
            for t in plan.trials
            if t.replication_ordinal == 0
        }
        seeds = list(first_replication_by_condition.values())
        assert len(set(seeds)) == len(seeds) == 2

    def test_different_control_id_yields_a_different_seed(self):
        spec = _flat_spec(
            target_run_count=1,
            stochastic_controls=[
                {"control_id": "seed-a", "role": "seed", "value": 1},
                {"control_id": "seed-b", "role": "seed", "value": 1},
            ],
        )
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        seeds = dict(plan.trials[0].stochastic_seeds)
        assert seeds["seed-a"] != seeds["seed-b"]

    def test_seeds_are_sorted_by_control_id(self):
        spec = _flat_spec(
            target_run_count=1,
            stochastic_controls=[
                {"control_id": "z-seed", "role": "seed", "value": 1},
                {"control_id": "a-seed", "role": "randomization", "value": 2},
            ],
        )
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        control_ids = [control_id for control_id, _ in plan.trials[0].stochastic_seeds]
        assert control_ids == sorted(control_ids)

    def test_only_seed_and_randomization_roles_get_a_derived_seed(self):
        spec = _flat_spec(
            target_run_count=1,
            stochastic_controls=[
                {"control_id": "seed-a", "role": "seed", "value": 1},
                {"control_id": "rand-a", "role": "randomization", "value": 2},
            ],
        )
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        control_ids = {control_id for control_id, _ in plan.trials[0].stochastic_seeds}
        assert control_ids == {"seed-a", "rand-a"}

    def test_seed_values_look_like_hex_digests(self):
        spec = _flat_spec(target_run_count=1)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        for _control_id, seed in plan.trials[0].stochastic_seeds:
            assert len(seed) == 64
            int(seed, 16)  # must be valid hex


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_trial_plan_is_frozen(self):
        spec = _flat_spec(target_run_count=1)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        with pytest.raises(Exception):  # noqa: B017 - dataclass frozen raises FrozenInstanceError
            plan.trials = ()  # type: ignore[misc]

    def test_planned_trial_is_frozen(self):
        spec = _flat_spec(target_run_count=1)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        trial = plan.trials[0]
        with pytest.raises(Exception):  # noqa: B017
            trial.condition_id = "mutated"  # type: ignore[misc]

    def test_trials_is_a_tuple_not_a_list(self):
        spec = _flat_spec(target_run_count=2)
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        assert isinstance(plan.trials, tuple)

    def test_per_trial_fields_are_tuples_not_lists_or_dicts(self):
        spec = _condition_reference_spec()
        plan = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())
        trial = plan.trials[0]
        assert isinstance(trial.factor_levels, tuple)
        assert isinstance(trial.parameter_bindings, tuple)
        assert isinstance(trial.stochastic_seeds, tuple)
        assert isinstance(trial.capture_spec_refs, tuple)

    def test_mutating_a_caller_supplied_condition_snapshot_digests_mapping_after_the_call_has_no_effect(self):
        spec = _condition_reference_spec()
        digests = {"cond-aggressive": "sha256:" + "1" * 64, "cond-stealthy": "sha256:" + "2" * 64}
        original = copy.deepcopy(digests)

        plan = expand_trial_plan(
            spec, source_set_digest=SOURCE_SET_DIGEST, condition_snapshot_digests=digests, policy=default_admission_policy()
        )
        digests["cond-aggressive"] = "sha256:" + "9" * 64
        digests.clear()

        for trial in plan.trials:
            assert trial.scenario_snapshot_digest == original[trial.condition_id]


# ---------------------------------------------------------------------------
# Unsupported stochastic role / allocation method
# ---------------------------------------------------------------------------


class TestUnsupportedStochasticRole:
    def test_an_unsupported_role_is_rejected(self):
        spec = _flat_spec(
            target_run_count=1,
            stochastic_controls=[{"control_id": "sampler", "role": "sampling", "value": 1}],
        )

        with pytest.raises(AdmissionRejection) as excinfo:
            expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())

        assert excinfo.value.diagnostics
        assert all(d.domain == EXPERIMENT_ADMISSION_DOMAIN for d in excinfo.value.diagnostics)
        assert all(d.is_error for d in excinfo.value.diagnostics)

    def test_a_supported_role_alongside_an_unsupported_role_still_rejects(self):
        spec = _flat_spec(
            target_run_count=1,
            stochastic_controls=[
                {"control_id": "seed-a", "role": "seed", "value": 1},
                {"control_id": "scheduler-a", "role": "scheduler", "value": "x"},
            ],
        )

        with pytest.raises(AdmissionRejection):
            expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())


class TestUnsupportedAllocationMethod:
    def test_an_unmapped_allocation_method_is_rejected_via_resolve_allocation_ordering(self):
        payload = _condition_spec_payload(
            condition_assignments={
                "cond-a": _condition_assignment("cond-a", {"f": "1"}, "1"),
                "cond-b": _condition_assignment("cond-b", {"f": "2"}, "2"),
            },
            compared_conditions=["cond-a", "cond-b"],
            allocation_method="definitely-not-a-real-method",
        )
        spec = ExperimentSpecModel.model_validate(payload)

        with pytest.raises(AdmissionRejection) as excinfo:
            expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())

        assert excinfo.value.diagnostics
        assert all(d.domain == EXPERIMENT_ADMISSION_DOMAIN for d in excinfo.value.diagnostics)

    def test_an_allocation_method_that_resolves_to_flat_is_rejected_for_a_condition_allocation(self):
        """``allocation_method="flat"`` maps to ``OrderingKind.FLAT`` in the
        default policy table, but a condition allocation (compared_conditions
        + condition_assignments present) has no flat expansion algorithm —
        this must fail closed rather than silently mis-expand."""
        payload = _condition_spec_payload(
            condition_assignments={
                "cond-a": _condition_assignment("cond-a", {"f": "1"}, "1"),
                "cond-b": _condition_assignment("cond-b", {"f": "2"}, "2"),
            },
            compared_conditions=["cond-a", "cond-b"],
            allocation_method="flat",
        )
        spec = ExperimentSpecModel.model_validate(payload)

        with pytest.raises(AdmissionRejection):
            expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=default_admission_policy())


# ---------------------------------------------------------------------------
# Fuzz (property-based)
# ---------------------------------------------------------------------------

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@pytest.mark.fuzz
class TestFuzzFlatExpansion:
    @given(target_run_count=st.integers(min_value=1, max_value=500))
    @settings(max_examples=25, deadline=None)
    def test_contiguous_ordering_unique_ids_and_stable_repeat(self, target_run_count):
        spec = _flat_spec(target_run_count=target_run_count)
        policy = default_admission_policy()

        plan1 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan2 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)

        assert [t.ordering_index for t in plan1.trials] == list(range(target_run_count))
        ids = [t.planned_trial_id for t in plan1.trials]
        assert len(set(ids)) == len(ids)
        assert plan1.canonical_bytes == plan2.canonical_bytes


@pytest.mark.fuzz
class TestFuzzConditionExpansion:
    @given(
        num_conditions=st.integers(min_value=1, max_value=6),
        target_runs_per_condition=st.integers(min_value=1, max_value=30),
    )
    @settings(max_examples=25, deadline=None)
    def test_contiguous_ordering_unique_ids_and_stable_repeat(self, num_conditions, target_runs_per_condition):
        condition_ids = [f"cond-{i}" for i in range(num_conditions)]
        condition_assignments = {
            cid: _condition_assignment(cid, {"f": cid}, cid) for cid in condition_ids
        }
        payload = _condition_spec_payload(
            condition_assignments=condition_assignments,
            compared_conditions=condition_ids,
            target_runs_per_condition=target_runs_per_condition,
        )
        spec = ExperimentSpecModel.model_validate(payload)
        policy = default_admission_policy()

        plan1 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan2 = expand_trial_plan(spec, source_set_digest=SOURCE_SET_DIGEST, policy=policy)

        total = num_conditions * target_runs_per_condition
        assert [t.ordering_index for t in plan1.trials] == list(range(total))
        expected_sequence = [
            (cid, ordinal) for cid in condition_ids for ordinal in range(target_runs_per_condition)
        ]
        assert [(t.condition_id, t.replication_ordinal) for t in plan1.trials] == expected_sequence
        ids = [t.planned_trial_id for t in plan1.trials]
        assert len(set(ids)) == len(ids)
        assert plan1.canonical_bytes == plan2.canonical_bytes


@pytest.mark.fuzz
class TestFuzzDictOrderingNeverChangesCanonicalBytes:
    @given(seed=st.integers(min_value=0, max_value=2**32 - 1))
    @settings(max_examples=25, deadline=None)
    def test_shuffled_condition_and_factor_dict_order_is_invariant(self, seed):
        import random

        rng = random.Random(seed)  # noqa: S311 - test-only shuffling, not plan derivation
        condition_order = ["cond-a", "cond-b"]
        rng.shuffle(condition_order)
        factor_order = ["factor-x", "factor-y"]
        rng.shuffle(factor_order)

        spec_shuffled = _two_factor_condition_spec(
            condition_dict_order=tuple(condition_order), factor_dict_order=tuple(factor_order)
        )
        spec_canonical = _two_factor_condition_spec()
        policy = default_admission_policy()

        plan_shuffled = expand_trial_plan(spec_shuffled, source_set_digest=SOURCE_SET_DIGEST, policy=policy)
        plan_canonical = expand_trial_plan(spec_canonical, source_set_digest=SOURCE_SET_DIGEST, policy=policy)

        assert plan_shuffled.canonical_bytes == plan_canonical.canonical_bytes
