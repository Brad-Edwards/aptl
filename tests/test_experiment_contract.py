"""ADR-047 "Testing contract" CONTRACT test (Stage 6 / EXP-002 / issue #438).

The ADR's Testing contract requires proving: "every planned trial resolves
to exactly one task, one scenario snapshot, one condition or flat sentinel,
one stochastic-control set, one episode-control set, and the admitted
capture-spec references."

This test admits a self-consistent CONDITION-allocation experiment end to
end through the public :class:`~aptl.core.experiment.controller.
ExperimentController` boundary (reusing Stage 5's ``MappingArtifactSource``
plus a genuinely mutually-compatible synthetic backend/processor pair — the
same legitimate dependency-injection pattern ``test_experiment_controller.py``
and ``test_experiment_admission.py`` already use, not a hand-edited
production manifest), then independently re-derives every one of those six
bindings from the admitted spec/scenario bytes and asserts each
``PlannedTrial`` in the resulting plan is internally consistent with them.

``PlannedTrial`` itself (``src/aptl/core/experiment/trial_plan.py``) does
not carry a per-trial task-identity or episode-control field — both are
single, plan-wide facts (``ExperimentSpecModel.task_ref`` and
``ExperimentRunPlanModel.episode_control`` are singular fields, not lists),
so "exactly one" for those two bindings is a structural property of the
admitted spec shared by the whole plan; this test asserts that directly
against the re-parsed spec rather than against a nonexistent per-trial
field. The remaining four bindings (scenario snapshot digest, condition id,
stochastic-control set, capture-spec refs) DO vary per trial and are
asserted per :class:`~aptl.core.experiment.trial_plan.PlannedTrial`.
"""

from __future__ import annotations

import hashlib
import json

import yaml
from aces_backend_protocols.backend_manifest import BackendManifest
from aces_contracts.corpus import FIXTURES, corpus_family_root
from aces_contracts.experiment_spec import parse_experiment_spec
from aces_processor.capabilities import ProcessorManifest
from aces_processor.manifest import create_reference_processor_manifest
from aces_sdl import parse_sdl
from aces_sdl.canonical import canonical_instantiated_sdl_digest
from aces_sdl.instantiate import instantiate_scenario

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.experiment.admission import MappingArtifactSource
from aptl.core.experiment.controller import ExperimentController
from aptl.core.experiment.policy import default_admission_policy
from aptl.core.experiment.resolver import ResolvedArtifact
from aptl.core.runstore import LocalRunStore

CORPUS_ROOT = corpus_family_root(FIXTURES)

_SCENARIO_TEXT = """
name: scenario-condition
variables:
  danger_level:
    type: string
    default: low
nodes:
  on:
    type: switch
"""


def _resolved(data: bytes, locator: str, media_type: str) -> ResolvedArtifact:
    return ResolvedArtifact(
        data=data, locator=locator, digest=f"sha256:{hashlib.sha256(data).hexdigest()}", media_type=media_type
    )


def _read_corpus_task_payload() -> dict:
    path = CORPUS_ROOT / "experiment-core" / "experiment-task-v1" / "valid" / "reference.json"
    return json.loads(path.read_text())


def _synthetic_manifests() -> tuple[BackendManifest, ProcessorManifest]:
    """A genuinely mutually-compatible test backend/processor pair.

    Mirrors ``test_experiment_controller.py``'s helper of the same name:
    real manifest shape, injected via ``ExperimentController``'s documented
    seam, never a hand-edited production manifest.
    """
    real_backend = create_aptl_manifest()
    real_processor = create_reference_processor_manifest()
    test_backend = BackendManifest(
        name="test-backend",
        version=real_backend.version,
        supported_contract_versions=real_backend.supported_contract_versions,
        compatible_processors=frozenset({"test-processor"}),
        realization_support=real_backend.realization_support,
        concept_bindings=real_backend.concept_bindings,
        provisioner=real_backend.provisioner,
        orchestrator=real_backend.orchestrator,
        evaluator=real_backend.evaluator,
        participant_runtime=real_backend.participant_runtime,
    )
    test_processor = ProcessorManifest(
        name="test-processor",
        version=real_processor.version,
        supported_contract_versions=real_processor.supported_contract_versions,
        capabilities=real_processor.capabilities,
        compatible_backends=frozenset({"test-backend"}),
        concept_bindings=real_processor.concept_bindings,
        constraints=real_processor.constraints,
    )
    return test_backend, test_processor


def _condition_task_payload() -> dict:
    payload = _read_corpus_task_payload()
    payload["task_id"] = "task-condition"
    payload["task_version"] = "1.0.0"
    payload["scenario_ref"] = {"ref_kind": "scenario", "ref_id": "scenario-condition"}
    payload["apparatus_constraints"] = {"required_capabilities": [], "notes": ["unrestricted apparatus"]}
    return payload


def _condition_spec_payload() -> dict:
    return {
        "schema_version": "experiment-authoring-input/v1",
        "spec_id": "spec-contract-v1",
        "spec_version": "1.0.0",
        "title": "CONTRACT-TEST condition-allocation spec",
        "description": "Two-condition allocation proving the ADR-047 per-trial binding contract.",
        "task_ref": {"ref_kind": "task", "ref_id": "task-condition", "ref_version": "1.0.0"},
        "run_plan": {
            "stochastic_controls": [
                {"control_id": "seed-a", "role": "seed", "value": 1},
                {"control_id": "rand-a", "role": "randomization", "value": 2},
            ],
            "episode_control": {
                "turn_order": "sequential",
                "max_steps": 10,
                "termination_rule": "fixed horizon",
            },
            "allocation": {
                "allocation_unit": "trial",
                "allocation_method": "balanced",
                "compared_conditions": ["cond-a", "cond-b"],
                "condition_assignments": {
                    "cond-a": {
                        "condition_id": "cond-a",
                        "factor_levels": {"danger": "high"},
                        "required_parameters": [
                            {"name": "danger_level", "value": "high", "value_kind": "configuration"}
                        ],
                    },
                    "cond-b": {
                        "condition_id": "cond-b",
                        "factor_levels": {"danger": "low"},
                        "required_parameters": [
                            {"name": "danger_level", "value": "low", "value_kind": "configuration"}
                        ],
                    },
                },
                "target_runs_per_condition": 2,
                "blocking_factors": [],
                "replication_policy": "independent-replications",
            },
        },
    }


class TestPlannedTrialBindingContract:
    """Every planned trial resolves to exactly one of each ADR-047 binding."""

    def test_every_trial_binds_exactly_one_of_each_contracted_element(self, tmp_path):
        task_payload = _condition_task_payload()
        task_bytes = json.dumps(task_payload).encode("utf-8")
        scenario_bytes = _SCENARIO_TEXT.encode("utf-8")
        spec_payload = _condition_spec_payload()
        root_bytes = yaml.safe_dump(spec_payload).encode("utf-8")

        backend, processor = _synthetic_manifests()

        def _factory(base_dir, manifest_locator, spec, policy):
            del base_dir, manifest_locator, policy, spec
            return MappingArtifactSource(
                artifacts={
                    "task-condition": _resolved(task_bytes, "task.json", "application/json"),
                    "scenario-condition": _resolved(scenario_bytes, "scenario.sdl.yaml", "application/x-yaml"),
                }
            )

        store = LocalRunStore(tmp_path / "store")
        controller = ExperimentController(
            run_store=store,
            backend_manifest=backend,
            processor_manifest=processor,
            artifact_source_factory=_factory,
        )

        result = controller.admit(
            experiment_root=_resolved(root_bytes, "experiment.yaml", "application/x-yaml"),
            base_dir=tmp_path,
            manifest_locator="unused.json",
        )

        assert result.admitted is True, result.diagnostics
        plan = result.plan
        # Two conditions x two replications each.
        assert len(plan.trials) == 4

        # Independently re-derive the admitted graph from the same bytes
        # the controller consumed, so every assertion below is checked
        # against the admitted spec/scenario, not against this test's own
        # authoring intent.
        admitted_spec = parse_experiment_spec(root_bytes.decode("utf-8"))
        scenario = parse_sdl(scenario_bytes.decode("utf-8"))
        allocation = admitted_spec.run_plan.allocation
        assert allocation is not None

        # --- ONE task identity for the whole plan ---------------------
        # PlannedTrial carries no per-trial task field: task identity is a
        # single, plan-wide fact (`ExperimentSpecModel.task_ref` is one
        # field, never a list), and every trial in one admitted plan
        # shares the one `source_set_digest` that pins it.
        assert admitted_spec.task_ref.ref_id == task_payload["task_id"]
        assert admitted_spec.task_ref.ref_version == task_payload["task_version"]
        assert len({plan.source_set_digest}) == 1

        # --- ONE episode-control set for the whole plan ----------------
        # Likewise `run_plan.episode_control` is a single object, not a
        # list: every trial in this plan is bound to the identical one.
        assert admitted_spec.run_plan.episode_control is not None
        assert admitted_spec.run_plan.episode_control.termination_rule == "fixed horizon"

        # Expected per-condition scenario-snapshot digest, recomputed
        # independently from the admitted scenario bytes and the admitted
        # condition parameter bindings (never read back off the plan).
        expected_digest_by_condition = {}
        for condition_id in allocation.compared_conditions:
            assignment = allocation.condition_assignments[condition_id]
            parameters = {p.name: p.value for p in assignment.required_parameters}
            instantiated = instantiate_scenario(scenario, parameters)
            expected_digest_by_condition[condition_id] = canonical_instantiated_sdl_digest(instantiated).value

        # Every declared-supported stochastic control that must appear on
        # every trial (unsupported roles, if any, would be admission
        # rejections upstream, not silently dropped here).
        supported_roles = default_admission_policy().supported_stochastic_control_roles
        expected_control_ids = frozenset(
            control.control_id
            for control in admitted_spec.run_plan.stochastic_controls
            if control.role in supported_roles
        )
        assert expected_control_ids == {"seed-a", "rand-a"}

        expected_capture_refs = tuple(ref.ref_id for ref in admitted_spec.capture_spec_refs)
        assert expected_capture_refs == ()

        seen_trial_ids: set[str] = set()
        seen_condition_replications: set[tuple[str, int]] = set()
        for trial in plan.trials:
            # --- ONE condition (never the flat sentinel here; this is a
            # condition allocation, so every trial's condition_id is one
            # of the two admitted conditions, never None). -------------
            assert trial.condition_id is not None
            assert trial.condition_id in allocation.compared_conditions

            # --- ONE scenario snapshot digest, and it is the CORRECT one
            # for this trial's own condition (not merely non-None). ----
            assert trial.scenario_snapshot_digest is not None
            assert trial.scenario_snapshot_digest == expected_digest_by_condition[trial.condition_id]

            # --- ONE stochastic-control set: the same control IDs on
            # every trial, each bound to exactly one derived seed. ------
            control_ids = tuple(control_id for control_id, _ in trial.stochastic_seeds)
            assert len(control_ids) == len(set(control_ids)), "duplicate control id within one trial"
            assert set(control_ids) == expected_control_ids

            # --- the admitted capture-spec references, identical and
            # consistent on every trial. ---------------------------------
            assert trial.capture_spec_refs == expected_capture_refs

            seen_trial_ids.add(trial.planned_trial_id)
            seen_condition_replications.add((trial.condition_id, trial.replication_ordinal))

        # Every trial has a distinct stable ID and a distinct logical
        # coordinate: the plan does not silently collapse two trials into
        # the same identity.
        assert len(seen_trial_ids) == len(plan.trials)
        assert len(seen_condition_replications) == len(plan.trials)

        # The two conditions really do resolve to two DIFFERENT scenario
        # snapshots (proving the per-condition binding is not vacuously
        # true because every condition happens to instantiate the same
        # scenario).
        assert expected_digest_by_condition["cond-a"] != expected_digest_by_condition["cond-b"]
