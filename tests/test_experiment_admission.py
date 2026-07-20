"""Tests for ``aptl.core.experiment.admission`` (ADR-047 Stage 5 - the
INTEGRATION KEYSTONE of EXP-002 / issue #438).

``admit_experiment`` is the single coordinator wiring Stages 1-4
(``errors``, ``policy``, ``resolver``, ``spec_loading``, ``apparatus``,
``capture_mapping``, ``trial_plan``) into one all-or-nothing sequence, ending
in create-once persistence via ``LocalRunStore.create_json_once`` with a
digest re-verification read-back. Two coverage axes matter most here:

* the ADMITTED happy path actually produces a persisted, digest-matching
  plan for both a capability-only task (default policy) and a task pinned
  to real APTL/reference-processor identities (rejected under default
  policy, admitted-with-exactly-one-warning under the
  ``allow_uncertified_apparatus`` debug override);
* the MUTATION-SPY proof that a REJECTED admission never calls any
  range-mutating entry point or writes to the run store — this is ADR-047's
  core "Range-mutation gate" boundary.

Uses ``MappingArtifactSource`` (an in-memory ``ref_id -> ResolvedArtifact``
seam) for everything except the dedicated
``TestBuildAssociatedArtifactSource*`` classes, which exercise the
production, on-disk, ``ProjectContainedResolver``-backed artifact source
directly (``tests/test_experiment_controller.py`` additionally exercises it
through the full ``ExperimentController.admit()`` composition).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sys

import pytest
import yaml
from aces_backend_protocols.backend_manifest import BackendManifest
from aces_contracts.associated_artifacts import (
    AssociatedArtifactManifestModel,
    associated_artifact_set_digest,
)
from aces_contracts.corpus import FIXTURES, corpus_family_root
from aces_contracts.diagnostics import Severity
from aces_processor.capabilities import ProcessorManifest
from aces_processor.manifest import create_reference_processor_manifest

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.experiment.admission import (
    AdmissionResult,
    MappingArtifactSource,
    admit_experiment,
    build_associated_artifact_source,
)
from aptl.core.experiment.errors import AdmissionRejection
from aptl.core.experiment.policy import default_admission_policy
from aptl.core.experiment.resolver import ResolvedArtifact
from aptl.core.experiment.spec_loading import load_experiment_root
from aptl.core.runstore import LocalRunStore

CORPUS_ROOT = corpus_family_root(FIXTURES)
SECRET = "sk-super-secret-injected-token-98765"


# ---------------------------------------------------------------------------
# Shared fixture-building helpers
# ---------------------------------------------------------------------------


def _resolved(data: bytes, locator: str, media_type: str) -> ResolvedArtifact:
    return ResolvedArtifact(
        data=data,
        locator=locator,
        digest=f"sha256:{hashlib.sha256(data).hexdigest()}",
        media_type=media_type,
    )


def _read_corpus_task_payload() -> dict:
    path = CORPUS_ROOT / "experiment-core" / "experiment-task-v1" / "valid" / "reference.json"
    return json.loads(path.read_text())


def _read_corpus_capture_spec_payload() -> dict:
    path = CORPUS_ROOT / "experiment-core" / "experiment-capture-spec-v1" / "valid" / "reference.json"
    return json.loads(path.read_text())


def _minimal_scenario_bytes() -> bytes:
    path = CORPUS_ROOT / "sdl" / "sdl-yaml-v1" / "valid" / "minimal.yaml"
    return path.read_bytes()


def _synthetic_manifests() -> tuple[BackendManifest, ProcessorManifest]:
    """A test-only manifest pair that genuinely mutually declares
    compatibility, cloned from the real aptl / reference-processor
    manifests' capability fields (only ``name``/compatibility differ). NOT
    the real canonical manifests — the sibling apparatus tests already
    prove admission must never fabricate compatibility by patching those;
    this is legitimate dependency injection through the ``backend_manifest``
    /``processor_manifest`` override params, proving the pipeline admits
    end-to-end when a certified-compatible pair genuinely exists.
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


def _capability_only_task_payload(*, declared_capability: str, extra_notes: list[str] | None = None) -> dict:
    payload = _read_corpus_task_payload()
    payload["task_id"] = "task-minimal"
    payload["task_version"] = "1.0.0"
    payload["scenario_ref"] = {"ref_kind": "scenario", "ref_id": "canonical-minimal"}
    payload["apparatus_constraints"] = {
        "required_capabilities": [declared_capability],
        "notes": extra_notes or [],
    }
    return payload


def _pinned_identity_task_payload() -> dict:
    payload = _read_corpus_task_payload()
    payload["task_id"] = "task-minimal"
    payload["task_version"] = "1.0.0"
    payload["scenario_ref"] = {"ref_kind": "scenario", "ref_id": "canonical-minimal"}
    payload["apparatus_constraints"] = {
        "allowed_processor_refs": [
            {"ref_kind": "processor", "ref_id": "aces-reference-processor", "ref_version": "0.1.0"}
        ],
        "allowed_backend_refs": [{"ref_kind": "backend", "ref_id": "aptl", "ref_version": "0.1.0"}],
        "required_manifest_refs": [
            {
                "ref_kind": "manifest",
                "ref_id": "aces-reference-processor",
                "ref_version": "processor-manifest/v2",
                "subject_ref": {
                    "ref_kind": "processor",
                    "ref_id": "aces-reference-processor",
                    "ref_version": "0.1.0",
                },
            },
            {
                "ref_kind": "manifest",
                "ref_id": "aptl",
                "ref_version": "backend-manifest/v2",
                "subject_ref": {"ref_kind": "backend", "ref_id": "aptl", "ref_version": "0.1.0"},
            },
        ],
        "required_capabilities": [],
        "notes": [],
    }
    return payload


def _flat_spec_payload(
    *,
    spec_id: str = "spec-minimal-v1",
    target_run_count: int = 3,
    capture_spec_refs: list[dict] | None = None,
) -> dict:
    payload: dict = {
        "schema_version": "experiment-authoring-input/v1",
        "spec_id": spec_id,
        "spec_version": "1.0.0",
        "title": "Minimal flat spec",
        "description": "Minimal flat allocation admission fixture.",
        "task_ref": {"ref_kind": "task", "ref_id": "task-minimal", "ref_version": "1.0.0"},
        "run_plan": {
            "stochastic_controls": [{"control_id": "seed-a", "role": "seed", "value": 1}],
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


class _Bundle:
    """A fully built admission-ready bundle: root/task/scenario (+ optional
    capture-spec) bytes plus a :class:`MappingArtifactSource` binding them
    by reference identity."""

    def __init__(self, *, task_payload: dict, spec_payload: dict, capture_spec_payload: dict | None = None):
        self.task_bytes = json.dumps(task_payload).encode("utf-8")
        self.scenario_bytes = _minimal_scenario_bytes()
        self.root_bytes = yaml.safe_dump(spec_payload).encode("utf-8")
        self.experiment_root = _resolved(self.root_bytes, "experiment.yaml", "application/x-yaml")

        artifacts = {
            task_payload["task_id"]: _resolved(self.task_bytes, "task.json", "application/json"),
            "canonical-minimal": _resolved(self.scenario_bytes, "scenario.sdl.yaml", "application/x-yaml"),
        }
        if capture_spec_payload is not None:
            capture_bytes = json.dumps(capture_spec_payload).encode("utf-8")
            artifacts[capture_spec_payload["capture_spec_id"]] = _resolved(
                capture_bytes, "capture.json", "application/json"
            )
        self.artifact_source = MappingArtifactSource(artifacts=artifacts)


def _capability_only_bundle(
    *, spec_id: str = "spec-minimal-v1", target_run_count: int = 3, extra_notes: list[str] | None = None
) -> tuple[_Bundle, BackendManifest, ProcessorManifest]:
    backend, processor = _synthetic_manifests()
    declared = sorted(backend.supported_contract_versions)[0]
    task_payload = _capability_only_task_payload(declared_capability=declared, extra_notes=extra_notes)
    spec_payload = _flat_spec_payload(spec_id=spec_id, target_run_count=target_run_count)
    return _Bundle(task_payload=task_payload, spec_payload=spec_payload), backend, processor


def _pinned_identity_bundle(*, spec_id: str = "spec-pinned-v1", target_run_count: int = 3) -> _Bundle:
    task_payload = _pinned_identity_task_payload()
    spec_payload = _flat_spec_payload(spec_id=spec_id, target_run_count=target_run_count)
    return _Bundle(task_payload=task_payload, spec_payload=spec_payload)


class _SpyRunStore:
    """Wraps a real :class:`LocalRunStore`, recording every protocol call
    so a rejected-admission test can assert NO write occurred at all."""

    def __init__(self, base_dir):
        self._inner = LocalRunStore(base_dir)
        self.calls: dict[str, int] = {}

    def _record(self, name: str) -> None:
        self.calls[name] = self.calls.get(name, 0) + 1

    def create_run(self, run_id):
        self._record("create_run")
        return self._inner.create_run(run_id)

    def write_file(self, run_id, relative_path, data):
        self._record("write_file")
        return self._inner.write_file(run_id, relative_path, data)

    def write_json(self, run_id, relative_path, obj):
        self._record("write_json")
        return self._inner.write_json(run_id, relative_path, obj)

    def write_jsonl(self, run_id, relative_path, records):
        self._record("write_jsonl")
        return self._inner.write_jsonl(run_id, relative_path, records)

    def append_jsonl(self, run_id, relative_path, records):
        self._record("append_jsonl")
        return self._inner.append_jsonl(run_id, relative_path, records)

    def copy_file(self, run_id, relative_path, source):
        self._record("copy_file")
        return self._inner.copy_file(run_id, relative_path, source)

    def create_json_once(self, namespace, name, payload):
        self._record("create_json_once")
        return self._inner.create_json_once(namespace, name, payload)

    def list_runs(self):
        self._record("list_runs")
        return self._inner.list_runs()

    def get_run_manifest(self, run_id):
        self._record("get_run_manifest")
        return self._inner.get_run_manifest(run_id)

    def get_run_path(self, run_id):
        self._record("get_run_path")
        return self._inner.get_run_path(run_id)


def _install_mutation_spies(monkeypatch) -> None:
    """Patch every range-mutating entry point ADR-047's "Range-mutation
    gate" names so a call from admission fails the test loudly instead of
    silently succeeding. Mirrors the pattern already proven in
    ``test_experiment_apparatus.py``'s
    ``TestPlanConditionFeasibilityNeverTouchesDocker``.
    """
    import aptl.core.collectors as collectors_module
    import aptl.core.deployment.docker_compose as docker_compose_module
    import aptl.core.env as env_module
    import aptl.core.lab as lab_module
    import aptl.core.soc_ca as soc_ca_module
    import aptl.core.ssh as ssh_module

    def _boom(*args, **kwargs):
        raise AssertionError("range-mutating entry point must never be called by rejected admission")

    monkeypatch.setattr(lab_module, "start_lab", _boom)
    monkeypatch.setattr(lab_module, "stop_lab", _boom)
    monkeypatch.setattr(lab_module, "clean_boot_lab", _boom)
    monkeypatch.setattr(soc_ca_module, "ensure_soc_certs", _boom)
    monkeypatch.setattr(ssh_module, "ensure_ssh_keys", _boom)
    monkeypatch.setattr(ssh_module, "ensure_pivot_key", _boom)
    monkeypatch.setattr(env_module, "hydrate_dotenv", _boom)
    monkeypatch.setattr(collectors_module, "_run_cmd", _boom)
    monkeypatch.setattr(docker_compose_module.subprocess, "run", _boom)

    for leftover in ("aptl.core.deployment.ssh_compose", "aces_runtime.manager"):
        monkeypatch.delitem(sys.modules, leftover, raising=False)


# ---------------------------------------------------------------------------
# AdmissionResult
# ---------------------------------------------------------------------------


class TestAdmissionResult:
    def test_rejected_never_carries_a_plan(self):
        from aces_contracts.diagnostics import Diagnostic

        d = Diagnostic(code="c", domain="experiment-admission", address="a", message="m")
        result = AdmissionResult.rejected((d,))

        assert result.admitted is False
        assert result.diagnostics == (d,)
        assert result.plan is None
        assert result.plan_digest is None
        assert result.persisted_path is None

    def test_rejected_requires_at_least_one_diagnostic(self):
        with pytest.raises(ValueError, match="diagnostic"):
            AdmissionResult.rejected(())

    def test_plain_constructor_rejects_a_rejected_shape_carrying_a_plan(self):
        with pytest.raises(ValueError, match="must never carry a plan"):
            AdmissionResult(admitted=False, diagnostics=(), plan_digest="sha256:" + "0" * 64)

    def test_plain_constructor_rejects_an_admitted_shape_missing_a_plan(self):
        with pytest.raises(ValueError, match="must carry plan"):
            AdmissionResult(admitted=True)


# ---------------------------------------------------------------------------
# admit_experiment — happy path (a): capability-only task, default policy
# ---------------------------------------------------------------------------


class TestAdmitExperimentHappyPathCapabilityOnly:
    def test_admits_under_default_policy_with_no_warnings(self, tmp_path):
        bundle, backend, processor = _capability_only_bundle()
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is True
        assert result.warnings == ()
        assert result.diagnostics == ()
        assert len(result.trial_ids) == 3
        assert len(result.plan.trials) == 3

    def test_persists_a_plan_whose_bytes_match_the_computed_digest(self, tmp_path):
        bundle, backend, processor = _capability_only_bundle()
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.persisted_path.exists()
        assert result.persisted_path.read_bytes() == result.plan.canonical_bytes
        assert result.plan_digest == result.plan.plan_digest
        assert result.persisted_path == tmp_path / "store" / "experiment-plans" / f"{result.plan.plan_id}.json"


# ---------------------------------------------------------------------------
# admit_experiment — happy path (b): identity-pinned task, real manifests
# ---------------------------------------------------------------------------


class TestAdmitExperimentHappyPathPinnedIdentity:
    def test_rejected_under_default_policy_for_mutual_incompatibility(self, tmp_path):
        bundle = _pinned_identity_bundle()
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
        )

        assert result.admitted is False
        assert any("mutual-incompatible" in d.code for d in result.diagnostics)

    def test_admitted_with_the_debug_override_and_exactly_one_warning(self, tmp_path):
        bundle = _pinned_identity_bundle()
        store = LocalRunStore(tmp_path / "store")
        policy = dataclasses.replace(default_admission_policy(), allow_uncertified_apparatus=True)

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=policy,
        )

        assert result.admitted is True
        assert len(result.warnings) == 1
        assert result.warnings[0].severity == Severity.WARNING
        assert "uncertified-compatibility" in result.warnings[0].code
        assert result.persisted_path.exists()
        assert result.persisted_path.read_bytes() == result.plan.canonical_bytes


# ---------------------------------------------------------------------------
# admit_experiment — condition allocation, all-or-nothing (Finding 3)
# ---------------------------------------------------------------------------

_CONDITION_ALLOCATION_SCENARIO_TEXT = """
name: scenario-condition-admission
variables:
  danger_level:
    type: string
    default: low
nodes:
  on:
    type: switch
"""


def _condition_allocation_task_payload() -> dict:
    payload = _read_corpus_task_payload()
    payload["task_id"] = "task-condition-admission"
    payload["task_version"] = "1.0.0"
    payload["scenario_ref"] = {"ref_kind": "scenario", "ref_id": "scenario-condition-admission"}
    payload["apparatus_constraints"] = {"required_capabilities": [], "notes": ["unrestricted apparatus"]}
    return payload


def _condition_allocation_spec_payload_one_infeasible() -> dict:
    """Two compared conditions, one of which binds an UNDECLARED SDL
    variable target -- ``run_reference_processor`` raises
    ``SDLInstantiationError`` for exactly this shape (proven directly in
    ``TestPlanConditionFeasibilityBrokenParameterBinding`` in
    ``test_experiment_apparatus.py``), which ``_plan_conditions`` normalizes
    into an ``AdmissionRejection``. ``cond-feasible`` sorts before
    ``cond-infeasible`` in ``compared_conditions`` (authored order), so the
    feasible condition is planned successfully FIRST and would already have
    a snapshot digest computed before the second condition blows up -- this
    is exactly what must NOT leak into a partial plan or a partial write.
    """
    return {
        "schema_version": "experiment-authoring-input/v1",
        "spec_id": "spec-condition-admission-v1",
        "spec_version": "1.0.0",
        "title": "One infeasible condition",
        "description": "Proves per-condition all-or-nothing admission (Finding 3).",
        "task_ref": {"ref_kind": "task", "ref_id": "task-condition-admission", "ref_version": "1.0.0"},
        "run_plan": {
            "stochastic_controls": [{"control_id": "seed-a", "role": "seed", "value": 1}],
            "episode_control": {
                "turn_order": "sequential",
                "max_steps": 10,
                "termination_rule": "fixed horizon",
            },
            "allocation": {
                "allocation_unit": "trial",
                "allocation_method": "balanced",
                "compared_conditions": ["cond-feasible", "cond-infeasible"],
                "condition_assignments": {
                    "cond-feasible": {
                        "condition_id": "cond-feasible",
                        "factor_levels": {"danger": "high"},
                        "required_parameters": [
                            {"name": "danger_level", "value": "high", "value_kind": "configuration"}
                        ],
                    },
                    "cond-infeasible": {
                        "condition_id": "cond-infeasible",
                        "factor_levels": {"danger": "undeclared"},
                        "required_parameters": [
                            {
                                "name": "totally-undeclared-target",
                                "value": "x",
                                "value_kind": "configuration",
                            }
                        ],
                    },
                },
                "target_runs_per_condition": 2,
                "blocking_factors": [],
                "replication_policy": "independent-replications",
            },
        },
    }


class TestAdmitExperimentConditionAllocationAllOrNothing:
    def test_one_infeasible_condition_rejects_the_whole_admission_with_no_partial_plan_or_write(self, tmp_path):
        task_payload = _condition_allocation_task_payload()
        task_bytes = json.dumps(task_payload).encode("utf-8")
        scenario_bytes = _CONDITION_ALLOCATION_SCENARIO_TEXT.encode("utf-8")
        spec_payload = _condition_allocation_spec_payload_one_infeasible()
        root_bytes = yaml.safe_dump(spec_payload).encode("utf-8")
        backend, processor = _synthetic_manifests()

        artifact_source = MappingArtifactSource(
            artifacts={
                "task-condition-admission": _resolved(task_bytes, "task.json", "application/json"),
                "scenario-condition-admission": _resolved(
                    scenario_bytes, "scenario.sdl.yaml", "application/x-yaml"
                ),
            }
        )
        store = _SpyRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=_resolved(root_bytes, "experiment.yaml", "application/x-yaml"),
            artifact_source=artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any("condition-parameters-invalid" in d.code for d in result.diagnostics)
        # No partial plan on the rejected result...
        assert result.plan is None
        assert result.plan_digest is None
        assert result.persisted_path is None
        assert result.trial_ids == ()
        # ...and nothing was ever written to the run store (the feasible
        # condition's own snapshot digest, computed before the second
        # condition failed, never reaches persistence).
        assert store.calls == {}


# ---------------------------------------------------------------------------
# admit_experiment — determinism
# ---------------------------------------------------------------------------


class TestAdmitExperimentDeterminism:
    def test_admitting_the_same_inputs_twice_yields_the_same_digest_and_is_idempotent(self, tmp_path):
        bundle, backend, processor = _capability_only_bundle()
        store = LocalRunStore(tmp_path / "store")

        first = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )
        second = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert first.admitted is True
        assert second.admitted is True
        assert first.plan_digest == second.plan_digest
        assert first.persisted_path == second.persisted_path
        assert first.trial_ids == second.trial_ids


@pytest.mark.fuzz
class TestFuzzAdmitExperimentDeterminism:
    from hypothesis import given, settings
    from hypothesis import strategies as st

    @given(target_run_count=st.integers(min_value=1, max_value=30))
    @settings(max_examples=20, deadline=None)
    def test_repeated_admission_is_deterministic_across_random_flat_counts(self, tmp_path_factory, target_run_count):
        bundle, backend, processor = _capability_only_bundle(
            spec_id=f"spec-fuzz-{target_run_count}", target_run_count=target_run_count
        )
        store = LocalRunStore(tmp_path_factory.mktemp("store"))

        first = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )
        second = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert first.admitted is True
        assert second.admitted is True
        assert first.plan_digest == second.plan_digest
        assert len(first.trial_ids) == target_run_count
        assert len(set(first.trial_ids)) == target_run_count


# ---------------------------------------------------------------------------
# Mutation spy (mandatory, security-critical) — ADR-047 "Range-mutation gate"
# ---------------------------------------------------------------------------


class TestMutationSpyRejectedAdmissionMakesNoMutatingCalls:
    def test_apparatus_fatal_rejection_makes_no_mutating_or_write_calls(self, tmp_path, monkeypatch):
        _install_mutation_spies(monkeypatch)
        bundle = _pinned_identity_bundle()
        store = _SpyRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
        )

        assert result.admitted is False
        assert store.calls == {}
        assert "aptl.core.deployment.ssh_compose" not in sys.modules
        assert "aces_runtime.manager" not in sys.modules

    def test_cross_artifact_identity_mismatch_rejection_makes_no_mutating_or_write_calls(
        self, tmp_path, monkeypatch
    ):
        _install_mutation_spies(monkeypatch)
        bundle, backend, processor = _capability_only_bundle()
        bad_task_payload = json.loads(bundle.task_bytes)
        bad_task_payload["task_id"] = "task-DIFFERENT-IDENTITY"
        bad_source = MappingArtifactSource(
            artifacts={
                "task-minimal": _resolved(
                    json.dumps(bad_task_payload).encode("utf-8"), "task.json", "application/json"
                ),
                "canonical-minimal": _resolved(bundle.scenario_bytes, "scenario.sdl.yaml", "application/x-yaml"),
            }
        )
        store = _SpyRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bad_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any("identity-mismatch" in d.code for d in result.diagnostics)
        assert store.calls == {}

    def test_oversize_root_rejection_makes_no_mutating_or_write_calls(self, tmp_path, monkeypatch):
        _install_mutation_spies(monkeypatch)
        bundle, backend, processor = _capability_only_bundle()
        tiny_policy = dataclasses.replace(default_admission_policy(), max_root_bytes=1)
        store = _SpyRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=tiny_policy,
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert store.calls == {}

    def test_capture_bearing_spec_fail_closed_rejection_makes_no_mutating_or_write_calls(
        self, tmp_path, monkeypatch
    ):
        _install_mutation_spies(monkeypatch)
        backend, processor = _synthetic_manifests()
        declared = sorted(backend.supported_contract_versions)[0]
        task_payload = _capability_only_task_payload(declared_capability=declared)
        capture_payload = _read_corpus_capture_spec_payload()
        capture_payload["capture_spec_id"] = "capture-minimal"
        capture_payload["spec_version"] = "1.0.0"
        capture_payload["scope_refs"] = [
            {"ref_kind": "task", "ref_id": task_payload["task_id"], "ref_version": task_payload["task_version"]}
        ]
        spec_payload = _flat_spec_payload(
            capture_spec_refs=[
                {"ref_kind": "capture-spec", "ref_id": "capture-minimal", "ref_version": "1.0.0"}
            ]
        )
        bundle = _Bundle(task_payload=task_payload, spec_payload=spec_payload, capture_spec_payload=capture_payload)
        store = _SpyRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any("capture-requirement-unsupported" in d.code for d in result.diagnostics)
        assert store.calls == {}


# ---------------------------------------------------------------------------
# Rejection-path coverage
# ---------------------------------------------------------------------------


class TestAdmitExperimentRejectionPaths:
    def test_oversize_root_is_rejected_with_safe_diagnostics(self, tmp_path):
        bundle, backend, processor = _capability_only_bundle()
        tiny_policy = dataclasses.replace(default_admission_policy(), max_root_bytes=1)
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=tiny_policy,
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert result.diagnostics
        assert result.plan is None

    def test_cross_artifact_identity_mismatch_is_rejected(self, tmp_path):
        bundle, backend, processor = _capability_only_bundle()
        bad_task_payload = json.loads(bundle.task_bytes)
        bad_task_payload["task_id"] = "task-DIFFERENT-IDENTITY"
        bad_source = MappingArtifactSource(
            artifacts={
                "task-minimal": _resolved(
                    json.dumps(bad_task_payload).encode("utf-8"), "task.json", "application/json"
                ),
                "canonical-minimal": _resolved(bundle.scenario_bytes, "scenario.sdl.yaml", "application/x-yaml"),
            }
        )
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bad_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any("identity-mismatch" in d.code for d in result.diagnostics)

    def test_capture_bearing_spec_fails_closed(self, tmp_path):
        backend, processor = _synthetic_manifests()
        declared = sorted(backend.supported_contract_versions)[0]
        task_payload = _capability_only_task_payload(declared_capability=declared)
        capture_payload = _read_corpus_capture_spec_payload()
        capture_payload["capture_spec_id"] = "capture-minimal"
        capture_payload["spec_version"] = "1.0.0"
        capture_payload["scope_refs"] = [
            {"ref_kind": "task", "ref_id": task_payload["task_id"], "ref_version": task_payload["task_version"]}
        ]
        spec_payload = _flat_spec_payload(
            capture_spec_refs=[
                {"ref_kind": "capture-spec", "ref_id": "capture-minimal", "ref_version": "1.0.0"}
            ]
        )
        bundle = _Bundle(task_payload=task_payload, spec_payload=spec_payload, capture_spec_payload=capture_payload)
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any("capture-requirement-unsupported" in d.code for d in result.diagnostics)

    def test_apparatus_fatal_independent_of_mutual_compat_is_rejected(self, tmp_path):
        backend, processor = _synthetic_manifests()
        task_payload = _capability_only_task_payload(declared_capability="totally-made-up-capability")
        spec_payload = _flat_spec_payload()
        bundle = _Bundle(task_payload=task_payload, spec_payload=spec_payload)
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any("capability-unsupported" in d.code for d in result.diagnostics)

    def test_secret_bearing_failing_input_never_leaks_into_diagnostics(self, tmp_path):
        backend, processor = _synthetic_manifests()
        task_payload = _capability_only_task_payload(
            declared_capability="totally-made-up-capability",
            extra_notes=[f"internal-secret={SECRET}"],
        )
        spec_payload = _flat_spec_payload()
        bundle = _Bundle(task_payload=task_payload, spec_payload=spec_payload)
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        for d in result.diagnostics:
            assert SECRET not in d.message
            assert SECRET not in d.code
            assert SECRET not in d.address

    def test_unresolvable_artifact_reference_is_rejected(self, tmp_path):
        bundle, backend, processor = _capability_only_bundle()
        empty_source = MappingArtifactSource(artifacts={})
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=empty_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any("artifact-source-unresolved" in d.code for d in result.diagnostics)


# ---------------------------------------------------------------------------
# Cross-artifact join guards -- each branch tested in isolation (Finding 6)
# ---------------------------------------------------------------------------


class TestAdmitExperimentCrossArtifactJoinGuards:
    def test_task_version_mismatch_is_rejected(self, tmp_path):
        # task_id matches ("task-minimal") but spec.task_ref pins a
        # ref_version the resolved task does not carry -- the SECOND branch
        # of _check_task_identity, distinct from the ref_id-mismatch branch
        # already covered by test_cross_artifact_identity_mismatch_is_rejected.
        bundle, backend, processor = _capability_only_bundle()
        spec_payload = _flat_spec_payload()
        spec_payload["task_ref"]["ref_version"] = "9.9.9"
        bad_root = _resolved(
            yaml.safe_dump(spec_payload).encode("utf-8"), "experiment.yaml", "application/x-yaml"
        )
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bad_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any(
            d.code == "aptl.experiment-admission.reference-identity-mismatch" and d.address == "task_ref.ref_version"
            for d in result.diagnostics
        )

    def test_intended_scenario_ref_disagreement_with_task_scenario_ref_is_rejected(self, tmp_path):
        # spec.intended_scenario_ref names a DIFFERENT ref_id than
        # task.scenario_ref ("canonical-minimal") -- _effective_scenario_ref's
        # task/scenario agreement gate.
        bundle, backend, processor = _capability_only_bundle()
        spec_payload = _flat_spec_payload()
        spec_payload["intended_scenario_ref"] = {"ref_kind": "scenario", "ref_id": "some-other-scenario-id"}
        bad_root = _resolved(
            yaml.safe_dump(spec_payload).encode("utf-8"), "experiment.yaml", "application/x-yaml"
        )
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bad_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any(
            d.code == "aptl.experiment-admission.task-scenario-ref-mismatch"
            and d.address == "intended_scenario_ref.ref_id"
            for d in result.diagnostics
        )

    def test_scenario_version_mismatch_is_rejected(self, tmp_path):
        # intended_scenario_ref pins the correct ref_id but a ref_version
        # the resolved scenario does not carry (the corpus minimal.yaml
        # scenario parses with version "*") -- _check_scenario_identity's
        # version branch. ref_kind must be "scenario-snapshot": a
        # ("scenario", id-only) ref rejects a ref_version/ref_digest at the
        # pydantic layer before admission's own cross-artifact join ever
        # runs (ACES: "generic scenario references are id-only").
        bundle, backend, processor = _capability_only_bundle()
        spec_payload = _flat_spec_payload()
        spec_payload["intended_scenario_ref"] = {
            "ref_kind": "scenario-snapshot",
            "ref_id": "canonical-minimal",
            "ref_version": "9.9.9",
        }
        bad_root = _resolved(
            yaml.safe_dump(spec_payload).encode("utf-8"), "experiment.yaml", "application/x-yaml"
        )
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bad_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any(
            d.code == "aptl.experiment-admission.reference-identity-mismatch"
            and d.address == "intended_scenario_ref.ref_version"
            for d in result.diagnostics
        )

    def test_scenario_digest_mismatch_is_rejected(self, tmp_path):
        # intended_scenario_ref pins the correct ref_id (no ref_version) but
        # a ref_digest that does not match the resolved scenario's own
        # canonical digest -- _check_scenario_identity's digest branch.
        # ref_kind must be "scenario-snapshot" (see the version-mismatch
        # test above for why).
        bundle, backend, processor = _capability_only_bundle()
        spec_payload = _flat_spec_payload()
        spec_payload["intended_scenario_ref"] = {
            "ref_kind": "scenario-snapshot",
            "ref_id": "canonical-minimal",
            "ref_digest": "sha256:" + "0" * 64,
        }
        bad_root = _resolved(
            yaml.safe_dump(spec_payload).encode("utf-8"), "experiment.yaml", "application/x-yaml"
        )
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bad_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any(
            d.code == "aptl.experiment-admission.scenario-ref-digest-mismatch"
            and d.address == "intended_scenario_ref.ref_digest"
            for d in result.diagnostics
        )

    def test_duplicate_capture_spec_refs_is_rejected(self, tmp_path):
        # Same capture-spec ref_id named twice in spec.capture_spec_refs --
        # _resolve_capture_specs' own duplicate-identity guard, which fires
        # before any capture-spec artifact is even resolved.
        bundle, backend, processor = _capability_only_bundle()
        spec_payload = _flat_spec_payload(
            capture_spec_refs=[
                {"ref_kind": "capture-spec", "ref_id": "capture-minimal", "ref_version": "1.0.0"},
                {"ref_kind": "capture-spec", "ref_id": "capture-minimal", "ref_version": "1.0.0"},
            ]
        )
        bad_root = _resolved(
            yaml.safe_dump(spec_payload).encode("utf-8"), "experiment.yaml", "application/x-yaml"
        )
        store = LocalRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bad_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert any(
            d.code == "aptl.experiment-admission.capture-spec-ref-duplicate" for d in result.diagnostics
        )


# ---------------------------------------------------------------------------
# _persist_plan — mismatch and failure diagnostics (Finding 4)
# ---------------------------------------------------------------------------


class _MismatchedReadBackRunStore:
    """A fake ``run_store`` whose ``create_json_once`` "succeeds" but
    persists bytes that do NOT match what the caller asked to persist
    (simulating e.g. a corrupted write or a concurrent external write to
    the same path) -- trips ``_persist_plan``'s post-write digest
    re-verification read-back.
    """

    def __init__(self, base_dir):
        self._base_dir = base_dir

    def create_json_once(self, namespace, name, payload):
        del payload
        path = self._base_dir / namespace / f"{name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'{"tampered": true}')
        return path


class _RaisingRunStore:
    """A fake ``run_store`` whose ``create_json_once`` always raises --
    simulating a ``RunStoreConflictError``/``SecretInvariantError`` (both
    ``ValueError`` subclasses) from the real ``LocalRunStore``.
    """

    def create_json_once(self, namespace, name, payload):
        del namespace, name, payload
        raise ValueError("simulated run-store write conflict")


class TestPersistPlanDiagnostics:
    def test_a_persisted_bytes_mismatch_is_rejected_with_the_specific_diagnostic(self, tmp_path):
        bundle, backend, processor = _capability_only_bundle()
        store = _MismatchedReadBackRunStore(tmp_path / "store")

        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert result.plan is None
        assert any(
            d.code == "aptl.experiment-admission.persisted-plan-digest-mismatch" for d in result.diagnostics
        )

    def test_a_persistence_failure_surfaces_as_a_rejection_not_an_unhandled_exception(self, tmp_path):
        bundle, backend, processor = _capability_only_bundle()
        store = _RaisingRunStore()

        # If admission ever let a bare ValueError from the run store escape
        # uncaught, this call itself would raise instead of returning --
        # asserting on the returned result (not a pytest.raises block) is
        # the point: a raised exception here fails the test just as surely
        # as a wrong diagnostic would.
        result = admit_experiment(
            experiment_root=bundle.experiment_root,
            artifact_source=bundle.artifact_source,
            run_store=store,
            policy=default_admission_policy(),
            backend_manifest=backend,
            processor_manifest=processor,
        )

        assert result.admitted is False
        assert result.plan is None
        assert any(d.code == "aptl.experiment-admission.plan-persistence-failed" for d in result.diagnostics)


# ---------------------------------------------------------------------------
# build_associated_artifact_source — production resolver-backed source
# ---------------------------------------------------------------------------


def _write_associated_artifact_bundle(base_dir, *, spec_id: str, task_bytes: bytes, scenario_bytes: bytes, corrupt_checksum: bool = False):
    (base_dir / "task.json").write_bytes(task_bytes)
    (base_dir / "scenario.sdl.yaml").write_bytes(scenario_bytes)

    def artifact_ref(artifact_id, uri, data, media_type, role, *, bad_checksum=False):
        checksum_value = "1" * 64 if bad_checksum else hashlib.sha256(data).hexdigest()
        return {
            "artifact_id": artifact_id,
            "role": role,
            "media_type": media_type,
            "uri": f"file:{uri}",
            "checksum": {"algorithm": "sha256", "value": checksum_value},
            "size_bytes": len(data),
            "created_at": "2026-05-26T00:00:00Z",
            "source": "test bundle",
            "satisfies_refs": [],
            "sensitivity": "internal",
        }

    artifacts = {
        "task-minimal": artifact_ref(
            "task-minimal", "task.json", task_bytes, "application/json", "other", bad_checksum=corrupt_checksum
        ),
        "canonical-minimal": artifact_ref(
            "canonical-minimal", "scenario.sdl.yaml", scenario_bytes, "application/x-yaml", "scenario-snapshot"
        ),
    }
    manifest_dict = {
        "schema_version": "associated-artifact-manifest/v1",
        "manifest_id": f"manifest-{spec_id}",
        "manifest_version": "1.0.0",
        "canonicalization_profile": "associated-artifact-set/v1",
        "scope": "experiment",
        "parent_ref": {"ref_kind": "authoring-input", "ref_id": spec_id, "ref_version": "1.0.0"},
        "artifacts": artifacts,
        "set_digest": "sha256:" + "0" * 64,
    }
    manifest_model = AssociatedArtifactManifestModel.model_validate(manifest_dict)
    manifest_dict["set_digest"] = associated_artifact_set_digest(manifest_model)
    manifest_path = base_dir / "associated-artifact-manifest.json"
    manifest_path.write_bytes(json.dumps(manifest_dict).encode("utf-8"))
    return manifest_path


class TestBuildAssociatedArtifactSource:
    def test_resolves_task_and_scenario_by_ref_identity(self, tmp_path):
        backend, _processor = _synthetic_manifests()
        declared = sorted(backend.supported_contract_versions)[0]
        task_payload = _capability_only_task_payload(declared_capability=declared)
        task_bytes = json.dumps(task_payload).encode("utf-8")
        scenario_bytes = _minimal_scenario_bytes()
        spec_payload = _flat_spec_payload(spec_id="spec-associated-v1")
        _write_associated_artifact_bundle(
            tmp_path, spec_id="spec-associated-v1", task_bytes=task_bytes, scenario_bytes=scenario_bytes
        )
        spec = load_experiment_root(
            yaml.safe_dump(spec_payload).encode("utf-8"), policy=default_admission_policy()
        )

        source = build_associated_artifact_source(
            tmp_path, "associated-artifact-manifest.json", spec, default_admission_policy()
        )

        task_artifact = source.artifact_for(spec.task_ref)
        assert task_artifact.data == task_bytes

    def test_a_corrupted_checksum_raises_admission_rejection(self, tmp_path):
        backend, _processor = _synthetic_manifests()
        declared = sorted(backend.supported_contract_versions)[0]
        task_payload = _capability_only_task_payload(declared_capability=declared)
        task_bytes = json.dumps(task_payload).encode("utf-8")
        scenario_bytes = _minimal_scenario_bytes()
        spec_payload = _flat_spec_payload(spec_id="spec-associated-bad-v1")
        _write_associated_artifact_bundle(
            tmp_path,
            spec_id="spec-associated-bad-v1",
            task_bytes=task_bytes,
            scenario_bytes=scenario_bytes,
            corrupt_checksum=True,
        )
        policy = default_admission_policy()
        spec = load_experiment_root(yaml.safe_dump(spec_payload).encode("utf-8"), policy=policy)

        with pytest.raises(AdmissionRejection) as excinfo:
            build_associated_artifact_source(tmp_path, "associated-artifact-manifest.json", spec, policy)

        assert excinfo.value.diagnostics
