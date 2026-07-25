"""Tests for ``aptl.core.experiment.controller.ExperimentController``
(ADR-047 "Experiment-controller boundary", Stage 5 / EXP-002 / issue #438).

Unlike ``test_experiment_admission.py`` (which drives ``admit_experiment``
directly through an in-memory ``MappingArtifactSource``), these tests
exercise the controller's default composition end-to-end: an on-disk
project bundle (task/scenario files plus an ACES associated-artifact
manifest binding them), resolved through the REAL
``build_associated_artifact_source`` -> ``ProjectContainedResolver`` path —
proving the production artifact-source wiring, not just the pure admission
sequence, actually works.

Execution (running the admitted plan's trials) is explicitly out of scope —
``ExperimentController`` has no ``.execute()``/``.run()`` method at all;
that is downstream work in #437/#459.
"""

from __future__ import annotations

import hashlib
import json

import pytest
import yaml
from aces_backend_protocols.backend_manifest import BackendManifest
from aces_contracts.associated_artifacts import (
    AssociatedArtifactManifestModel,
    associated_artifact_set_digest,
)
from aces_contracts.corpus import FIXTURES, corpus_family_root
from aces_processor.capabilities import ProcessorManifest
from aces_processor.manifest import create_reference_processor_manifest

from aptl.backends.aces_manifest import create_aptl_manifest
from aptl.core.experiment.admission import MappingArtifactSource
from aptl.core.experiment.controller import ExperimentController
from aptl.core.experiment.policy import default_admission_policy
from aptl.core.experiment.resolver import ResolvedArtifact
from aptl.core.runstore import LocalRunStore

CORPUS_ROOT = corpus_family_root(FIXTURES)


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


def _minimal_scenario_bytes() -> bytes:
    path = CORPUS_ROOT / "sdl" / "sdl-yaml-v1" / "valid" / "minimal.yaml"
    return path.read_bytes()


def _synthetic_manifests() -> tuple[BackendManifest, ProcessorManifest]:
    """See ``test_experiment_admission.py``'s helper of the same name for
    why this test-only, but genuinely mutually-compatible, manifest pair
    is legitimate dependency injection rather than fabricated compatibility."""
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


def _capability_only_task_payload(*, declared_capability: str) -> dict:
    payload = _read_corpus_task_payload()
    payload["task_id"] = "task-minimal"
    payload["task_version"] = "1.0.0"
    payload["scenario_ref"] = {"ref_kind": "scenario", "ref_id": "canonical-minimal"}
    payload["apparatus_constraints"] = {"required_capabilities": [declared_capability], "notes": []}
    return payload


def _flat_spec_payload(*, spec_id: str = "spec-controller-v1", target_run_count: int = 3) -> dict:
    return {
        "schema_version": "experiment-authoring-input/v1",
        "spec_id": spec_id,
        "spec_version": "1.0.0",
        "title": "Controller happy-path spec",
        "description": "Minimal flat allocation controller fixture.",
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


def _write_associated_artifact_bundle(
    base_dir, *, spec_id: str, task_bytes: bytes, scenario_bytes: bytes, corrupt_checksum: bool = False
) -> None:
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
    (base_dir / "associated-artifact-manifest.json").write_bytes(json.dumps(manifest_dict).encode("utf-8"))


class TestExperimentControllerHappyPath:
    def test_admit_returns_an_admitted_result_through_the_production_artifact_source(self, tmp_path):
        backend, processor = _synthetic_manifests()
        declared = sorted(backend.supported_contract_versions)[0]
        task_payload = _capability_only_task_payload(declared_capability=declared)
        task_bytes = json.dumps(task_payload).encode("utf-8")
        scenario_bytes = _minimal_scenario_bytes()
        spec_payload = _flat_spec_payload()
        root_bytes = yaml.safe_dump(spec_payload).encode("utf-8")

        base_dir = tmp_path / "project"
        base_dir.mkdir()
        _write_associated_artifact_bundle(
            base_dir, spec_id=spec_payload["spec_id"], task_bytes=task_bytes, scenario_bytes=scenario_bytes
        )

        store = LocalRunStore(tmp_path / "store")
        controller = ExperimentController(run_store=store, backend_manifest=backend, processor_manifest=processor)

        result = controller.admit(
            experiment_root=_resolved(root_bytes, "experiment.yaml", "application/x-yaml"),
            base_dir=base_dir,
            manifest_locator="associated-artifact-manifest.json",
        )

        assert result.admitted is True
        assert len(result.trial_ids) == 3
        assert result.persisted_path.exists()
        assert result.persisted_path.read_bytes() == result.plan.canonical_bytes

    def test_defaults_policy_and_manifests_when_not_injected(self, tmp_path):
        controller = ExperimentController(run_store=LocalRunStore(tmp_path / "store"))

        assert controller.policy is not None
        assert controller.backend_manifest is not None
        assert controller.processor_manifest is not None
        assert controller.backend_manifest.name == "aptl"

    def test_has_no_execution_method(self):
        # ADR-047: execution (running an admitted plan's trials) is
        # downstream work (#437/#459); the controller must not implement it.
        for forbidden in ("execute", "run", "run_trials", "start"):
            assert not hasattr(ExperimentController, forbidden)


class TestExperimentControllerRejectionPaths:
    def test_a_corrupted_checksum_in_the_associated_artifact_manifest_is_rejected(self, tmp_path):
        backend, processor = _synthetic_manifests()
        declared = sorted(backend.supported_contract_versions)[0]
        task_payload = _capability_only_task_payload(declared_capability=declared)
        task_bytes = json.dumps(task_payload).encode("utf-8")
        scenario_bytes = _minimal_scenario_bytes()
        spec_payload = _flat_spec_payload(spec_id="spec-controller-bad-v1")
        root_bytes = yaml.safe_dump(spec_payload).encode("utf-8")

        base_dir = tmp_path / "project"
        base_dir.mkdir()
        _write_associated_artifact_bundle(
            base_dir,
            spec_id=spec_payload["spec_id"],
            task_bytes=task_bytes,
            scenario_bytes=scenario_bytes,
            corrupt_checksum=True,
        )

        store = LocalRunStore(tmp_path / "store")
        controller = ExperimentController(run_store=store, backend_manifest=backend, processor_manifest=processor)

        result = controller.admit(
            experiment_root=_resolved(root_bytes, "experiment.yaml", "application/x-yaml"),
            base_dir=base_dir,
            manifest_locator="associated-artifact-manifest.json",
        )

        assert result.admitted is False
        assert result.plan is None
        assert result.diagnostics

    def test_a_malformed_root_document_is_rejected_not_raised(self, tmp_path):
        store = LocalRunStore(tmp_path / "store")
        controller = ExperimentController(run_store=store)
        base_dir = tmp_path / "project"
        base_dir.mkdir()

        result = controller.admit(
            experiment_root=_resolved(b"not: [valid, experiment", "experiment.yaml", "application/x-yaml"),
            base_dir=base_dir,
            manifest_locator="does-not-matter.json",
        )

        assert result.admitted is False
        assert result.diagnostics


class TestExperimentControllerInjectableArtifactSourceFactory:
    def test_a_test_injected_factory_bypasses_the_filesystem_entirely(self, tmp_path):
        backend, processor = _synthetic_manifests()
        declared = sorted(backend.supported_contract_versions)[0]
        task_payload = _capability_only_task_payload(declared_capability=declared)
        task_bytes = json.dumps(task_payload).encode("utf-8")
        scenario_bytes = _minimal_scenario_bytes()
        spec_payload = _flat_spec_payload(spec_id="spec-controller-mapping-v1")
        root_bytes = yaml.safe_dump(spec_payload).encode("utf-8")

        def _factory(base_dir, manifest_locator, spec, policy):
            del base_dir, manifest_locator, policy, spec
            return MappingArtifactSource(
                artifacts={
                    "task-minimal": _resolved(task_bytes, "task.json", "application/json"),
                    "canonical-minimal": _resolved(scenario_bytes, "scenario.sdl.yaml", "application/x-yaml"),
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
            base_dir=tmp_path / "nonexistent-unused-dir",
            manifest_locator="unused.json",
        )

        assert result.admitted is True
