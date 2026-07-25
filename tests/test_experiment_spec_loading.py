"""Tests for ``aptl.core.experiment.spec_loading`` (ADR-047 "ACES contracts
remain authoritative" + "Input shape").

Uses the installed ACES fixture corpus
(``aces_contracts.corpus.corpus_family_root(FIXTURES)``) as the contract
test source rather than a copied-in schema, per ADR-047's testing contract.
"""

from __future__ import annotations

import hashlib
import io
import json

import pytest
from aces_contracts.associated_artifacts import (
    AssociatedArtifactManifestModel,
    AssociatedArtifactValidationLimits,
    associated_artifact_set_digest,
)
from aces_contracts.contracts import (
    ExperimentCaptureSpecModel,
    ExperimentTaskModel,
)
from aces_contracts.corpus import FIXTURES, corpus_family_root
from aces_contracts.experiment_spec import ExperimentSpecModel
from aces_sdl.canonical import canonical_sdl_digest
from aces_sdl.scenario import Scenario

from aptl.core.experiment.errors import EXPERIMENT_ADMISSION_DOMAIN, AdmissionRejection
from aptl.core.experiment.policy import AdmissionPolicy, default_admission_policy
from aptl.core.experiment.spec_loading import (
    load_capture_spec,
    load_experiment_root,
    load_task,
    parse_scenario_bytes,
    validate_associated_artifacts,
)

CORPUS_ROOT = corpus_family_root(FIXTURES)
SECRET = "sk-super-secret-injected-token-98765"


def _read(*parts: str) -> bytes:
    path = CORPUS_ROOT
    for part in parts:
        path = path / part
    return path.read_bytes()


# ---------------------------------------------------------------------------
# load_experiment_root
# ---------------------------------------------------------------------------


class TestLoadExperimentRootHappyPath:
    def test_loads_the_valid_corpus_fixture(self):
        data = _read(
            "experiment-core", "experiment-authoring-input-v1", "valid", "reference.json"
        )

        model = load_experiment_root(data, policy=default_admission_policy())

        assert isinstance(model, ExperimentSpecModel)
        assert model.spec_id == "spec-techvault-red-tactic-sweep-v1"


class TestLoadExperimentRootDuplicateKeyPreflight:
    def test_rejects_a_duplicate_top_level_key(self):
        text = (
            "schema_version: experiment-authoring-input/v1\n"
            "spec_id: s1\n"
            "spec_version: v1\n"
            "title: t\n"
            "title: t-again\n"
            "description: d\n"
            "task_ref: {ref_kind: task, ref_id: t1}\n"
            "run_plan: {}\n"
        )
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection) as excinfo:
            load_experiment_root(data, policy=policy)

        assert excinfo.value.diagnostics
        assert all(d.domain == EXPERIMENT_ADMISSION_DOMAIN for d in excinfo.value.diagnostics)

    def test_rejects_a_duplicate_nested_key(self):
        text = (
            "schema_version: experiment-authoring-input/v1\n"
            "spec_id: s1\n"
            "spec_version: v1\n"
            "title: t\n"
            "description: d\n"
            "task_ref: {ref_kind: task, ref_id: t1, ref_id: t2}\n"
            "run_plan: {}\n"
        )
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            load_experiment_root(data, policy=policy)

    def test_rejects_a_multi_document_stream(self):
        text = "schema_version: experiment-authoring-input/v1\n---\nspec_id: s1\n"
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            load_experiment_root(data, policy=policy)

    def test_a_document_without_duplicate_keys_reaches_aces_validation(self):
        # No duplicate key, but otherwise incomplete -> ACES itself rejects
        # it (a real ValidationError normalized), proving the preflight
        # does not itself reject well-formed-but-incomplete documents.
        text = "schema_version: experiment-authoring-input/v1\n"
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection) as excinfo:
            load_experiment_root(data, policy=policy)

        assert excinfo.value.diagnostics


class TestLoadExperimentRootByteLimit:
    def test_rejects_a_document_over_max_root_bytes(self):
        data = _read(
            "experiment-core", "experiment-authoring-input-v1", "valid", "reference.json"
        )
        policy = AdmissionPolicy(max_root_bytes=10)

        with pytest.raises(AdmissionRejection):
            load_experiment_root(data, policy=policy)

    def test_accepts_a_document_within_max_root_bytes(self):
        data = _read(
            "experiment-core", "experiment-authoring-input-v1", "valid", "reference.json"
        )
        policy = AdmissionPolicy(max_root_bytes=len(data))

        load_experiment_root(data, policy=policy)  # must not raise


class TestLoadExperimentRootInvalidUtf8AndNul:
    def test_rejects_invalid_utf8(self):
        policy = default_admission_policy()
        with pytest.raises(AdmissionRejection):
            load_experiment_root(b"\xff\xfe\x00\x01", policy=policy)

    def test_rejects_an_embedded_nul_byte(self):
        text = b"schema_version: experiment-authoring-input/v1\x00\n"
        policy = default_admission_policy()
        with pytest.raises(AdmissionRejection):
            load_experiment_root(text, policy=policy)


class TestLoadExperimentRootDoesNotLeakSecrets:
    def test_a_rejected_field_value_never_appears_in_the_diagnostics(self):
        text = (
            "schema_version: experiment-authoring-input/v1\n"
            "spec_id: s1\n"
            "spec_version: v1\n"
            "title: t\n"
            "description: d\n"
            f"task_ref: {{ref_kind: {SECRET}, ref_id: t1}}\n"
            "run_plan: {}\n"
        )
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection) as excinfo:
            load_experiment_root(data, policy=policy)

        for d in excinfo.value.diagnostics:
            assert SECRET not in d.message
            assert SECRET not in d.code
            assert SECRET not in d.address


# ---------------------------------------------------------------------------
# load_task
# ---------------------------------------------------------------------------


class TestLoadTaskHappyPath:
    def test_loads_the_valid_corpus_fixture(self):
        data = _read("experiment-core", "experiment-task-v1", "valid", "reference.json")

        model = load_task(data, policy=default_admission_policy())

        assert isinstance(model, ExperimentTaskModel)
        assert model.task_id == "task-techvault-red-team-v1"


class TestLoadTaskRejections:
    def test_rejects_a_duplicate_json_member(self):
        text = '{"schema_version": "experiment-task/v1", "task_id": "a", "task_id": "b"}'
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            load_task(data, policy=policy)

    def test_rejects_over_max_artifact_bytes(self):
        data = _read("experiment-core", "experiment-task-v1", "valid", "reference.json")
        policy = AdmissionPolicy(max_artifact_bytes=10)

        with pytest.raises(AdmissionRejection):
            load_task(data, policy=policy)

    def test_rejects_invalid_json(self):
        policy = default_admission_policy()
        with pytest.raises(AdmissionRejection):
            load_task(b"not json at all {{{", policy=policy)

    def test_does_not_leak_a_secret_in_a_rejected_field(self):
        payload = {
            "schema_version": "experiment-task/v1",
            "task_id": "t",
            "task_version": SECRET,  # wrong type expectations aside, use a
            # structurally-invalid field to force a validation error whose
            # rejected value is the secret.
        }
        text = json.dumps(payload)
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection) as excinfo:
            load_task(data, policy=policy)

        for d in excinfo.value.diagnostics:
            assert SECRET not in d.message


# ---------------------------------------------------------------------------
# load_capture_spec
# ---------------------------------------------------------------------------


class TestLoadCaptureSpecHappyPath:
    def test_loads_the_valid_corpus_fixture(self):
        data = _read(
            "experiment-core", "experiment-capture-spec-v1", "valid", "reference.json"
        )

        model = load_capture_spec(data, policy=default_admission_policy())

        assert isinstance(model, ExperimentCaptureSpecModel)
        assert model.capture_spec_id == "capture-techvault-evidence-v1"


class TestLoadCaptureSpecRejections:
    def test_rejects_a_duplicate_json_member(self):
        text = (
            '{"schema_version": "experiment-capture-spec/v1", '
            '"capture_spec_id": "a", "capture_spec_id": "b"}'
        )
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            load_capture_spec(data, policy=policy)

    def test_rejects_over_max_artifact_bytes(self):
        data = _read(
            "experiment-core", "experiment-capture-spec-v1", "valid", "reference.json"
        )
        policy = AdmissionPolicy(max_artifact_bytes=10)

        with pytest.raises(AdmissionRejection):
            load_capture_spec(data, policy=policy)


# ---------------------------------------------------------------------------
# parse_scenario_bytes
# ---------------------------------------------------------------------------


class TestParseScenarioBytesHappyPath:
    def test_parses_the_valid_corpus_fixture(self):
        data = _read("sdl", "sdl-yaml-v1", "valid", "minimal.yaml")

        scenario, digest = parse_scenario_bytes(data, policy=default_admission_policy())

        assert isinstance(scenario, Scenario)
        assert digest.value.startswith("sha256:")

    def test_canonical_digest_is_stable_across_two_parses_of_the_same_bytes(self):
        data = _read("sdl", "sdl-yaml-v1", "valid", "core-scalars.yaml")

        _, digest1 = parse_scenario_bytes(data, policy=default_admission_policy())
        _, digest2 = parse_scenario_bytes(data, policy=default_admission_policy())

        assert digest1 == digest2
        assert digest1.value == digest2.value

    def test_matches_the_aces_canonical_digest_api_directly(self):
        data = _read("sdl", "sdl-yaml-v1", "valid", "minimal.yaml")

        scenario, digest = parse_scenario_bytes(data, policy=default_admission_policy())

        assert digest == canonical_sdl_digest(scenario)


class TestParseScenarioBytesRejectsImports:
    def test_rejects_a_scenario_that_declares_imports(self):
        text = "name: x\nimports:\n  - path: some-module.yaml\n"
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection) as excinfo:
            parse_scenario_bytes(data, policy=policy)

        assert excinfo.value.diagnostics
        assert all(d.domain == EXPERIMENT_ADMISSION_DOMAIN for d in excinfo.value.diagnostics)

    def test_empty_imports_list_is_not_rejected(self):
        data = _read("sdl", "sdl-yaml-v1", "valid", "minimal.yaml")
        scenario, _ = parse_scenario_bytes(data, policy=default_admission_policy())
        assert scenario.imports == []


class TestParseScenarioBytesByteLimitAndRejections:
    def test_rejects_over_max_artifact_bytes(self):
        data = _read("sdl", "sdl-yaml-v1", "valid", "minimal.yaml")
        policy = AdmissionPolicy(max_artifact_bytes=2)

        with pytest.raises(AdmissionRejection):
            parse_scenario_bytes(data, policy=policy)

    def test_rejects_structurally_invalid_sdl(self):
        policy = default_admission_policy()
        with pytest.raises(AdmissionRejection):
            parse_scenario_bytes(b"not: [valid, sdl", policy=policy)

    def test_does_not_leak_a_secret_embedded_in_invalid_sdl(self):
        text = f"name: x\nnodes:\n  {SECRET}: not-a-valid-node-shape\n"
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection) as excinfo:
            parse_scenario_bytes(data, policy=policy)

        for d in excinfo.value.diagnostics:
            assert SECRET not in d.message


# ---------------------------------------------------------------------------
# validate_associated_artifacts (wiring helper)
# ---------------------------------------------------------------------------


def _build_valid_manifest_and_parent() -> tuple[AssociatedArtifactManifestModel, ExperimentTaskModel, bytes]:
    task_payload = json.loads(
        _read("experiment-core", "experiment-task-v1", "valid", "reference.json")
    )
    task = ExperimentTaskModel.model_validate(task_payload)

    data = b"associated artifact bytes for admission wiring test"
    digest_hex = hashlib.sha256(data).hexdigest()
    manifest_payload = {
        "schema_version": "associated-artifact-manifest/v1",
        "manifest_id": "wiring-test-manifest",
        "manifest_version": "1.0.0",
        "canonicalization_profile": "associated-artifact-set/v1",
        "scope": "experiment",
        "parent_ref": {
            "ref_kind": "task",
            "ref_id": task.task_id,
            "ref_version": task.task_version,
        },
        "artifacts": {
            "art1": {
                "artifact_id": "art1",
                "role": "operator-guide",
                "media_type": "text/plain",
                "uri": f"urn:sha256:{digest_hex}",
                "checksum": {"algorithm": "sha256", "value": digest_hex},
                "size_bytes": len(data),
                "created_at": "2026-07-12T00:00:00Z",
                "source": "test",
                "sensitivity": "internal",
            }
        },
        "set_digest": "sha256:" + "0" * 64,
    }
    provisional = AssociatedArtifactManifestModel.model_validate(manifest_payload)
    manifest_payload["set_digest"] = associated_artifact_set_digest(provisional)
    manifest = AssociatedArtifactManifestModel.model_validate(manifest_payload)
    return manifest, task, data


class TestValidateAssociatedArtifacts:
    def test_does_not_raise_when_the_manifest_and_readers_are_valid(self):
        manifest, task, data = _build_valid_manifest_and_parent()

        validate_associated_artifacts(
            manifest,
            parent=task,
            artifact_readers={"art1": io.BytesIO(data)},
            limits=AssociatedArtifactValidationLimits(),
        )  # must not raise

    def test_raises_admission_rejection_when_a_reader_binding_is_missing(self):
        manifest, task, _ = _build_valid_manifest_and_parent()
        limits = AssociatedArtifactValidationLimits()

        with pytest.raises(AdmissionRejection) as excinfo:
            validate_associated_artifacts(
                manifest,
                parent=task,
                artifact_readers={},
                limits=limits,
            )

        assert excinfo.value.diagnostics
        assert all(d.is_error for d in excinfo.value.diagnostics)

    def test_raises_admission_rejection_on_parent_mismatch(self):
        manifest, _task, data = _build_valid_manifest_and_parent()
        other_task_payload = json.loads(
            _read("experiment-core", "experiment-task-v1", "valid", "reference.json")
        )
        other_task_payload["task_id"] = "a-completely-different-task"
        other_task = ExperimentTaskModel.model_validate(other_task_payload)
        reader = io.BytesIO(data)
        limits = AssociatedArtifactValidationLimits()

        with pytest.raises(AdmissionRejection):
            validate_associated_artifacts(
                manifest,
                parent=other_task,
                artifact_readers={"art1": reader},
                limits=limits,
            )


# ---------------------------------------------------------------------------
# Fuzz
# ---------------------------------------------------------------------------

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@pytest.mark.fuzz
class TestFuzzDuplicateKeyDocumentsAlwaysReject:
    @given(
        key=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=12),
        value_a=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12),
        value_b=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12),
    )
    @settings(max_examples=100, deadline=1000)
    def test_a_duplicated_top_level_key_always_rejects_the_root(self, key, value_a, value_b):
        text = (
            "schema_version: experiment-authoring-input/v1\n"
            "spec_id: s1\n"
            "spec_version: v1\n"
            "title: t\n"
            "description: d\n"
            "task_ref: {ref_kind: task, ref_id: t1}\n"
            "run_plan: {}\n"
            f"{key}: {value_a}\n"
            f"{key}: {value_b}\n"
        )
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            load_experiment_root(data, policy=policy)

    @given(
        key=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=12),
        value_a=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12),
        value_b=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12),
    )
    @settings(max_examples=100, deadline=1000)
    def test_a_duplicated_json_member_always_rejects_task_loading(self, key, value_a, value_b):
        text = (
            '{"schema_version": "experiment-task/v1", '
            f'"{key}": "{value_a}", "{key}": "{value_b}"}}'
        )
        data = text.encode("utf-8")
        policy = default_admission_policy()

        with pytest.raises(AdmissionRejection):
            load_task(data, policy=policy)
