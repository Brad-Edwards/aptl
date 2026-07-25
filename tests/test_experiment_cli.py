"""Tests for ``aptl experiment admit`` (ADR-047 "Experiment-controller
boundary", Stage 6 / EXP-002 / issue #438).

Builds an on-disk project bundle (task/scenario files plus an ACES
associated-artifact manifest binding them, mirroring
``test_experiment_controller.py``'s helper of the same shape) and drives the
real Typer CLI through ``CliRunner`` — proving the production
``ExperimentController`` -> ``build_associated_artifact_source`` ->
``ProjectContainedResolver`` wiring end to end, not just the pure admission
sequence.

Covers: the ``allow_uncertified_apparatus`` debug-flag behavior (rejected
without it, admitted-with-a-warning with it — same real-manifest mutual
apparatus-mismatch gate exercised in ``test_experiment_admission.py`` and
``test_experiment_controller.py``), a content-derived rejection that must
not leak an embedded secret into stdout/stderr, the ADR "Range-mutation
gate" (no range-mutating entry point is ever called), and ``--help``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml
from aces_contracts.associated_artifacts import (
    AssociatedArtifactManifestModel,
    associated_artifact_set_digest,
)
from aces_contracts.corpus import FIXTURES, corpus_family_root
from typer.testing import CliRunner

from aptl.cli.main import app

CORPUS_ROOT = corpus_family_root(FIXTURES)
SECRET = "sk-super-secret-cli-injected-token-13579"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# Shared fixture-building helpers (on-disk bundle)
# ---------------------------------------------------------------------------


def _read_corpus_task_payload() -> dict:
    path = CORPUS_ROOT / "experiment-core" / "experiment-task-v1" / "valid" / "reference.json"
    return json.loads(path.read_text())


def _minimal_scenario_bytes() -> bytes:
    path = CORPUS_ROOT / "sdl" / "sdl-yaml-v1" / "valid" / "minimal.yaml"
    return path.read_bytes()


def _pinned_identity_task_payload(*, extra_notes: list[str] | None = None) -> dict:
    """A task whose apparatus_constraints pin the REAL aptl/reference-processor
    identities — the exact shape ``test_experiment_admission.py`` uses to
    exercise the real mutual-compatibility gate (rejected by default,
    admitted-with-one-warning under ``allow_uncertified_apparatus``)."""
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
        "notes": extra_notes or [],
    }
    return payload


def _capability_only_task_payload(*, declared_capability: str, extra_notes: list[str] | None = None) -> dict:
    """A task requiring a single (possibly unsupported) capability — used
    for the content-derived rejection / secret-leak test, mirroring
    ``test_experiment_admission.py``'s helper of the same shape."""
    payload = _read_corpus_task_payload()
    payload["task_id"] = "task-minimal"
    payload["task_version"] = "1.0.0"
    payload["scenario_ref"] = {"ref_kind": "scenario", "ref_id": "canonical-minimal"}
    payload["apparatus_constraints"] = {
        "required_capabilities": [declared_capability],
        "notes": extra_notes or [],
    }
    return payload


def _flat_spec_payload(*, spec_id: str = "spec-cli-v1", target_run_count: int = 3) -> dict:
    return {
        "schema_version": "experiment-authoring-input/v1",
        "spec_id": spec_id,
        "spec_version": "1.0.0",
        "title": "CLI admission fixture",
        "description": "Minimal flat allocation CLI fixture.",
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


def _write_bundle(base_dir: Path, *, spec_id: str, task_bytes: bytes, scenario_bytes: bytes) -> None:
    (base_dir / "task.json").write_bytes(task_bytes)
    (base_dir / "scenario.sdl.yaml").write_bytes(scenario_bytes)

    def artifact_ref(artifact_id: str, uri: str, data: bytes, media_type: str, role: str) -> dict:
        return {
            "artifact_id": artifact_id,
            "role": role,
            "media_type": media_type,
            "uri": f"file:{uri}",
            "checksum": {"algorithm": "sha256", "value": hashlib.sha256(data).hexdigest()},
            "size_bytes": len(data),
            "created_at": "2026-05-26T00:00:00Z",
            "source": "test bundle",
            "satisfies_refs": [],
            "sensitivity": "internal",
        }

    artifacts = {
        "task-minimal": artifact_ref("task-minimal", "task.json", task_bytes, "application/json", "other"),
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


def _build_pinned_identity_project(tmp_path: Path, *, spec_id: str = "spec-cli-v1") -> Path:
    base_dir = tmp_path / spec_id
    base_dir.mkdir()
    task_payload = _pinned_identity_task_payload()
    task_bytes = json.dumps(task_payload).encode("utf-8")
    scenario_bytes = _minimal_scenario_bytes()
    spec_payload = _flat_spec_payload(spec_id=spec_id)
    root_bytes = yaml.safe_dump(spec_payload).encode("utf-8")
    (base_dir / "experiment.yaml").write_bytes(root_bytes)
    _write_bundle(base_dir, spec_id=spec_id, task_bytes=task_bytes, scenario_bytes=scenario_bytes)
    return base_dir


_CLI_ARGS = [
    "experiment",
    "admit",
    "experiment.yaml",
    "--manifest",
    "associated-artifact-manifest.json",
]


class TestExperimentAdmitCliHelp:
    def test_admit_command_declares_its_documented_parameters(self) -> None:
        # The Rich-rendered ``--help`` output is TTY/width/Rich-version
        # dependent and unreliable to assert on across CI environments (some
        # non-TTY renderers capture only an empty bordered panel). Assert the
        # declared command surface directly — it is what the help is generated
        # from — so the contract holds regardless of the rendering environment.
        import typer.main

        admit = typer.main.get_command(app).commands["experiment"].commands["admit"]
        names = {p.name for p in admit.params}
        opts = {opt for p in admit.params for opt in p.opts}
        assert "spec_path" in names
        assert "--manifest" in opts
        assert "--allow-uncertified-apparatus" in opts
        allow = next(
            p for p in admit.params if "--allow-uncertified-apparatus" in p.opts
        )
        assert "DEBUG/DEV ONLY" in (allow.help or "")

    def test_experiment_group_exposes_the_admit_command(self) -> None:
        import typer.main

        experiment = typer.main.get_command(app).commands["experiment"]
        assert "admit" in experiment.commands


class TestExperimentAdmitDebugOverrideFlag:
    def test_rejected_without_the_override_flag(self, runner: CliRunner, tmp_path: Path) -> None:
        base_dir = _build_pinned_identity_project(tmp_path, spec_id="spec-cli-reject-v1")

        result = runner.invoke(app, [*_CLI_ARGS, "--base-dir", str(base_dir)])

        assert result.exit_code == 1
        assert "Admitted plan" not in result.stdout
        assert "Experiment admission failed" in result.stderr
        assert "mutual-incompatible" in result.stderr

    def test_admitted_with_the_override_flag_and_prints_a_warning(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        base_dir = _build_pinned_identity_project(tmp_path, spec_id="spec-cli-admit-v1")

        result = runner.invoke(
            app, [*_CLI_ARGS, "--base-dir", str(base_dir), "--allow-uncertified-apparatus"]
        )

        assert result.exit_code == 0, result.stderr
        assert "Admitted plan plan-" in result.stdout
        assert "digest:" in result.stdout
        assert "trials:    3" in result.stdout
        assert "persisted:" in result.stdout
        # The debug-override warning is rendered too, not silently dropped.
        assert "uncertified-compatibility" in result.stdout

        persisted_dir = base_dir / "runs" / "experiment-plans"
        assert persisted_dir.exists()
        assert any(persisted_dir.iterdir())


class TestExperimentAdmitRejectionIsSafe:
    def test_content_derived_rejection_exits_one_and_never_leaks_an_embedded_secret(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        base_dir = tmp_path / "project"
        base_dir.mkdir()
        spec_id = "spec-cli-secret-v1"
        task_payload = _capability_only_task_payload(
            declared_capability="totally-made-up-capability",
            extra_notes=[f"internal-secret={SECRET}"],
        )
        task_bytes = json.dumps(task_payload).encode("utf-8")
        scenario_bytes = _minimal_scenario_bytes()
        spec_payload = _flat_spec_payload(spec_id=spec_id)
        root_bytes = yaml.safe_dump(spec_payload).encode("utf-8")
        (base_dir / "experiment.yaml").write_bytes(root_bytes)
        _write_bundle(base_dir, spec_id=spec_id, task_bytes=task_bytes, scenario_bytes=scenario_bytes)

        result = runner.invoke(app, [*_CLI_ARGS, "--base-dir", str(base_dir)])

        assert result.exit_code == 1
        assert "capability-unsupported" in result.stderr
        assert SECRET not in result.stdout
        assert SECRET not in result.stderr
        assert (result.exception is None) or isinstance(result.exception, SystemExit)


class TestExperimentAdmitNeverMutatesTheRange:
    def test_admission_never_calls_a_range_mutating_entry_point(
        self, runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ADR-047 "Range-mutation gate": admission — rejected OR admitted —
        must never hydrate ``.env``, generate keys/certs, or call
        ``DeploymentBackend``/lab-lifecycle entry points. Mirrors the spy
        pattern in ``test_experiment_admission.py``'s
        ``_install_mutation_spies``.
        """
        import aptl.core.env as env_module
        import aptl.core.lab as lab_module
        import aptl.core.soc_ca as soc_ca_module
        import aptl.core.ssh as ssh_module

        def _boom(*args: object, **kwargs: object) -> None:
            raise AssertionError("range-mutating entry point must never be called by `aptl experiment admit`")

        monkeypatch.setattr(lab_module, "start_lab", _boom)
        monkeypatch.setattr(lab_module, "stop_lab", _boom)
        monkeypatch.setattr(lab_module, "clean_boot_lab", _boom)
        monkeypatch.setattr(soc_ca_module, "ensure_soc_certs", _boom)
        monkeypatch.setattr(ssh_module, "ensure_ssh_keys", _boom)
        monkeypatch.setattr(ssh_module, "ensure_pivot_key", _boom)
        monkeypatch.setattr(env_module, "hydrate_dotenv", _boom)

        base_dir = _build_pinned_identity_project(tmp_path, spec_id="spec-cli-spy-v1")

        # The admitted path (the more dangerous of the two to get wrong,
        # since it is the "success" case most likely to accidentally chain
        # into execution) still must not touch any of the above.
        result = runner.invoke(
            app, [*_CLI_ARGS, "--base-dir", str(base_dir), "--allow-uncertified-apparatus"]
        )
        assert result.exit_code == 0, result.stderr

        # The rejected path (default policy, same bundle) likewise.
        base_dir_rejected = _build_pinned_identity_project(tmp_path, spec_id="spec-cli-spy-reject-v1")
        result_rejected = runner.invoke(app, [*_CLI_ARGS, "--base-dir", str(base_dir_rejected)])
        assert result_rejected.exit_code == 1
