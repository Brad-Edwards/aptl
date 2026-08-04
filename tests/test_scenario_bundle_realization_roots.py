"""Issue #874: every realization root resolves against the scenario bundle.

#866 anchored content *placement* to ``bundle.root``. The remaining realization
roots — the Compose profile index, component build contexts, and the
stateful/generated-artifact roots — still resolved against the engine's
``project_dir``. These tests are the decoupling in the differential form the
architecture preflight requires: an asset that exists *only* in APTL's checkout
must not satisfy a scenario handed to APTL rooted elsewhere, while an in-tree
scenario (whose bundle root *is* the project directory) is unchanged.

The tests fall in two families:

- *resolver* tests drive a leaf resolver with a bundle root that differs from
  the engine tree and assert the engine-only asset does not satisfy it;
- *wiring* tests assert the production ingress paths actually resolve one bundle
  and thread ``bundle.root`` to the leaf resolvers, so the seam cannot be
  claimed while a path still passes ``project_dir``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_ENGINE_ONLY_COMPOSE = """\
services:
  engine_only:
    image: busybox
    profiles: [engine_only]
"""


# --- Anchor 2: the Compose profile index -----------------------------------


def test_profile_index_reads_the_bundle_root_not_the_engine(tmp_path):
    """The indexed Compose model is scenario input; it comes from the bundle.

    A ``docker-compose.yml`` that exists only in the engine checkout must not be
    indexed for a scenario rooted elsewhere. Otherwise a rehomed scenario would
    silently bind against APTL's own services.
    """

    from aptl.backends.raes_profiles import load_compose_profile_index

    engine = tmp_path / "engine"
    engine.mkdir()
    (engine / "docker-compose.yml").write_text(_ENGINE_ONLY_COMPOSE, encoding="utf-8")
    elsewhere = tmp_path / "bundle"
    elsewhere.mkdir()

    # The engine's compose service must not be indexed for a bundle rooted
    # elsewhere; only the engine root sees its own docker-compose.yml.
    assert "engine_only" not in load_compose_profile_index(elsewhere).services
    assert "engine_only" in load_compose_profile_index(engine).services


def test_interpret_provisioning_plan_indexes_the_bundle_root(monkeypatch):
    """`interpret_provisioning_plan` must load the profile index from the bundle.

    The transitional #866 comment kept the index on ``project_dir`` as "engine
    infrastructure"; #874 reverses that — the indexed model binds scenario nodes
    to services, so it is bundle input.
    """

    from pathlib import Path as _Path

    from aptl.backends import raes_realization
    from aptl.core.config import AptlConfig
    from aptl.core.scenario_bundle import project_tree_bundle

    seen: dict[str, object] = {}

    def _capture(root):
        seen["root"] = root
        raise RuntimeError("stop after capture")

    monkeypatch.setattr(
        "aptl.backends.raes_realization.load_compose_profile_index", _capture
    )

    bundle = project_tree_bundle(_Path("/tmp/some/bundle"), _Path("scenarios/x.sdl.yaml"))

    class _Plan:
        resources: dict = {}
        operations: list = []

    plan = _Plan()
    config = AptlConfig()
    with pytest.raises(RuntimeError):
        raes_realization.interpret_provisioning_plan(
            plan=plan,
            config=config,
            bundle=bundle,
        )

    assert seen["root"] == bundle.root
    assert seen["root"] != _Path.cwd()


# --- Anchor 3: stateful / generated-artifact roots -------------------------


def test_artifact_source_path_anchors_to_the_bundle_root(tmp_path):
    """Generated-artifact source locations resolve under the bundle root."""

    from aptl.core.deployment._compose_stateful_model import artifact_source_path

    elsewhere = tmp_path / "bundle"
    elsewhere.mkdir()

    class _Artifact:
        generator = "certificate_bundle"

    source = artifact_source_path(elsewhere, _Artifact())

    assert elsewhere.resolve() in source.resolve().parents or source.resolve() == elsewhere.resolve()


# --- Wiring: no ingress path reconstructs project_dir as the scenario root ---


def _capture_availability_root(monkeypatch, seen):
    """Stub the ingress collaborators and capture the scenario_root threaded to
    artifact availability, stopping before any real planning runs."""

    from unittest.mock import MagicMock

    from aptl.backends import raes

    def _capture(scenario, backend, *, scenario_root=None, component_root=None):
        seen["scenario_root"] = scenario_root
        seen["component_root"] = component_root
        raise RuntimeError("stop after capture")

    monkeypatch.setattr(raes, "parse_sdl_file", lambda path: object())
    monkeypatch.setattr(raes, "create_aptl_runtime_target", lambda **kwargs: MagicMock())
    monkeypatch.setattr(raes, "RuntimeManager", lambda target: MagicMock())
    monkeypatch.setattr(raes, "artifact_availability_for_scenario", _capture)


def test_selected_profiles_path_threads_the_bundle_root_to_availability(
    monkeypatch, tmp_path
):
    """The no-start selected-profile query executes and threads the resolved
    bundle root — not the raw project dir — to artifact availability (#874)."""

    from aptl.backends import _raes_scenario_queries
    from aptl.core.config import AptlConfig
    from aptl.core.scenario_bundle import project_tree_bundle

    # An unresolved project dir whose .resolve() differs, so a regression that
    # threads the raw project dir (rather than the resolved bundle root) fails.
    project_dir = tmp_path / ".." / tmp_path.name
    scenario_path = tmp_path / "scenarios" / "demo.sdl.yaml"
    seen: dict[str, object] = {}
    _capture_availability_root(monkeypatch, seen)

    config = AptlConfig()
    with pytest.raises(RuntimeError):
        _raes_scenario_queries.selected_profiles_for_scenario(
            project_dir, config, object(), scenario_path
        )

    assert seen["scenario_root"] == project_tree_bundle(project_dir, scenario_path).root
    assert seen["scenario_root"] != project_dir


def test_admitted_stateful_ownership_path_threads_the_bundle_root_to_availability(
    monkeypatch, tmp_path
):
    """The admitted-stateful query executes and threads the resolved bundle root
    to artifact availability, not the raw project dir (#874)."""

    from aptl.backends import _raes_scenario_queries
    from aptl.core.config import AptlConfig
    from aptl.core.scenario_bundle import project_tree_bundle

    project_dir = tmp_path / ".." / tmp_path.name
    scenario_path = tmp_path / "scenarios" / "demo.sdl.yaml"
    seen: dict[str, object] = {}
    _capture_availability_root(monkeypatch, seen)

    config = AptlConfig()
    with pytest.raises(RuntimeError):
        _raes_scenario_queries.admitted_stateful_artifact_ownership(
            project_dir, config, object(), scenario_path
        )

    assert seen["scenario_root"] == project_tree_bundle(project_dir, scenario_path).root
    assert seen["scenario_root"] != project_dir


# --- Compose execution boundary: project-directory + operator-.env authority ---


def test_compose_uses_scenario_root_as_project_directory_and_keeps_operator_env(tmp_path):
    """Compose resolves scenario inputs against the bundle root; secrets stay on project_dir.

    Docker Compose resolves relative build contexts, binds, includes, and
    ``env_file`` entries against its project directory. For a realized scenario
    that must be the bundle root, while the operator secret source stays the
    control-plane ``project_dir/.env`` bound explicitly — a bundle-local ``.env``
    decoy must never win (issue #874).
    """

    from aptl.core.deployment.docker_compose import DockerComposeBackend

    engine = tmp_path / "engine"
    engine.mkdir()
    (engine / ".env").write_text("OPERATOR=1\n", encoding="utf-8")
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    (bundle_root / ".env").write_text("DECOY=1\n", encoding="utf-8")

    backend = DockerComposeBackend(engine)
    cmd = backend._build_command(
        "up",
        [],
        compose_files=(bundle_root / "docker-compose.yml",),
        scenario_root=bundle_root,
    )

    assert "--project-directory" in cmd
    assert cmd[cmd.index("--project-directory") + 1] == str(bundle_root)
    assert "--env-file" in cmd
    assert cmd[cmd.index("--env-file") + 1] == str(engine / ".env")
    # The bundle-local .env decoy must never be bound.
    assert str(bundle_root / ".env") not in cmd


def test_compose_binds_empty_env_source_when_operator_env_absent(tmp_path):
    """With no operator .env, Compose must not fall back to a bundle-local .env.

    ``--project-directory`` points Compose at the bundle root, so without an
    explicit ``--env-file`` Compose would auto-discover ``<bundle>/.env`` and let
    the bundle control interpolation. When the operator ``project_dir/.env`` is
    absent the backend must bind an empty control-plane source instead (#874).
    """

    import os

    from aptl.core.deployment.docker_compose import DockerComposeBackend

    engine = tmp_path / "engine"
    engine.mkdir()  # no engine/.env
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    (bundle_root / ".env").write_text("DECOY=1\n", encoding="utf-8")

    backend = DockerComposeBackend(engine)
    cmd = backend._build_command(
        "up",
        [],
        compose_files=(bundle_root / "docker-compose.yml",),
        scenario_root=bundle_root,
    )

    assert "--env-file" in cmd
    assert cmd[cmd.index("--env-file") + 1] == os.devnull
    assert str(bundle_root / ".env") not in cmd


def test_compose_legacy_path_without_scenario_root_adds_no_root_flags(tmp_path):
    """The legacy direct path (no bundle) is unchanged: no project-directory/env-file."""

    from aptl.core.deployment.docker_compose import DockerComposeBackend

    backend = DockerComposeBackend(tmp_path)
    cmd = backend._build_command("ps", [])

    assert "--project-directory" not in cmd
    assert "--env-file" not in cmd


def test_realize_threads_the_bundle_root_as_scenario_root(monkeypatch, tmp_path):
    """The provisioner must realize against the bundle root, not the engine checkout."""

    from unittest.mock import MagicMock

    from aptl.backends.raes_provisioner import AptlProvisioner
    from aptl.core.config import AptlConfig
    from aptl.core.lab_types import LabResult
    from aptl.core.scenario_bundle import project_tree_bundle

    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    bundle = project_tree_bundle(bundle_root, bundle_root / "scenarios" / "demo.sdl.yaml")

    seen: dict[str, object] = {}
    backend = MagicMock()

    def _capture_realize(
        realization, *, build=True, scenario_root, substrate_digests=None
    ):
        seen["scenario_root"] = scenario_root
        return LabResult(success=True)

    backend.realize.side_effect = _capture_realize

    provisioner = AptlProvisioner(
        project_dir=tmp_path / "engine",
        config=AptlConfig(),
        deployment_backend=backend,
        bundle=bundle,
    )

    realization = MagicMock()
    realization.profiles = frozenset()
    realization.details.return_value = {}
    realization.generated_artifacts = ()
    realization.deployment_spec.return_value = object()
    monkeypatch.setattr(
        provisioner, "_compose_validity_diagnostics", lambda profiles: []
    )
    monkeypatch.setattr(
        "aptl.backends.raes_provisioner.observe_realization", lambda *a, **k: {}
    )
    monkeypatch.setattr(
        provisioner, "_with_artifact_satisfactions", lambda plan, snap, real: snap
    )

    from raes_contracts.runtime_state import RuntimeSnapshot

    provisioner._apply_valid_plan(MagicMock(), RuntimeSnapshot(), [], realization)

    assert seen["scenario_root"] == bundle.root
    assert seen["scenario_root"] != (tmp_path / "engine")
