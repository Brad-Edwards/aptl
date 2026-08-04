"""The bundle seam that decouples a scenario from the APTL checkout.

APTL anchors every scenario asset to its own project directory today. The bundle
names what is being realized and the root its content resolves against, so a
scenario can be rehomed by changing the resolver rather than realization.

The property that matters is containment against the *bundle* root: an acquired
bundle must not reach into the engine's tree, and the engine must not satisfy a
scenario asset from its own tree.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aptl.core.scenario_bundle import (
    PathContainmentError,
    ScenarioSourceKind,
    project_tree_bundle,
)

_PROJECT = Path(__file__).resolve().parents[1]


def _bundle(root: Path):
    return project_tree_bundle(root, Path("scenarios") / "demo.sdl.yaml")


def test_identity_drops_the_start_state_suffixes():
    bundle = _bundle(_PROJECT)

    assert bundle.identity == "demo"


def test_in_tree_resolver_anchors_content_to_the_project():
    """The transitional resolver must not change today's behaviour."""

    bundle = _bundle(_PROJECT)

    assert bundle.root == _PROJECT
    assert bundle.source_kind is ScenarioSourceKind.PROJECT_TREE


def test_assets_resolve_against_the_bundle_root(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "note.txt").write_text("planted", encoding="utf-8")

    bundle = _bundle(tmp_path)

    assert bundle.read_asset("assets/note.txt") == b"planted"


def test_a_bundle_cannot_read_outside_its_own_root(tmp_path):
    """The whole point: an acquired bundle must not reach the engine's tree."""

    outside = tmp_path / "engine-secret"
    outside.write_text("not yours", encoding="utf-8")
    inner = tmp_path / "bundle"
    inner.mkdir()

    bundle = _bundle(inner)

    with pytest.raises(PathContainmentError):
        bundle.read_asset("../engine-secret")


def test_a_symlink_out_of_the_bundle_is_refused(tmp_path):
    """Containment is enforced by the symlink-refusing reader, not by joining."""

    outside = tmp_path / "engine-secret"
    outside.write_text("not yours", encoding="utf-8")
    inner = tmp_path / "bundle"
    inner.mkdir()
    (inner / "leak").symlink_to(outside)

    bundle = _bundle(inner)
    with pytest.raises(PathContainmentError):
        bundle.read_asset("leak")


def test_details_carry_identity_not_location():
    """Two runs of one bundle staged at different paths are the same scenario."""

    here = _bundle(_PROJECT).details()
    elsewhere = project_tree_bundle(
        Path("/tmp"), Path("scenarios") / "demo.sdl.yaml"
    ).details()

    assert here == elsewhere
    assert not any("/" in value for value in here.values())


def test_realization_anchors_content_to_the_bundle_not_the_engine(tmp_path):
    """Content must resolve against the bundle root, not APTL's checkout.

    This is the decoupling in one assertion: given a bundle rooted outside the
    project, a scenario asset that exists only in the engine's tree must not
    resolve. Without it a rehomed scenario would keep silently working because
    the engine happened to hold the same files.
    """

    from aptl.backends.raes_content_realization import _resolve_project_source

    engine = tmp_path / "engine"
    (engine / "scenarios").mkdir(parents=True)
    (engine / "scenarios" / "planted.txt").write_text("engine copy", encoding="utf-8")
    elsewhere = tmp_path / "bundle"
    elsewhere.mkdir()

    resolved, diagnostics = _resolve_project_source(
        "provision.content.x", "scenarios/planted.txt", elsewhere
    )

    # The engine's copy must not satisfy it: either the resolver refuses, or it
    # resolves beneath the bundle where the file simply is not present and the
    # caller reports source-file-missing.
    assert resolved is None or not resolved.is_file(), (
        "content resolved from the engine tree while anchored to a bundle"
    )
    if resolved is not None:
        assert elsewhere in resolved.parents


def test_component_build_contexts_anchor_to_the_scenario_not_the_engine(tmp_path):
    """A build context is scenario content and must resolve against the bundle.

    Component images are declared by the scenario, so a scenario handed over from
    elsewhere must not build one out of APTL's own `containers/` tree. Without
    this the engine would keep satisfying component builds from its checkout and
    a rehomed scenario would appear to work.
    """

    from aptl.backends.raes_artifact_availability import _context_dockerfile

    engine = tmp_path / "engine"
    (engine / "containers" / "widget").mkdir(parents=True)
    (engine / "containers" / "widget" / "Dockerfile").write_text(
        "FROM scratch\n", encoding="utf-8"
    )
    elsewhere = tmp_path / "bundle"
    elsewhere.mkdir()

    assert _context_dockerfile(engine, "widget") is not None
    assert _context_dockerfile(elsewhere, "widget") is None


def test_a_specification_id_cannot_escape_the_context_root(tmp_path):
    """Specification ids are authored data and are treated as untrusted."""

    from aptl.backends.raes_artifact_availability import _context_dockerfile

    (tmp_path / "containers").mkdir()

    for hostile in ("../..", "../escape", "a/b", ".", ".."):
        assert _context_dockerfile(tmp_path, hostile) is None


# -- per-invocation env-pack staging and its sweep (issue #875) --------------


def _staged_tree(staging_root: Path, name: str, *, age_seconds: float) -> Path:
    """Create a staged-tree sibling with a controlled mtime."""

    import os
    import time

    tree = staging_root / name / "techvault"
    tree.mkdir(parents=True)
    (tree / "marker").write_text("x", encoding="utf-8")
    when = time.time() - age_seconds
    os.utime(staging_root / name, (when, when))
    return staging_root / name


def test_the_sweep_removes_stale_staged_trees_and_keeps_live_ones(tmp_path):
    """Finished invocations leave their tree behind; the sweep bounds the growth.

    Per-invocation staging never deletes a tree a peer might still be reading, so
    without a sweep the staging root grows forever. A tree younger than the
    threshold could still belong to a live realization and must survive.
    """

    from aptl.core.scenario_bundle import (
        _STAGING_SWEEP_AGE_SECONDS,
        _sweep_stale_stagings,
    )

    staging_root = tmp_path / "staging"
    staging_root.mkdir()
    stale = _staged_tree(staging_root, "techvault.111-aaa", age_seconds=_STAGING_SWEEP_AGE_SECONDS * 2)
    fresh = _staged_tree(staging_root, "techvault.222-bbb", age_seconds=5)

    _sweep_stale_stagings(staging_root, "techvault")

    assert not stale.exists()
    assert (fresh / "techvault" / "marker").is_file()


def test_the_sweep_only_touches_this_identity_and_leaves_other_entries_alone(tmp_path):
    """One pack's sweep must not delete another pack's (or anyone else's) tree."""

    from aptl.core.scenario_bundle import _sweep_stale_stagings

    staging_root = tmp_path / "staging"
    staging_root.mkdir()
    other_pack = _staged_tree(staging_root, "otherpack.111-aaa", age_seconds=99999)
    prefix_lookalike = _staged_tree(staging_root, "techvaultx.111-aaa", age_seconds=99999)
    loose_file = staging_root / "techvault.notadir"
    loose_file.write_text("x", encoding="utf-8")

    _sweep_stale_stagings(staging_root, "techvault")

    assert other_pack.exists()
    assert prefix_lookalike.exists()
    assert loose_file.exists()


def test_the_sweep_is_best_effort_on_an_unreadable_staging_root(tmp_path):
    """A sweep failure must never fail the realization it was tidying up for."""

    from aptl.core.scenario_bundle import _sweep_stale_stagings

    _sweep_stale_stagings(tmp_path / "does-not-exist", "techvault")


def test_env_pack_staging_is_per_invocation_and_excludes_bytecode(tmp_path, monkeypatch):
    """Two invocations never share a tree, and installer bytecode never stages.

    A shared tree lets one caller rmtree or read a tree another is copying, and a
    ``__pycache__`` written into an installed pack is an installer artifact the
    pack manifest never lists -- staging it would make env-packs' exact-inventory
    gate reject the pack (issue #875).
    """

    from aptl.core.scenario_bundle import env_pack_bundle

    source = tmp_path / "src" / "demo"
    (source / "sdl").mkdir(parents=True)
    (source / "sdl" / "demo.sdl.yaml").write_text("name: demo\n", encoding="utf-8")
    (source / "__pycache__").mkdir()
    (source / "__pycache__" / "mod.cpython-312.pyc").write_bytes(b"\x00")
    (source / "mod.pyc").write_bytes(b"\x00")

    # env-packs owns pack validation and has its own suite; the staging
    # behaviour under test here is APTL's.
    monkeypatch.setattr(
        "aptl.core.scenario_bundle._validate_staged_pack", lambda staged, identity: None
    )
    first = env_pack_bundle(tmp_path / "staging", "demo", source_pack=source)
    second = env_pack_bundle(tmp_path / "staging", "demo", source_pack=source)

    # Distinct trees, each still named for the pack identity (env-packs'
    # validate_pack checks the directory name against the declared identity).
    assert first.root != second.root
    assert first.root.name == second.root.name == "demo"
    assert first.sdl_path.is_file()
    # Installer bytecode is not part of the pack's declared inventory.
    assert not (first.root / "__pycache__").exists()
    assert not (first.root / "mod.pyc").exists()


def test_a_missing_env_pack_source_fails_closed(tmp_path):
    """APTL never realizes a pack it could not stage."""

    from aptl.core.scenario_bundle import EnvPackError, env_pack_bundle

    with pytest.raises(EnvPackError, match="env-pack source not found"):
        env_pack_bundle(tmp_path / "staging", "demo", source_pack=tmp_path / "absent")


def test_a_staged_pack_without_its_sdl_document_fails_closed(tmp_path, monkeypatch):
    """A pack that declares no sdl/<identity>.sdl.yaml has nothing to realize."""

    from aptl.core.scenario_bundle import EnvPackError, env_pack_bundle

    source = tmp_path / "src" / "demo"
    (source / "sdl").mkdir(parents=True)
    (source / "sdl" / "other.sdl.yaml").write_text("name: other\n", encoding="utf-8")
    monkeypatch.setattr(
        "aptl.core.scenario_bundle._validate_staged_pack", lambda staged, identity: None
    )

    with pytest.raises(EnvPackError, match="declares no sdl/demo.sdl.yaml"):
        env_pack_bundle(tmp_path / "staging", "demo", source_pack=source)
