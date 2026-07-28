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

    with pytest.raises(PathContainmentError):
        _bundle(inner).read_asset("leak")


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
