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
    assert bundle.pack_identity is None


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


def test_env_pack_staging_is_per_invocation_and_excludes_bytecode(tmp_path):
    """Two invocations never share a tree, and installer bytecode never stages.

    A shared tree lets one caller rmtree or read a tree another is copying, and a
    ``__pycache__`` written into an installed pack is an installer artifact the
    pack manifest never lists -- staging it would make env-packs' exact-inventory
    gate reject the pack (issue #875). The owned fixture is a real pack, so both
    stagings pass env-packs' own gates rather than a bypassed validator.
    """

    import shutil

    from aptl.core.scenario_bundle import env_pack_bundle
    from tests.fixture_pack import FIXTURE_PACK_IDENTITY, FIXTURE_PACK_SOURCE

    source = tmp_path / "src" / FIXTURE_PACK_IDENTITY
    shutil.copytree(FIXTURE_PACK_SOURCE, source)
    (source / "__pycache__").mkdir()
    (source / "__pycache__" / "mod.cpython-312.pyc").write_bytes(b"\x00")
    (source / "mod.pyc").write_bytes(b"\x00")

    first = env_pack_bundle(
        tmp_path / "staging", FIXTURE_PACK_IDENTITY, source_pack=source
    )
    second = env_pack_bundle(
        tmp_path / "staging", FIXTURE_PACK_IDENTITY, source_pack=source
    )

    # Distinct trees, each still named for the pack identity (env-packs'
    # validate_pack checks the directory name against the declared identity).
    assert first.root != second.root
    assert first.root.name == second.root.name == FIXTURE_PACK_IDENTITY
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


def test_a_source_that_is_not_a_pack_fails_closed(tmp_path):
    """A source env-packs rejects must raise, never return a usable bundle."""

    from aptl.core.scenario_bundle import EnvPackError, env_pack_bundle

    broken = tmp_path / "broken-pack"
    broken.mkdir()
    (broken / "pack.yaml").write_text("name: broken\n", encoding="utf-8")

    with pytest.raises(EnvPackError):
        env_pack_bundle(tmp_path / "staged", "broken", source_pack=broken)


def test_a_changed_source_pack_is_restaged_not_reused(tmp_path, monkeypatch):
    """A new pack release (different content) re-stages; it is not reused.

    Staging the same identity from a source whose content changed must realize
    the new bytes rather than serve a previous invocation's tree (issue #875).
    """

    import json
    import shutil

    from aptl.core.scenario_bundle import env_pack_bundle

    # Bypass env-packs' full validator (the synthetic packs here are minimal);
    # exercise only the stage/reuse decision in _stage_and_validate.
    monkeypatch.setattr(
        "aptl.core.scenario_bundle._validate_staged_pack", lambda staged, identity: None
    )
    src_a = tmp_path / "src-a" / "demo"
    (src_a / "sdl").mkdir(parents=True)
    (src_a / "sdl" / "demo.sdl.yaml").write_text("version: 1\n", encoding="utf-8")
    (src_a / "associated-artifacts.json").write_text(
        json.dumps({"set_digest": "sha256:aaaa"}), encoding="utf-8"
    )
    staging = tmp_path / "staged"

    first = env_pack_bundle(staging, "demo", source_pack=src_a)
    assert first.sdl_path.read_text(encoding="utf-8") == "version: 1\n"

    # A second source at the same identity with different content + set digest.
    src_b = tmp_path / "src-b" / "demo"
    shutil.copytree(src_a, src_b)
    (src_b / "sdl" / "demo.sdl.yaml").write_text("version: 2\n", encoding="utf-8")
    (src_b / "associated-artifacts.json").write_text(
        json.dumps({"set_digest": "sha256:bbbb"}), encoding="utf-8"
    )

    second = env_pack_bundle(staging, "demo", source_pack=src_b)
    # The changed source is realized, not the reused first-release bytes.
    assert second.sdl_path.read_text(encoding="utf-8") == "version: 2\n"


# -- the owned fixture pack, admitted like any released pack (issue #985) ----


def _copied_fixture(destination: Path) -> Path:
    """Copy the owned fixture pack to ``destination/<identity>`` and return it."""

    import shutil

    from tests.fixture_pack import FIXTURE_PACK_IDENTITY, FIXTURE_PACK_SOURCE

    copied = destination / FIXTURE_PACK_IDENTITY
    shutil.copytree(FIXTURE_PACK_SOURCE, copied)
    return copied


def test_the_owned_fixture_pack_is_admitted_by_the_production_resolver(tmp_path):
    """The fixture is a real pack: env-packs' own gates admit it unmodified.

    Core tests use this pack instead of the released TechVault one, so a pack
    release cannot break them. That only holds while the fixture passes the same
    ``validate_pack`` and content-manifest gates a released pack does.
    """

    import json

    from aptl.core.scenario_bundle import PackIdentity
    from tests.fixture_pack import (
        FIXTURE_PACK_IDENTITY,
        FIXTURE_PACK_SOURCE,
        FIXTURE_SDL,
        admit_fixture_pack,
    )

    staging = tmp_path / "staged-packs"
    bundle = admit_fixture_pack(staging)

    declared = json.loads(
        (FIXTURE_PACK_SOURCE / "associated-artifacts.json").read_text(encoding="utf-8")
    )
    assert bundle.source_kind is ScenarioSourceKind.ENV_PACK
    assert bundle.identity == FIXTURE_PACK_IDENTITY
    assert bundle.pack_identity == PackIdentity(
        pack_id=FIXTURE_PACK_IDENTITY,
        pack_version="1.0.0",
        set_digest=declared["set_digest"],
    )
    # The bundle roots at a staged copy, never at the checked-in source.
    assert staging in bundle.root.parents
    assert bundle.sdl_path == bundle.root / "sdl" / f"{FIXTURE_PACK_IDENTITY}.sdl.yaml"
    assert bundle.sdl_path.read_bytes() == FIXTURE_SDL.read_bytes()


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("changed-byte", "content manifest is invalid"),
        ("undeclared-member", "content manifest is invalid"),
    ),
)
def test_a_fixture_that_drifts_from_its_manifest_is_refused(
    tmp_path, mutation, reason
):
    """Admission is byte-bound: a changed or extra member fails the pack closed."""

    from aptl.core.scenario_bundle import EnvPackError, env_pack_bundle
    from tests.fixture_pack import FIXTURE_PACK_IDENTITY

    source = _copied_fixture(tmp_path / "src")
    notice = source / "assets" / "content" / "notice.txt"
    if mutation == "changed-byte":
        notice.write_bytes(notice.read_bytes() + b"drift\n")
    else:
        (notice.parent / "undeclared.txt").write_text("extra\n", encoding="utf-8")

    with pytest.raises(EnvPackError, match=reason):
        env_pack_bundle(tmp_path / "staged", FIXTURE_PACK_IDENTITY, source_pack=source)


def test_staged_members_are_singly_linked_even_from_a_hardlinked_source(tmp_path):
    """Installers hardlink package data; staging must yield singly-linked files.

    env-packs refuses any member that is not a singly-linked regular file, so an
    installed pack cannot be validated in place. The source here is hardlinked
    on purpose, so the property is proven rather than assumed from whichever
    installer happened to lay the package down.
    """

    import os

    from raes_env_packs import validate_pack

    from aptl.core.scenario_bundle import env_pack_bundle
    from tests.fixture_pack import FIXTURE_PACK_IDENTITY

    original = _copied_fixture(tmp_path / "original")
    installed = tmp_path / "installed" / FIXTURE_PACK_IDENTITY
    for member in sorted(original.rglob("*")):
        target = installed / member.relative_to(original)
        if member.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            os.link(member, target)
    assert os.stat(installed / "pack.yaml").st_nlink == 2
    assert validate_pack(str(installed)).ok is False

    bundle = env_pack_bundle(
        tmp_path / "staged", FIXTURE_PACK_IDENTITY, source_pack=installed
    )

    staged_files = [path for path in bundle.root.rglob("*") if path.is_file()]
    assert staged_files
    assert all(os.stat(path).st_nlink == 1 for path in staged_files)
    assert validate_pack(str(bundle.root)).ok is True


def test_an_admitted_pack_reads_only_inside_its_staged_root(tmp_path):
    """A real in-pack asset reads back; an escaping path is refused."""

    from tests.fixture_pack import FIXTURE_PACK_SOURCE, admit_fixture_pack

    bundle = admit_fixture_pack(tmp_path / "staged")

    expected = (FIXTURE_PACK_SOURCE / "pack.yaml").read_bytes()
    assert bundle.read_asset("pack.yaml") == expected
    with pytest.raises(PathContainmentError):
        bundle.read_asset("../pack.yaml")


def test_concurrent_admissions_each_get_an_isolated_valid_tree(tmp_path):
    """Concurrent staging to one root must give every caller a valid tree.

    Several suites stage packs under one shared root; under pytest-xdist two
    workers staging at once would otherwise rmtree/copytree over each other and
    one would read a half-copied pack. Per-invocation isolation gives each caller
    its own fresh directory, so every concurrent admission succeeds (issue #875).
    """

    from concurrent.futures import ThreadPoolExecutor

    from tests.fixture_pack import admit_fixture_pack

    staging = tmp_path / "staged-packs"
    with ThreadPoolExecutor(max_workers=8) as pool:
        bundles = [
            future.result()
            for future in [pool.submit(admit_fixture_pack, staging) for _ in range(16)]
        ]

    assert len({bundle.root for bundle in bundles}) == 16
    assert all(bundle.sdl_path.is_file() for bundle in bundles)
    assert all(staging in bundle.root.parents for bundle in bundles)
