"""The pack-backed bundle resolver: APTL realizes the scenario from an env-pack.

Content #875: APTL must realize TechVault from the ``raes-env-packs`` pack, not
its own checkout. The env-pack ships inside the installed ``raes_env_packs``
package; APTL's job (its side of the ADR-046 seam) is *trusted source
acquisition*: locate the bundled pack, stage an immutable owned copy, and refuse
to use it unless env-packs' own ``validate_pack`` /
``validate_pack_content_manifest`` gates pass. The staged root becomes the
``ScenarioBundle`` root every downstream consumer already resolves against.

Staging is not incidental: a pip/uv install hardlinks package files, and
env-packs refuses any pack member that is not a singly-linked regular file, so
the bundled location cannot be validated in place. Staging a fresh copy is what
makes the pack a singly-linked, containment-checked, owned tree.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aptl.core.scenario_bundle import (
    EnvPackError,
    PathContainmentError,
    ScenarioSourceKind,
    env_pack_bundle,
)

pytestmark = pytest.mark.integration


def test_env_pack_bundle_stages_and_validates_the_bundled_techvault_pack(
    tmp_path: Path,
) -> None:
    staging = tmp_path / "staged-packs"
    bundle = env_pack_bundle(staging, "techvault")

    assert bundle.source_kind is ScenarioSourceKind.ENV_PACK
    assert bundle.identity == "techvault"
    # The bundle roots at the staged copy, never at the installed package.
    assert staging in bundle.root.parents or bundle.root.parent == staging
    assert bundle.sdl_path == bundle.root / "sdl" / "techvault.sdl.yaml"
    assert bundle.sdl_path.is_file()
    assert (bundle.root / "pack.yaml").is_file()
    assert (bundle.root / "associated-artifacts.json").is_file()


def test_staged_pack_members_are_singly_linked_regular_files(tmp_path: Path) -> None:
    # The installer hardlinks package data (st_nlink >= 2); staging must yield
    # fresh singly-linked files or env-packs' validator rejects the pack.
    bundle = env_pack_bundle(tmp_path / "staged", "techvault")
    assert os.stat(bundle.root / "pack.yaml").st_nlink == 1

    # And env-packs' own gate passes on the staged root.
    from raes_env_packs import validate_pack

    result = validate_pack(str(bundle.root))
    assert getattr(result, "ok", None) is True
    assert not (getattr(result, "diagnostics", []) or [])


def test_read_asset_is_contained_to_the_staged_root(tmp_path: Path) -> None:
    bundle = env_pack_bundle(tmp_path / "staged", "techvault")
    # A real in-pack asset reads back.
    assert bundle.read_asset("pack.yaml")
    # A path escaping the staged root is refused, not silently satisfied from
    # elsewhere.
    with pytest.raises(PathContainmentError):
        bundle.read_asset("../pack.yaml")


def test_resolver_fails_closed_on_an_invalid_pack(tmp_path: Path) -> None:
    # A source that is not a valid pack must raise, never return a usable bundle.
    broken = tmp_path / "broken-pack"
    broken.mkdir()
    (broken / "pack.yaml").write_text("name: broken\n", encoding="utf-8")
    with pytest.raises(EnvPackError):
        env_pack_bundle(tmp_path / "staged", "broken", source_pack=broken)


def test_resolver_fails_closed_on_a_missing_pack(tmp_path: Path) -> None:
    with pytest.raises(EnvPackError):
        env_pack_bundle(
            tmp_path / "staged", "nope", source_pack=tmp_path / "does-not-exist"
        )


def test_scenario_selection_resolves_the_env_pack_when_configured(tmp_path: Path) -> None:
    # config.scenario.source == "env-pack" selects the staged pack (default
    # selection, no explicit --scenario-path override).
    from aptl.backends.raes import resolve_scenario_bundle
    from aptl.core.config import AptlConfig

    config = AptlConfig(scenario={"identity": "techvault", "source": "env-pack"})
    bundle = resolve_scenario_bundle(tmp_path, None, config)
    assert bundle.source_kind is ScenarioSourceKind.ENV_PACK
    assert bundle.identity == "techvault"
    assert bundle.sdl_path.is_file()
    # An explicit path overrides the pack (operator override stays project-tree).
    local = tmp_path / "scenarios" / "custom.sdl.yaml"
    override = resolve_scenario_bundle(tmp_path, local, config)
    assert override.source_kind is ScenarioSourceKind.PROJECT_TREE


def test_concurrent_staging_of_one_root_each_gets_a_valid_isolated_tree(
    tmp_path: Path,
) -> None:
    """Concurrent staging to one root must give every caller a valid tree.

    Several suites stage the default pack under one shared root; under -n auto
    two workers staging the same tree at once would otherwise rmtree/copytree
    over each other and one would read a half-copied pack ("associated artifact
    manifest failed RAES byte binding"). Per-invocation isolation gives each
    caller its own fresh directory, so all concurrent stages succeed and none
    share a tree another is copying (issue #875).
    """

    from concurrent.futures import ThreadPoolExecutor

    staging = tmp_path / "staged-packs"

    def _stage() -> Path:
        return env_pack_bundle(staging, "techvault").sdl_path

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = [f.result() for f in [pool.submit(_stage) for _ in range(16)]]

    # Every concurrent stage returned a valid staged SDL (a raise on a
    # half-copied tree would surface through f.result()), and each is its own
    # isolated tree under the shared root.
    assert len(results) == 16
    assert len({p for p in results}) == 16
    assert all(p.is_file() and p.name == "techvault.sdl.yaml" for p in results)
    assert all(staging in p.parents for p in results)


def test_a_changed_source_pack_is_restaged_not_reused(tmp_path: Path) -> None:
    """A new pack release (different set digest) re-stages; it is not reused.

    Reuse keys on the pack's associated-artifacts set digest, so staging the
    same identity from a source whose content changed must replace the staged
    tree rather than serve the previous release's bytes (issue #875).
    """

    import json
    import shutil

    from aptl.core.scenario_bundle import env_pack_bundle as _bundle

    # A first source, staged once.
    src_a = tmp_path / "src-a" / "demo"
    (src_a / "sdl").mkdir(parents=True)
    (src_a / "sdl" / "demo.sdl.yaml").write_text("version: 1\n", encoding="utf-8")
    (src_a / "associated-artifacts.json").write_text(
        json.dumps({"set_digest": "sha256:aaaa"}), encoding="utf-8"
    )
    staging = tmp_path / "staged"

    def _stage(source: Path):
        # Bypass env-packs' full validator (the synthetic packs here are minimal);
        # exercise only the stage/reuse decision in _stage_and_validate.
        import aptl.core.scenario_bundle as sb

        original = sb._validate_staged_pack
        sb._validate_staged_pack = lambda *_a, **_k: None
        try:
            return _bundle(staging, "demo", source_pack=source)
        finally:
            sb._validate_staged_pack = original

    first = _stage(src_a)
    assert first.sdl_path.read_text(encoding="utf-8") == "version: 1\n"

    # A second source at the same identity with different content + set digest.
    src_b = tmp_path / "src-b" / "demo"
    shutil.copytree(src_a, src_b)
    (src_b / "sdl" / "demo.sdl.yaml").write_text("version: 2\n", encoding="utf-8")
    (src_b / "associated-artifacts.json").write_text(
        json.dumps({"set_digest": "sha256:bbbb"}), encoding="utf-8"
    )

    second = _stage(src_b)
    # The changed source is realized, not the reused first-release bytes.
    assert second.sdl_path.read_text(encoding="utf-8") == "version: 2\n"
