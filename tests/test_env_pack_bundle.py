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
