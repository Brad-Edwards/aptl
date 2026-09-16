"""Runtime-owned bindings for the exact released TechVault pack."""

from pathlib import Path

from aptl.core.scenario_bundle import PackIdentity, ScenarioBundle, ScenarioSourceKind
from aptl_techvault.runtime_parameters import (
    TECHVAULT_PACK_SET_DIGEST,
    runtime_parameters_for_bundle,
)


def _bundle(*, digest: str = TECHVAULT_PACK_SET_DIGEST) -> ScenarioBundle:
    return ScenarioBundle(
        identity="techvault",
        root=Path("/pack"),
        sdl_path=Path("/pack/sdl/techvault.sdl.yaml"),
        source_kind=ScenarioSourceKind.ENV_PACK,
        pack_identity=PackIdentity("techvault", "0.1.0", digest),
    )


def test_exact_release_receives_fresh_per_run_ad_flags() -> None:
    first = runtime_parameters_for_bundle(_bundle())
    second = runtime_parameters_for_bundle(_bundle())

    assert first is not None
    assert second is not None
    assert set(first) == {"flag_ad_user", "flag_ad_root"}
    assert first != second
    assert str(first["flag_ad_user"]).startswith("APTL{user_ad_")
    assert str(first["flag_ad_root"]).startswith("APTL{root_ad_")


def test_unqualified_pack_digest_gets_no_implicit_bindings() -> None:
    assert runtime_parameters_for_bundle(_bundle(digest="sha256:" + "0" * 64)) is None
