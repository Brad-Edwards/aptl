"""Runtime-owned bindings for the exact released TechVault pack."""

from importlib import metadata
from pathlib import Path

from aptl.backends.scenario_runtime_parameters import (
    ENTRY_POINT_GROUP,
    resolve_runtime_parameters,
)
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


def test_exact_release_receives_fresh_per_run_host_flags() -> None:
    first = runtime_parameters_for_bundle(_bundle())
    second = runtime_parameters_for_bundle(_bundle())

    assert first is not None
    assert second is not None
    hosts = {"victim", "workstation", "webapp", "fileshare", "ad"}
    expected = {f"flag_{host}_{level}" for host in hosts for level in ("user", "root")}
    assert set(first) == expected
    assert first != second
    for host in hosts:
        for level in ("user", "root"):
            assert str(first[f"flag_{host}_{level}"]).startswith(
                f"APTL{{{level}_{host}_"
            )


def test_unqualified_pack_digest_gets_no_implicit_bindings() -> None:
    assert runtime_parameters_for_bundle(_bundle(digest="sha256:" + "0" * 64)) is None


def test_runtime_parameters_are_registered_through_the_adapter() -> None:
    entries = {
        entry.name: entry.value
        for entry in metadata.entry_points(group=ENTRY_POINT_GROUP)
    }

    assert entries["techvault"].startswith("aptl_techvault.")
    assert resolve_runtime_parameters(_bundle()) is not None


def test_framework_never_imports_the_techvault_parameter_provider_directly() -> None:
    framework = Path(__file__).resolve().parents[1] / "src" / "aptl"
    offenders = {
        str(path.relative_to(framework))
        for path in framework.rglob("*.py")
        if "aptl_techvault.runtime_parameters" in path.read_text(encoding="utf-8")
    }

    assert offenders == set()


def test_framework_never_imports_the_techvault_package_directly() -> None:
    framework = Path(__file__).resolve().parents[1] / "src" / "aptl"
    offenders = {
        str(path.relative_to(framework))
        for path in framework.rglob("*.py")
        if "from aptl_techvault" in path.read_text(encoding="utf-8")
        or "import aptl_techvault" in path.read_text(encoding="utf-8")
    }

    assert offenders == set()
