"""Build caches consume verified pack inputs without retaining scenario source."""

from pathlib import Path

import pytest


def test_cache_inputs_are_verified_lockfiles_only(tmp_path):
    from aptl_techvault.build_cache import prepare_cache_inputs

    result = prepare_cache_inputs(tmp_path / "inputs", tmp_path / "staging")
    assert result.pack_id == "techvault"
    assert (tmp_path / "inputs/aptl-mcp-common/package-lock.json").is_file()
    assert (tmp_path / "inputs/mcp-red/package-lock.json").is_file()
    paths = list((tmp_path / "inputs").rglob("*"))
    assert all(
        p.name in {"package.json", "package-lock.json"} for p in paths if p.is_file()
    )


def test_cache_refuses_an_unqualified_pack_before_writing(tmp_path, monkeypatch):
    from dataclasses import replace
    from aptl.core.scenario_bundle import env_pack_bundle, PackIdentity
    from aptl_techvault import build_cache

    bundle = env_pack_bundle(tmp_path / "source")
    bundle = replace(
        bundle, pack_identity=PackIdentity("techvault", "0.1.0", "sha256:" + "0" * 64)
    )
    monkeypatch.setattr(build_cache, "env_pack_bundle", lambda *args: bundle)
    with pytest.raises(ValueError, match="identity"):
        build_cache.prepare_cache_inputs(tmp_path / "inputs", tmp_path / "staging")
    assert not (tmp_path / "inputs").exists()


def test_dependency_cache_omits_lifecycle_scripts_without_changing_pack_artifact(
    tmp_path,
):
    import io
    import json
    import tarfile
    from raes_env_packs import resolve_pack_artifact
    from aptl_techvault.build_cache import prepare_cache_inputs

    prepare_cache_inputs(tmp_path / "inputs", tmp_path / "staging")
    manifest_path = "aptl-mcp-common/package.json"
    derived = json.loads((tmp_path / "inputs" / manifest_path).read_text())
    assert "scripts" not in derived
    pack_root = next((tmp_path / "staging").rglob("pack.yaml")).parent
    verified = resolve_pack_artifact(pack_root, "techvault-red-mcp-sources")
    with tarfile.open(fileobj=io.BytesIO(verified.data)) as archive:
        source = json.load(archive.extractfile(manifest_path))
    assert source["scripts"]["prepare"]
    assert derived == {key: value for key, value in source.items() if key != "scripts"}
