"""Tests for ``aptl.core.assets`` — DEP-008 self-contained lab distribution.

These are fast, hermetic unit tests. Materialization is exercised against
small synthetic source trees (via monkeypatched ``resolve_asset_source``) so
the suite never copies the real 31M scenario tree, plus one test that runs
the real-repo git selection to guarantee no secrets are ever shipped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aptl.core import assets
from aptl.core.assets import AssetError, materialize
from aptl.core.config import load_config

REPO_ROOT = Path(__file__).resolve().parents[1]


def _make_fake_bundle(root: Path) -> Path:
    """Create a small, already-filtered bundle tree (as the wheel ships)."""
    bundle = root / "_labdata"
    (bundle / "config").mkdir(parents=True)
    (bundle / "scenarios").mkdir(parents=True)
    (bundle / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (bundle / "config" / "certs.yml").write_text("x: 1\n", encoding="utf-8")
    (bundle / "scenarios" / "catalog.json").write_text("{}\n", encoding="utf-8")
    return bundle


@pytest.fixture
def fake_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bundle = _make_fake_bundle(tmp_path / "pkg")
    monkeypatch.setattr(assets, "resolve_asset_source", lambda: (bundle, True))
    return bundle


def test_materialize_copies_bundle_and_writes_config(
    fake_bundle: Path, tmp_path: Path
) -> None:
    target = tmp_path / "lab"
    result = materialize(target)

    assert result.from_bundle is True
    assert result.config_created is True
    assert (target / "docker-compose.yml").is_file()
    assert (target / "config" / "certs.yml").is_file()
    assert (target / "scenarios" / "catalog.json").is_file()
    assert (target / "aptl.json").is_file()
    assert result.files_written == 3


def test_materialize_default_config_is_valid(fake_bundle: Path, tmp_path: Path) -> None:
    target = tmp_path / "lab"
    materialize(target)
    config = load_config(target / "aptl.json")
    assert config.lab.name == "aptl"
    assert "kali" in config.containers.enabled_profiles()


def test_materialize_refuses_conflict_without_force(
    fake_bundle: Path, tmp_path: Path
) -> None:
    target = tmp_path / "lab"
    materialize(target)
    with pytest.raises(AssetError, match="already contains lab assets"):
        materialize(target)


def test_materialize_force_overwrites(fake_bundle: Path, tmp_path: Path) -> None:
    target = tmp_path / "lab"
    materialize(target)
    (target / "docker-compose.yml").write_text("stale\n", encoding="utf-8")
    materialize(target, force=True)
    assert (target / "docker-compose.yml").read_text(encoding="utf-8") == "services: {}\n"


def test_materialize_can_skip_config(fake_bundle: Path, tmp_path: Path) -> None:
    target = tmp_path / "lab"
    result = materialize(target, write_config=False)
    assert result.config_created is False
    assert not (target / "aptl.json").exists()


def test_materialize_creates_missing_target(fake_bundle: Path, tmp_path: Path) -> None:
    target = tmp_path / "deep" / "nested" / "lab"
    materialize(target)
    assert (target / "docker-compose.yml").is_file()


def test_default_config_json_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "aptl.json"
    path.write_text(assets.default_config_json(), encoding="utf-8")
    config = load_config(path)
    assert config.deployment.provider == "docker-compose"


def test_resolve_within_rejects_escape(tmp_path: Path) -> None:
    with pytest.raises(AssetError, match="outside target directory"):
        assets._resolve_within(tmp_path, Path("../escape"))


def test_resolve_within_allows_nested(tmp_path: Path) -> None:
    resolved = assets._resolve_within(tmp_path, Path("a/b/c.txt"))
    assert resolved == (tmp_path / "a" / "b" / "c.txt").resolve()


def test_resolve_asset_source_prefers_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "_labdata"
    bundle.mkdir()
    monkeypatch.setattr(assets, "bundled_labdata_dir", lambda: bundle)
    source, from_bundle = assets.resolve_asset_source()
    assert (source, from_bundle) == (bundle, True)


def test_resolve_asset_source_checkout_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(assets, "bundled_labdata_dir", lambda: None)
    monkeypatch.setattr(assets, "checkout_root", lambda: tmp_path)
    source, from_bundle = assets.resolve_asset_source()
    assert (source, from_bundle) == (tmp_path, False)


def test_resolve_asset_source_errors_when_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(assets, "bundled_labdata_dir", lambda: None)
    monkeypatch.setattr(assets, "checkout_root", lambda: None)
    with pytest.raises(AssetError, match="Lab assets not found"):
        assets.resolve_asset_source()


def test_checkout_root_detects_this_repo() -> None:
    assert assets.checkout_root() == REPO_ROOT


def test_checkout_root_none_when_not_a_repo(tmp_path: Path) -> None:
    fake_pkg = tmp_path / "src" / "aptl"
    fake_pkg.mkdir(parents=True)
    assert assets.checkout_root(package_dir=fake_pkg) is None


def test_bundled_labdata_dir_absent_in_checkout() -> None:
    # Running from the source tree, no _labdata has been staged into the package.
    assert assets.bundled_labdata_dir() is None


def test_bundled_labdata_dir_returns_path_when_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    labdata = tmp_path / "_labdata"
    labdata.mkdir()

    class _FakeAnchor:
        def joinpath(self, _name: str) -> Path:
            return labdata

    monkeypatch.setattr(assets.importlib.resources, "files", lambda _pkg: _FakeAnchor())
    assert assets.bundled_labdata_dir() == labdata


def test_bundled_labdata_dir_none_on_lookup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise(_pkg: str) -> None:
        raise ModuleNotFoundError("no package")

    monkeypatch.setattr(assets.importlib.resources, "files", _raise)
    assert assets.bundled_labdata_dir() is None


def test_iter_source_files_checkout_uses_git(tmp_path: Path) -> None:
    # Against the real repo (a git checkout), the git path is taken.
    rels = {p.as_posix() for p in assets._iter_source_files(REPO_ROOT, from_bundle=False)}
    assert "docker-compose.yml" in rels
    assert not any("soc_certs" in r for r in rels)


# --- selection / secret-exclusion -----------------------------------------


def _make_fake_checkout(root: Path) -> None:
    """A checkout-like tree with real assets and gitignored secrets/artifacts."""
    (root / "config" / "wazuh_cluster").mkdir(parents=True)
    (root / "config" / "soc_certs").mkdir(parents=True)
    (root / "config" / "lab-ssh").mkdir(parents=True)
    (root / "containers" / "kali" / "__pycache__").mkdir(parents=True)
    (root / "web" / "node_modules").mkdir(parents=True)
    (root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (root / "config" / "wazuh_cluster" / "wazuh.yml").write_text("a: 1\n", encoding="utf-8")
    (root / "config" / "soc_certs" / "ca.key").write_text("SECRET\n", encoding="utf-8")
    (root / "config" / "lab-ssh" / "id_rsa").write_text("SECRET\n", encoding="utf-8")
    (root / "containers" / "kali" / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    (root / "containers" / "kali" / "__pycache__" / "x.pyc").write_text("", encoding="utf-8")
    # A stray compiled file directly under a tracked dir (not in __pycache__)
    # must still be excluded by suffix.
    (root / "containers" / "kali" / "stale.pyc").write_text("", encoding="utf-8")
    (root / "web" / "node_modules" / "dep.js").write_text("", encoding="utf-8")


def test_walk_checkout_excludes_secrets_and_artifacts(tmp_path: Path) -> None:
    _make_fake_checkout(tmp_path)
    selected = {p.as_posix() for p in assets._walk_checkout(tmp_path)}

    assert "docker-compose.yml" in selected
    assert "config/wazuh_cluster/wazuh.yml" in selected
    assert "containers/kali/Dockerfile" in selected
    # Secrets and build artifacts must never be selected.
    assert not any("soc_certs" in s for s in selected)
    assert not any("lab-ssh" in s for s in selected)
    assert not any("__pycache__" in s for s in selected)
    assert not any("node_modules" in s for s in selected)
    assert not any(s.endswith(".pyc") for s in selected)


def test_materialize_from_checkout_excludes_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    _make_fake_checkout(checkout)
    monkeypatch.setattr(assets, "resolve_asset_source", lambda: (checkout, False))

    target = tmp_path / "lab"
    materialize(target)

    assert (target / "docker-compose.yml").is_file()
    assert (target / "containers" / "kali" / "Dockerfile").is_file()
    assert not (target / "config" / "soc_certs").exists()
    assert not (target / "config" / "lab-ssh").exists()
    assert not list(target.rglob("*.pyc"))
    assert not list(target.rglob("node_modules"))


def test_materialize_from_bundle_skips_pip_compiled_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pip byte-compiles the installed bundle; materialize must not copy .pyc."""
    bundle = tmp_path / "pkg" / "_labdata"
    (bundle / "src" / "aptl" / "__pycache__").mkdir(parents=True)
    (bundle / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (bundle / "src" / "aptl" / "mod.py").write_text("x = 1\n", encoding="utf-8")
    (bundle / "src" / "aptl" / "__pycache__" / "mod.cpython-312.pyc").write_text(
        "", encoding="utf-8"
    )
    monkeypatch.setattr(assets, "resolve_asset_source", lambda: (bundle, True))

    target = tmp_path / "lab"
    materialize(target)

    assert (target / "docker-compose.yml").is_file()
    assert (target / "src" / "aptl" / "mod.py").is_file()
    assert not list(target.rglob("*.pyc"))
    assert not list(target.rglob("__pycache__"))


def test_real_repo_git_selection_ships_no_secrets() -> None:
    """The real repository's tracked asset set must never include secrets."""
    tracked = assets._git_tracked(REPO_ROOT)
    assert tracked is not None, "expected a git checkout"
    posix = [p.as_posix() for p in tracked]

    assert "docker-compose.yml" in posix
    assert any(p.startswith("scenarios/") for p in posix)
    assert any(p.startswith("config/") for p in posix)

    for path in posix:
        assert "soc_certs" not in path
        assert "lab-ssh" not in path
        assert "wazuh_indexer_ssl_certs" not in path
        assert not path.endswith((".pyc", ".pyo"))
        # Only public key material lives under a tracked keys/ path.
        assert not path.endswith("id_rsa")
