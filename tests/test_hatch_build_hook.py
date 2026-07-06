"""Tests for the wheel build hook (hatch_build.py, DEP-008 / issue #659).

``hatch_build.py`` runs in the build backend environment, which has neither
the ``aptl`` package on ``sys.path`` nor ``hatchling`` available at test
time. We stub ``hatchling`` so the module imports, then exercise its file
selection and force-include mapping. This guards the wheel's asset set (and
its exclusion of secrets) in the fast suite without a full wheel build.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[1]


def _install_hatchling_stub() -> None:
    if "hatchling.builders.hooks.plugin.interface" in sys.modules:
        return

    class BuildHookInterface:
        def __init__(self, root: str = ".", *args: object, **kwargs: object) -> None:
            self.root = root

    chain = [
        "hatchling",
        "hatchling.builders",
        "hatchling.builders.hooks",
        "hatchling.builders.hooks.plugin",
        "hatchling.builders.hooks.plugin.interface",
    ]
    for name in chain:
        sys.modules[name] = ModuleType(name)
    sys.modules["hatchling.builders.hooks.plugin.interface"].BuildHookInterface = (
        BuildHookInterface
    )


def _load_hatch_build() -> ModuleType:
    _install_hatchling_stub()
    spec = importlib.util.spec_from_file_location(
        "hatch_build", REPO_ROOT / "hatch_build.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_fake_checkout(root: Path) -> None:
    (root / "config" / "soc_certs").mkdir(parents=True)
    (root / "containers" / "kali" / "__pycache__").mkdir(parents=True)
    (root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (root / "config" / "certs.yml").write_text("x: 1\n", encoding="utf-8")
    (root / "config" / "soc_certs" / "ca.key").write_text("SECRET\n", encoding="utf-8")
    (root / "containers" / "kali" / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    (root / "containers" / "kali" / "__pycache__" / "x.pyc").write_text("", encoding="utf-8")


def test_hook_uses_shared_manifest() -> None:
    hatch_build = _load_hatch_build()
    from aptl import _asset_manifest

    assert hatch_build._ASSET_ROOTS == _asset_manifest.ASSET_ROOTS
    assert hatch_build._EXCLUDED_DIR_NAMES == _asset_manifest.EXCLUDED_DIR_NAMES
    assert hatch_build._LABDATA_PREFIX == _asset_manifest.LABDATA_PREFIX


def test_walk_excludes_secrets_and_artifacts(tmp_path: Path) -> None:
    hatch_build = _load_hatch_build()
    _make_fake_checkout(tmp_path)
    selected = {p.as_posix() for p in hatch_build.CustomBuildHook._walk(tmp_path)}

    assert "docker-compose.yml" in selected
    assert "containers/kali/Dockerfile" in selected
    assert not any("soc_certs" in s for s in selected)
    assert not any("__pycache__" in s for s in selected)
    assert not any(s.endswith(".pyc") for s in selected)


def test_initialize_maps_assets_under_labdata(tmp_path: Path) -> None:
    hatch_build = _load_hatch_build()
    _make_fake_checkout(tmp_path)
    # Force the walk path (this synthetic tree is not a git repo).
    hook = hatch_build.CustomBuildHook(str(tmp_path))
    build_data: dict[str, object] = {}
    hook.initialize("0", build_data)

    force_include = build_data["force_include"]
    targets = set(force_include.values())
    assert "aptl/_labdata/docker-compose.yml" in targets
    assert "aptl/_labdata/containers/kali/Dockerfile" in targets
    assert not any("soc_certs" in t for t in targets)
    assert not any(t.endswith(".pyc") for t in targets)
    # Sources are absolute paths inside the given root.
    for source in force_include:
        assert str(tmp_path) in source


def test_initialize_skips_minimal_context(tmp_path: Path) -> None:
    """A build context without docker-compose.yml (service images) bundles nothing."""
    hatch_build = _load_hatch_build()
    # Mimic the misp-suricata-sync / web-api context: no docker-compose.yml.
    (tmp_path / "src").mkdir()
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (tmp_path / "src" / "mod.py").write_text("x = 1\n", encoding="utf-8")

    hook = hatch_build.CustomBuildHook(str(tmp_path))
    build_data: dict[str, object] = {}
    hook.initialize("0", build_data)

    assert build_data.get("force_include", {}) == {}


def test_real_repo_git_selection_is_clean() -> None:
    hatch_build = _load_hatch_build()
    tracked = hatch_build.CustomBuildHook._git_tracked(REPO_ROOT)
    assert tracked is not None
    posix = [p.as_posix() for p in tracked]
    assert "docker-compose.yml" in posix
    for path in posix:
        assert "soc_certs" not in path
        assert "lab-ssh" not in path
        assert "wazuh_indexer_ssl_certs" not in path
