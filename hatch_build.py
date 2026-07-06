"""Hatchling build hook: bundle git-tracked lab assets into the wheel.

Issue #659 / DEP-008. The published ``aptl-labs`` wheel historically
carried only ``src/aptl`` (the Python control plane), so a PyPI install
still required a full ``git clone`` to obtain the assets a lab needs to
build and run. This hook bundles every *git-tracked* asset a lab needs —
``docker-compose.yml``, the scenario/config/container trees, the web
frontend, helper scripts, and the Python source that several container
images build from — into the wheel under ``aptl/_labdata/<relpath>`` so
that ``pipx install aptl-labs`` + ``aptl lab init <dir>`` +
``aptl lab start`` works without a clone. ``aptl.core.assets`` resolves
the bundle via ``importlib.resources``.

Only git-tracked files are bundled. That is the mechanism that keeps
generated secrets and local state out of the distribution:
``config/soc_certs``, ``config/lab-ssh``, ``config/wazuh_indexer_ssl_certs``,
``keys/``, ``.aptl/`` and ``__pycache__`` are all gitignored and therefore
never shipped. When git is unavailable (a wheel built from an sdist has
no ``.git``), a walk fallback reproduces the same exclusions; the sdist
itself only contains tracked files, so walking it yields the same set.
"""

from __future__ import annotations

import importlib.util
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


def _load_manifest() -> Any:
    """Load the dependency-free asset manifest by file path.

    Loading the single file directly (rather than ``import aptl._asset_manifest``)
    keeps the build hook working in a build environment that has neither the
    package on ``sys.path`` nor the runtime dependencies installed, while still
    sharing one source of truth with ``aptl.core.assets`` (issue #659).
    """
    manifest_path = Path(__file__).parent / "src" / "aptl" / "_asset_manifest.py"
    spec = importlib.util.spec_from_file_location("_aptl_asset_manifest", manifest_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load asset manifest from {manifest_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_MANIFEST = _load_manifest()
_ASSET_ROOTS: tuple[str, ...] = _MANIFEST.ASSET_ROOTS
_LABDATA_PREFIX: str = _MANIFEST.LABDATA_PREFIX
_EXCLUDED_DIR_NAMES: frozenset[str] = _MANIFEST.EXCLUDED_DIR_NAMES
_EXCLUDED_SUFFIXES: tuple[str, ...] = _MANIFEST.EXCLUDED_SUFFIXES
_DISTRIBUTION_MARKER: str = _MANIFEST.DISTRIBUTION_MARKER


class CustomBuildHook(BuildHookInterface):
    """Force-include the git-tracked lab-asset tree under ``aptl/_labdata``."""

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        # Editable installs (`pip install -e`) redirect imports to the source
        # tree via a .pth; they must not materialize the bundle into
        # site-packages, which would create a partial real `aptl/` package
        # (only aptl/_labdata, no __init__.py/core) that shadows the editable
        # redirect and breaks `import aptl.core` (issue #659). Dev/editable
        # runtime resolves lab assets from the checkout via
        # aptl.core.assets.checkout_root().
        if version == "editable":
            return
        root = Path(self.root)
        # Only bundle when building the full lab distribution. Service
        # container images (misp-suricata-sync, web API) build with a minimal
        # context that copies only pyproject.toml/README.md/src/hatch_build.py
        # and run `pip install .`; they must load this hook but must not pull
        # the lab bundle into their wheel (issue #659 review).
        if not (root / _DISTRIBUTION_MARKER).is_file():
            return
        force_include: dict[str, str] = build_data.setdefault("force_include", {})
        for rel in self._iter_asset_files(root):
            source = root / rel
            target = f"{_LABDATA_PREFIX}/{rel.as_posix()}"
            force_include[str(source)] = target

    def _iter_asset_files(self, root: Path) -> Iterator[Path]:
        tracked = self._git_tracked(root)
        if tracked is not None:
            yield from tracked
            return
        yield from self._walk(root)

    @staticmethod
    def _git_tracked(root: Path) -> list[Path] | None:
        """Return tracked asset files, or ``None`` when git is unavailable."""
        try:
            completed = subprocess.run(
                ["git", "ls-files", "-z", "--", *_ASSET_ROOTS],
                cwd=root,
                capture_output=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError):
            return None
        rels = [Path(p) for p in completed.stdout.decode("utf-8").split("\0") if p]
        return rels or None

    @staticmethod
    def _walk(root: Path) -> Iterator[Path]:
        for entry in _ASSET_ROOTS:
            base = root / entry
            if base.is_file():
                yield Path(entry)
                continue
            if not base.is_dir():
                continue
            for path in base.rglob("*"):
                if not path.is_file():
                    continue
                rel = path.relative_to(root)
                if any(part in _EXCLUDED_DIR_NAMES for part in rel.parts):
                    continue
                if path.suffix in _EXCLUDED_SUFFIXES:
                    continue
                yield rel
