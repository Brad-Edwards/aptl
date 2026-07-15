"""Locate and materialize the bundled lab-asset tree (DEP-008, issue #659).

This module is the single canonical boundary between the wheel-owned,
immutable lab-asset source tree and a mutable, runnable lab *project
directory*. Every other module keeps resolving assets against a
``project_dir`` (``project_dir / "docker-compose.yml"`` etc.); this module
is only responsible for producing such a directory.

Two source layouts are supported transparently:

* **Installed wheel** — the build hook (``hatch_build.py``) stages the
  git-tracked asset tree under ``aptl/_labdata/`` inside the wheel;
  :func:`bundled_labdata_dir` finds it via ``importlib.resources``.
* **Source checkout** — when running from a working tree (editable install
  or tests) ``_labdata`` does not exist, so the repository root is used as
  the source and the git-tracked asset set is selected the same way the
  build hook selects it.

In both cases only git-tracked assets are materialized, so generated
secrets and local state (``config/soc_certs``, ``config/lab-ssh``,
``config/wazuh_indexer_ssl_certs``, ``keys/``, ``.aptl/``, ``__pycache__``)
never leak into a materialized project.
"""

from __future__ import annotations

import importlib.resources
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from aptl._asset_manifest import (
    ASSET_ROOTS as _ASSET_ROOTS,
    EXCLUDED_DIR_NAMES as _EXCLUDED_DIR_NAMES,
    EXCLUDED_SUFFIXES as _EXCLUDED_SUFFIXES,
    LABDATA_DIRNAME as _LABDATA_DIRNAME,
)
from aptl.core.config import AptlConfig
from aptl.utils.logging import get_logger

log = get_logger("assets")

_CONFIG_FILENAME = "aptl.json"


class AssetError(RuntimeError):
    """Raised when lab assets cannot be located or materialized."""


@dataclass(frozen=True)
class MaterializeResult:
    """Outcome of :func:`materialize`."""

    target_dir: Path
    source_dir: Path
    from_bundle: bool
    files_written: int
    config_created: bool


def bundled_labdata_dir() -> Path | None:
    """Return the wheel-bundled ``_labdata`` directory, or ``None``.

    ``None`` means the package was imported from a source checkout rather
    than an installed wheel, in which case :func:`checkout_root` supplies
    the assets instead.
    """
    try:
        resource = importlib.resources.files("aptl").joinpath(_LABDATA_DIRNAME)
    except (ModuleNotFoundError, TypeError):
        return None
    if resource.is_dir():
        return Path(str(resource))
    return None


def checkout_root(package_dir: Path | None = None) -> Path | None:
    """Return the repository root when running from a source checkout.

    The package lives at ``<root>/src/aptl/__init__.py`` in a checkout, so
    the root is two parents above the package directory. It only qualifies
    as an asset source when it actually carries the lab tree.

    Args:
        package_dir: The ``src/aptl`` directory; defaults to the location of
            this module. Injectable so the non-checkout branch is testable.
    """
    if package_dir is None:
        package_dir = Path(__file__).resolve().parent.parent
    root = package_dir.parent.parent
    if (root / "docker-compose.yml").is_file() and (root / "scenarios").is_dir():
        return root
    return None


def resolve_asset_source() -> tuple[Path, bool]:
    """Return ``(source_dir, from_bundle)`` for the lab-asset tree.

    Prefers the wheel bundle; falls back to the source checkout. Raises
    :class:`AssetError` when neither is available.
    """
    bundled = bundled_labdata_dir()
    if bundled is not None:
        return bundled, True
    root = checkout_root()
    if root is not None:
        return root, False
    raise AssetError(
        "Lab assets not found: the installed package has no bundled "
        "_labdata and this is not a source checkout. Reinstall aptl-labs."
    )


def default_config_json() -> str:
    """Return the default ``aptl.json`` contents for a fresh lab project."""
    payload = AptlConfig().model_dump(mode="json", exclude_none=True)
    return json.dumps(payload, indent=4) + "\n"


# Git env vars that redirect where git resolves the repo/worktree/index.
# A git hook (e.g. pre-commit) exports these pointing at the real repo; if
# they leak into ``git ls-files`` below they make it resolve to the ambient
# repo instead of ``root``, so a non-repo checkout is reported as carrying the
# real repo's tracked files and materialize/bundle then fails copying paths the
# checkout lacks. Strip them so selection is always scoped to ``root``.
_GIT_LOCATION_ENV = frozenset(
    {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_PREFIX",
        "GIT_NAMESPACE",
    }
)


def _git_tracked(root: Path) -> list[Path] | None:
    """Return tracked asset files under ``root``, or ``None`` without git.

    Runs ``git ls-files`` with the inherited git *location* environment
    (``GIT_DIR``/``GIT_WORK_TREE``/``GIT_INDEX_FILE`` etc.) stripped, so a
    caller running inside a git hook cannot make selection resolve to the
    ambient repo instead of ``root``.
    """
    env = {k: v for k, v in os.environ.items() if k not in _GIT_LOCATION_ENV}
    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z", "--", *_ASSET_ROOTS],
            cwd=root,
            capture_output=True,
            check=True,
            env=env,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    rels = [Path(p) for p in completed.stdout.decode("utf-8").split("\0") if p]
    return rels or None


def _is_excluded(rel: Path) -> bool:
    """Return whether a relative path is a gitignored secret/artifact."""
    if any(part in _EXCLUDED_DIR_NAMES for part in rel.parts):
        return True
    return rel.suffix in _EXCLUDED_SUFFIXES


def _walk_checkout(root: Path) -> Iterator[Path]:
    """Yield asset files under ``root``, applying the exclusion denylist."""
    for entry in _ASSET_ROOTS:
        base = root / entry
        if base.is_file():
            yield Path(entry)
            continue
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            rel = path.relative_to(root)
            if path.is_file() and not _is_excluded(rel):
                yield rel


def _iter_bundle_files(source: Path) -> Iterator[Path]:
    """Yield files under a wheel bundle, skipping post-install artifacts.

    The wheel ships a clean bundle, but pip byte-compiles the installed
    ``.py`` files, so ``__pycache__``/``*.pyc`` appear next to them in
    site-packages after install. Re-applying the exclusion denylist keeps a
    materialized project free of that compiled noise.
    """
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(source)
        if not _is_excluded(rel):
            yield rel


def _iter_source_files(source: Path, from_bundle: bool) -> Iterator[Path]:
    """Yield asset file paths (relative to ``source``) to materialize."""
    if from_bundle:
        yield from _iter_bundle_files(source)
        return
    tracked = _git_tracked(source)
    yield from (tracked if tracked is not None else _walk_checkout(source))


def _resolve_within(base: Path, relative: Path) -> Path:
    """Resolve ``base / relative`` and confirm it stays inside ``base``."""
    resolved = (base / relative).resolve()
    base_resolved = base.resolve()
    if not resolved.is_relative_to(base_resolved):
        raise AssetError(f"Refusing to write outside target directory: {relative}")
    return resolved


def materialize(
    target_dir: Path,
    *,
    force: bool = False,
    write_config: bool = True,
) -> MaterializeResult:
    """Copy the bundled lab assets into ``target_dir`` as a lab project.

    Args:
        target_dir: Destination directory (created if missing).
        force: Overwrite pre-existing files. When ``False`` the copy
            refuses if any destination file already exists, so an
            accidental ``init`` never clobbers an existing project.
        write_config: Write a default ``aptl.json`` when one is absent.

    Returns:
        A :class:`MaterializeResult` describing what was written.

    Raises:
        AssetError: If assets cannot be located, a path escapes
            ``target_dir``, or a conflict is found while ``force`` is
            ``False``.
    """
    source, from_bundle = resolve_asset_source()
    target_dir = target_dir.expanduser()
    files = list(_iter_source_files(source, from_bundle))

    planned = [(rel, _resolve_within(target_dir, rel)) for rel in files]
    if not force:
        conflicts = [str(rel) for rel, dest in planned if dest.exists()]
        if conflicts:
            preview = ", ".join(sorted(conflicts)[:5])
            raise AssetError(
                f"{target_dir} already contains lab assets "
                f"({len(conflicts)} conflicting file(s): {preview}...). "
                "Use --force to overwrite or choose an empty directory."
            )

    target_dir.mkdir(parents=True, exist_ok=True)
    for rel, dest in planned:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / rel, dest)

    config_created = False
    if write_config:
        config_path = _resolve_within(target_dir, Path(_CONFIG_FILENAME))
        if force or not config_path.exists():
            config_path.write_text(default_config_json(), encoding="utf-8")
            config_created = True

    log.info(
        "Materialized %d lab asset(s) into %s (from %s)",
        len(planned),
        target_dir,
        "wheel bundle" if from_bundle else "source checkout",
    )
    return MaterializeResult(
        target_dir=target_dir,
        source_dir=source,
        from_bundle=from_bundle,
        files_written=len(planned),
        config_created=config_created,
    )
