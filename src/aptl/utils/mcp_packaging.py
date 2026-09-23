"""Package built MCP servers so they run outside their build tree.

npm links the shared `aptl-mcp-common` package into each MCP's `node_modules`
as a symlink into the monorepo. That link is fine in a checkout and useless
anywhere else, so anything that ships an MCP — the seat image, a wheel, an
archive — has to replace it with the real package first.

Archiving is deterministic and refuses to carry runtime identity: a packaged
MCP must be the same bytes for the same inputs, and must never pick up the
credentials or generated state sitting beside it in a working project.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
from collections.abc import Iterator
from pathlib import Path

from aptl.utils.deterministic_archive import (
    deterministic_tarinfo,
    hash_file_nofollow,
    open_nofollow,
)

# Runtime identity and credentials that live in a working project and must not
# travel with a packaged one.
_EXCLUDED_PARTS = frozenset(
    {
        ".aptl",
        ".git",
        ".env",
        "soc_certs",
        "lab-ssh",
        "wazuh_indexer_ssl_certs",
    }
)

# Build residue that is either machine-specific or reproducible on demand.
_EXCLUDED_DIRECTORY_PARTS = frozenset({".bin", "node_gyp_bins", "__pycache__"})
_SECRET_DIRECTORY = ".secrets"
_EXCLUDED_ROOT_DIRECTORIES = frozenset(
    {".git", ".venv", ".pytest_cache", ".mypy_cache", ".ruff_cache", "build", "dist"}
)
_PACKAGE_DIRECTORIES = frozenset(
    {
        "assets",
        "config",
        "containers",
        "examples",
        "mcp",
        "participant-profiles",
        "plugins",
        "scenarios",
        "scripts",
        "web",
    }
)
_PACKAGE_FILES = frozenset(
    {
        ".mcp.json.example",
        "aptl.json",
        "docker-compose.yml",
        "docker-compose.capture.yml",
        "docker-compose.observability.yml",
        "generate-indexer-certs.yml",
    }
)


def flatten_common_dependencies(project: Path) -> None:
    """Replace each linked `aptl-mcp-common` with the package it points at.

    npm installs common's dependencies under its real directory rather than
    under each consumer, so the copy preserves that closure and Node resolves
    the same versions from the relocated package.
    """

    for directory in sorted((project / "mcp").iterdir()):
        linked = directory / "node_modules/aptl-mcp-common"
        if linked.is_symlink():
            target = linked.resolve(strict=True)
            if not target.is_relative_to(project / "mcp"):
                raise ValueError("MCP dependency link escapes package")
            linked.unlink()
            shutil.copytree(target, linked, ignore=shutil.ignore_patterns(".bin"))


def admit_packaged_path(name: str) -> None:
    """Reject runtime state and credentials from a packaged project."""

    parts = Path(name).parts
    if (
        any(part in _EXCLUDED_PARTS for part in parts)
        or any(part.startswith(".env") for part in parts)
        or name == ".mcp.json"
        or name.startswith("keys/")
    ):
        raise ValueError("runtime identity or credentials must not be packaged")


def archive_project(project: Path, output: Path) -> dict[str, str]:
    """Archive a built project deterministically, returning each file's digest."""

    project = project.resolve(strict=True)
    tracked = _tracked_project_files(project)
    files: dict[str, str] = {}
    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
        for relative, path in _project_files(project):
            name = relative.as_posix()
            if tracked is not None and name not in tracked and not _generated_asset(relative):
                continue
            admit_packaged_path(name)
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(project) or not resolved.is_file():
                raise ValueError("build output escapes the packaged project")
            digest, size = hash_file_nofollow(resolved)
            info = deterministic_tarinfo(
                name,
                is_dir=False,
                size=size,
                mode=0o755 if resolved.stat().st_mode & 0o111 else 0o644,
            )
            with open_nofollow(resolved) as handle:
                archive.addfile(info, handle)
            files[name] = digest
    return files


def _tracked_project_files(project: Path) -> set[str] | None:
    """Use the checkout index to exclude local, untracked runtime data."""

    if not (project / ".git").exists():
        return None
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", *_PACKAGE_DIRECTORIES, *_PACKAGE_FILES],
        cwd=project,
        capture_output=True,
        check=True,
    )
    return {name for name in result.stdout.decode().split("\0") if name}


def _generated_asset(relative: Path) -> bool:
    """Admit only the build output needed from an otherwise clean checkout."""

    parts = relative.parts
    return (
        len(parts) >= 4
        and parts[0] == "mcp"
        and parts[2] in {"build", "node_modules"}
    ) or (len(parts) >= 3 and parts[:2] == ("web", "build"))


def _package_directory_allowed(relative_root: Path, name: str) -> bool:
    """Keep only package directories, excluding local state at every depth."""

    if relative_root == Path(".") and name not in _PACKAGE_DIRECTORIES:
        return False
    return not (
        name.startswith(".env")
        or name in _EXCLUDED_PARTS
        or name in _EXCLUDED_DIRECTORY_PARTS
        or name == _SECRET_DIRECTORY
        or (relative_root == Path(".") and name in _EXCLUDED_ROOT_DIRECTORIES)
    )


def _package_file_allowed(relative_root: Path, name: str) -> bool:
    """Keep only package files, excluding local identity at every depth."""

    if relative_root == Path(".") and name not in _PACKAGE_FILES:
        return False
    return not (
        name in _EXCLUDED_PARTS
        or name.startswith(".env")
        or name == _SECRET_DIRECTORY
    )


def _linked_common_files(
    project: Path, relative_root: Path, path: Path
) -> Iterator[tuple[Path, Path]]:
    """Expand only npm's expected common-package link into the archive."""

    target = path.resolve(strict=True)
    if (
        path.name != "aptl-mcp-common"
        or relative_root.parts[:1] != ("mcp",)
        or relative_root.parts[-1:] != ("node_modules",)
        or target != project / "mcp/aptl-mcp-common"
    ):
        raise ValueError("linked package directory escapes the project")
    for linked_root, linked_dirs, linked_files in os.walk(target, followlinks=False):
        linked_dirs[:] = sorted(
            name
            for name in linked_dirs
            if _package_directory_allowed(Path("mcp"), name)
        )
        for name in sorted(linked_files):
            if _package_file_allowed(Path("mcp"), name):
                linked_path = Path(linked_root) / name
                yield (
                    relative_root / path.name / linked_path.relative_to(target),
                    linked_path,
                )


def _project_files(project: Path) -> Iterator[tuple[Path, Path]]:
    """Walk package files without visiting local state or changing npm links."""

    for root, directories, filenames in os.walk(project, followlinks=False):
        directory = Path(root)
        relative_root = directory.relative_to(project)
        kept = []
        for name in sorted(directories):
            if not _package_directory_allowed(relative_root, name):
                continue
            path = directory / name
            if path.is_symlink():
                yield from _linked_common_files(project, relative_root, path)
            else:
                kept.append(name)
        directories[:] = kept
        for name in sorted(filenames):
            if _package_file_allowed(relative_root, name):
                yield relative_root / name, directory / name
