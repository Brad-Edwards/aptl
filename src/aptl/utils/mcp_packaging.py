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

import hashlib
import os
import shutil
import subprocess
import tarfile
from collections.abc import Iterator
from pathlib import Path

from aptl.utils.deterministic_archive import (
    deterministic_tarinfo,
)

from aptl.utils.pathsafe import open_contained_nofollow

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
            if target != project / "mcp/aptl-mcp-common":
                raise ValueError("MCP dependency link escapes package")
            # Validate the whole closure before replacing npm's one allowed link.
            list(_common_files(target))
            linked.unlink()
            shutil.copytree(
                target, linked, ignore=_ignore_common_state,
                copy_function=lambda source, dest, root=target: _copy_common_file(root, source, dest),
            )


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
            # Keep the lexical path: resolving before no-follow would disguise
            # a credential symlink as an ordinary, innocuously named asset.
            with open_contained_nofollow(project, path.relative_to(project)) as handle:
                digest = hashlib.file_digest(handle, "sha256").hexdigest()
                status = os.fstat(handle.fileno())
                handle.seek(0)
                info = deterministic_tarinfo(
                    name, is_dir=False, size=status.st_size,
                    mode=0o755 if status.st_mode & 0o111 else 0o644,
                )
                archive.addfile(info, handle)
            files[name] = "sha256:" + digest
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
    for linked_path in _common_files(target):
        yield relative_root / path.name / linked_path.relative_to(target), linked_path


def _common_files(target: Path) -> Iterator[Path]:
    """Reject nested links, including directory links, in the common closure."""

    for root, directories, files in os.walk(target, followlinks=False):
        directories[:] = sorted(
            name for name in directories if _package_directory_allowed(Path("mcp"), name)
        )
        for name in directories:
            if (Path(root) / name).is_symlink():
                raise ValueError("nested MCP dependency symlink is forbidden")
        for name in sorted(files):
            if _package_file_allowed(Path("mcp"), name):
                path = Path(root) / name
                with open_contained_nofollow(target, path.relative_to(target)):
                    yield path


def _ignore_common_state(directory: str, names: list[str]) -> list[str]:
    """Apply the archive exclusions while materializing npm's dependency."""

    return [name for name in names if not (
        _package_directory_allowed(Path("mcp"), name)
        if (Path(directory) / name).is_dir()
        else _package_file_allowed(Path("mcp"), name)
    )]


def _copy_common_file(target: Path, source: str, destination: str) -> str:
    """Copy through the same containment boundary as the archive reader."""

    with open_contained_nofollow(target, Path(source).relative_to(target)) as handle:
        with open(destination, "xb") as output:
            shutil.copyfileobj(handle, output)
            os.fchmod(output.fileno(), os.fstat(handle.fileno()).st_mode & 0o777)
    return destination


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
