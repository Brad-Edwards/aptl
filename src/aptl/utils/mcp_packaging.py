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

import shutil
import tarfile
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
        or name == ".mcp.json"
        or name.startswith("keys/")
    ):
        raise ValueError("runtime identity or credentials must not be packaged")


def archive_project(project: Path, output: Path) -> dict[str, str]:
    """Archive a built project deterministically, returning each file's digest."""

    files: dict[str, str] = {}
    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(project.rglob("*")):
            if path.is_dir() or _EXCLUDED_DIRECTORY_PARTS.intersection(path.parts):
                continue
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(project) or not resolved.is_file():
                raise ValueError("build output escapes the packaged project")
            relative = path.relative_to(project).as_posix()
            admit_packaged_path(relative)
            digest, size = hash_file_nofollow(resolved)
            info = deterministic_tarinfo(
                relative,
                is_dir=False,
                size=size,
                mode=0o755 if path.stat().st_mode & 0o111 else 0o644,
            )
            with open_nofollow(resolved) as handle:
                archive.addfile(info, handle)
            files[relative] = digest
    return files
