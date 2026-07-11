"""Content named-volume seeding for typed ACES content-placement realization.

Issue #689 / ADR-046's TechVault addendum: `content-placement` ACES
resources must lower into typed backend realization or fail closed before
`aptl lab start` side effects, reusing the ADR-043 named-volume seed seam
(``NamedVolumeSeed`` / ``SeedFile`` / ``seed_named_volumes``) rather than a
second Docker-copy mechanism. This module is the content-specific sibling of
:mod:`aptl.core.suricata_seed`: it turns typed
:class:`~aptl.core.deployment.realization.DeploymentContentRealization`
records (already validated for containment and realizability by
:mod:`aptl.backends.aces_content_realization`) into the seed specs the
deployment backend materializes.

Inline text is rendered into the ignored ``.aptl/content/`` state tree
first — mirroring the ADR-028 credential render path — so the seed
container always binds a real, containment-checked host directory rather
than embedding operator/scenario text into a shell string.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from aptl.core.credentials import (
    PathContainmentError,
    _canonical_generated_path,
    _resolve_within_project,
)
from aptl.core.deployment.realization import DeploymentContentRealization
from aptl.core.seed_spec import NamedVolumeSeed, SeedFile

__all__ = ["build_content_volume_seeds"]

# Root of the rendered-content tree (ignored, mirrors `.aptl/config/`).
_RENDERED_CONTENT_ROOT = Path(".aptl/content")

_SLUG_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def build_content_volume_seeds(
    project_dir: Path,
    content: Sequence[DeploymentContentRealization],
) -> tuple[NamedVolumeSeed, ...]:
    """Build ADR-043 named-volume seed specs for typed content placements.

    One seed per content item. Each source path is re-resolved through the
    existing project-containment primitives here (independent of any
    upstream interpreter check), so a symlink or path escaping the project
    root is rejected before any seed container runs.

    Raises:
        PathContainmentError: if a source or rendered path escapes the
            project root, or resolves through a symlinked component.
        FileNotFoundError: if a project-contained source path is missing.
    """
    return tuple(_seed_for_content(project_dir, item) for item in content)


def _seed_for_content(
    project_dir: Path, item: DeploymentContentRealization
) -> NamedVolumeSeed:
    """Build the named-volume seed for one typed content realization."""
    if item.source_kind == "inline-text":
        return _inline_text_seed(project_dir, item)
    if item.source_kind in ("project-file", "project-directory"):
        return _project_source_seed(project_dir, item)
    # "empty-directory": an explicit empty-directory declaration has
    # nothing to copy. The seed still runs (a harmless no-op `set -e`
    # script) so the operation stays uniform for every content kind.
    return NamedVolumeSeed(
        volume_suffix=item.volume_suffix,
        source_dir=project_dir,
        files=(),
    )


def _inline_text_seed(
    project_dir: Path, item: DeploymentContentRealization
) -> NamedVolumeSeed:
    """Render bounded inline text and seed it as a single-file volume copy."""
    basename = PurePosixPath(item.dest_relpath).name
    rendered_dir = _canonical_generated_path(
        project_dir, _RENDERED_CONTENT_ROOT / _content_slug(item.address)
    )
    rendered_dir.mkdir(parents=True, exist_ok=True)
    rendered_file = rendered_dir / basename
    rendered_file.write_text(item.inline_text or "", encoding="utf-8")
    return NamedVolumeSeed(
        volume_suffix=item.volume_suffix,
        source_dir=rendered_dir,
        files=(SeedFile(src=basename, dest=item.dest_relpath),),
    )


def _project_source_seed(
    project_dir: Path, item: DeploymentContentRealization
) -> NamedVolumeSeed:
    """Bind a checked-in project-contained file or directory source."""
    source_relpath = item.source_relpath
    if source_relpath is None:
        raise PathContainmentError(
            f"Content placement {item.address!r} declared source kind "
            f"{item.source_kind!r} without a source path."
        )
    resolved = _resolve_within_project(project_dir, Path(source_relpath))
    if not resolved.exists():
        raise FileNotFoundError(
            f"Content source not found for {item.address!r}: {resolved}"
        )
    return NamedVolumeSeed(
        volume_suffix=item.volume_suffix,
        source_dir=resolved.parent,
        files=(SeedFile(src=resolved.name, dest=item.dest_relpath),),
    )


def _content_slug(address: str) -> Path:
    """Return a filesystem-safe, code-defined subdirectory name for an address."""
    return Path(_SLUG_RE.sub("_", address))
