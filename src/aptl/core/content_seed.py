"""Content named-volume seeding for typed RAES content-placement realization.

Issue #689 / ADR-046's TechVault addendum: `content-placement` RAES
resources must lower into typed backend realization or fail closed before
`aptl lab start` side effects, reusing the ADR-043 named-volume seed seam
(``NamedVolumeSeed`` / ``SeedFile`` / ``seed_named_volumes``) rather than a
second Docker-copy mechanism. This module is the content-specific sibling of
:mod:`aptl.core.suricata_seed`: it turns typed
:class:`~aptl.core.deployment.realization.DeploymentContentRealization`
records (already validated for containment and realizability by
:mod:`aptl.backends.raes_content_realization`) into the seed specs the
deployment backend materializes.

Inline text is rendered into the ignored ``.aptl/content/`` state tree
first — mirroring the ADR-028 credential render path — so the seed
container always binds a real, containment-checked host directory rather
than embedding operator/scenario text into a shell string.
"""

from __future__ import annotations

import io
import re
import shutil
import tarfile
from collections.abc import Callable, Sequence
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
    builder = _SEED_BUILDERS.get(item.source_kind, _empty_directory_seed)
    return builder(project_dir, item)


def _empty_directory_seed(
    project_dir: Path, item: DeploymentContentRealization
) -> NamedVolumeSeed:
    """Seed an explicit empty-directory declaration, which has nothing to copy.

    The seed still runs (a harmless no-op `set -e` script) so the operation
    stays uniform for every content kind.
    """
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


def _pack_artifact_seed(
    project_dir: Path, item: DeploymentContentRealization
) -> NamedVolumeSeed:
    """Resolve env-pack content by identity + digest and seed the verified bytes.

    ``project_dir`` is the bundle root — the staged, validated pack for an
    env-pack bundle. The bytes are opened once through
    :func:`raes_env_packs.resolve_pack_artifact`, which byte-binds the returned
    ``bytes`` to the pack manifest's ``sha256`` digest, so the content is
    provably the declared artifact rather than whatever a host path happened to
    hold. The declared digest is re-checked here as defence in depth; a mismatch
    or an unresolvable id raises, failing the run closed before any seed
    container runs. A ``pack-directory`` artifact is an ``application/x-tar``
    archive extracted (data-filtered) under the rendered-content tree.
    """

    from raes_env_packs import resolve_pack_artifact

    if not item.artifact_id or not item.artifact_digest:
        raise PathContainmentError(
            f"Pack content {item.address!r} declared no artifact identity."
        )
    resolved = resolve_pack_artifact(str(project_dir), item.artifact_id)
    resolved_digest = getattr(resolved.identity, "digest", None)
    if resolved_digest != item.artifact_digest:
        raise ValueError(
            f"Pack content {item.address!r} digest mismatch: declared "
            f"{item.artifact_digest!r}, resolved {resolved_digest!r}."
        )
    rendered_dir = _canonical_generated_path(
        project_dir, _RENDERED_CONTENT_ROOT / _content_slug(item.address)
    )
    if rendered_dir.exists():
        shutil.rmtree(rendered_dir)
    rendered_dir.mkdir(parents=True, exist_ok=True)
    if item.source_kind == "pack-directory":
        extracted = rendered_dir / "tree"
        extracted.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(resolved.data), mode="r:*") as archive:
            archive.extractall(extracted, filter="data")
        return NamedVolumeSeed(
            volume_suffix=item.volume_suffix,
            source_dir=rendered_dir,
            files=(SeedFile(src="tree", dest=item.dest_relpath),),
        )
    basename = PurePosixPath(item.dest_relpath).name
    (rendered_dir / basename).write_bytes(resolved.data)
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


# The realization's declared source kind decides how its bytes reach the volume.
# Any other kind (an explicit empty directory) seeds nothing.
_SEED_BUILDERS: dict[
    str, Callable[[Path, DeploymentContentRealization], NamedVolumeSeed]
] = {
    "inline-text": _inline_text_seed,
    "pack-file": _pack_artifact_seed,
    "pack-directory": _pack_artifact_seed,
    "project-file": _project_source_seed,
    "project-directory": _project_source_seed,
}
