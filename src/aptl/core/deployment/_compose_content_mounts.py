"""Deliver declared content to image (Compose) nodes as bind mounts (#875).

Content for an image-free node is placed into its container by the generic
materializer. An image node is a Compose service with a fixed image whose config
files are read from fixed paths, so its content is delivered the way the retiring
``docker-compose.yml`` delivered it: a read-only bind mount of the resolved file
at its declared destination.

The bytes are resolved from the pristine pack (``scenario_root``, byte-bound by
digest) but written under ``realization_root`` (the writable engine checkout),
never back into the pack, so the pack's digest-validated inventory stays intact.
The resulting per-service mounts are emitted as a Compose override.
"""

from __future__ import annotations

import io
import re
import shutil
import tarfile
from pathlib import Path, PurePosixPath

from aptl.core.deployment.realization import (
    DeploymentContentRealization,
    DeploymentRealizationSpec,
)

CONTENT_MOUNT_ROOT_RELPATH = Path(".aptl") / "realization" / "content"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def image_node_content_override(
    realization: DeploymentRealizationSpec,
    scenario_root: Path,
    realization_root: Path,
) -> dict[str, object]:
    """Return a Compose override mounting each image node's declared content.

    Only content whose target is an image node (a Compose service) is handled;
    image-free targets are delivered by the generic materializer elsewhere.
    """

    # Bind sources must be absolute: Docker resolves a relative source against
    # the Compose project directory (the staged pack), where the generated file
    # does not exist, and would create the target as an empty directory (#875).
    realization_root = realization_root.resolve()
    imaged = {image.address for image in realization.images}
    service_by_address = {
        node.address: node.service_name
        for node in realization.nodes
        if node.service_name
    }
    services: dict[str, dict[str, object]] = {}
    for item in realization.content:
        if item.target_address not in imaged:
            continue
        service_name = service_by_address.get(item.target_address)
        if not service_name:
            continue
        source = _place_content(item, scenario_root, realization_root)
        if source is None:
            continue
        target = "/" + item.dest_relpath.lstrip("/")
        services.setdefault(service_name, {}).setdefault("volumes", []).append(
            {
                "type": "bind",
                "source": str(source),
                "target": target,
                "read_only": True,
            }
        )
    return {"services": services} if services else {"services": {}}


def _place_content(
    item: DeploymentContentRealization,
    scenario_root: Path,
    realization_root: Path,
) -> Path | None:
    """Resolve one content item's bytes and write them under realization_root.

    Returns the host path to bind, or ``None`` for a source kind that carries no
    bytes to mount.
    """

    slug = item.address.rsplit(".", 1)[-1]
    basename = PurePosixPath(item.dest_relpath).name or slug

    placed: Path | None = None
    if item.source_kind == "inline-text" and item.inline_text is not None:
        root = _content_output_root(realization_root, slug)
        placed = root / basename
        _remove_previous_output(placed)
        placed.write_text(item.inline_text, encoding="utf-8")
    elif item.source_kind in ("pack-file", "pack-directory") and item.artifact_id:
        root = _content_output_root(realization_root, slug)
        placed = _place_pack_content(item, scenario_root, root, basename)
    elif (
        item.source_kind in ("project-file", "project-directory")
        and item.source_relpath
    ):
        placed = _project_content_source(item, scenario_root)
    return placed


def _content_output_root(realization_root: Path, slug: str) -> Path:
    """Create one output root without following project-state symlinks."""

    realization_root.mkdir(parents=True, exist_ok=True)
    current = realization_root
    for part in (*CONTENT_MOUNT_ROOT_RELPATH.parts, slug):
        current = current / part
        if current.is_symlink():
            raise ValueError("content realization output path contains a symlink")
        current.mkdir(exist_ok=True)
        if not current.is_dir():
            raise ValueError("content realization output path is not a directory")
    return current


def _remove_previous_output(path: Path) -> None:
    """Remove generated output that a prior container may have made read-only."""

    if path.is_symlink():
        raise ValueError("content realization output path contains a symlink")
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def _project_content_source(
    item: DeploymentContentRealization,
    scenario_root: Path,
) -> Path | None:
    """Return a project source path when it exists with its declared kind.

    A declared ``project-file`` that resolves to a directory (or the reverse) is
    not the content the scenario declared, so nothing is bound for it.
    """

    source = (scenario_root / item.source_relpath).resolve()
    if item.source_kind == "project-file":
        return source if source.is_file() else None
    return source if source.is_dir() else None


def _place_pack_content(
    item: DeploymentContentRealization,
    scenario_root: Path,
    root: Path,
    basename: str,
) -> Path | None:
    """Resolve and verify env-pack content, writing it under realization_root."""

    from raes_env_packs import resolve_pack_artifact

    resolved = resolve_pack_artifact(str(scenario_root), item.artifact_id)
    digest = getattr(resolved.identity, "digest", None)
    if item.artifact_digest and _SHA256_RE.fullmatch(item.artifact_digest or ""):
        if digest != item.artifact_digest:
            raise ValueError(
                f"pack content digest mismatch for {item.artifact_id}: "
                f"{digest} != {item.artifact_digest}"
            )
    if item.source_kind == "pack-directory":
        tree = root / "tree"
        _remove_previous_output(tree)
        tree.mkdir()
        with tarfile.open(fileobj=io.BytesIO(resolved.data), mode="r:*") as archive:
            archive.extractall(tree, filter="data")
        return tree
    destination = root / basename
    _remove_previous_output(destination)
    destination.write_bytes(resolved.data)
    return destination
