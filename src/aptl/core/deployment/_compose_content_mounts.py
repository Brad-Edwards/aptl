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
    root = realization_root / CONTENT_MOUNT_ROOT_RELPATH / slug
    basename = PurePosixPath(item.dest_relpath).name or slug

    if item.source_kind == "inline-text" and item.inline_text is not None:
        root.mkdir(parents=True, exist_ok=True)
        destination = root / basename
        destination.write_text(item.inline_text, encoding="utf-8")
        return destination

    if item.source_kind in ("pack-file", "pack-directory") and item.artifact_id:
        return _place_pack_content(item, scenario_root, root, basename)

    if item.source_kind == "project-file" and item.source_relpath:
        source = (scenario_root / item.source_relpath).resolve()
        return source if source.is_file() else None

    if item.source_kind == "project-directory" and item.source_relpath:
        source = (scenario_root / item.source_relpath).resolve()
        return source if source.is_dir() else None

    return None


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
    root.mkdir(parents=True, exist_ok=True)
    if item.source_kind == "pack-directory":
        tree = root / "tree"
        tree.mkdir(exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(resolved.data), mode="r:*") as archive:
            archive.extractall(tree, filter="data")
        return tree
    destination = root / basename
    destination.write_bytes(resolved.data)
    return destination
