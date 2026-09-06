"""Canonical exact Docker image-identity parsing for realization checks."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re

EXACT_IMAGE_INSPECT_FORMAT = (
    "{{json .RepoDigests}}\t{{.Id}}\t{{.Os}}/{{.Architecture}}"
    '{{if index . "Variant"}}/{{index . "Variant"}}{{end}}'
)
IMAGE_ID_INSPECT_FORMAT = "{{.Id}}"
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class DockerPlatform:
    """Canonical Docker OS, architecture, and optional architecture variant."""

    os: str
    architecture: str
    variant: str = ""


@dataclass(frozen=True)
class ExactDockerImageIdentity:
    """Immutable daemon-local ID and platform for one exact repo digest."""

    image_id: str
    platform: DockerPlatform


def normalized_platform(value: object) -> DockerPlatform | None:
    """Normalize Docker platform aliases without losing variant semantics."""

    raw = str(value or "").strip().lower()
    parts = raw.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    os_name, architecture = parts[:2]
    variant = parts[2] if len(parts) > 2 else ""
    aliases = {
        "x86_64": ("amd64", ""),
        "aarch64": ("arm64", "v8"),
        "arm64": ("arm64", "v8"),
        "armv8l": ("arm", "v8"),
        "armv7l": ("arm", "v7"),
        "armhf": ("arm", "v7"),
        "armv6l": ("arm", "v6"),
        "i386": ("386", ""),
        "i686": ("386", ""),
    }
    architecture, inferred_variant = aliases.get(architecture, (architecture, ""))
    if not variant:
        variant = inferred_variant
    elif not variant.startswith("v") and architecture in {"arm", "arm64"}:
        variant = f"v{variant}"
    return DockerPlatform(os_name, architecture, variant)


def platform_is_compatible(daemon: DockerPlatform, image: DockerPlatform) -> bool:
    """Whether an image platform can run natively on the selected daemon."""

    if (daemon.os, daemon.architecture) != (image.os, image.architecture):
        return False
    return daemon.variant == image.variant


def exact_inspected_image_identity(
    stdout: object,
    image_ref: str,
) -> ExactDockerImageIdentity | None:
    """Parse identity only when inspection proves the requested repo digest."""

    try:
        repo_digests_raw, image_id, platform_raw = (
            str(stdout or "").strip().split("\t", 2)
        )
        repo_digests = json.loads(repo_digests_raw)
    except (TypeError, ValueError):
        return None
    platform = normalized_platform(platform_raw)
    canonical_ref = _canonical_repo_digest(image_ref)
    if (
        not isinstance(repo_digests, list)
        or canonical_ref is None
        or not {image_ref, canonical_ref}.intersection(repo_digests)
        or not _IMAGE_ID.fullmatch(image_id)
        or platform is None
    ):
        return None
    return ExactDockerImageIdentity(image_id=image_id, platform=platform)


def _canonical_repo_digest(image_ref: str) -> str | None:
    """Return Docker's canonical ``repository@digest`` spelling.

    Docker accepts an authored ``repository:tag@digest`` pull reference but
    records it in ``RepoDigests`` without the redundant tag. Registry ports are
    retained because only a colon in the final path component can delimit a tag.
    """

    repository_and_tag, separator, digest = image_ref.rpartition("@")
    if not separator or not _IMAGE_ID.fullmatch(digest):
        return None
    prefix, slash, leaf = repository_and_tag.rpartition("/")
    repository_leaf = leaf.split(":", 1)[0]
    repository = f"{prefix}{slash}{repository_leaf}"
    return f"{repository}@{digest}" if repository_leaf else None


def inspected_image_id(stdout: object) -> str | None:
    """Return one exact daemon-local config image id from inspect output."""

    image_id = str(stdout or "").strip()
    return image_id if _IMAGE_ID.fullmatch(image_id) else None
